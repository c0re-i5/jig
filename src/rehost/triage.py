# SPDX-License-Identifier: MIT
"""Classify a crashing run, bucket duplicates, and write a replay report.

Unicorn Cortex-M does not implement the fault status registers or an MPU.
A crash is whatever ``Machine.run`` already recorded: an unmapped or
protection hook, an ``UcError`` string, or a sentence from the NVIC model.
This module names that stop. It does not invent CFSR bits.

Bucket id
    The id is the first 16 hex digits of SHA-256 over one ASCII line::

        fault_class|reason|fault_pc|lr_fp|preceding_pcs|handler_frame|edges

    * ``fault_pc`` is the faulting PC with the Thumb bit cleared, 8 lowercase
      hex digits.
    * ``lr_fp`` is that same encoding of ``LR & ~1`` when LR has the Thumb bit
      set, is not an EXC_RETURN value (top nibble ``F``), and falls in an
      executable non-peripheral region. Otherwise ``-``. With no memory map,
      the Thumb bit and the nibble check are the whole test.
    * ``preceding_pcs`` is the last 4 retired PCs, Thumb bit cleared, comma
      separated. A trailing PC equal to ``fault_pc`` is dropped first. ``-``
      when none remain. The machine keeps the last 8 retired PCs.
    * ``handler_frame`` is ``stacked_pc,stacked_lr`` (8 hex digits each, raw)
      when IPSR is non-zero, SP is 4-byte aligned, and the 32-byte integer
      frame at SP can be read. Otherwise ``-``. This is the frame the NVIC
      model stacked, not a walk of caller frames.
    * ``edges`` is the last 4 coverage-edge indexes, decimal, comma separated,
      or ``-``. The index is the AFL update used by ``rehost.coverage`` for a
      65536-byte map::

          cur = ((pc >> 1) ^ (pc >> 17)) & 65535
          index = cur ^ prev
          prev = cur >> 1

      The machine records that tail for every retired instruction, including
      a run that never attached a bitmap, so a fuzz iteration and a replay
      hash the same edges.

    The faulting data address is not part of the hash. Two inputs that die
    at the same instruction with the same class, reason, and tail share a
    bucket even when the bad pointer differs. ``null_deref`` is the exception
    to that sameness: an access below ``0x100`` is its own class.

    The representative input for a bucket is the shortest one. Equal lengths
    keep the earliest. ``seen`` counts every crashing execution merged into
    the bucket. ``jig-emu triage`` deletes ``buckets/`` and ``reports/`` and
    rebuilds them from the files in ``crashes/``, in sorted name order.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import struct
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from rehost.errors import BackendError, MachineError, RehostError
from rehost.memory import PERM_EXEC, PERM_WRITE
from rehost.result import RunResult

NULL_LIMIT = 0x100
STACK_SLACK = 0x40
FINGERPRINT_PCS = 4
FINGERPRINT_EDGES = 4
BUCKET_ID_HEX = 16
_HEX_PREVIEW = 64

_ACCESS = {
    "unmapped_fetch",
    "unmapped_read",
    "unmapped_write",
    "prot_fetch",
    "prot_read",
    "prot_write",
}
_FAULT_EXC = {3: "hardfault", 4: "memmanage", 5: "bus_fault", 6: "usage_fault"}
_EXC_NAME = {
    2: "NMI",
    3: "HardFault",
    4: "MemManage",
    5: "BusFault",
    6: "UsageFault",
    11: "SVCall",
    14: "PendSV",
    15: "SysTick",
}
_TITLES = {
    "null_deref": "Null pointer",
    "unmapped_fetch": "Unmapped instruction fetch",
    "unmapped_read": "Unmapped data read",
    "unmapped_write": "Unmapped data write",
    "prot_fetch": "Fetch from non-executable memory",
    "prot_read": "Read from protected memory",
    "prot_write": "Write to protected memory",
    "stack_overflow": "Stack overflow",
    "bad_sp": "Bad stack pointer",
    "hardfault": "HardFault",
    "memmanage": "MemManage",
    "bus_fault": "BusFault",
    "usage_fault": "UsageFault",
    "bkpt": "Breakpoint",
    "halt_crash": "Halt at a crash address",
    "other": "Unclassified fault",
}

_MISALIGNED_ENTRY = re.compile(
    r"^exception (\d+) entry with misaligned stack pointer (0x[0-9a-fA-F]+)$"
)
_MISALIGNED_RETURN = re.compile(
    r"^exception return with misaligned stack pointer (0x[0-9a-fA-F]+)$"
)
_COULD_STACK = re.compile(r"^exception (\d+) could not stack at (0x[0-9a-fA-F]+)")
_COULD_UNSTACK = re.compile(r"^exception return could not unstack at (0x[0-9a-fA-F]+)")
_LOCKUP = re.compile(r"^exception (\d+) escalated to lockup$")
_ALREADY = re.compile(r"^lockup: exception (\d+) is already active$")
_VECTOR_THUMB = re.compile(
    r"^exception (\d+) vector (0x[0-9a-fA-F]+) is not a Thumb address$"
)
_VECTOR_FETCH = re.compile(
    r"^exception (\d+) vector fetch at (0x[0-9a-fA-F]+) failed\b"
)
_UNMAPPED_FETCH = re.compile(r"^unmapped fetch at (0x[0-9a-fA-F]+)$")
_UNMAPPED_DATA = re.compile(
    r"^unmapped (read_unmapped|write_unmapped|read|write) at (0x[0-9a-fA-F]+) size (\d+)$"
)
_PROT = re.compile(r"^prot (fetch|read|write) at (0x[0-9a-fA-F]+) size (\d+)$")
_READ_INSN = re.compile(r"^could not read instruction at (0x[0-9a-fA-F]+)")
_EXACT_EXC = re.compile(r"^exception (\d+)$")
_HALT = re.compile(r"^halt address (0x[0-9a-fA-F]+)$")

LIMITS = (
    "Unicorn's Cortex-M backend has no MPU and does not update CFSR, HFSR, "
    "MMFAR, or BFAR. MemManage, BusFault, and UsageFault are reported when "
    "the NVIC model was entering exception 4, 5, or 6, or when the stop is "
    "the matching undefined-instruction or INVSTATE case. An unmapped access "
    "stays an unmapped class: the model stops in the hook instead of taking "
    "the fault exception. The fingerprint is LR when it points at executable "
    "Thumb code, the retired-instruction tail, the last four edge indexes, "
    "and the integer frame at SP when IPSR is non-zero. It is not a "
    "frame-pointer unwind."
)
REPRESENTATIVE_RULE = (
    "The representative is the shortest crashing input for the bucket. "
    "Equal lengths keep the earliest input."
)


@dataclass(frozen=True)
class ReplayTarget:
    """Machine-source flags that rebuild this target from ``jig-emu run``."""

    args: tuple[str, ...]

    def command(self, input_path: Path) -> str:
        import shlex

        parts = ["jig-emu", "run", *self.args, "--input", str(input_path)]
        return " ".join(shlex.quote(part) for part in parts)


@dataclass(frozen=True)
class FaultClassification:
    """One crashing execution, named and hashed."""

    fault_class: str
    reason: str
    title: str
    explanation: str
    detail: str
    pc: int
    lr: int
    sp: int
    xpsr: int
    ipsr: int
    fault_address: int | None
    access: str | None
    access_size: int | None
    preceding_pcs: tuple[int, ...]
    recent_pcs: tuple[int, ...]
    edges: tuple[int, ...]
    recent_edges: tuple[int, ...]
    lr_fingerprint: int | None
    handler_frame: tuple[int, int] | None
    material: str
    bucket_id: str


@dataclass(frozen=True)
class TriageNote:
    bucket_id: str
    fault_class: str
    created: bool
    replaced: bool
    seen: int
    report_path: Path


@dataclass
class _Parsed:
    fault_class: str
    reason: str
    address: int | None = None
    access: str | None = None
    size: int | None = None
    exc: int | None = None
    reported: str | None = None
    overflow_candidate: bool = False


def bucket_material(
    *,
    fault_class: str,
    reason: str,
    fault_pc: int,
    lr_fingerprint: int | None,
    preceding_pcs: tuple[int, ...],
    handler_frame: tuple[int, int] | None,
    edges: tuple[int, ...],
) -> str:
    """The exact ASCII line hashed into a bucket id."""
    return "|".join(
        (
            fault_class,
            reason,
            f"{fault_pc & ~1:08x}",
            _lr_token(lr_fingerprint),
            _pcs_token(preceding_pcs),
            _frame_token(handler_frame),
            _edges_token(edges),
        )
    )


def bucket_id(material: str) -> str:
    """First 16 hex digits of SHA-256(``material``)."""
    return hashlib.sha256(material.encode("ascii")).hexdigest()[:BUCKET_ID_HEX]


def classify(
    result: RunResult,
    *,
    memory=None,
    read_memory=None,
) -> FaultClassification:
    """Name ``result`` from its detail line, registers, and optional map."""
    parsed = _parse(result.detail or "", result)
    if (
        parsed.fault_class in _ACCESS
        and parsed.address is not None
        and (parsed.address & 0xFFFFFFFF) < NULL_LIMIT
    ):
        parsed.fault_class = "null_deref"
    if (
        parsed.overflow_candidate
        and parsed.fault_class == "bad_sp"
        and _fell_off(result.sp, parsed.address, memory)
    ):
        parsed.fault_class = "stack_overflow"
    xpsr = int(result.registers.get("xpsr", 0)) & 0xFFFFFFFF
    ipsr = xpsr & 0x1FF
    fault_pc = result.pc & ~1
    recent_pcs = tuple(int(pc) & 0xFFFFFFFF for pc in result.recent_pcs)
    recent_edges = tuple(int(edge) for edge in result.recent_edges)
    preceding = _preceding(recent_pcs, fault_pc)
    edges = recent_edges[-FINGERPRINT_EDGES:]
    lr_fp = _lr_fingerprint(result.lr, memory)
    frame = _handler_frame(ipsr, result.sp, read_memory)
    material = bucket_material(
        fault_class=parsed.fault_class,
        reason=parsed.reason,
        fault_pc=fault_pc,
        lr_fingerprint=lr_fp,
        preceding_pcs=preceding,
        handler_frame=frame,
        edges=edges,
    )
    return FaultClassification(
        fault_class=parsed.fault_class,
        reason=parsed.reason,
        title=_TITLES.get(parsed.fault_class, parsed.fault_class),
        explanation=_explain(parsed, result.detail or ""),
        detail=result.detail or "",
        pc=result.pc & 0xFFFFFFFF,
        lr=result.lr & 0xFFFFFFFF,
        sp=result.sp & 0xFFFFFFFF,
        xpsr=xpsr,
        ipsr=ipsr,
        fault_address=None if parsed.address is None else parsed.address & 0xFFFFFFFF,
        access=parsed.access,
        access_size=parsed.size,
        preceding_pcs=preceding,
        recent_pcs=recent_pcs,
        edges=edges,
        recent_edges=recent_edges,
        lr_fingerprint=lr_fp,
        handler_frame=frame,
        material=material,
        bucket_id=bucket_id(material),
    )


def guest_reader(machine):
    """Read guest RAM for the handler frame. Failures become a missing frame."""

    def read(address: int, size: int) -> bytes | None:
        try:
            return machine.read_memory(address, size)
        except (MachineError, BackendError, OSError, ValueError):
            return None

    return read


def note_crash(store: TriageStore, machine, data: bytes, result: RunResult, *, crash_path: Path | None = None) -> TriageNote:
    """Classify ``result`` and merge it into ``store``."""
    return store.record(
        data,
        result,
        memory=machine.memory,
        read_memory=guest_reader(machine),
        crash_path=crash_path,
        machine_name=machine.config.name,
    )


class TriageStore:
    """``out/buckets`` and ``out/reports`` for one campaign directory."""

    def __init__(self, out: Path, replay: ReplayTarget | None = None) -> None:
        self.out = Path(out)
        self.replay = replay

    def reset(self) -> None:
        """Drop bucket state so a re-triage counts the crash files only."""
        with self._lock():
            buckets = self.out / "buckets"
            for child in buckets.iterdir():
                if child.name == ".lock":
                    continue
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
            reports = self.out / "reports"
            if reports.exists():
                shutil.rmtree(reports)
            self._write_index({"version": 1, "buckets": {}})

    def record(
        self,
        data: bytes,
        result: RunResult,
        *,
        memory=None,
        read_memory=None,
        crash_path: Path | None = None,
        machine_name: str = "",
    ) -> TriageNote:
        classification = classify(result, memory=memory, read_memory=read_memory)
        blob = bytes(data)
        with self._lock():
            index = self._read_index()
            buckets = index["buckets"]
            current = buckets.get(classification.bucket_id)
            created = False
            replaced = False
            if current is None:
                doc = _document(
                    classification,
                    result,
                    data=blob,
                    seen=1,
                    replay=self.replay,
                    crash_path=crash_path,
                    machine_name=machine_name,
                    out=self.out,
                )
                self._write_case(doc, blob)
                buckets[classification.bucket_id] = _index_entry(doc, self.out)
                created = True
                seen = 1
            elif len(blob) < int(current["input_length"]):
                doc = _document(
                    classification,
                    result,
                    data=blob,
                    seen=int(current["seen"]) + 1,
                    replay=self.replay,
                    crash_path=crash_path,
                    machine_name=machine_name,
                    out=self.out,
                )
                self._write_case(doc, blob)
                buckets[classification.bucket_id] = _index_entry(doc, self.out)
                replaced = True
                seen = doc["seen"]
            else:
                path = Path(current["report_json"])
                doc = json.loads(path.read_text(encoding="utf-8"))
                doc["seen"] = int(current["seen"]) + 1
                self._write_reports(doc)
                current["seen"] = doc["seen"]
                seen = doc["seen"]
            self._write_index(index)
        return TriageNote(
            bucket_id=classification.bucket_id,
            fault_class=classification.fault_class,
            created=created,
            replaced=replaced,
            seen=seen,
            report_path=self.out / "reports" / f"{classification.bucket_id}.md",
        )

    def bucket_count(self) -> int:
        try:
            return len(self._read_index()["buckets"])
        except RehostError:
            return 0

    def report_paths(self) -> list[Path]:
        try:
            buckets = self._read_index()["buckets"]
        except RehostError:
            return []
        return [Path(entry["report"]) for entry in buckets.values()]

    def summary(self) -> str:
        buckets = self._read_index()["buckets"]
        lines = [f"buckets: {len(buckets)}"]
        for bucket_id, entry in buckets.items():
            lines.append(
                f"bucket: {bucket_id} class: {entry['fault_class']} "
                f"seen: {entry['seen']} report: {entry['report']}"
            )
        return "\n".join(lines)

    @contextmanager
    def _lock(self):
        directory = self.out / "buckets"
        directory.mkdir(parents=True, exist_ok=True)
        handle = (directory / ".lock").open("a+")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()

    def _read_index(self) -> dict:
        path = self.out / "buckets" / "index.json"
        if not path.is_file():
            return {"version": 1, "buckets": {}}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RehostError(f"crash bucket index is not JSON: {path}") from exc
        if data.get("version") != 1 or not isinstance(data.get("buckets"), dict):
            raise RehostError(f"crash bucket index {path} has an unexpected shape")
        return data

    def _write_index(self, index: dict) -> None:
        _atomic_write(
            self.out / "buckets" / "index.json",
            (json.dumps(index, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )

    def _write_case(self, doc: dict, data: bytes) -> None:
        representative = Path(doc["input"]["path"])
        _atomic_write(representative, data)
        self._write_reports(doc)

    def _write_reports(self, doc: dict) -> None:
        bucket_id = doc["bucket_id"]
        _atomic_write(
            self.out / "reports" / f"{bucket_id}.json",
            (json.dumps(doc, indent=2) + "\n").encode("utf-8"),
        )
        _atomic_write(
            self.out / "reports" / f"{bucket_id}.md",
            render_markdown(doc).encode("utf-8"),
        )


def render_markdown(doc: dict) -> str:
    """Human report. The same fields are in the JSON sidecar."""
    site = [
        f"- pc: {doc['pc']}",
        f"- lr: {doc['lr']}",
        f"- sp: {doc['sp']}",
        f"- xpsr: {doc['xpsr']}",
        f"- ipsr: {doc['ipsr']}",
        f"- detail: {doc['detail'] or '-'}",
        f"- fault address: {_address_line(doc)}",
        f"- preceding pcs: {_join_words(doc['preceding_pcs'])}",
        f"- lr fingerprint: {doc['lr_fingerprint'] or '-'}",
        f"- handler frame: {_frame_line(doc['handler_frame'])}",
        f"- edges: {_join_edges(doc['edges'])}",
        f"- instructions: {doc['instructions']}",
        f"- bucket material: {doc['material']}",
    ]
    registers = doc.get("registers") or {}
    register_lines = [f"- {name}: {registers[name]}" for name in sorted(registers)]
    crash_file = doc["input"].get("crash_file") or "-"
    hex_line = doc["input"]["hex"]
    if doc["input"].get("hex_truncated"):
        hex_line += " (first 64 bytes)"
    replay = doc.get("replay") or "jig-emu run <machine flags> --input <representative>"
    lines = [
        f"# {doc['fault_class']} `{doc['bucket_id']}`",
        "",
        f"Title: {doc['title']}",
        f"Fault class: {doc['fault_class']}",
        f"Reason: {doc['reason']}",
        f"Bucket: {doc['bucket_id']}",
        f"Seen: {doc['seen']}",
        f"Machine: {doc.get('machine') or '-'}",
        f"Status: {doc['status']}",
        "",
        "## What happened",
        "",
        doc["explanation"],
        "",
        doc["limits"],
        "",
        REPRESENTATIVE_RULE,
        "",
        "Bucket id is the first 16 hex digits of SHA-256 over the bucket material line.",
        "",
        "## Site",
        "",
        *site,
        "",
        "## Registers",
        "",
        *(register_lines or ["-"]),
        "",
        "## Input",
        "",
        f"- path: {doc['input']['path']}",
        f"- crash file: {crash_file}",
        f"- sha256: {doc['input']['sha256']}",
        f"- length: {doc['input']['length']}",
        f"- hex: {hex_line}",
        "",
        "## Replay",
        "",
        "```",
        replay,
        "```",
        "",
    ]
    return "\n".join(lines)


def _document(
    classification: FaultClassification,
    result: RunResult,
    *,
    data: bytes,
    seen: int,
    replay: ReplayTarget | None,
    crash_path: Path | None,
    machine_name: str,
    out: Path,
) -> dict:
    bucket_id = classification.bucket_id
    representative = (out / "buckets" / bucket_id / "representative").resolve()
    preview, truncated = _hex_preview(data)
    frame = classification.handler_frame
    return {
        "version": 1,
        "bucket_id": bucket_id,
        "fault_class": classification.fault_class,
        "reason": classification.reason,
        "title": classification.title,
        "explanation": classification.explanation,
        "limits": LIMITS,
        "status": result.status,
        "detail": classification.detail,
        "machine": machine_name,
        "pc": _hex(classification.pc),
        "lr": _hex(classification.lr),
        "sp": _hex(classification.sp),
        "xpsr": _hex(classification.xpsr),
        "ipsr": classification.ipsr,
        "fault_address": None if classification.fault_address is None else _hex(classification.fault_address),
        "access": classification.access,
        "access_size": classification.access_size,
        "preceding_pcs": [_hex(pc) for pc in classification.preceding_pcs],
        "recent_pcs": [_hex(pc) for pc in classification.recent_pcs],
        "edges": list(classification.edges),
        "recent_edges": list(classification.recent_edges),
        "lr_fingerprint": None if classification.lr_fingerprint is None else _hex(classification.lr_fingerprint),
        "handler_frame": None
        if frame is None
        else {"pc": _hex(frame[0]), "lr": _hex(frame[1])},
        "material": classification.material,
        "instructions": result.instructions,
        "seen": seen,
        "input": {
            "path": str(representative),
            "crash_file": None if crash_path is None else str(Path(crash_path).resolve()),
            "sha256": hashlib.sha256(data).hexdigest(),
            "length": len(data),
            "hex": preview,
            "hex_truncated": truncated,
        },
        "replay": None if replay is None else replay.command(representative),
        "registers": {
            name: _hex(int(result.registers[name])) for name in sorted(result.registers)
        },
    }


def _index_entry(doc: dict, out: Path) -> dict:
    bucket_id = doc["bucket_id"]
    return {
        "fault_class": doc["fault_class"],
        "reason": doc["reason"],
        "seen": doc["seen"],
        "input_length": doc["input"]["length"],
        "input_sha256": doc["input"]["sha256"],
        "pc": doc["pc"],
        "representative": doc["input"]["path"],
        "report": str((out / "reports" / f"{bucket_id}.md").resolve()),
        "report_json": str((out / "reports" / f"{bucket_id}.json").resolve()),
    }


def _parse(detail: str, result: RunResult) -> _Parsed:
    detail = detail.strip()
    match = _MISALIGNED_ENTRY.fullmatch(detail)
    if match:
        return _Parsed("bad_sp", "misaligned", address=_addr(match.group(2)), exc=int(match.group(1)))
    match = _MISALIGNED_RETURN.fullmatch(detail)
    if match:
        return _Parsed("bad_sp", "misaligned", address=_addr(match.group(1)))
    match = _COULD_STACK.match(detail)
    if match:
        return _Parsed(
            "bad_sp",
            "frame",
            address=_addr(match.group(2)),
            exc=int(match.group(1)),
            overflow_candidate=True,
        )
    match = _COULD_UNSTACK.match(detail)
    if match:
        return _Parsed("bad_sp", "frame", address=_addr(match.group(1)))
    if detail == "exception return stacked xPSR.T is clear":
        return _Parsed("usage_fault", "invstate")
    if "floating-point" in detail and "EXC_RETURN" in detail:
        return _Parsed("other", "fp-frame")
    if detail.startswith("exception return") or "EXC_RETURN" in detail or detail.startswith("invalid EXC_RETURN"):
        return _Parsed("hardfault", "exc-return")
    match = _LOCKUP.fullmatch(detail)
    if match:
        return _Parsed("hardfault", "lockup", exc=int(match.group(1)))
    match = _ALREADY.fullmatch(detail)
    if match:
        return _Parsed("hardfault", "lockup", exc=int(match.group(1)))
    match = _VECTOR_THUMB.fullmatch(detail)
    if match:
        return _vector_parsed(int(match.group(1)), _addr(match.group(2)), "vector")
    match = _VECTOR_FETCH.match(detail)
    if match:
        return _vector_parsed(int(match.group(1)), _addr(match.group(2)), "vector-fetch")
    match = _UNMAPPED_FETCH.fullmatch(detail)
    if match:
        return _Parsed(
            "unmapped_fetch",
            "fetch",
            address=_addr(match.group(1)),
            access="fetch",
            reported="unmapped",
        )
    match = _UNMAPPED_DATA.fullmatch(detail)
    if match:
        kind = "write" if "write" in match.group(1) else "read"
        return _Parsed(
            f"unmapped_{kind}",
            kind,
            address=_addr(match.group(2)),
            access=kind,
            size=int(match.group(3)),
            reported="unmapped",
        )
    match = _PROT.fullmatch(detail)
    if match:
        kind = match.group(1)
        return _Parsed(
            f"prot_{kind}",
            kind,
            address=_addr(match.group(2)),
            access=kind,
            size=int(match.group(3)),
            reported="prot",
        )
    match = _READ_INSN.match(detail)
    if match:
        address = _addr(match.group(1))
        if "PROT" in detail:
            return _Parsed("prot_fetch", "fetch", address=address, access="fetch", reported="prot")
        return _Parsed(
            "unmapped_fetch", "fetch", address=address, access="fetch", reported="unmapped"
        )
    if "UC_ERR_INSN_INVALID" in detail or "Invalid instruction" in detail:
        return _Parsed("usage_fault", "undef")
    if "UC_ERR_FETCH_PROT" in detail or "FETCH_PROT" in detail:
        return _Parsed("prot_fetch", "fetch", address=result.pc & ~1, access="fetch", reported="prot")
    if "UC_ERR_READ_PROT" in detail or "READ_PROT" in detail:
        return _Parsed("prot_read", "read", access="read", reported="prot")
    if "UC_ERR_WRITE_PROT" in detail or "WRITE_PROT" in detail:
        return _Parsed("prot_write", "write", access="write", reported="prot")
    if "UC_ERR_FETCH_UNMAPPED" in detail or "FETCH_UNMAPPED" in detail:
        return _Parsed(
            "unmapped_fetch",
            "fetch",
            address=result.pc & ~1,
            access="fetch",
            reported="unmapped",
        )
    if "UC_ERR_READ_UNMAPPED" in detail or "READ_UNMAPPED" in detail:
        return _Parsed("unmapped_read", "read", access="read", reported="unmapped")
    if "UC_ERR_WRITE_UNMAPPED" in detail or "WRITE_UNMAPPED" in detail:
        return _Parsed("unmapped_write", "write", access="write", reported="unmapped")
    match = _EXACT_EXC.fullmatch(detail)
    if match:
        number = int(match.group(1))
        if number == 7:
            return _Parsed("bkpt", "bkpt", exc=7)
        return _Parsed("other", f"unicorn-exc-{number}", exc=number)
    if detail == "bkpt":
        return _Parsed("bkpt", "bkpt")
    match = _HALT.fullmatch(detail)
    if match:
        return _Parsed("halt_crash", "halt", address=_addr(match.group(1)))
    if "SYSRESETREQ" in detail:
        return _Parsed("other", "reset")
    return _Parsed("other", "unknown")


def _vector_parsed(exc: int, address: int, reason: str) -> _Parsed:
    fault_class = _FAULT_EXC.get(exc, "other")
    if fault_class == "other":
        reason = f"{reason}-{exc}"
    return _Parsed(fault_class, reason, address=address, exc=exc, access="fetch")


def _explain(parsed: _Parsed, detail: str) -> str:
    address = None if parsed.address is None else _hex(parsed.address)
    access = parsed.access or "access"
    if parsed.fault_class == "null_deref":
        where = address or "a low address"
        if parsed.reported == "prot":
            how = (
                f"The {access} at {where} lands in memory the machine file does not "
                "permit. A store through a null pointer into flash or the vector "
                "table looks like this when that window is mapped read-only."
            )
        else:
            how = (
                f"The {access} at {where} misses the machine map. A null pointer "
                "plus a small field offset is the usual shape."
            )
        return (
            f"{how} Unicorn stops in the memory hook and leaves IPSR unchanged. "
            "The stop is not delivered as MemManage or BusFault."
        )
    if parsed.fault_class == "unmapped_fetch":
        return (
            f"The CPU tried to fetch an instruction from {address or 'an unmapped address'}, "
            f"which is not in the machine map ({detail}). Unicorn stops in the unmapped-fetch "
            "hook and leaves IPSR unchanged. On a Cortex-M this is the stop a BusFault "
            "handler would see, or HardFault when BusFault is disabled."
        )
    if parsed.fault_class in {"unmapped_read", "unmapped_write"}:
        return (
            f"The guest tried to {access} {address or 'an unmapped address'}, which is not "
            f"in the machine map ({detail}). Unicorn stops in the unmapped hook and leaves "
            "IPSR unchanged. On a Cortex-M this is the stop a BusFault handler would see, "
            "or HardFault when BusFault is disabled."
        )
    if parsed.fault_class in {"prot_fetch", "prot_read", "prot_write"}:
        return (
            f"The {access} at {address or 'the faulting address'} is inside a mapped "
            f"region whose machine-file permissions reject it ({detail}). This is the "
            "rehost map, not an MPU MemManage fault. Unicorn stops on the protection "
            "hook and leaves the fault status registers unchanged."
        )
    if parsed.fault_class == "stack_overflow":
        return (
            f"Exception entry could not store the integer frame at {address or 'the frame'} "
            f"({detail}). The stack pointer still points into a writable RAM region and "
            "the frame sits just below that region, which is a descending stack that "
            "walked off the bottom. The NVIC model stops instead of taking a fault exception."
        )
    if parsed.fault_class == "bad_sp":
        return (
            f"The stack pointer could not be used for exception entry or return ({detail}). "
            "Either it is not 4-byte aligned, or the frame address is not writable RAM. "
            "A misaligned pointer and a pointer that has left every RAM region both land "
            "in this class. A frame that falls just off the low end of RAM is "
            "stack_overflow instead."
        )
    if parsed.fault_class == "hardfault":
        name = _exc_name(parsed.exc)
        if parsed.reason == "lockup":
            return (
                f"{name} could not be taken, and HardFault could not be entered either "
                f"({detail}). The NVIC model stops in lockup. On a chip that is the "
                "terminal HardFault escalation."
            )
        if parsed.reason == "exc-return":
            return (
                f"Exception return failed an integrity check ({detail}). The NVIC model "
                "stops. On a chip this return becomes HardFault."
            )
        if parsed.reason == "vector":
            return (
                f"HardFault was entered, and the vector table entry is not a Thumb "
                f"address ({detail})."
            )
        if parsed.reason == "vector-fetch":
            return (
                f"The HardFault vector could not be fetched ({detail}). The model stops "
                "there instead of nesting another fault."
            )
        return f"The run stopped in HardFault ({detail})."
    if parsed.fault_class == "memmanage":
        return (
            f"The NVIC model was entering MemManage, exception 4 ({detail}). "
            "Unicorn has no MPU, so a plain unmapped access is not given this class. "
            "MMFSR is not implemented; the detail line is the record of the stop."
        )
    if parsed.fault_class == "bus_fault":
        return (
            f"The NVIC model was entering BusFault, exception 5 ({detail}). "
            "An unmapped fetch or data access is classified on its own, because the "
            "unmapped hook stops the run before a BusFault exception is taken. BFAR "
            "is not implemented."
        )
    if parsed.fault_class == "usage_fault":
        if parsed.reason == "undef":
            return (
                f"Unicorn rejected the instruction as undefined ({detail}) and stopped. "
                "It does not enter UsageFault or HardFault, and UFSR is unchanged. On a "
                "Cortex-M with UsageFault disabled, the reset default, the same "
                "instruction escalates to HardFault."
            )
        if parsed.reason == "invstate":
            return (
                f"Exception return found the stacked xPSR.T bit clear ({detail}). "
                "That is the INVSTATE case. The model stops. A chip takes UsageFault, "
                "or HardFault when UsageFault is disabled."
            )
        return (
            f"The NVIC model was entering UsageFault, exception 6 ({detail}). "
            "UFSR is not implemented."
        )
    if parsed.fault_class == "bkpt":
        return (
            "The guest executed BKPT. With halt_on_bkpt the status is halted and the "
            "fuzzer keeps the input only when this PC is listed in fuzz.crash_addresses. "
            "With halt_on_bkpt off, Unicorn's breakpoint vector is reported as "
            "'exception 7', which is the engine's BKPT number and not UsageFault."
        )
    if parsed.fault_class == "halt_crash":
        return (
            f"The guest halted at a PC listed in fuzz.crash_addresses ({detail}). "
            "The status is halted. The fuzzer records a crash because the machine "
            "file names this address as the bug."
        )
    if parsed.reason == "fp-frame":
        return (
            f"An EXC_RETURN asked for the extended floating-point stack frame ({detail}). "
            "That frame is not modeled, so the run stops. This is not a classified "
            "guest memory fault."
        )
    if parsed.reason == "reset":
        return (
            f"The guest wrote AIRCR.SYSRESETREQ ({detail}). The model stops the run "
            "instead of resetting the core."
        )
    if parsed.reason.startswith("unicorn-exc-"):
        return (
            f"Unicorn's interrupt hook reported vector {parsed.exc} ({detail}). "
            "That number is the engine vector, not an IPSR exception number. "
            "Vector 7 is BKPT and is classified as bkpt; this vector is not one of "
            "the fault stops the NVIC model names."
        )
    return (
        f"The stop does not match the Cortex-M cases this classifier knows ({detail}). "
        "The detail line is the raw record from the backend or the NVIC model."
    )


def _preceding(recent: tuple[int, ...], fault_pc: int) -> tuple[int, ...]:
    pcs = [pc & ~1 for pc in recent]
    if pcs and pcs[-1] == (fault_pc & ~1):
        pcs.pop()
    return tuple(pcs[-FINGERPRINT_PCS:])


def _lr_fingerprint(lr: int, memory) -> int | None:
    lr &= 0xFFFFFFFF
    if lr == 0 or (lr >> 28) == 0xF or (lr & 1) == 0:
        return None
    target = lr & ~1
    if memory is None:
        return target
    for region in memory.regions:
        if region.peripheral is not None:
            continue
        if region.perms & PERM_EXEC and region.base <= target < region.end:
            return target
    return None


def _handler_frame(ipsr: int, sp: int, read_memory) -> tuple[int, int] | None:
    if ipsr == 0 or read_memory is None:
        return None
    sp &= 0xFFFFFFFF
    if sp & 3:
        return None
    try:
        blob = read_memory(sp, 32)
    except (MachineError, BackendError, OSError, ValueError, TypeError):
        return None
    if not isinstance(blob, (bytes, bytearray)) or len(blob) != 32:
        return None
    words = struct.unpack("<8I", bytes(blob))
    return words[6], words[5]


def _fell_off(sp: int, frame: int | None, memory) -> bool:
    if memory is None or frame is None:
        return False
    sp &= 0xFFFFFFFF
    frame &= 0xFFFFFFFF
    for region in memory.regions:
        if region.peripheral is not None or not (region.perms & PERM_WRITE):
            continue
        if not (region.base <= sp < region.end):
            continue
        gap = region.base - frame
        if 0 < gap <= STACK_SLACK:
            return True
    return False


def _exc_name(exc: int | None) -> str:
    if exc is None:
        return "The synchronous exception"
    if exc >= 16:
        return f"IRQ {exc - 16}"
    return _EXC_NAME.get(exc, f"Exception {exc}")


def _addr(text: str) -> int:
    return int(text, 16)


def _hex(value: int) -> str:
    return f"0x{value & 0xFFFFFFFF:08x}"


def _lr_token(lr: int | None) -> str:
    if lr is None:
        return "-"
    return f"{lr & 0xFFFFFFFF:08x}"


def _pcs_token(pcs: tuple[int, ...]) -> str:
    if not pcs:
        return "-"
    return ",".join(f"{pc & 0xFFFFFFFF:08x}" for pc in pcs)


def _frame_token(frame: tuple[int, int] | None) -> str:
    if frame is None:
        return "-"
    return f"{frame[0] & 0xFFFFFFFF:08x},{frame[1] & 0xFFFFFFFF:08x}"


def _edges_token(edges: tuple[int, ...]) -> str:
    if not edges:
        return "-"
    return ",".join(str(edge) for edge in edges)


def _hex_preview(data: bytes) -> tuple[str, bool]:
    if len(data) <= _HEX_PREVIEW:
        return data.hex(), False
    return data[:_HEX_PREVIEW].hex(), True


def _address_line(doc: dict) -> str:
    if doc.get("fault_address") is None:
        return "-"
    access = doc.get("access")
    size = doc.get("access_size")
    text = doc["fault_address"]
    if access:
        text += f" ({access}"
        if size is not None:
            text += f", {size} bytes"
        text += ")"
    return text


def _frame_line(frame) -> str:
    if not frame:
        return "-"
    return f"pc {frame['pc']} lr {frame['lr']}"


def _join_words(values) -> str:
    return ", ".join(values) if values else "-"


def _join_edges(values) -> str:
    return ", ".join(str(value) for value in values) if values else "-"


def _atomic_write(path: Path, blob: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as handle:
        handle.write(blob)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
