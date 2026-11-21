# SPDX-License-Identifier: MIT
"""QEMU Cortex-M backend.

``qemu-system-arm`` executes Thumb on the ``mps2-an385`` board (Cortex-M3),
which QEMU already ships. That board's SSRAM covers the synthetic maps at
``0x00000000`` and ``0x20000000``:

* ``0x00000000`` for 8 MiB: SSRAM1 and its alias
* ``0x20000000`` for 8 MiB: SSRAM2/3 and its alias
* ``0x21000000`` for 16 MiB: PSRAM

Registers, memory, and single-step go through the gdbstub. Banked
registers (MSP, PSP, CONTROL, PRIMASK, BASEPRI, FAULTMASK) are written by
retiring ``msr``, because this QEMU's gdbstub read them but does not apply
``P`` writes. QMP checks that the CPU is held at startup (``-S``) and quits
the process.

Pages outside those windows are not MPS2 RAM. The UART at ``0x40000000`` and
the GPIO at ``0x40001000`` land in the FPGA peripheral window, and SysTick
lands in the real system control space. Those pages are a host shadow.
Decoded loads and stores that touch a shadow page, a plugin hook, an unmapped
address, or a permission the map does not allow are not issued to the board.
They call the same ``CpuBackend`` hooks ``Machine`` installs for Unicorn, so
the UART, GPIO, and SysTick plugins see the access.

``inject_irq`` only records the request. Exception entry stays on the Unicorn
backend. ``WFI`` and ``WFE`` are retired without stepping: QEMU's gdbstub
blocks in ``WFI`` until an interrupt arrives, and this adapter does not
deliver one.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass

from rehost.backends.base import CpuBackend, MemAccess
from rehost.backends.registry import register_backend
from rehost.backends.unicorn_cortexm import BKPT_VECTOR, SVC_VECTOR
from rehost.errors import BackendError
from rehost.memory import PERM_EXEC, PERM_READ, PERM_WRITE
from rehost.nvic import raz_sp

logger = logging.getLogger(__name__)

QEMU_MACHINE = "mps2-an385"
QEMU_CPU = "cortex-m3"
_QEMU_BINARY = "qemu-system-arm"

# (base, size) windows that read back stores on mps2-an385. See the module
# docstring. A page is board RAM only when its first byte falls in one.
_RAM_WINDOWS = (
    (0x00000000, 0x00800000),
    (0x20000000, 0x00800000),
    (0x21000000, 0x01000000),
)

_SNAPSHOT_REGS = (
    "r0",
    "r1",
    "r2",
    "r3",
    "r4",
    "r5",
    "r6",
    "r7",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "sp",
    "lr",
    "pc",
    "xpsr",
    "msp",
    "psp",
    "control",
    "primask",
    "basepri",
    "faultmask",
)
_STACK_REGS = frozenset({"sp", "msp", "psp"})
_WFI = 0xBF30
_WFE = 0xBF20
# SYSm fields for MSR. QEMU 8.2's gdbstub accepts P packets for these
# registers and still leaves them unchanged, so a write retires ``msr`` on
# the guest. The pad is the last word of MPS2 PSRAM; the previous bytes are
# saved and restored.
_MSR_SYSM = {
    "msp": 8,
    "psp": 9,
    "primask": 16,
    "basepri": 17,
    "faultmask": 19,
    "control": 20,
}
_MSR_PAD = 0x21FFFF00

# Thumb-2 immediate (encoding T3) load/store: (width, store, signed).
_T3_MEM = {
    0xF800: (1, True, False),
    0xF810: (1, False, False),
    0xF880: (2, True, False),
    0xF890: (2, False, False),
    0xF8C0: (4, True, False),
    0xF8D0: (4, False, False),
    0xF910: (1, False, True),
    0xF990: (2, False, True),
}
# Thumb-1 register-offset load/store: opcode field (hw >> 9) & 7.
_T1_REG = {
    0: (4, True, False),
    1: (2, True, False),
    2: (1, True, False),
    3: (1, False, True),
    4: (4, False, False),
    5: (2, False, False),
    6: (1, False, False),
    7: (2, False, True),
}

_REG_TAG = re.compile(r"<reg\b([^>]*)/?>", re.IGNORECASE)
_ATTR = re.compile(r'([A-Za-z_][\w:.-]*)\s*=\s*"([^"]*)"')
_HREF = re.compile(r'href="([^"]+)"')

_LIVE: set[QemuCortexM] = set()


def _close_live() -> None:
    for backend in list(_LIVE):
        backend.close()


atexit.register(_close_live)


def resolve_qemu(binary: str | None = None) -> str:
    """Return the ``qemu-system-arm`` path, or raise naming that binary."""
    if binary is None:
        binary = os.environ.get("JIG_QEMU") or None
    if not binary:
        binary = shutil.which(_QEMU_BINARY)
    if not binary or not os.path.isfile(binary) or not os.access(binary, os.X_OK):
        where = binary or "PATH"
        raise BackendError(
            f"{_QEMU_BINARY} was not found ({where}). "
            f"Install QEMU and put the {_QEMU_BINARY} binary on PATH "
            "to use the qemu backend."
        )
    return binary


def gdb_register_map(documents: list[str]) -> dict[str, int]:
    """Map gdb feature-XML register names to stub register numbers."""
    names: dict[str, int] = {}
    next_num = 0
    for document in documents:
        for match in _REG_TAG.finditer(document):
            attrs = {key.lower(): value for key, value in _ATTR.findall(match.group(1))}
            name = attrs.get("name", "").lower()
            if not name:
                continue
            if "regnum" in attrs:
                number = int(attrs["regnum"], 0)
            else:
                number = next_num
            next_num = number + 1
            names[name] = number
    if "xpsr" not in names and "cpsr" in names:
        names["xpsr"] = names["cpsr"]
    return names


def thumb2_memory_base(hw1: int) -> int | None:
    """Base register of a Thumb-2 load/store this decoder does not fully parse.

    Returns None when ``hw1`` is not in that encoding space. The low nibble
    of those encodings is Rn.
    """
    if hw1 < 0xE800:
        return None
    if (hw1 & 0xFE00) in (0xF800, 0xE800):
        return hw1 & 0xF
    return None


@dataclass(frozen=True)
class MemOp:
    """One data access inside a decoded instruction."""

    address: int
    width: int
    rt: int
    store: bool
    value: int = 0
    signed: bool = False


@dataclass(frozen=True)
class Decoded:
    """A decoded instruction the backend may have to perform itself."""

    size: int
    ops: tuple[MemOp, ...]


def decode_thumb(hw1: int, hw2: int, pc: int, read_reg) -> Decoded | None:
    """Decode a single load or store. Other instructions return None.

    ``read_reg`` takes an architectural register number (0-15) and returns
    its current value. ``pc`` is the address of this instruction.
    """
    if hw1 >= 0xE800:
        return _decode_thumb2(hw1, hw2, read_reg)
    return _decode_thumb1(hw1, pc, read_reg)


def _reg_name(number: int) -> str:
    if number == 13:
        return "sp"
    if number == 14:
        return "lr"
    if number == 15:
        return "pc"
    if 0 <= number <= 12:
        return f"r{number}"
    raise BackendError(f"register number {number} is not a Cortex-M GPR")


def _sign_extend(value: int, width: int) -> int:
    bits = width * 8
    value &= (1 << bits) - 1
    if value & (1 << (bits - 1)):
        value -= 1 << bits
    return value & 0xFFFFFFFF


def _mem(address: int, width: int, rt: int, store: bool, value: int, signed: bool) -> MemOp:
    masked = value & ((1 << (8 * width)) - 1) if store else 0
    return MemOp(address & 0xFFFFFFFF, width, rt, store, masked, signed)


def _decode_thumb1(hw1: int, pc: int, read_reg) -> Decoded | None:
    if (hw1 & 0xF800) == 0x4800:
        rt = (hw1 >> 8) & 7
        address = ((pc + 4) & ~3) + (hw1 & 0xFF) * 4
        return Decoded(2, (_mem(address, 4, rt, False, 0, False),))
    if (hw1 & 0xF000) == 0x5000:
        width, store, signed = _T1_REG[(hw1 >> 9) & 7]
        rm = (hw1 >> 6) & 7
        rn = (hw1 >> 3) & 7
        rt = hw1 & 7
        address = (read_reg(rn) + read_reg(rm)) & 0xFFFFFFFF
        value = read_reg(rt) if store else 0
        return Decoded(2, (_mem(address, width, rt, store, value, signed),))
    kind = _thumb1_immediate(hw1)
    if kind is not None:
        width, store, signed, scale = kind
        imm = ((hw1 >> 6) & 0x1F) * scale
        rn = (hw1 >> 3) & 7
        rt = hw1 & 7
        address = (read_reg(rn) + imm) & 0xFFFFFFFF
        value = read_reg(rt) if store else 0
        return Decoded(2, (_mem(address, width, rt, store, value, signed),))
    if (hw1 & 0xF800) in (0x9000, 0x9800):
        store = (hw1 & 0xF800) == 0x9000
        rt = (hw1 >> 8) & 7
        address = (read_reg(13) + (hw1 & 0xFF) * 4) & 0xFFFFFFFF
        value = read_reg(rt) if store else 0
        return Decoded(2, (_mem(address, 4, rt, store, value, False),))
    return None


def _thumb1_immediate(hw1: int) -> tuple[int, bool, bool, int] | None:
    """Width, store, signed, and immediate scale for a 16-bit imm load/store."""
    op = hw1 & 0xF800
    if op == 0x6000:
        return 4, True, False, 4
    if op == 0x6800:
        return 4, False, False, 4
    if op == 0x7000:
        return 1, True, False, 1
    if op == 0x7800:
        return 1, False, False, 1
    if op == 0x8000:
        return 2, True, False, 2
    if op == 0x8800:
        return 2, False, False, 2
    return None


def _decode_thumb2(hw1: int, hw2: int, read_reg) -> Decoded | None:
    kind = _T3_MEM.get(hw1 & 0xFFF0)
    if kind is None:
        return None
    width, store, signed = kind
    rn = hw1 & 0xF
    rt = (hw2 >> 12) & 0xF
    # Encoding T3 puts the 12-bit offset in the low bits. T4 (pre/post-index)
    # uses a different first-halfword prefix and is left undecoded.
    imm = hw2 & 0xFFF
    address = (read_reg(rn) + imm) & 0xFFFFFFFF
    value = read_reg(rt) if store else 0
    return Decoded(4, (_mem(address, width, rt, store, value, signed),))


class _Gdb:
    """A small gdb remote client. Enough for registers, memory, and one step."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._buf = b""
        self._ack = True
        sock.settimeout(3)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def handshake(self) -> None:
        reply = self.cmd("qSupported:swbreak+;hwbreak+")
        if "PacketSize=" not in reply:
            raise BackendError(f"gdbstub rejected qSupported ({reply!r})")
        noack = self.cmd("QStartNoAckMode")
        if noack not in ("OK", ""):
            raise BackendError(f"gdbstub rejected QStartNoAckMode ({noack!r})")
        self._ack = False
        stop = self.cmd("?")
        if not stop or stop[0] not in "TS":
            raise BackendError(f"gdbstub did not halt the CPU ({stop!r})")

    def cmd(self, packet: str) -> str:
        raw = packet.encode("ascii")
        frame = b"$" + raw + b"#" + f"{sum(raw) & 0xFF:02x}".encode("ascii")
        try:
            self._sock.sendall(frame)
            if self._ack:
                ack = self._read_exact(1)
                if ack != b"+":
                    raise BackendError(f"gdbstub nack for {packet.split(':', 1)[0]}")
            while True:
                body = self._read_packet()
                # Console output is ``O`` plus hex bytes. The ack ``OK`` is
                # not that packet: ``K`` is not a hex digit.
                if _is_console_output(body):
                    continue
                return body
        except socket.timeout as exc:
            raise BackendError(
                "qemu-system-arm gdbstub timed out. "
                "WFI and WFE are retired without stepping; another blocking "
                "instruction can still stall the stub."
            ) from exc
        except OSError as exc:
            raise BackendError(f"qemu-system-arm gdbstub closed: {exc}") from exc

    def read_reg(self, number: int) -> int:
        reply = self.cmd(f"p{number:x}")
        if reply.startswith("E") or len(reply) < 8:
            raise BackendError(f"gdb register {number} read failed ({reply})")
        try:
            return int.from_bytes(bytes.fromhex(reply[:8]), "little")
        except ValueError as exc:
            raise BackendError(f"gdb register {number} returned {reply!r}") from exc

    def write_reg(self, number: int, value: int) -> None:
        encoded = (value & 0xFFFFFFFF).to_bytes(4, "little").hex()
        reply = self.cmd(f"P{number:x}={encoded}")
        if reply != "OK":
            raise BackendError(f"gdb register {number} write failed ({reply})")

    def read_mem(self, address: int, size: int) -> bytes:
        out = bytearray()
        cursor = address
        left = size
        while left:
            take = min(left, 480)
            reply = self.cmd(f"m{cursor:x},{take:x}")
            if reply.startswith("E"):
                raise BackendError(f"gdb read {cursor:#x} size {take} failed ({reply})")
            try:
                chunk = bytes.fromhex(reply)
            except ValueError as exc:
                raise BackendError(f"gdb read {cursor:#x} returned {reply[:40]!r}") from exc
            if len(chunk) != take:
                raise BackendError(f"gdb read {cursor:#x} returned {len(chunk)} bytes, expected {take}")
            out += chunk
            cursor += take
            left -= take
        return bytes(out)

    def write_mem(self, address: int, data: bytes) -> None:
        cursor = 0
        while cursor < len(data):
            chunk = data[cursor : cursor + 480]
            reply = self.cmd(f"M{address + cursor:x},{len(chunk):x}:{chunk.hex()}")
            if reply != "OK":
                raise BackendError(f"gdb write {address + cursor:#x} failed ({reply})")
            cursor += len(chunk)

    def step(self) -> None:
        reply = self.cmd("s")
        if not reply or reply[0] not in "TS":
            raise BackendError(f"gdb single-step failed ({reply!r})")

    def xfer(self, annex: str) -> str:
        offset = 0
        parts: list[str] = []
        while True:
            reply = self.cmd(f"qXfer:features:read:{annex}:{offset:x},ff0")
            if not reply or reply[0] not in "ml":
                raise BackendError(f"gdb feature {annex} is unavailable ({reply[:60]!r})")
            parts.append(reply[1:])
            if reply[0] == "l":
                return "".join(parts)
            offset += len(reply) - 1

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            return

    def _read_exact(self, count: int) -> bytes:
        while len(self._buf) < count:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise BackendError("qemu-system-arm gdbstub closed the connection")
            self._buf += chunk
        out = self._buf[:count]
        self._buf = self._buf[count:]
        return out

    def _read_packet(self) -> str:
        while True:
            if not self._buf:
                chunk = self._sock.recv(65536)
                if not chunk:
                    raise BackendError("qemu-system-arm gdbstub closed the connection")
                self._buf += chunk
            if self._buf[:1] in (b"+", b"-"):
                self._buf = self._buf[1:]
                continue
            break
        if self._buf[:1] != b"$":
            raise BackendError(f"gdbstub sent {self._buf[:24]!r}")
        self._buf = self._buf[1:]
        raw = bytearray()
        while b"#" not in raw:
            if not self._buf:
                chunk = self._sock.recv(65536)
                if not chunk:
                    raise BackendError("qemu-system-arm gdbstub closed the connection")
                self._buf += chunk
            raw += self._buf
            self._buf = b""
        body, rest = raw.split(b"#", 1)
        self._buf = bytes(rest)
        checksum = self._read_exact(2)
        expect = f"{sum(body) & 0xFF:02x}".encode("ascii")
        if checksum.lower() != expect:
            raise BackendError("gdbstub checksum mismatch")
        return _unescape(bytes(body)).decode("latin1")


class _Qmp:
    """Newline-delimited QMP. Events between a command and its reply are skipped."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._buf = b""
        sock.settimeout(5)
        self.banner = self._read()

    def cmd(self, execute: str, **arguments: object) -> dict:
        message: dict[str, object] = {"execute": execute}
        if arguments:
            message["arguments"] = arguments
        try:
            self._sock.sendall(json.dumps(message).encode() + b"\n")
            while True:
                obj = self._read()
                if "error" in obj:
                    info = obj["error"]
                    desc = info.get("desc", info) if isinstance(info, dict) else info
                    raise BackendError(f"QMP {execute} failed: {desc}")
                if "return" in obj:
                    result = obj["return"]
                    return result if isinstance(result, dict) else {"result": result}
        except socket.timeout as exc:
            raise BackendError(f"QMP {execute} timed out") from exc
        except OSError as exc:
            raise BackendError(f"QMP connection closed during {execute}: {exc}") from exc

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            return

    def _read(self) -> dict:
        while b"\n" not in self._buf:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise BackendError("QMP closed the connection")
            self._buf += chunk
        line, self._buf = self._buf.split(b"\n", 1)
        return json.loads(line.decode())


@register_backend("qemu")
@register_backend("qemu-cortex-m")
class QemuCortexM(CpuBackend):
    """Cortex-M via ``qemu-system-arm -machine mps2-an385``.

    Unicorn stays the default (``arch: cortex-m``). Select this backend with
    ``--backend qemu`` or with ``arch: qemu`` / ``arch: qemu-cortex-m``.
    """

    arch = "qemu-cortex-m"
    page_size = 0x1000

    def __init__(self, *, binary: str | None = None) -> None:
        super().__init__()
        self.binary = resolve_qemu(binary)
        self._closed = False
        self._proc: subprocess.Popen[bytes] | None = None
        self._log: tempfile._TemporaryFileWrapper[bytes] | None = None
        self._qmp: _Qmp | None = None
        self._gdb: _Gdb | None = None
        self._regnums: dict[str, int] = {}
        self._pages: dict[int, int] = {}
        self._ram_pages: set[int] = set()
        self._shadow: dict[int, bytearray] = {}
        self._code_hooks: list = []
        self._intr_hooks: list = []
        self._read_hooks: list[tuple[int, int, object]] = []
        self._write_hooks: list[tuple[int, int, object]] = []
        self._unmapped_hooks: list = []
        self._prot_hooks: list = []
        self._stop = False
        self._launch()

    def close(self) -> None:
        """Stop ``qemu-system-arm``. Safe to call more than once."""
        if self._closed:
            return
        self._closed = True
        self._code_hooks.clear()
        self._intr_hooks.clear()
        self._read_hooks.clear()
        self._write_hooks.clear()
        self._unmapped_hooks.clear()
        self._prot_hooks.clear()
        _LIVE.discard(self)
        if self._qmp is not None:
            try:
                self._qmp.cmd("quit")
            except BackendError:
                pass
            self._qmp.close()
            self._qmp = None
        if self._gdb is not None:
            self._gdb.close()
            self._gdb = None
        proc = self._proc
        self._proc = None
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except OSError:
                proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    proc.kill()
                proc.wait(timeout=1)
        if self._log is not None:
            self._log.close()
            self._log = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            return

    def map_memory(self, address: int, size: int, perms: int) -> None:
        self._check_pages(address, size)
        self._require_perms(perms)
        pages = range(address, address + size, self.page_size)
        for page in pages:
            if page in self._pages:
                raise BackendError(f"mem_map {address:#x} size {size:#x} overlaps an existing mapping")
        for page in pages:
            self._pages[page] = perms
            if _page_is_ram(page):
                self._ram_pages.add(page)
            else:
                self._shadow[page] = bytearray(self.page_size)

    def protect_memory(self, address: int, size: int, perms: int) -> None:
        self._check_pages(address, size)
        self._require_perms(perms)
        pages = range(address, address + size, self.page_size)
        missing = [page for page in pages if page not in self._pages]
        if missing:
            raise BackendError(f"mem_protect {address:#x} is not mapped")
        for page in pages:
            self._pages[page] = perms

    def write_memory(self, address: int, data: bytes) -> None:
        data = bytes(data)
        self._copy_memory(address, data, write=True)

    def read_memory(self, address: int, size: int) -> bytes:
        if size < 0:
            raise BackendError(f"mem_read size {size} is negative")
        return self._copy_memory(address, b"\x00" * size, write=False)

    def read_register(self, name: str) -> int:
        number = self._reg_number(name)
        try:
            value = self._gdb_client().read_reg(number)
        except BackendError as exc:
            raise BackendError(f"cannot read {name}: {exc}") from exc
        if name == "pc":
            return value & ~1
        if name in _STACK_REGS:
            return raz_sp(value)
        return value & 0xFFFFFFFF

    def write_register(self, name: str, value: int) -> None:
        if not isinstance(value, int) or isinstance(value, bool):
            raise BackendError(f"register {name} value must be an int, not {value!r}")
        number = self._reg_number(name)
        stored = value & 0xFFFFFFFF
        if name in _STACK_REGS:
            stored = raz_sp(stored)
        if name in _MSR_SYSM:
            self._msr(name, stored)
            return
        if name == "pc" and stored & 1:
            xpsr = self.read_register("xpsr") | (1 << 24)
            self._gdb_client().write_reg(self._reg_number("xpsr"), xpsr)
            stored &= ~1
        try:
            self._gdb_client().write_reg(number, stored)
        except BackendError as exc:
            raise BackendError(f"cannot write {name}: {exc}") from exc

    def read_registers(self) -> dict[str, int]:
        values: dict[str, int] = {}
        for name in _SNAPSHOT_REGS:
            if name not in self._regnums:
                continue
            try:
                values[name] = self.read_register(name)
            except BackendError:
                logger.debug("qemu gdbstub has no readable register %s", name)
        return values

    def write_registers(self, values: dict[str, int]) -> None:
        for name, value in values.items():
            self.write_register(name, value)

    def start(self, pc: int, *, until: int, timeout_us: int, count: int) -> bool:
        if self._closed:
            raise BackendError("qemu backend is closed")
        self._stop = False
        self.cpu_fault = None
        self.write_register("pc", pc | 1)
        xpsr = self.read_register("xpsr")
        if (xpsr & (1 << 24)) == 0:
            self.write_register("xpsr", xpsr | (1 << 24))
        deadline = time.monotonic() + (timeout_us / 1_000_000) if timeout_us else None
        executed = 0
        stop_at = (until & ~1) if until <= 0xFFFFFFFF else None
        while not self._stop:
            if deadline is not None and time.monotonic() >= deadline:
                return True
            if count and executed >= count:
                return False
            current = self.read_register("pc") & ~1
            if stop_at is not None and current == stop_at:
                return False
            self._one_instruction(current)
            executed += 1
        return False

    def stop(self) -> None:
        self._stop = True

    def hook_code(self, callback) -> None:
        self._code_hooks.append(callback)

    def hook_interrupt(self, callback) -> None:
        self._intr_hooks.append(callback)

    def hook_memory_read(self, callback, start: int, end: int) -> None:
        self._read_hooks.append((start, end, callback))

    def hook_memory_write(self, callback, start: int, end: int) -> None:
        self._write_hooks.append((start, end, callback))

    def hook_unmapped(self, callback) -> None:
        self._unmapped_hooks.append(callback)

    def hook_prot(self, callback) -> None:
        self._prot_hooks.append(callback)

    def prepare_run(self) -> None:
        super().prepare_run()
        self._stop = False

    def ensure_system_control(self) -> None:
        """Leave the board SCS to QEMU.

        A SysTick (or other) plugin the machine mapped is a shadow page and
        is dispatched through the memory hooks. This backend does not install
        the Unicorn NVIC model on ``0xE000E000``.
        """
        return None

    def _launch(self) -> None:
        _LIVE.add(self)
        gdb_port, qmp_port = _free_ports(2)
        self._log = tempfile.TemporaryFile()
        argv = [
            self.binary,
            "-machine",
            QEMU_MACHINE,
            "-cpu",
            QEMU_CPU,
            "-nographic",
            "-monitor",
            "none",
            "-serial",
            "null",
            "-qmp",
            f"tcp:127.0.0.1:{qmp_port},server=on,wait=off",
            "-gdb",
            f"tcp:127.0.0.1:{gdb_port},server=on,wait=off",
            "-S",
        ]
        logger.debug("starting %s", " ".join(argv))
        try:
            self._proc = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=self._log,
                start_new_session=True,
            )
            qsock = _connect(qmp_port, self._proc)
            self._qmp = _Qmp(qsock)
            self._qmp.cmd("qmp_capabilities")
            status = self._qmp.cmd("query-status")
            if status.get("running"):
                raise BackendError(f"{_QEMU_BINARY} did not start stopped (-S)")
            gsock = _connect(gdb_port, self._proc)
            self._gdb = _Gdb(gsock)
            self._gdb.handshake()
            self._load_regs()
        except Exception as exc:
            detail = self._stderr_tail()
            self.close()
            message = str(exc)
            if detail and detail not in message:
                message = f"{message} qemu said: {detail}"
            if isinstance(exc, BackendError):
                raise BackendError(message) from exc
            raise BackendError(f"failed to start {_QEMU_BINARY} ({self.binary}): {message}") from exc

    def _msr(self, name: str, value: int) -> None:
        """Retire ``msr <name>, r0`` so a banked register actually changes.

        The gdbstub read path returns these registers. Its write path does
        not update them. One instruction at ``_MSR_PAD`` does.
        """
        gdb = self._gdb_client()
        r0_num = self._reg_number("r0")
        pc_num = self._reg_number("pc")
        xpsr_num = self._reg_number("xpsr")
        saved_r0 = gdb.read_reg(r0_num)
        saved_pc = gdb.read_reg(pc_num)
        saved_xpsr = gdb.read_reg(xpsr_num)
        saved_mem = gdb.read_mem(_MSR_PAD, 4)
        insn = (0xF380).to_bytes(2, "little") + (0x8800 | _MSR_SYSM[name]).to_bytes(2, "little")
        try:
            gdb.write_mem(_MSR_PAD, insn)
            gdb.write_reg(r0_num, value & 0xFFFFFFFF)
            gdb.write_reg(pc_num, _MSR_PAD)
            gdb.write_reg(xpsr_num, saved_xpsr | (1 << 24))
            gdb.step()
            landed = gdb.read_reg(pc_num) & ~1
            if landed != _MSR_PAD + 4:
                ipsr = gdb.read_reg(xpsr_num) & 0x1FF
                raise BackendError(f"msr {name} did not retire (pc {landed:#x}, ipsr {ipsr})")
        finally:
            gdb.write_mem(_MSR_PAD, saved_mem)
            gdb.write_reg(r0_num, saved_r0)
            gdb.write_reg(pc_num, saved_pc & ~1)
            gdb.write_reg(xpsr_num, saved_xpsr)

    def _load_regs(self) -> None:
        gdb = self._gdb_client()
        root = gdb.xfer("target.xml")
        documents = [root]
        for href in _HREF.findall(root):
            documents.append(gdb.xfer(href))
        self._regnums = gdb_register_map(documents)
        missing = [name for name in ("r0", "sp", "lr", "pc", "xpsr") if name not in self._regnums]
        if missing:
            raise BackendError("qemu gdbstub is missing registers: " + ", ".join(missing))

    def _one_instruction(self, pc: int) -> None:
        fetched = self._fetch(pc)
        if fetched is None:
            return
        hw1, hw2, size = fetched
        for callback in list(self._code_hooks):
            callback(pc, size)
            if self._stop:
                return
        if (self.read_register("pc") & ~1) != pc:
            return
        if size == 2 and (hw1 & 0xFF00) == 0xBE00:
            self._fire_intr(BKPT_VECTOR)
            return
        if size == 2 and hw1 in (_WFI, _WFE):
            self._advance(pc, 2)
            return
        if size == 2 and (hw1 & 0xFF00) == 0xDF00:
            self._fire_intr(SVC_VECTOR)
            if not self._stop:
                self._advance(pc, 2)
            return
        decoded = decode_thumb(hw1, hw2, pc, self._read_gpr)
        if decoded is not None and any(self._needs_intercept(op) for op in decoded.ops):
            self._emulate(pc, decoded)
            return
        if decoded is None and size == 4:
            self._refuse_undecoded_memory(pc, hw1, hw2)
            if self._stop:
                return
        self._gdb_client().step()
        if self._stop:
            return
        ipsr = self.read_register("xpsr") & 0x1FF
        if ipsr:
            self.cpu_fault = f"qemu exception {ipsr} at {pc:#x}"
            self._stop = True

    def _fetch(self, pc: int) -> tuple[int, int, int] | None:
        if not self._fetch_allowed(pc):
            return None
        hw1 = int.from_bytes(self.read_memory(pc, 2), "little")
        if hw1 < 0xE800:
            return hw1, 0, 2
        if not self._fetch_allowed(pc + 2):
            return None
        hw2 = int.from_bytes(self.read_memory(pc + 2, 2), "little")
        return hw1, hw2, 4

    def _fetch_allowed(self, address: int) -> bool:
        page = address & ~(self.page_size - 1)
        perms = self._pages.get(page)
        if perms is None:
            if not self._ask(MemAccess("fetch_unmapped", address, 2, 0), self._unmapped_hooks):
                self._stop = True
                return False
            perms = self._pages.get(page)
            if perms is None:
                self._stop = True
                return False
        if not perms & PERM_EXEC:
            if not self._ask(MemAccess("fetch_prot", address, 2, 0), self._prot_hooks):
                self._stop = True
                return False
        if page not in self._ram_pages:
            raise BackendError(
                f"pc {address:#x} is not in {QEMU_MACHINE} RAM; "
                f"{_QEMU_BINARY} cannot fetch from that window"
            )
        return True

    def _refuse_undecoded_memory(self, pc: int, hw1: int, hw2: int) -> None:
        base = thumb2_memory_base(hw1)
        if base is None or base == 15:
            return
        base_val = self._read_gpr(base) & 0xFFFFFFFF
        if not (
            self._needs_intercept_addr(base_val, 4, store=False)
            or self._needs_intercept_addr(base_val, 4, store=True)
        ):
            return
        raise BackendError(
            f"undecoded load/store at {pc:#x} (encoding {hw1:04x} {hw2:04x}); "
            f"base {_reg_name(base)} is {base_val:#x}, which is not {QEMU_MACHINE} RAM. "
            f"Refusing to let {_QEMU_BINARY} perform the access."
        )

    def _emulate(self, pc: int, decoded: Decoded) -> None:
        for op in decoded.ops:
            if not self._guest_access(op):
                return
        self._advance(pc, decoded.size)

    def _guest_access(self, op: MemOp) -> bool:
        address = op.address & 0xFFFFFFFF
        if not self._span_mapped(address, op.width):
            kind = "write_unmapped" if op.store else "read_unmapped"
            value = op.value if op.store else 0
            if not self._ask(MemAccess(kind, address, op.width, value), self._unmapped_hooks):
                self._stop = True
                return False
            if not self._span_mapped(address, op.width):
                self._stop = True
                return False
        if not self._perms_allow(address, op.width, store=op.store):
            kind = "write_prot" if op.store else "read_prot"
            value = op.value if op.store else 0
            if not self._ask(MemAccess(kind, address, op.width, value), self._prot_hooks):
                self._stop = True
                return False
        if op.store:
            data = (op.value & _mask(op.width)).to_bytes(op.width, "little")
            self.write_memory(address, data)
            self._fire_mem(self._write_hooks, address, op.width, op.value & _mask(op.width))
        else:
            old = int.from_bytes(self.read_memory(address, op.width), "little")
            self._fire_mem(self._read_hooks, address, op.width, old)
            if self._stop:
                return False
            raw = int.from_bytes(self.read_memory(address, op.width), "little")
            value = _sign_extend(raw, op.width) if op.signed else raw
            self.write_register(_reg_name(op.rt), value)
        return not self._stop

    def _needs_intercept(self, op: MemOp) -> bool:
        return self._needs_intercept_addr(op.address, op.width, store=op.store)

    def _needs_intercept_addr(self, address: int, width: int, *, store: bool) -> bool:
        address &= 0xFFFFFFFF
        if width <= 0 or address + width - 1 > 0xFFFFFFFF:
            return True
        cursor = address
        last = address + width - 1
        while True:
            page = cursor & ~(self.page_size - 1)
            perms = self._pages.get(page)
            if perms is None or page not in self._ram_pages:
                return True
            need = PERM_WRITE if store else PERM_READ
            if not perms & need:
                return True
            page_last = page + self.page_size - 1
            if last <= page_last:
                break
            cursor = page_last + 1
        return _hooks_cover(self._read_hooks, address, width) or _hooks_cover(
            self._write_hooks, address, width
        )

    def _span_mapped(self, address: int, width: int) -> bool:
        if width <= 0 or address + width - 1 > 0xFFFFFFFF:
            return False
        cursor = address
        last = address + width - 1
        while True:
            page = cursor & ~(self.page_size - 1)
            if page not in self._pages:
                return False
            page_last = page + self.page_size - 1
            if last <= page_last:
                return True
            cursor = page_last + 1

    def _perms_allow(self, address: int, width: int, *, store: bool) -> bool:
        need = PERM_WRITE if store else PERM_READ
        cursor = address
        last = address + width - 1
        while True:
            page = cursor & ~(self.page_size - 1)
            perms = self._pages.get(page, 0)
            if not perms & need:
                return False
            page_last = page + self.page_size - 1
            if last <= page_last:
                return True
            cursor = page_last + 1

    def _advance(self, pc: int, size: int) -> None:
        if self._stop:
            return
        if (self.read_register("pc") & ~1) != (pc & ~1):
            return
        self.write_register("pc", (pc + size) | 1)

    def _fire_intr(self, vector: int) -> None:
        for callback in list(self._intr_hooks):
            callback(vector)
            if self._stop:
                return

    def _fire_mem(self, hooks: list[tuple[int, int, object]], address: int, width: int, value: int) -> None:
        for start, end, callback in list(hooks):
            if address + width - 1 < start or address > end:
                continue
            callback(address, width, value)
            if self._stop:
                return

    def _ask(self, event: MemAccess, hooks: list) -> bool:
        if not hooks:
            return False
        for callback in hooks:
            if not callback(event):
                return False
        return True

    def _read_gpr(self, number: int) -> int:
        return self.read_register(_reg_name(number))

    def _copy_memory(self, address: int, data: bytes, *, write: bool) -> bytes:
        if not data:
            return b""
        out = bytearray()
        cursor = address
        offset = 0
        while offset < len(data):
            page = cursor & ~(self.page_size - 1)
            if page not in self._pages:
                action = "mem_write" if write else "mem_read"
                raise BackendError(f"{action} {address:#x} size {len(data)} is not mapped")
            page_off = cursor - page
            take = min(len(data) - offset, self.page_size - page_off)
            chunk = data[offset : offset + take]
            if page in self._shadow:
                buffer = self._shadow[page]
                if write:
                    buffer[page_off : page_off + take] = chunk
                else:
                    out += buffer[page_off : page_off + take]
            else:
                gdb = self._gdb_client()
                if write:
                    gdb.write_mem(cursor, chunk)
                else:
                    out += gdb.read_mem(cursor, take)
            cursor += take
            offset += take
        return bytes(out)

    def _reg_number(self, name: str) -> int:
        try:
            return self._regnums[name]
        except KeyError as exc:
            known = ", ".join(name for name in _SNAPSHOT_REGS if name in self._regnums)
            raise BackendError(f"unknown register {name!r}; known: {known}") from exc

    def _gdb_client(self) -> _Gdb:
        if self._gdb is None or self._closed:
            raise BackendError("qemu backend is closed")
        return self._gdb

    def _check_pages(self, address: int, size: int) -> None:
        page = self.page_size
        if address % page or size % page or size <= 0:
            raise BackendError(
                f"mapping address {address:#x} size {size:#x} is not aligned to {page:#x}"
            )

    def _stderr_tail(self) -> str:
        log = self._log
        if log is None:
            return ""
        try:
            log.flush()
            log.seek(0)
            text = log.read().decode("utf-8", errors="replace").strip()
        except Exception:
            return ""
        if len(text) > 500:
            return text[-500:]
        return text

    @staticmethod
    def _require_perms(perms: int) -> None:
        if perms & (PERM_READ | PERM_WRITE | PERM_EXEC) == 0:
            raise BackendError("refusing to map a page with empty permissions")


def _page_is_ram(page: int) -> bool:
    for base, size in _RAM_WINDOWS:
        if base <= page < base + size:
            return True
    return False


def _hooks_cover(hooks: list[tuple[int, int, object]], address: int, width: int) -> bool:
    last = address + width - 1
    for start, end, _callback in hooks:
        if last < start or address > end:
            continue
        return True
    return False


def _mask(width: int) -> int:
    return (1 << (8 * width)) - 1


def _is_console_output(body: str) -> bool:
    """True for a gdb ``Oxx`` console packet, not the ``OK`` acknowledgement."""
    if len(body) < 3 or body[0] != "O":
        return False
    rest = body[1:]
    if len(rest) % 2:
        return False
    return all(char in "0123456789abcdefABCDEF" for char in rest)


def _unescape(data: bytes) -> bytes:
    out = bytearray()
    index = 0
    while index < len(data):
        byte = data[index]
        if byte == 0x7D and index + 1 < len(data):
            index += 1
            out.append(data[index] ^ 0x20)
        elif byte == 0x2A and out and index + 1 < len(data):
            index += 1
            count = data[index] - 29
            if count > 0:
                out.extend([out[-1]] * count)
        else:
            out.append(byte)
        index += 1
    return bytes(out)


def _free_ports(count: int) -> list[int]:
    """Distinct localhost ports. Sockets stay open until every port is chosen."""
    holders = []
    ports: list[int] = []
    for _ in range(count):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        ports.append(int(sock.getsockname()[1]))
        holders.append(sock)
    for sock in holders:
        sock.close()
    return ports


def _connect(port: int, proc: subprocess.Popen[bytes]) -> socket.socket:
    deadline = time.monotonic() + 5
    last = "connection refused"
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise BackendError(f"{_QEMU_BINARY} exited ({proc.returncode}) before the stub accepted a connection")
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=0.2)
            sock.settimeout(5)
            return sock
        except OSError as exc:
            last = str(exc)
            time.sleep(0.02)
    raise BackendError(f"timed out connecting to {_QEMU_BINARY} on port {port}: {last}")
