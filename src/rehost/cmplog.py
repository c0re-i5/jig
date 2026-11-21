# SPDX-License-Identifier: MIT
"""Concrete comparison logging and input-to-state replacement.

This is the in-process campaign's CmpLog stage. It is not symbolic
execution and it is not AFL++'s CmpLog shared-memory mode.

A shadow run sets ``CmpLog.active``. The machine's existing Unicorn code
hook (``UC_HOOK_CODE``, the same callback that updates the edge map) then
decodes the instruction about to retire and records the register and
immediate values. Only instructions the machine has already decided will
execute are visible, so a compare skipped because an exception was taken
instead is not logged. The log is cleared at the start of that run. It is
not guest state and it is not part of the snapshot.

``input_to_state`` searches the current input for either operand and
builds candidates that write the other operand over that span, plus a
byte swap and plus or minus one. A compare the shadow run did not reach
contributes nothing. Transforms other than those three are not modeled.

Patterns that are decoded:

* Thumb ``CMP`` / ``CMN`` (immediate and register, including high registers)
* Thumb ``SUBS`` (the flag-setting subtract: immediate and register)
* Thumb-2 ``CMP`` / ``CMN`` / flag-setting ``SUB`` with a modified immediate
* Thumb-2 register forms of those, after a simple LSL, LSR, ASR, or ROR
* a 1, 2, or 4 byte load immediately followed by one of the compares above,
  so the load's width is kept for the operand search

Not decoded: ``TST``, ``TEQ``, ``RRX``, a shift of 32, and any compare
whose operand is ``PC``. A campaign that never attaches a ``CmpLog`` does
not decode.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from rehost.errors import BackendError

# Unique operand pairs kept from one shadow run. A countdown loop can
# otherwise fill the log with a subtract-immediate on every iteration.
_MAX_PAIRS = 64
_DEFAULT_CANDIDATES = 64
_DEFAULT_HITS = 8

_REGS = (
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
)


@dataclass(frozen=True)
class Comparison:
    """One observed compare: the two concrete operands and the widths to try.

    ``left`` and ``right`` are the values the instruction compared, after a
    simple register shift when the encoding had one. ``widths`` is the set
    of byte lengths the replacer should search for (1, 2, and/or 4).
    """

    left: int
    right: int
    widths: tuple[int, ...]
    kind: str
    address: int


@dataclass(frozen=True)
class _Op:
    """A decoded compare that still needs register values filled in."""

    kind: str
    left_reg: int
    right_reg: int | None
    immediate: int | None
    hint: int
    shift_type: int = 0
    shift_amount: int = 0


@dataclass(frozen=True)
class _Load:
    reg: int
    size: int


class CmpLog:
    """Operand log for one shadow run. Inactive until ``active`` is set."""

    def __init__(self) -> None:
        self.active = False
        self.pairs: list[Comparison] = []
        self._index: dict[tuple, int] = {}
        self._pending: _Load | None = None
        self._pending_at: int | None = None

    def begin_run(self) -> None:
        """Drop pairs from the previous shadow run."""
        self.pairs.clear()
        self._index.clear()
        self._pending = None
        self._pending_at = None

    def on_instruction(self, machine, address: int, size: int) -> None:
        """Record a compare at ``address``, or remember a load for the next one.

        Called from the machine code hook before the instruction executes, so
        the registers still hold the operands. No-op unless ``active``.
        """
        if not self.active:
            return
        if size not in (2, 4):
            self._pending = None
            return
        try:
            code = machine.backend.read_memory(address, size)
        except BackendError:
            self._pending = None
            return
        pending = self._pending if self._pending_at == address else None
        self._pending = None
        self._pending_at = None
        op = decode_compare(code)
        if op is not None:
            self._record(machine, address, op, pending)
            return
        load = _decode_load(code)
        if load is not None:
            self._pending = load
            self._pending_at = address + size

    def _record(self, machine, address: int, op: _Op, pending: _Load | None) -> None:
        if op.left_reg == 15 or op.right_reg == 15:
            return
        try:
            left = _reg(machine, op.left_reg)
            if op.right_reg is None:
                right = op.immediate if op.immediate is not None else 0
            else:
                right = _shifted(_reg(machine, op.right_reg), op.shift_type, op.shift_amount)
        except BackendError:
            return
        if right is None:
            return
        left &= 0xFFFFFFFF
        right &= 0xFFFFFFFF
        if left == right:
            return
        widths = _widths(left, right, op.hint)
        if pending is not None and pending.reg in (op.left_reg, op.right_reg):
            widths = tuple(w for w in (1, 2, 4) if w in widths or w == pending.size)
        if not widths:
            return
        key = (op.kind, left, right)
        existing = self._index.get(key)
        if existing is not None:
            merged = tuple(w for w in (1, 2, 4) if w in self.pairs[existing].widths or w in widths)
            if merged != self.pairs[existing].widths:
                self.pairs[existing] = Comparison(left, right, merged, op.kind, address)
            return
        if len(self.pairs) >= _MAX_PAIRS:
            return
        self._index[key] = len(self.pairs)
        self.pairs.append(Comparison(left, right, widths, op.kind, address))


def input_to_state(
    data: bytes,
    comparisons: Iterable[Comparison],
    *,
    limit: int = _DEFAULT_CANDIDATES,
    hits_per_pattern: int = _DEFAULT_HITS,
) -> list[bytes]:
    """Candidates that substitute one compare operand for the other.

    Exact replacements are produced before plus or minus one. Little-endian
    patterns are tried before the byte-swapped form. Each hit is one span in
    the input; a value that occurs several times is tried at each site, up
    to ``hits_per_pattern`` sites. The input length does not change.
    """
    blob = bytes(data)
    if not blob or limit < 1:
        return []
    seen = {blob}
    out: list[bytes] = []
    for candidate in _replacements(blob, comparisons, hits_per_pattern):
        if candidate in seen:
            continue
        seen.add(candidate)
        out.append(candidate)
        if len(out) >= limit:
            break
    return out


def decode_compare(code: bytes) -> _Op | None:
    """Return a compare shape, or None if ``code`` is not one we handle."""
    if len(code) < 2:
        return None
    first = int.from_bytes(code[:2], "little")
    if len(code) >= 4 and first >= 0xE800:
        second = int.from_bytes(code[2:4], "little")
        return _decode_wide(first, second)
    return _decode_narrow(first)


def thumb_expand_imm(imm12: int) -> int | None:
    """ThumbExpandImm from the ARMv7-M ARM. None if the pattern is UNPREDICTABLE."""
    imm12 &= 0xFFF
    if (imm12 >> 10) == 0:
        imm8 = imm12 & 0xFF
        kind = (imm12 >> 8) & 0x3
        if kind == 0:
            return imm8
        if imm8 == 0:
            return None
        if kind == 1:
            return (imm8 << 16) | imm8
        if kind == 2:
            return (imm8 << 24) | (imm8 << 8)
        return (imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8
    unrotated = 0x80 | (imm12 & 0x7F)
    rotation = (imm12 >> 7) & 0x1F
    return _ror(unrotated, rotation)


def _replacements(
    data: bytes,
    comparisons: Iterable[Comparison],
    hits_per_pattern: int,
) -> Iterator[bytes]:
    cached = list(comparisons)
    # Exact hits first, then the neighbor values, so a magic word is tried
    # before the campaign spends executions on off-by-one guesses.
    for delta in (0, 1, -1):
        for comparison in cached:
            yield from _replace_one(data, comparison, delta, hits_per_pattern)


def _replace_one(
    data: bytes,
    comparison: Comparison,
    delta: int,
    hits_per_pattern: int,
) -> Iterator[bytes]:
    for width in comparison.widths:
        if width not in (1, 2, 4):
            continue
        mask = (1 << (8 * width)) - 1
        endians = ("little", "big") if width > 1 else ("little",)
        for src, dst in ((comparison.left, comparison.right), (comparison.right, comparison.left)):
            if (src & mask) == ((dst + delta) & mask) and delta == 0:
                continue
            for src_endian in endians:
                pattern = (src & mask).to_bytes(width, src_endian)
                for offset in _hits(data, pattern, hits_per_pattern):
                    for dst_endian in endians:
                        repl = ((dst + delta) & mask).to_bytes(width, dst_endian)
                        if repl == data[offset : offset + width]:
                            continue
                        yield data[:offset] + repl + data[offset + width :]


def _hits(data: bytes, pattern: bytes, limit: int) -> list[int]:
    found: list[int] = []
    start = 0
    while len(found) < limit:
        index = data.find(pattern, start)
        if index < 0:
            return found
        found.append(index)
        start = index + 1
    return found


def _widths(left: int, right: int, hint: int) -> tuple[int, ...]:
    """Byte lengths worth searching. A wide value is not searched as a byte."""
    span = max(left, right) & 0xFFFFFFFF
    chosen = {hint} if hint in (1, 2, 4) else set()
    if span <= 0xFF:
        chosen.add(1)
    elif span <= 0xFFFF:
        chosen.add(2)
    else:
        chosen.add(4)
    return tuple(width for width in (1, 2, 4) if width in chosen and span < (1 << (8 * width)))


def _decode_narrow(hw: int) -> _Op | None:
    # CMP (immediate) T1: 00101 Rn imm8.
    if (hw & 0xF800) == 0x2800:
        return _Op("cmp", (hw >> 8) & 7, None, hw & 0xFF, 1)
    # SUB (immediate) T2, flag-setting: 00111 Rd imm8. Rd = Rd - imm8.
    if (hw & 0xF800) == 0x3800:
        return _Op("subs", (hw >> 8) & 7, None, hw & 0xFF, 1)
    # SUB (immediate) T1, flag-setting: 0001111 imm3 Rn Rd.
    if (hw & 0xFE00) == 0x1E00:
        return _Op("subs", (hw >> 3) & 7, None, (hw >> 6) & 7, 1)
    # SUB (register) T1, flag-setting: 0001101 Rm Rn Rd. Flags come from Rn - Rm.
    if (hw & 0xFE00) == 0x1A00:
        return _Op("subs", (hw >> 3) & 7, (hw >> 6) & 7, None, 4)
    # CMP (register) T1, low registers: 0100001010 Rm Rn.
    if (hw & 0xFFC0) == 0x4280:
        return _Op("cmp", hw & 7, (hw >> 3) & 7, None, 4)
    # CMN (register) T1: 0100001011 Rm Rn.
    if (hw & 0xFFC0) == 0x42C0:
        return _Op("cmn", hw & 7, (hw >> 3) & 7, None, 4)
    # CMP (register) T2, high registers: 01000101 N Rm Rn.
    if (hw & 0xFF00) == 0x4500:
        rn = (((hw >> 7) & 1) << 3) | (hw & 7)
        rm = (hw >> 3) & 0xF
        return _Op("cmp", rn, rm, None, 4)
    return None


def _decode_wide(hw1: int, hw2: int) -> _Op | None:
    # Data-processing (modified immediate). Bit 15 of the second halfword is
    # the "0" that separates these from other 32-bit forms.
    if (hw2 & 0x8000) == 0:
        rn = hw1 & 0xF
        rd = (hw2 >> 8) & 0xF
        imm12 = (((hw1 >> 10) & 1) << 11) | (((hw2 >> 12) & 7) << 8) | (hw2 & 0xFF)
        expanded = thumb_expand_imm(imm12)
        if expanded is not None:
            # CMP (immediate) is SUB with S=1 and Rd=15. SUBS is the same
            # encoding with a real destination. CMN (immediate) is ADD.
            if (hw1 & 0xFBF0) == 0xF1B0:
                if rd == 15:
                    return _Op("cmp", rn, None, expanded, 4)
                return _Op("subs", rn, None, expanded, 4)
            if (hw1 & 0xFBF0) == 0xF110 and rd == 15:
                return _Op("cmn", rn, None, expanded, 4)
    # Data-processing (shifted register). S=1 is part of the match.
    if (hw2 & 0x8000) == 0 and (hw1 & 0xFFF0) in (0xEBB0, 0xEA90):
        rn = hw1 & 0xF
        rd = (hw2 >> 8) & 0xF
        rm = hw2 & 0xF
        shift_amount = (((hw2 >> 12) & 7) << 2) | ((hw2 >> 6) & 3)
        shift_type = (hw2 >> 4) & 3
        if (hw1 & 0xFFF0) == 0xEBB0 and rd == 15:
            kind = "cmp"
        elif (hw1 & 0xFFF0) == 0xEBB0:
            kind = "subs"
        elif rd == 15:
            kind = "cmn"
        else:
            return None
        return _Op(kind, rn, rm, None, 4, shift_type, shift_amount)
    return None


def _decode_load(code: bytes) -> _Load | None:
    """A plain integer load whose destination a following compare may use."""
    if len(code) < 2:
        return None
    hw = int.from_bytes(code[:2], "little")
    if len(code) >= 4 and hw >= 0xE800:
        hw2 = int.from_bytes(code[2:4], "little")
        # LDRB / LDRH / LDR (immediate) T2/T3: 11111000 1001/1011/1101 Rn Rt imm12.
        if (hw & 0xFFF0) == 0xF890:
            return _Load((hw2 >> 12) & 0xF, 1)
        if (hw & 0xFFF0) == 0xF8B0:
            return _Load((hw2 >> 12) & 0xF, 2)
        if (hw & 0xFFF0) == 0xF8D0:
            return _Load((hw2 >> 12) & 0xF, 4)
        return None
    # 16-bit loads. The low 3 bits are Rt except for the PC-relative form.
    if (hw & 0xF800) == 0x6800:
        return _Load(hw & 7, 4)
    if (hw & 0xF800) == 0x7800:
        return _Load(hw & 7, 1)
    if (hw & 0xF800) == 0x8800:
        return _Load(hw & 7, 2)
    if (hw & 0xF800) == 0x4800:
        return _Load((hw >> 8) & 7, 4)
    if (hw & 0xFE00) == 0x5800:
        return _Load(hw & 7, 4)
    if (hw & 0xFE00) == 0x5C00:
        return _Load(hw & 7, 1)
    if (hw & 0xFE00) == 0x5A00:
        return _Load(hw & 7, 2)
    if (hw & 0xFE00) == 0x5600:
        return _Load(hw & 7, 1)
    if (hw & 0xFE00) == 0x5E00:
        return _Load(hw & 7, 2)
    return None


def _shifted(value: int, shift_type: int, amount: int) -> int | None:
    """Apply a Thumb-2 shift. None means RRX or a shift of 32, which we skip."""
    value &= 0xFFFFFFFF
    if amount == 0:
        if shift_type == 0:
            return value
        return None
    if shift_type == 0:
        return (value << amount) & 0xFFFFFFFF
    if shift_type == 1:
        return value >> amount
    if shift_type == 2:
        if value & 0x80000000:
            return ((value >> amount) | (0xFFFFFFFF << (32 - amount))) & 0xFFFFFFFF
        return value >> amount
    if shift_type == 3:
        return _ror(value, amount)
    return None


def _ror(value: int, amount: int) -> int:
    amount &= 31
    value &= 0xFFFFFFFF
    if amount == 0:
        return value
    return ((value >> amount) | (value << (32 - amount))) & 0xFFFFFFFF


def _reg(machine, number: int) -> int:
    if not 0 <= number <= 15:
        raise BackendError(f"register {number} is out of range")
    return machine.backend.read_register(_REGS[number]) & 0xFFFFFFFF
