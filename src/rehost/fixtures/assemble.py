# SPDX-License-Identifier: MIT
"""A tiny Thumb/Thumb-2 assembler for in-repo fixtures.

It encodes the instructions the synthetic programs use (``movw``/``movt``,
``mov`` / ``movs``, ``ldr``/``str`` immediate, ``adds``, ``add rd, sp``,
``bx``, ``svc``, ``mrs`` / ``msr``, ``cpsid`` / ``cpsie``, ``wfi`` / ``wfe``,
``bkpt``, ``nop``, and short ``b``) plus ``.word`` / ``.thumb_word``. It is
not a general assembler. CI never needs a cross toolchain, and the bytes it
emits are executed by the Unicorn backend.
"""

from __future__ import annotations

import re
import struct

from rehost.errors import AssembleError

_IGNORED_PREFIXES = (
    ".thumb",
    ".syntax",
    ".cpu",
    ".arch",
    ".text",
    ".global",
    ".globl",
    ".thumb_func",
    ".type",
    ".section",
    ".eabi_attribute",
    ".fpu",
    ".code",
    ".file",
    ".ident",
)

_WIDTHS = {
    "movw": 4,
    "movt": 4,
    "mov": 2,
    "movs": 2,
    "str": 2,
    "ldr": 2,
    "adds": 2,
    "add": 2,
    "bx": 2,
    "bkpt": 2,
    "nop": 2,
    "b": 2,
    "b.n": 2,
    "wfi": 2,
    "wfe": 2,
    "cpsid": 2,
    "cpsie": 2,
    "svc": 2,
    "mrs": 4,
    "msr": 4,
}

# SYSm values from the ARMv7-M MRS/MSR encodings.
_SYSM = {
    "apsr": 0,
    "iapsr": 1,
    "eapsr": 2,
    "xpsr": 3,
    "ipsr": 5,
    "epsr": 6,
    "iepsr": 7,
    "msp": 8,
    "psp": 9,
    "primask": 16,
    "basepri": 17,
    "basepri_max": 18,
    "faultmask": 19,
    "control": 20,
}

_NUMBER = re.compile(r"-?(?:0x[0-9a-fA-F]+|\d+)\Z")
_LABEL_NAME = re.compile(r"[A-Za-z_.][\w.]*\Z")
_LABEL_LINE = re.compile(r"^([A-Za-z_.][\w.]*)\s*:\s*(.*)$")
_MOV = re.compile(
    r"^(?P<op>movw|movt|movs)\s+(?P<rd>r\d+|sp|lr|pc)\s*,\s*#(?P<imm>-?(?:0x[0-9a-fA-F]+|\d+))$",
    re.IGNORECASE,
)
_MEM = re.compile(
    r"^(?P<op>str|ldr)\s+(?P<rt>r\d+|sp|lr|pc)\s*,\s*\[\s*(?P<rn>r\d+|sp|lr|pc)\s*"
    r"(?:,\s*#(?P<imm>-?(?:0x[0-9a-fA-F]+|\d+)))?\s*\]$",
    re.IGNORECASE,
)
_BKPT = re.compile(r"^bkpt(?:\s+#(?P<imm>0x[0-9a-fA-F]+|\d+))?$", re.IGNORECASE)
_NOP = re.compile(r"^nop(?:\.n)?$", re.IGNORECASE)
_BRANCH = re.compile(r"^b(?:\.n)?\s+([A-Za-z_.][\w.]*)$", re.IGNORECASE)
_MOV_REG = re.compile(
    r"^mov\s+(?P<rd>r\d+|sp|lr|pc)\s*,\s*(?P<rm>r\d+|sp|lr|pc)$",
    re.IGNORECASE,
)
_ADDS = re.compile(
    r"^adds\s+(?P<rd>r\d+)\s*,\s*#(?P<imm>-?(?:0x[0-9a-fA-F]+|\d+))$",
    re.IGNORECASE,
)
_ADD_SP = re.compile(
    r"^add\s+(?P<rd>r\d+)\s*,\s*sp\s*,\s*#(?P<imm>-?(?:0x[0-9a-fA-F]+|\d+))$",
    re.IGNORECASE,
)
_BX = re.compile(r"^bx\s+(?P<rm>r\d+|sp|lr|pc)$", re.IGNORECASE)
_SVC = re.compile(r"^svc\s+#(?P<imm>0x[0-9a-fA-F]+|\d+)$", re.IGNORECASE)
_CPS = re.compile(r"^cps(?P<effect>id|ie)\s+i$", re.IGNORECASE)
_HINT = re.compile(r"^(?P<op>wfi|wfe)$", re.IGNORECASE)
_MRS = re.compile(
    r"^mrs\s+(?P<rd>r\d+|sp|lr|pc)\s*,\s*(?P<sysm>[A-Za-z_][A-Za-z0-9_]*)$",
    re.IGNORECASE,
)
_MSR = re.compile(
    r"^msr\s+(?P<sysm>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*(?P<rn>r\d+|sp|lr|pc)$",
    re.IGNORECASE,
)


def assemble(source: str, *, base: int = 0) -> bytes:
    """Assemble ``source`` and return the image, including any vector words."""
    image, _labels = assemble_image(source, base=base)
    return image


def assemble_image(source: str, *, base: int = 0) -> tuple[bytes, dict[str, int]]:
    """Assemble ``source``. Labels are absolute addresses (``base`` + offset)."""
    if base < 0:
        raise AssembleError("assemble base must be >= 0")
    statements = _parse(source, base)
    labels = {name: address for name, address in _labels_of(statements)}
    out = bytearray()
    for item in statements:
        if item[0] != "stmt":
            continue
        _line_no, _text, address, encoded = _encode_statement(item, labels)
        if address != base + len(out):
            raise AssembleError("internal assembler address mismatch")
        out += encoded
    return bytes(out), labels


def _labels_of(statements: list[tuple]) -> list[tuple[str, int]]:
    return [(item[1], item[2]) for item in statements if item[0] == "label"]


def _parse(source: str, base: int) -> list[tuple]:
    statements: list[tuple] = []
    pc = base
    labels_seen: dict[str, int] = {}
    for line_no, raw in enumerate(source.splitlines(), start=1):
        text = _strip_comment(raw)
        if not text:
            continue
        while True:
            match = _LABEL_LINE.match(text)
            if not match:
                break
            name = match.group(1)
            if name in labels_seen:
                raise AssembleError(f"line {line_no}: duplicate label {name}")
            labels_seen[name] = pc
            statements.append(("label", name, pc, line_no))
            text = match.group(2).strip()
            if not text:
                break
        if not text:
            continue
        lowered = text.lower()
        if lowered.startswith(".word") or lowered.startswith(".thumb_word"):
            statements.append(("stmt", line_no, text, pc, 4))
            pc += 4
            continue
        if lowered.startswith("."):
            if lowered.startswith(_IGNORED_PREFIXES):
                continue
            raise AssembleError(f"line {line_no}: unsupported directive {text.split()[0]}")
        op = text.split(None, 1)[0].lower()
        if op not in _WIDTHS:
            raise AssembleError(f"line {line_no}: unknown instruction {op}")
        width = _WIDTHS[op]
        statements.append(("stmt", line_no, text, pc, width))
        pc += width
    return statements


def _strip_comment(line: str) -> str:
    cut = len(line)
    for marker in ("//", ";", "@"):
        index = line.find(marker)
        if index != -1:
            cut = min(cut, index)
    return line[:cut].strip()


def _encode_statement(item: tuple, labels: dict[str, int]) -> tuple[int, str, int, bytes]:
    _kind, line_no, text, address, _width = item
    lowered = text.lower()
    if lowered.startswith(".thumb_word") or lowered.startswith(".word"):
        parts = text.split(None, 1)
        if len(parts) != 2:
            raise AssembleError(f"line {line_no}: {parts[0]} needs an operand")
        thumb = parts[0].lower() == ".thumb_word"
        encoded = _encode_word(parts[1], labels, thumb=thumb, line_no=line_no)
        return line_no, text, address, encoded
    encoded = _encode_insn(text, address, labels, line_no)
    return line_no, text, address, encoded


def _encode_word(operand: str, labels: dict[str, int], *, thumb: bool, line_no: int) -> bytes:
    token = operand.strip()
    if _NUMBER.fullmatch(token):
        value = int(token, 0)
    else:
        if not _LABEL_NAME.fullmatch(token) or token not in labels:
            raise AssembleError(f"line {line_no}: unknown label or word operand {token!r}")
        value = labels[token]
        if thumb:
            value |= 1
    if not 0 <= value <= 0xFFFFFFFF:
        raise AssembleError(f"line {line_no}: word {value:#x} does not fit in 32 bits")
    return struct.pack("<I", value)


def _encode_insn(text: str, address: int, labels: dict[str, int], line_no: int) -> bytes:
    match = _MOV.fullmatch(text)
    if match:
        op = match.group("op").lower()
        reg = _register(match.group("rd"), line_no, low_only=(op == "movs"))
        imm = int(match.group("imm"), 0)
        if op == "movs":
            if not 0 <= imm <= 0xFF:
                raise AssembleError(f"line {line_no}: movs immediate must fit in 8 bits")
            return struct.pack("<H", 0x2000 | (reg << 8) | imm)
        if not 0 <= imm <= 0xFFFF:
            raise AssembleError(f"line {line_no}: {op} immediate must fit in 16 bits")
        return _mov_wide(op, reg, imm)

    match = _MEM.fullmatch(text)
    if match:
        op = match.group("op").lower()
        rt = _register(match.group("rt"), line_no, low_only=True)
        rn = _register(match.group("rn"), line_no, low_only=True)
        imm_text = match.group("imm")
        imm = 0 if imm_text is None else int(imm_text, 0)
        if imm < 0 or imm > 124 or imm % 4 != 0:
            raise AssembleError(f"line {line_no}: {op} offset must be a multiple of 4 from 0 to 124")
        imm5 = imm >> 2
        base = 0x6000 if op == "str" else 0x6800
        return struct.pack("<H", base | (imm5 << 6) | (rn << 3) | rt)

    match = _BKPT.fullmatch(text)
    if match:
        imm_text = match.group("imm")
        imm = 0 if imm_text is None else int(imm_text, 0)
        if not 0 <= imm <= 0xFF:
            raise AssembleError(f"line {line_no}: bkpt immediate must fit in 8 bits")
        return struct.pack("<H", 0xBE00 | imm)

    if _NOP.fullmatch(text):
        return struct.pack("<H", 0xBF00)

    match = _HINT.fullmatch(text)
    if match:
        return struct.pack("<H", 0xBF30 if match.group("op").lower() == "wfi" else 0xBF20)

    match = _CPS.fullmatch(text)
    if match:
        return struct.pack("<H", 0xB672 if match.group("effect").lower() == "id" else 0xB662)

    match = _BX.fullmatch(text)
    if match:
        rm = _register(match.group("rm"), line_no, low_only=False)
        return struct.pack("<H", 0x4700 | (rm << 3))

    match = _SVC.fullmatch(text)
    if match:
        imm = int(match.group("imm"), 0)
        if not 0 <= imm <= 0xFF:
            raise AssembleError(f"line {line_no}: svc immediate must fit in 8 bits")
        return struct.pack("<H", 0xDF00 | imm)

    match = _ADDS.fullmatch(text)
    if match:
        rd = _register(match.group("rd"), line_no, low_only=True)
        imm = int(match.group("imm"), 0)
        if not 0 <= imm <= 0xFF:
            raise AssembleError(f"line {line_no}: adds immediate must fit in 8 bits")
        return struct.pack("<H", 0x3000 | (rd << 8) | imm)

    match = _ADD_SP.fullmatch(text)
    if match:
        rd = _register(match.group("rd"), line_no, low_only=True)
        imm = int(match.group("imm"), 0)
        if imm < 0 or imm > 1020 or imm % 4 != 0:
            raise AssembleError(
                f"line {line_no}: add rd, sp immediate must be a multiple of 4 from 0 to 1020"
            )
        return struct.pack("<H", 0xA800 | (rd << 8) | (imm >> 2))

    match = _MOV_REG.fullmatch(text)
    if match:
        rd = _register(match.group("rd"), line_no, low_only=False)
        rm = _register(match.group("rm"), line_no, low_only=False)
        encoded = 0x4600 | (((rd >> 3) & 1) << 7) | (rm << 3) | (rd & 7)
        return struct.pack("<H", encoded)

    match = _MRS.fullmatch(text)
    if match:
        rd = _register(match.group("rd"), line_no, low_only=False)
        sysm = _sysm(match.group("sysm"), line_no)
        return struct.pack("<HH", 0xF3EF, 0x8000 | (rd << 8) | sysm)

    match = _MSR.fullmatch(text)
    if match:
        rn = _register(match.group("rn"), line_no, low_only=False)
        sysm = _sysm(match.group("sysm"), line_no)
        return struct.pack("<HH", 0xF380 | rn, 0x8800 | sysm)

    match = _BRANCH.fullmatch(text)
    if match:
        label = match.group(1)
        if label not in labels:
            raise AssembleError(f"line {line_no}: unknown branch target {label}")
        return _branch(address, labels[label], line_no)

    raise AssembleError(f"line {line_no}: could not encode {text!r}")


def _mov_wide(op: str, reg: int, imm16: int) -> bytes:
    """Thumb-2 ``movw`` (T3) or ``movt`` (T1). ``imm16`` is packed imm4:i:imm3:imm8."""
    imm4 = (imm16 >> 12) & 0xF
    bit = (imm16 >> 11) & 0x1
    imm3 = (imm16 >> 8) & 0x7
    imm8 = imm16 & 0xFF
    prefix = 0xF240 if op == "movw" else 0xF2C0
    hw1 = prefix | (bit << 10) | imm4
    hw2 = (imm3 << 12) | (reg << 8) | imm8
    return struct.pack("<HH", hw1, hw2)


def _branch(address: int, target: int, line_no: int) -> bytes:
    # Thumb B encoding T2: offset is from PC+4, imm11 is offset/2.
    offset = target - (address + 4)
    if offset % 2 != 0 or not -2048 <= offset <= 2046:
        raise AssembleError(
            f"line {line_no}: branch from {address:#x} to {target:#x} is out of range"
        )
    imm11 = (offset >> 1) & 0x7FF
    return struct.pack("<H", 0xE000 | imm11)


def _sysm(token: str, line_no: int) -> int:
    try:
        return _SYSM[token.lower()]
    except KeyError as exc:
        known = ", ".join(sorted(_SYSM))
        raise AssembleError(f"line {line_no}: unknown special register {token}; known: {known}") from exc


def _register(token: str, line_no: int, *, low_only: bool) -> int:
    name = token.lower()
    if name == "sp":
        number = 13
    elif name == "lr":
        number = 14
    elif name == "pc":
        number = 15
    elif name.startswith("r") and name[1:].isdigit():
        number = int(name[1:])
    else:
        raise AssembleError(f"line {line_no}: unknown register {token}")
    if number > 15:
        raise AssembleError(f"line {line_no}: unknown register {token}")
    if low_only and number > 7:
        raise AssembleError(
            f"line {line_no}: {token} cannot be used with this 16-bit instruction"
        )
    return number
