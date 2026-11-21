# SPDX-License-Identifier: MIT
"""A tiny RV32I assembler for in-repo fixtures.

It encodes the instructions the synthetic RISC-V program and its tests use:

* ``lui rd, imm20``
* ``addi rd, rs1, imm12``
* ``lw rd, imm(rs1)``
* ``sw rs2, imm(rs1)``
* ``sb rs2, imm(rs1)``
* ``jal rd, label`` and the ``j label`` pseudo (``jal zero, label``)
* ``ebreak``
* ``.word``

Registers are the ABI names (``zero``, ``ra``, ``sp``, ``gp``, ``tp``,
``t0``-``t6``, ``s0``-``s11``, ``a0``-``a7``), ``fp`` (``s0``), and ``x0``-``x31``.
Immediates are decimal or ``0x`` hex. ``addi`` / load / store immediates are
signed 12-bit. ``lui`` takes an unsigned 20-bit immediate.

It is not a general assembler. Compressed encodings, ``mul``, and FP ops are
rejected. CI never needs a cross toolchain.
"""

from __future__ import annotations

import re
import struct

from rehost.errors import AssembleError

_LABEL_NAME = re.compile(r"[A-Za-z_.][\w.]*\Z")
_LABEL_LINE = re.compile(r"^([A-Za-z_.][\w.]*)\s*:\s*(.*)$")
_LUI = re.compile(
    r"^lui\s+(?P<rd>[A-Za-z0-9]+)\s*,\s*(?P<imm>-?(?:0x[0-9a-fA-F]+|\d+))$",
    re.IGNORECASE,
)
_ADDI = re.compile(
    r"^addi\s+(?P<rd>[A-Za-z0-9]+)\s*,\s*(?P<rs1>[A-Za-z0-9]+)\s*,\s*"
    r"(?P<imm>-?(?:0x[0-9a-fA-F]+|\d+))$",
    re.IGNORECASE,
)
_MEM = re.compile(
    r"^(?P<op>lw|sw|sb)\s+(?P<reg>[A-Za-z0-9]+)\s*,\s*"
    r"(?P<imm>-?(?:0x[0-9a-fA-F]+|\d+))\s*\(\s*(?P<base>[A-Za-z0-9]+)\s*\)$",
    re.IGNORECASE,
)
_JAL = re.compile(
    r"^jal\s+(?P<rd>[A-Za-z0-9]+)\s*,\s*(?P<target>[A-Za-z_.][\w.]*)$",
    re.IGNORECASE,
)
_J = re.compile(r"^j\s+(?P<target>[A-Za-z_.][\w.]*)$", re.IGNORECASE)
_EBREAK = re.compile(r"^ebreak$", re.IGNORECASE)
_WORD = re.compile(r"^\.word\s+(?P<imm>-?(?:0x[0-9a-fA-F]+|\d+))$", re.IGNORECASE)

_WIDTHS = {
    "lui": 4,
    "addi": 4,
    "lw": 4,
    "sw": 4,
    "sb": 4,
    "jal": 4,
    "j": 4,
    "ebreak": 4,
}

_REGS = {
    "zero": 0,
    "ra": 1,
    "sp": 2,
    "gp": 3,
    "tp": 4,
    "t0": 5,
    "t1": 6,
    "t2": 7,
    "s0": 8,
    "fp": 8,
    "s1": 9,
    "a0": 10,
    "a1": 11,
    "a2": 12,
    "a3": 13,
    "a4": 14,
    "a5": 15,
    "a6": 16,
    "a7": 17,
    "s2": 18,
    "s3": 19,
    "s4": 20,
    "s5": 21,
    "s6": 22,
    "s7": 23,
    "s8": 24,
    "s9": 25,
    "s10": 26,
    "s11": 27,
    "t3": 28,
    "t4": 29,
    "t5": 30,
    "t6": 31,
}
for _number in range(32):
    _REGS[f"x{_number}"] = _number


def assemble(source: str, *, base: int = 0) -> bytes:
    """Assemble ``source`` and return the image."""
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
        if lowered.startswith(".word"):
            statements.append(("stmt", line_no, text, pc, 4))
            pc += 4
            continue
        if lowered.startswith("."):
            raise AssembleError(f"line {line_no}: unsupported directive {text.split()[0]}")
        op = text.split(None, 1)[0].lower()
        if op not in _WIDTHS:
            raise AssembleError(f"line {line_no}: unknown instruction {op}")
        statements.append(("stmt", line_no, text, pc, _WIDTHS[op]))
        pc += _WIDTHS[op]
    return statements


def _strip_comment(line: str) -> str:
    cut = len(line)
    for marker in ("//", ";", "#"):
        index = line.find(marker)
        if index != -1:
            cut = min(cut, index)
    return line[:cut].strip()


def _encode_statement(item: tuple, labels: dict[str, int]) -> tuple[int, str, int, bytes]:
    _kind, line_no, text, address, _width = item
    if text.lower().startswith(".word"):
        match = _WORD.fullmatch(text.strip())
        if not match:
            raise AssembleError(f"line {line_no}: .word needs one 32-bit operand")
        value = int(match.group("imm"), 0)
        if not 0 <= value <= 0xFFFFFFFF:
            raise AssembleError(f"line {line_no}: word {value:#x} does not fit in 32 bits")
        return line_no, text, address, struct.pack("<I", value)
    encoded = _encode_insn(text, address, labels, line_no)
    return line_no, text, address, encoded


def _encode_insn(text: str, address: int, labels: dict[str, int], line_no: int) -> bytes:
    match = _LUI.fullmatch(text)
    if match:
        rd = _register(match.group("rd"), line_no)
        imm = int(match.group("imm"), 0)
        if not 0 <= imm <= 0xFFFFF:
            raise AssembleError(f"line {line_no}: lui immediate must fit in 20 unsigned bits")
        return _pack((imm << 12) | (rd << 7) | 0x37)

    match = _ADDI.fullmatch(text)
    if match:
        rd = _register(match.group("rd"), line_no)
        rs1 = _register(match.group("rs1"), line_no)
        imm = _simm12(int(match.group("imm"), 0), line_no, what="addi")
        return _pack((imm << 20) | (rs1 << 15) | (rd << 7) | 0x13)

    match = _MEM.fullmatch(text)
    if match:
        op = match.group("op").lower()
        reg = _register(match.group("reg"), line_no)
        base = _register(match.group("base"), line_no)
        imm = _simm12(int(match.group("imm"), 0), line_no, what=op)
        if op == "lw":
            return _pack((imm << 20) | (base << 15) | (2 << 12) | (reg << 7) | 0x03)
        funct3 = 0 if op == "sb" else 2
        imm11_5 = (imm >> 5) & 0x7F
        imm4_0 = imm & 0x1F
        return _pack(
            (imm11_5 << 25) | (reg << 20) | (base << 15) | (funct3 << 12) | (imm4_0 << 7) | 0x23
        )

    match = _JAL.fullmatch(text)
    if match:
        rd = _register(match.group("rd"), line_no)
        return _jal(address, _target(match.group("target"), labels, line_no), rd, line_no)

    match = _J.fullmatch(text)
    if match:
        return _jal(address, _target(match.group("target"), labels, line_no), 0, line_no)

    if _EBREAK.fullmatch(text):
        return _pack(0x00100073)

    raise AssembleError(f"line {line_no}: could not encode {text!r}")


def _jal(address: int, target: int, rd: int, line_no: int) -> bytes:
    offset = target - address
    if offset % 2 != 0 or not -(1 << 20) <= offset <= (1 << 20) - 2:
        raise AssembleError(
            f"line {line_no}: jal from {address:#x} to {target:#x} is out of range"
        )
    imm = offset & 0x1FFFFF
    imm20 = (imm >> 20) & 1
    imm10_1 = (imm >> 1) & 0x3FF
    imm11 = (imm >> 11) & 1
    imm19_12 = (imm >> 12) & 0xFF
    word = (imm20 << 31) | (imm10_1 << 21) | (imm11 << 20) | (imm19_12 << 12) | (rd << 7) | 0x6F
    return _pack(word)


def _target(name: str, labels: dict[str, int], line_no: int) -> int:
    if not _LABEL_NAME.fullmatch(name) or name not in labels:
        raise AssembleError(f"line {line_no}: unknown branch target {name}")
    return labels[name]


def _simm12(value: int, line_no: int, *, what: str) -> int:
    if not -2048 <= value <= 2047:
        raise AssembleError(f"line {line_no}: {what} immediate must fit in signed 12 bits")
    return value & 0xFFF


def _register(token: str, line_no: int) -> int:
    try:
        return _REGS[token.lower()]
    except KeyError as exc:
        raise AssembleError(f"line {line_no}: unknown register {token}") from exc


def _pack(word: int) -> bytes:
    return struct.pack("<I", word & 0xFFFFFFFF)
