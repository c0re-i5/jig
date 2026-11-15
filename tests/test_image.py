# SPDX-License-Identifier: MIT
"""ELF32 and Intel HEX load next to the raw-bin path.

The fixtures are built in this process. Nothing here is a third-party image,
and nothing is written into the tree with an ELF header or a firmware suffix.
"""

from __future__ import annotations

import struct

import pytest

from rehost.cli import main
from rehost.config import parse_config
from rehost.errors import MachineError
from rehost.fixtures.assemble import assemble
from rehost.image import parse_elf, parse_firmware, parse_ihex
from rehost.machine import Machine

_PROGRAM = """
movs r0, #7
bkpt #0
"""

_LOAD_ADDRESS = """
movw r0, #0x100
movt r0, #0
ldr r1, [r0, #0]
movw r2, #0
movt r2, #0x2000
ldr r3, [r2, #0]
bkpt #0
"""


def test_raw_image_still_lands_at_load_base_and_at_an_explicit_base():
    image = assemble(_PROGRAM)
    machine = _machine()
    machine.load_image(image)
    assert machine.read_memory(0, len(image)) == image
    result = machine.run()
    assert result.status == "halted"
    assert result.registers["r0"] == 7

    shifted = _machine()
    shifted.load_image(image, base=0x20)
    assert shifted.read_memory(0x20, len(image)) == image
    assert shifted.read_memory(0, 4) == b"\x00\x00\x00\x00"


def test_elf_and_hex_match_a_raw_run(tmp_path, capsys):
    image = assemble(_PROGRAM)
    elf = build_elf([(0, 0, image)])
    hex_image = encode_ihex([(0, image)])
    assert parse_firmware(image)[0] == "raw"
    assert parse_firmware(elf)[0] == "elf"
    assert parse_firmware(hex_image)[0] == "ihex"

    for blob in (elf, hex_image):
        machine = _machine()
        machine.load_image(blob)
        result = machine.run()
        assert result.status == "halted"
        assert result.registers["r0"] == 7
        assert machine.read_memory(0, len(image)) == image

    config = tmp_path / "machine.yaml"
    config.write_text(_YAML, encoding="utf-8")
    for name in ("image.elf", "image.hex", "image.ihex", "firmware.bin"):
        path = tmp_path / name
        path.write_bytes(elf if name.endswith(".elf") or name.endswith(".bin") else hex_image)
        code = main(["run", "-v", "--config", str(config), "--firmware", str(path)])
        out = capsys.readouterr().out
        assert code == 0
        assert "status: halted" in out
        assert "r0: 0x00000007" in out


def test_elf_pt_load_uses_paddr_not_the_sram_vaddr():
    # The second segment's virtual address is SRAM. The bytes belong at the
    # load address in flash, which is what a reset handler copies from.
    code = assemble(_LOAD_ADDRESS)
    marker = (0xA5A5A5A5).to_bytes(4, "little")
    elf = build_elf(
        [
            (0, 0, code),
            (0x100, 0x20000000, marker),
        ]
    )
    machine = _machine()
    machine.load_image(elf)
    assert machine.read_memory(0x100, 4) == marker
    assert machine.read_u32(0x20000000) == 0
    result = machine.run()
    assert result.status == "halted"
    assert result.registers["r1"] == 0xA5A5A5A5
    assert result.registers["r3"] == 0


def test_zero_paddr_falls_back_to_vaddr_and_a_zero_pair_stays_at_zero():
    word = b"\x11\x22\x33\x44"
    at_sram = build_elf([(0, 0x20000000, word)])
    machine = _machine()
    machine.load_image(at_sram)
    assert machine.read_memory(0x20000000, 4) == word
    assert machine.read_memory(0, 4) == b"\x00\x00\x00\x00"

    code = assemble(_PROGRAM)
    at_zero = build_elf([(0, 0, code)])
    zero = _machine()
    zero.load_image(at_zero)
    assert zero.read_memory(0, len(code)) == code


def test_bss_style_pt_load_with_no_file_bytes_is_skipped():
    code = assemble(_PROGRAM)
    elf = build_elf([(0, 0, code), (0x20000000, 0x20000000, b"")])
    segments = parse_elf(elf)
    assert len(segments) == 1
    assert segments[0].address == 0


def test_elf_and_hex_reject_an_explicit_base_and_a_span_outside_the_map():
    code = assemble(_PROGRAM)
    elf = build_elf([(0, 0, code)])
    hex_image = encode_ihex([(0, code)])
    machine = _machine()
    with pytest.raises(MachineError, match="ELF images carry their own load addresses"):
        machine.load_image(elf, base=0)
    with pytest.raises(MachineError, match="Intel HEX images carry their own load addresses"):
        machine.load_image(hex_image, base=0)

    outside = build_elf([(0x08000000, 0x08000000, code)])
    with pytest.raises(MachineError, match=r"PT_LOAD segment 0.*0x8000000.*outside the memory map"):
        _machine().load_image(outside)
    high = encode_ihex([(0x08000000, code)])
    with pytest.raises(MachineError, match=r"Intel HEX data at 0x8000000.*outside the memory map"):
        _machine().load_image(high)


def test_elf_rejects_truncated_class_endian_machine_and_a_segment_past_eof():
    with pytest.raises(MachineError, match="truncated"):
        parse_elf(b"\x7fELF")
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[6] = 1
    with pytest.raises(MachineError, match="ELF32"):
        parse_elf(bytes(header))
    header[4] = 1
    header[5] = 2
    with pytest.raises(MachineError, match="little-endian"):
        parse_elf(bytes(header))
    with pytest.raises(MachineError, match="EM_ARM"):
        parse_elf(build_elf([(0, 0, b"\x00\xbe")], machine=3))
    with pytest.raises(MachineError, match="not a loadable image"):
        parse_elf(build_elf([(0, 0, b"\x00\xbe")], elf_type=1))
    with pytest.raises(MachineError, match="no PT_LOAD"):
        parse_elf(build_elf([(0, 0, b"\x00\xbe")], p_type=4))
    with pytest.raises(MachineError, match="extends past the end"):
        parse_elf(build_elf([(0, 0, b"\x00\xbe")], filesz=0x100))


def test_ihex_extended_address_checksum_and_eof():
    payload = b"\x7e\x00"
    image = encode_ihex([(0x08000100, payload)])
    segments = parse_ihex(image)
    assert len(segments) == 1
    assert segments[0].address == 0x08000100
    assert segments[0].data == payload

    # Type 02: segment 0x1000 << 4 is 0x10000, plus offset 0x20.
    line = _record(0, 0x02, b"\x10\x00")
    data = _record(0x20, 0x00, b"\xab")
    eof = _record(0, 0x01, b"")
    parsed = parse_ihex(f"{line}\n{data}\n{eof}\n".encode())
    assert parsed[0].address == 0x10020
    assert parsed[0].data == b"\xab"

    # A later record overwrites one byte and still merges the span.
    first = _record(0, 0x00, b"\x01\x02")
    second = _record(1, 0x00, b"\x09")
    merged = parse_ihex(f"{first}\n{second}\n{eof}\n".encode())
    assert merged[0].data == b"\x01\x09"

    bad = bytearray(image)
    # Flip a hex digit in the data record so the checksum fails.
    text = bad.decode()
    lines = text.splitlines()
    data_line = next(line for line in lines if line[7:9] == "00")
    flipped = data_line[:-2] + ("0" if data_line[-2] != "0" else "1") + data_line[-1]
    broken = text.replace(data_line, flipped, 1).encode()
    with pytest.raises(MachineError, match="bad checksum"):
        parse_ihex(broken)
    with pytest.raises(MachineError, match="end-of-file"):
        parse_ihex(b":00000001FF\n:0000000000\n")
    with pytest.raises(MachineError, match="no data records"):
        parse_ihex(b":00000001FF\n")
    with pytest.raises(MachineError, match="no end-of-file"):
        parse_ihex(b":0100000001FE\n")

    # A binary that merely starts with ':' is still raw.
    raw = b":not-hex\x00\xff"
    assert parse_firmware(raw) == ("raw", [])


def test_cli_reports_a_segment_outside_the_map(tmp_path, capsys):
    config = tmp_path / "machine.yaml"
    config.write_text(_YAML, encoding="utf-8")
    image = tmp_path / "high.elf"
    image.write_bytes(build_elf([(0x08000000, 0x08000000, assemble(_PROGRAM))]))
    code = main(["run", "--config", str(config), "--firmware", str(image)])
    err = capsys.readouterr().err
    assert code == 4
    assert "outside the memory map" in err
    assert "0x8000000" in err


def build_elf(
    segments: list[tuple[int, int, bytes]],
    *,
    machine: int = 40,
    elf_type: int = 2,
    p_type: int = 1,
    filesz: int | None = None,
) -> bytes:
    """Minimal little-endian ELF32. ``segments`` are ``(p_paddr, p_vaddr, bytes)``."""
    phoff = 52
    phnum = len(segments)
    body = bytearray()
    phdrs = bytearray()
    cursor = phoff + phnum * 32
    for paddr, vaddr, data in segments:
        size = len(data) if filesz is None else filesz
        phdrs += struct.pack(
            "<IIIIIIII",
            p_type,
            cursor,
            vaddr,
            paddr,
            size,
            size,
            5,
            4,
        )
        body += data
        cursor += len(data)
    header = bytearray(52)
    header[0:4] = b"\x7fELF"
    header[4] = 1
    header[5] = 1
    header[6] = 1
    struct.pack_into("<HHI", header, 16, elf_type, machine, 1)
    struct.pack_into("<III", header, 24, 0, phoff, 0)
    struct.pack_into("<HHHHHH", header, 40, 52, 32, phnum, 0, 0, 0)
    return bytes(header) + bytes(phdrs) + bytes(body)


def encode_ihex(spans: list[tuple[int, bytes]]) -> bytes:
    lines: list[str] = []
    upper: int | None = None
    for address, data in spans:
        pos = 0
        while pos < len(data):
            here = address + pos
            ela = here >> 16
            if ela != upper:
                lines.append(_record(0, 0x04, bytes((ela >> 8, ela & 0xFF))))
                upper = ela
            room = 0x10000 - (here & 0xFFFF)
            chunk = data[pos : pos + min(16, room)]
            lines.append(_record(here & 0xFFFF, 0x00, chunk))
            pos += len(chunk)
    lines.append(_record(0, 0x01, b""))
    return ("\n".join(lines) + "\n").encode()


def _record(offset: int, record_type: int, data: bytes) -> str:
    raw = bytes((len(data), (offset >> 8) & 0xFF, offset & 0xFF, record_type)) + data
    checksum = (-sum(raw)) & 0xFF
    return ":" + (raw + bytes((checksum,))).hex().upper()


def _machine() -> Machine:
    return Machine(parse_config({
        "name": "image-load",
        "arch": "cortex-m",
        "load": {"base": 0},
        "memory": [
            {"name": "flash", "base": 0, "size": 0x1000, "perms": "rwx"},
            {"name": "sram", "base": 0x20000000, "size": 0x1000, "perms": "rw"},
        ],
        "boot": {"mode": "entry", "sp": 0x20001000, "entry": 0},
        "run": {"timeout_ms": 200, "max_instructions": 100, "halt_on_bkpt": True},
    }))


_YAML = """
name: image-load
arch: cortex-m
load: {base: 0}
memory:
  - {name: flash, base: 0, size: 0x1000, perms: rwx}
  - {name: sram, base: 0x20000000, size: 0x1000, perms: rw}
boot: {mode: entry, sp: 0x20001000, entry: 0}
run: {timeout_ms: 200, max_instructions: 100, halt_on_bkpt: true}
"""
