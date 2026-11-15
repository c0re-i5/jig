# SPDX-License-Identifier: MIT
"""Starter maps from synthetic ELF and Intel HEX images. No third-party firmware."""

from __future__ import annotations

import struct

import pytest

from rehost.cli import main
from rehost.config import load_config
from rehost.errors import MachineError
from rehost.mapinit import format_inspection, inspect_image, render_machine_yaml
from rehost.machine import Machine


def _record(offset: int, record_type: int, data: bytes) -> str:
    raw = bytes((len(data), (offset >> 8) & 0xFF, offset & 0xFF, record_type)) + data
    checksum = (-sum(raw)) & 0xFF
    return ":" + (raw + bytes((checksum,))).hex().upper()


def _ihex(spans: list[tuple[int, bytes]]) -> bytes:
    lines = []
    upper: int | None = None
    for address, data in spans:
        pos = 0
        while pos < len(data):
            here = address + pos
            ela = here >> 16
            if ela != upper:
                lines.append(_record(0, 0x04, bytes((ela >> 8, ela & 0xFF))))
                upper = ela
            chunk = data[pos : pos + 16]
            lines.append(_record(here & 0xFFFF, 0x00, chunk))
            pos += len(chunk)
    lines.append(_record(0, 0x01, b""))
    return ("\n".join(lines) + "\n").encode()


def build_elf(segments: list[tuple]) -> bytes:
    """Minimal ELF32. Each tuple is ``(paddr, vaddr, data, memsz, flags)``."""
    phoff = 52
    phnum = len(segments)
    body = bytearray()
    phdrs = bytearray()
    cursor = phoff + phnum * 32
    for paddr, vaddr, data, memsz, flags in segments:
        phdrs += struct.pack(
            "<IIIIIIII",
            1,
            cursor,
            vaddr,
            paddr,
            len(data),
            memsz,
            flags,
            4,
        )
        body += data
        cursor += len(data)
    header = bytearray(52)
    header[0:4] = b"\x7fELF"
    header[4] = 1
    header[5] = 1
    header[6] = 1
    struct.pack_into("<HHI", header, 16, 2, 40, 1)
    struct.pack_into("<III", header, 24, 0, phoff, 0)
    struct.pack_into("<HHHHHH", header, 40, 52, 32, phnum, 0, 0, 0)
    return bytes(header) + bytes(phdrs) + bytes(body)


def _cnc_shaped() -> bytes:
    # Odd Atollic-style stack top, reset Thumb entry inside the first bytes,
    # a .data image whose virtual address is SRAM, and one USART-like constant.
    blob = bytearray()
    blob += (0x2001FFFF).to_bytes(4, "little")
    blob += (0x08000009).to_bytes(4, "little")
    blob += b"\x00" * 8
    blob += (0x40004400).to_bytes(4, "little")
    data = b"\x11\x22\x33\x44"
    load = 0x08000000 + len(blob)
    return build_elf(
        [
            (0x08000000, 0x08000000, bytes(blob), len(blob), 5),
            (load, 0x20000000, data, len(data), 6),
            (0x20000004, 0x20000004, b"", 0x20, 6),
        ]
    )


def _k64_shaped() -> bytes:
    # Initial SP sits just above SRAM_L, and .data extends past it.
    vectors = (0x1FFF0200).to_bytes(4, "little") + (0x00000411).to_bytes(4, "little")
    vectors += b"\x00" * 8
    code = b"\x00\xbf\x00\xbf"
    return build_elf(
        [
            (0x00000000, 0x00000000, vectors, len(vectors), 5),
            (0x00000410, 0x00000410, code, len(code), 5),
            (0x00000500, 0x1FFF0200, b"\x01\x02\x03\x04", 0x100, 6),
            (0x1FFF0000, 0x1FFF0000, b"", 0x200, 6),
        ]
    )


def test_cnc_shaped_elf_suggests_stack_top_and_a_constant_window():
    info = inspect_image(_cnc_shaped())
    assert info.kind == "elf"
    assert info.vector is not None
    assert info.vector.sp == 0x2001FFFF
    assert info.vector.thumb
    flash = next(region for region in info.regions if region.name == "flash")
    sram = next(region for region in info.regions if region.name == "sram")
    assert flash.base == 0x08000000
    assert flash.perms == "rx"
    assert flash.size >= 0x1000
    assert sram.base == 0x20000000
    assert sram.size == 0x20000
    mmio = next(region for region in info.regions if region.base == 0x40004400)
    assert mmio.peripheral == "unimplemented"
    assert any(region.peripheral == "systick" for region in info.regions)
    text = format_inspection(info)
    assert "0x2001ffff" in text
    yaml_text = render_machine_yaml(info, name="cnc-shaped")
    assert "TODO:" in yaml_text
    assert "unimplemented" in yaml_text
    assert "peripheral: systick" in yaml_text


def test_k64_shaped_elf_adds_slack_when_sp_is_not_the_top():
    info = inspect_image(_k64_shaped())
    sram = next(region for region in info.regions if region.name == "sram")
    flash = next(region for region in info.regions if region.name == "flash")
    assert flash.base == 0x00000000
    assert sram.base == 0x1FFF0000
    assert sram.size == 0x10000
    assert any("starter space" in region.comment for region in info.regions)
    rendered = render_machine_yaml(info, name="k64-shaped")
    assert "0x1fff0000" in rendered


def test_rendered_yaml_loads_the_elf_it_came_from():
    elf = _cnc_shaped()
    info = inspect_image(elf)
    text = render_machine_yaml(info, name="load-me")
    # parse already happened inside render. Build a machine and boot.
    from pathlib import Path
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "board.yaml"
        path.write_text(text, encoding="utf-8")
        machine = Machine(load_config(path))
        machine.load_image(elf)
        machine.boot()
    # 0x2001FFFF with the low bits cleared, which is what the CPU model does.
    assert machine.backend.read_register("sp") == 0x2001FFFC


def test_raw_bin_is_rejected_and_hex_uses_the_lowest_address():
    with pytest.raises(MachineError, match="raw bin"):
        inspect_image(b"\x00\x01\x02\x03" * 8)
    vectors = (0x20001000).to_bytes(4, "little") + (0x08000011).to_bytes(4, "little")
    info = inspect_image(_ihex([(0x08000000, vectors + b"\x00" * 8)]))
    assert info.kind == "ihex"
    assert info.vector is not None
    assert info.vector.sp == 0x20001000
    flash = next(region for region in info.regions if region.name == "flash")
    assert flash.base == 0x08000000


def test_cli_map_init_and_inspect(tmp_path, capsys):
    elf_path = tmp_path / "Image"
    elf_path.write_bytes(_cnc_shaped())
    out = tmp_path / "board.yaml"
    code = main(["map", "init", str(elf_path), "-o", str(out), "--name", "from-elf"])
    assert code == 0, capsys.readouterr().err
    assert out.is_file()
    loaded = load_config(out)
    assert loaded.name == "from-elf"
    assert any(region.peripheral == "systick" for region in loaded.memory)
    again = main(["map", "init", str(elf_path), "-o", str(out)])
    assert again == 4
    assert "already exists" in capsys.readouterr().err
    forced = main(["map", "init", str(elf_path), "-o", str(out), "--force"])
    assert forced == 0
    code = main(["inspect", str(elf_path)])
    report = capsys.readouterr().out
    assert code == 0
    assert "format: ELF32" in report
    assert "initial SP" in report
