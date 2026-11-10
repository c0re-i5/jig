# SPDX-License-Identifier: MIT
"""The in-repo UART/GPIO/SysTick program runs to BKPT without external firmware."""

from __future__ import annotations

from pathlib import Path

from rehost.fixtures import build_fixture
from rehost.machine import Machine

_BANNED = {".bin", ".rom", ".elf", ".hex", ".ihex", ".srec", ".fw"}


def test_uart_gpio_fixture_contract():
    image = build_fixture("uart-gpio")
    assert len(image) < 512
    assert int.from_bytes(image[:4], "little") == 0x20004000
    assert image.endswith(b"\x00\xbe")

    machine = Machine.from_fixture("uart-gpio")
    result = machine.run()

    assert result.status == "halted"
    assert result.detail == "bkpt"
    assert result.pc == len(image) - 2
    assert result.instructions < 100
    assert bytes(machine.peripheral("uart0").tx) == b"A"
    assert machine.peripheral("gpioa").odr == 1
    assert machine.read_u32(0x20000000) == 0x00C0FFEE
    assert machine.read_u32(0x20000008) & 0x80 == 0x80
    assert any(entry.kind == "read" and entry.address == 0xE000E018 for entry in result.trace)
    assert machine.read_u32(0x20000004) == 0


def test_repository_ships_no_firmware_blobs():
    root = Path(__file__).resolve().parents[1]
    found = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if ".git" in path.parts or "__pycache__" in path.parts:
            continue
        if path.suffix.lower() in _BANNED:
            found.append(str(path.relative_to(root)))
    assert found == []


def test_examples_match_packaged_fixtures():
    root = Path(__file__).resolve().parents[1]
    packaged = root / "src" / "rehost" / "fixtures" / "data"
    examples = root / "examples"
    for name in (
        "uart_gpio.s",
        "uart_gpio.yaml",
        "fuzz_echo.s",
        "fuzz_echo.yaml",
        "fuzz_crash.s",
        "fuzz_crash.yaml",
    ):
        assert (examples / name).read_text(encoding="utf-8") == (
            packaged / name
        ).read_text(encoding="utf-8")
