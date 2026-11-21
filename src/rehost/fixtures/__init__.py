# SPDX-License-Identifier: MIT
"""Synthetic fixtures assembled in-repo.

These are hand-written Thumb and RV32I programs used by tests and
``jig-emu run --fixture``. They are not third-party firmware, and this
package does not download any.
"""

from __future__ import annotations

from pathlib import Path

from rehost.errors import ConfigError
from rehost.fixtures.assemble import assemble
from rehost.fixtures.assemble_riscv import assemble as assemble_rv32

_DATA = Path(__file__).resolve().parent / "data"

FIXTURES: dict[str, dict[str, str]] = {
    "uart-gpio": {
        "asm": "uart_gpio.s",
        "config": "uart_gpio.yaml",
        "summary": "Posts 'A' to UART, sets a GPIO latch, reads SysTick, stores a magic word, then BKPT.",
    },
    "fuzz-echo": {
        "asm": "fuzz_echo.s",
        "config": "fuzz_echo.yaml",
        "summary": "Loads the word at SRAM 0x20000100 and writes its low byte to UART.",
    },
    "fuzz-crash": {
        "asm": "fuzz_crash.s",
        "config": "fuzz_crash.yaml",
        "summary": "Halts on BKPT unless the fuzz buffer starts with the bytes JIG!, which fault.",
    },
    "modbus-rtu": {
        "asm": "modbus_rtu.s",
        "config": "modbus_rtu.yaml",
        "summary": "IRQ-driven Modbus RTU: answers Read Holding Registers 0 with 0x1234, else an exception.",
    },
    "plant-floor": {
        "asm": "plant_floor.s",
        "config": "plant_floor.yaml",
        "base": "0x08000000",
        "summary": (
            "STM32-shaped controller: one SysTick, then a Modbus RTU read on USART2. "
            "Fuzz buffer JIG! fetches unmapped memory."
        ),
    },
    "uart-gpio-rv32": {
        "asm": "uart_gpio_rv32.s",
        "config": "uart_gpio_rv32.yaml",
        "isa": "rv32",
        "summary": (
            "RV32I: posts 'A' to a UART, sets a GPIO latch, stores a magic word "
            "and the UART status, then EBREAK."
        ),
    },
}


def list_fixtures() -> list[str]:
    return sorted(FIXTURES)


def fixture_summary(name: str) -> str:
    return _spec(name)["summary"]


def fixture_config_path(name: str) -> Path:
    path = _DATA / _spec(name)["config"]
    if not path.is_file():
        raise ConfigError(f"packaged fixture config is missing: {path}")
    return path


def fixture_source(name: str) -> str:
    path = _DATA / _spec(name)["asm"]
    if not path.is_file():
        raise ConfigError(f"packaged fixture source is missing: {path}")
    return path.read_text(encoding="utf-8")


def build_fixture(name: str) -> bytes:
    """Assemble a named fixture to a raw image.

    The default assemble base is 0, which matches fixtures loaded at address 0.
    A fixture that sets ``base`` (the plant-floor image at ``0x08000000``) is
    assembled there so ``.thumb_word`` entries match ``load.base``.
    """
    spec = _spec(name)
    base = int(spec.get("base", "0"), 0)
    source = fixture_source(name)
    if spec.get("isa") == "rv32":
        return assemble_rv32(source, base=base)
    return assemble(source, base=base)


def _spec(name: str) -> dict[str, str]:
    try:
        return FIXTURES[name]
    except KeyError as exc:
        known = ", ".join(list_fixtures()) or "(none)"
        raise ConfigError(f"unknown fixture {name!r}. Available: {known}") from exc
