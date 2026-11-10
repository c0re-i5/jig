# SPDX-License-Identifier: MIT
"""Synthetic Cortex-M fixtures assembled in-repo.

These are hand-written Thumb programs used by tests and ``jig-emu run
--fixture``. They are not third-party firmware, and this package does not
download any.
"""

from __future__ import annotations

from pathlib import Path

from rehost.errors import ConfigError
from rehost.fixtures.assemble import assemble

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
    """Assemble a named fixture to a raw image. The load address is 0."""
    return assemble(fixture_source(name))


def _spec(name: str) -> dict[str, str]:
    try:
        return FIXTURES[name]
    except KeyError as exc:
        known = ", ".join(list_fixtures()) or "(none)"
        raise ConfigError(f"unknown fixture {name!r}. Available: {known}") from exc
