# SPDX-License-Identifier: MIT
"""Cortex-M bit-band alias window.

An access in this region reads or writes a single bit of ``target``. The
mapping is the one in the ARM architecture:

    byte_offset = (alias - base) // 32
    bit         = ((alias - base) % 32) // 4
    address     = target + byte_offset

Bit 0 of the written value selects the bit. A read returns that bit in bit 0
and zeros everywhere else. The target may be a peripheral plugin or ordinary
RAM. The alias does not store its own copy of the bit.

This is a general address alias, not an STM32 device. A machine file points
``target`` at the start of the bit-band region (``0x40000000`` for the
peripheral alias at ``0x42000000``, ``0x20000000`` for the SRAM alias at
``0x22000000``).
"""

from __future__ import annotations

from typing import Any, Callable

from rehost.config import parse_u32
from rehost.errors import ConfigError
from rehost.peripherals.base import Peripheral
from rehost.peripherals.registry import register

_ADDRESS_SPACE = 0x1_0000_0000


@register("bitband")
class Bitband(Peripheral):
    config_keys = frozenset({"read_default", "target"})

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        if "target" not in self.config:
            raise ConfigError(
                f"{self.name} bitband requires config.target, the first address the alias maps onto"
            )
        self.target = parse_u32(self.config["target"], what=f"{self.name} bitband target")
        if self.size % 32 != 0:
            raise ConfigError(
                f"{self.name} bitband size must be a multiple of 32 bytes, not {self.size:#x}"
            )
        self.span = self.size // 32
        if self.target + self.span > _ADDRESS_SPACE:
            raise ConfigError(f"{self.name} bitband target extends past the 32-bit address space")
        alias_end = self.base + self.size
        target_end = self.target + self.span
        if not (alias_end <= self.target or target_end <= self.base):
            raise ConfigError(
                f"{self.name} bitband alias [{self.base:#x}, {alias_end:#x}) "
                f"overlaps its target [{self.target:#x}, {target_end:#x})"
            )
        self._load_byte: Callable[[int], int] | None = None
        self._store_byte: Callable[[int, int], None] | None = None

    def bind(
        self,
        load_byte: Callable[[int], int],
        store_byte: Callable[[int, int], None],
    ) -> None:
        """Connect the alias to the machine that owns the target bytes."""
        self._load_byte = load_byte
        self._store_byte = store_byte

    def read(self, offset: int, size: int) -> int:
        if self._load_byte is None:
            return 0
        address, bit = self.locate(offset)
        current = self._load_byte(address) & 0xFF
        return 1 if (current >> bit) & 1 else 0

    def write(self, offset: int, size: int, value: int) -> None:
        if self._store_byte is None or self._load_byte is None:
            return
        address, bit = self.locate(offset)
        current = self._load_byte(address) & 0xFF
        if value & 1:
            updated = current | (1 << bit)
        else:
            updated = current & ~(1 << bit)
        self._store_byte(address, updated & 0xFF)

    def locate(self, offset: int) -> tuple[int, int]:
        """Return ``(target_byte, bit_in_byte)`` for an offset in this alias."""
        if offset < 0 or offset >= self.size:
            raise ConfigError(f"{self.name} bitband offset {offset:#x} is outside the alias")
        return self.target + (offset // 32), (offset % 32) // 4
