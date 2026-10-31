# SPDX-License-Identifier: MIT
"""GPIO latch stub.

``ODR`` stores what firmware writes. ``IDR`` returns the configured input
sample, or the output latch when ``loopback`` is true. Other offsets are
logged. This is not an STM32 or NXP GPIO block; offsets are config.
"""

from __future__ import annotations

from typing import Any

from rehost.config import parse_u32
from rehost.errors import ConfigError
from rehost.memory import access_mask
from rehost.peripherals.base import Peripheral, extract_field, insert_field
from rehost.peripherals.registry import register


@register("gpio")
class Gpio(Peripheral):
    config_keys = frozenset({"read_default", "odr_offset", "idr_offset", "idr", "loopback"})

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.odr_offset = parse_u32(self.config.get("odr_offset", 0), what=f"{self.name} odr_offset")
        self.idr_offset = parse_u32(self.config.get("idr_offset", 4), what=f"{self.name} idr_offset")
        self.idr = parse_u32(self.config.get("idr", 0), what=f"{self.name} idr")
        loopback = self.config.get("loopback", False)
        if not isinstance(loopback, bool):
            raise ConfigError(f"{self.name} loopback must be true or false")
        self.loopback = loopback
        if self.odr_offset == self.idr_offset:
            raise ConfigError(f"{self.name} odr_offset and idr_offset must differ")
        self.require_aligned(self.odr_offset, what="odr")
        self.require_aligned(self.idr_offset, what="idr")
        self.odr = 0

    def read(self, offset: int, size: int) -> int:
        if self.odr_offset <= offset < self.odr_offset + 4 and offset + size <= self.odr_offset + 4:
            return extract_field(self.odr, offset, size, self.odr_offset)
        if self.idr_offset <= offset < self.idr_offset + 4 and offset + size <= self.idr_offset + 4:
            source = self.odr if self.loopback else self.idr
            return extract_field(source, offset, size, self.idr_offset)
        self.log_unhandled("read", offset, size, None)
        return self.read_default & access_mask(size)

    def write(self, offset: int, size: int, value: int) -> None:
        if self.odr_offset <= offset < self.odr_offset + 4 and offset + size <= self.odr_offset + 4:
            self.odr = insert_field(self.odr, offset, size, self.odr_offset, value) & 0xFFFFFFFF
            return
        if self.idr_offset <= offset < self.idr_offset + 4:
            return
        self.log_unhandled("write", offset, size, value)

    def snapshot_state(self) -> dict[str, Any]:
        return {"odr": self.odr, "idr": self.idr}

    def restore_state(self, state: dict[str, Any]) -> None:
        self.odr = int(state["odr"]) & 0xFFFFFFFF
        self.idr = int(state["idr"]) & 0xFFFFFFFF

    def debug_lines(self) -> list[str]:
        return [f"{self.name} odr: {self.odr:#x}"]
