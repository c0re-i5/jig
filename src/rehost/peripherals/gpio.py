# SPDX-License-Identifier: MIT
"""GPIO latch stub.

``ODR`` stores what firmware writes. ``IDR`` returns the configured input
sample, or the output latch when ``loopback`` is true. Optional ``bsrr_offset``
is an STM32-style bit set/reset register: a 1 in the low half sets the matching
``ODR`` bit, a 1 in the high half clears it, and a bit set in both halves
clears. Other offsets are logged. This is not an STM32 or NXP GPIO block;
offsets are config.
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
    config_keys = frozenset(
        {"read_default", "odr_offset", "idr_offset", "idr", "loopback", "bsrr_offset"}
    )

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
        if "bsrr_offset" in self.config:
            self.bsrr_offset: int | None = parse_u32(
                self.config["bsrr_offset"], what=f"{self.name} bsrr_offset"
            )
            self.require_aligned(self.bsrr_offset, what="bsrr")
            if self.bsrr_offset in (self.odr_offset, self.idr_offset):
                raise ConfigError(f"{self.name} bsrr_offset must not alias odr or idr")
        else:
            self.bsrr_offset = None
        self.odr = 0

    def read(self, offset: int, size: int) -> int:
        if self.odr_offset <= offset < self.odr_offset + 4 and offset + size <= self.odr_offset + 4:
            return extract_field(self.odr, offset, size, self.odr_offset)
        if self.idr_offset <= offset < self.idr_offset + 4 and offset + size <= self.idr_offset + 4:
            source = self.odr if self.loopback else self.idr
            return extract_field(source, offset, size, self.idr_offset)
        if self._in_bsrr(offset, size):
            return 0
        self.log_unhandled("read", offset, size, None)
        return self.read_default & access_mask(size)

    def write(self, offset: int, size: int, value: int) -> None:
        if self.odr_offset <= offset < self.odr_offset + 4 and offset + size <= self.odr_offset + 4:
            self.odr = insert_field(self.odr, offset, size, self.odr_offset, value) & 0xFFFFFFFF
            return
        if self.idr_offset <= offset < self.idr_offset + 4 and offset + size <= self.idr_offset + 4:
            return
        if self._in_bsrr(offset, size):
            self._write_bsrr(offset, size, value)
            return
        self.log_unhandled("write", offset, size, value)

    def _in_bsrr(self, offset: int, size: int) -> bool:
        base = self.bsrr_offset
        return base is not None and base <= offset and offset + size <= base + 4

    def _write_bsrr(self, offset: int, size: int, value: int) -> None:
        """Apply the bytes firmware stored. Unwritten bytes of the word do nothing."""
        assert self.bsrr_offset is not None
        placed = insert_field(0, offset, size, self.bsrr_offset, value)
        span = ((1 << (8 * size)) - 1) << (8 * (offset - self.bsrr_offset))
        set_mask = placed & span & 0xFFFF
        reset_mask = (placed & span) >> 16
        # A bit written in both halves clears. STM32 documents BRx over BSx.
        self.odr = ((self.odr | set_mask) & ~reset_mask) & 0xFFFFFFFF

    def snapshot_state(self) -> dict[str, Any]:
        return {"odr": self.odr, "idr": self.idr}

    def restore_state(self, state: dict[str, Any]) -> None:
        self.odr = int(state["odr"]) & 0xFFFFFFFF
        self.idr = int(state["idr"]) & 0xFFFFFFFF

    def debug_lines(self) -> list[str]:
        return [f"{self.name} odr: {self.odr:#x}"]
