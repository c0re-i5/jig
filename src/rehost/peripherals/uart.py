# SPDX-License-Identifier: MIT
"""Byte-oriented UART stub.

Not a 16550. Firmware that writes the data register posts the low byte into
``tx``. A read of the data register pops one byte from ``rx`` or returns 0.
The status register reports transmitter-empty and receiver-ready bits from
config. Any other offset is logged and returns ``read_default``.
"""

from __future__ import annotations

from typing import Any

from rehost.config import parse_u32
from rehost.errors import ConfigError
from rehost.memory import access_mask
from rehost.peripherals.base import Peripheral
from rehost.peripherals.registry import register


@register("uart")
class Uart(Peripheral):
    config_keys = frozenset(
        {
            "read_default",
            "data_offset",
            "status_offset",
            "tx_empty_mask",
            "rx_ready_mask",
            "rx",
        }
    )
    _TX_CAP = 1 << 20

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.data_offset = parse_u32(self.config.get("data_offset", 0), what=f"{self.name} data_offset")
        self.status_offset = parse_u32(
            self.config.get("status_offset", 4), what=f"{self.name} status_offset"
        )
        self.tx_empty_mask = parse_u32(
            self.config.get("tx_empty_mask", 0x80), what=f"{self.name} tx_empty_mask"
        )
        self.rx_ready_mask = parse_u32(
            self.config.get("rx_ready_mask", 0x01), what=f"{self.name} rx_ready_mask"
        )
        if self.data_offset == self.status_offset:
            raise ConfigError(f"{self.name} data_offset and status_offset must differ")
        self.require_aligned(self.data_offset, what="data")
        self.require_aligned(self.status_offset, what="status")
        self.tx = bytearray()
        self.tx_dropped = 0
        self.rx = bytearray(_as_bytes(self.config.get("rx", b""), what=f"{self.name} rx"))

    def read(self, offset: int, size: int) -> int:
        if offset == self.data_offset:
            if self.rx:
                return self.rx.pop(0) & access_mask(size)
            return 0
        if offset == self.status_offset:
            flags = self.tx_empty_mask
            if self.rx:
                flags |= self.rx_ready_mask
            return flags & access_mask(size)
        self.log_unhandled("read", offset, size, None)
        return self.read_default & access_mask(size)

    def write(self, offset: int, size: int, value: int) -> None:
        if offset == self.data_offset:
            if len(self.tx) < self._TX_CAP:
                self.tx.append(value & 0xFF)
            else:
                self.tx_dropped += 1
            return
        if offset == self.status_offset:
            return
        self.log_unhandled("write", offset, size, value)

    def snapshot_state(self) -> dict[str, Any]:
        return {"tx": bytes(self.tx), "rx": bytes(self.rx), "tx_dropped": self.tx_dropped}

    def restore_state(self, state: dict[str, Any]) -> None:
        self.tx = bytearray(state["tx"])
        self.rx = bytearray(state["rx"])
        self.tx_dropped = int(state["tx_dropped"])

    def debug_lines(self) -> list[str]:
        preview = bytes(self.tx[:32])
        extra = "" if len(self.tx) <= 32 else f" (+{len(self.tx) - 32} more)"
        shown = preview.hex() or "(empty)"
        return [f"{self.name} tx: {shown}{extra}"]


def _as_bytes(value: object, *, what: str) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        try:
            return value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ConfigError(f"{what} must be ASCII") from exc
    if isinstance(value, list):
        return bytes(parse_u32(item, what=what) & 0xFF for item in value)
    raise ConfigError(f"{what} must be a string or a list of bytes")
