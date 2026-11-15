# SPDX-License-Identifier: MIT
"""Byte-oriented UART stub.

Not a 16550, and not a vendor USART. Firmware that writes the data register
posts the low byte into ``tx``. A read of the data register pops one byte from
``rx`` or returns 0. The status register reports transmitter-empty and
receiver-ready bits from config. Any other offset is logged and returns
``read_default``.

``data_offset`` and ``status_offset`` are exact byte offsets, not required to
be word-aligned. A Kinetis UART keeps its status at ``0x04`` and its data
register at ``0x07``; a byte access at that offset hits the register. A wider
access hits it only when the access starts at the same offset.

``rx_irq`` (alias ``irq``) is an NVIC external IRQ number. When the RX queue
goes from empty to non-empty, the plugin latches that IRQ through the same
``inject_irq`` path the machine already uses. Omitting the key leaves the line
quiet, including when ``rx`` is preloaded. The latch is edge-triggered unless
``rx_level`` is true: edge mode fires once per burst and again only after the
queue has been emptied, and the handler is expected to drain RX. Level mode
pends again on the next instruction while bytes remain, which is a ready bit
that stays set after a one-byte read. Draining RX does not clear a pending
bit that was already latched; taking the exception or writing ICPR does, as
with any other NVIC line.
"""

from __future__ import annotations

from typing import Any, Callable

from rehost.config import parse_u32
from rehost.errors import ConfigError
from rehost.memory import access_mask
from rehost.nvic import NUM_EXTERNAL
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
            "rx_irq",
            "irq",
            "rx_level",
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
        self._require_offset(self.data_offset, what="data")
        self._require_offset(self.status_offset, what="status")
        self.rx_irq = _parse_rx_irq(self.name, self.config)
        rx_level = self.config.get("rx_level", False)
        if not isinstance(rx_level, bool):
            raise ConfigError(f"{self.name} rx_level must be true or false")
        self.rx_level = rx_level
        self.tx = bytearray()
        self.tx_dropped = 0
        self.rx = bytearray(_as_bytes(self.config.get("rx", b""), what=f"{self.name} rx"))
        # True after the rising edge has been reported for the current burst.
        self.rx_irq_armed = False
        self._inject: Callable[[int], None] | None = None

    def _require_offset(self, offset: int, *, what: str) -> None:
        if offset >= self.size:
            raise ConfigError(
                f"{self.name} {what} at {offset:#x} does not fit in a {self.size:#x}-byte region"
            )

    def bind_rx_irq(self, inject: Callable[[int], None]) -> None:
        """Connect the RX latch to ``Machine.inject_irq`` (or a test double).

        A queue that was already non-empty latches immediately, so a byte
        supplied in the machine file is pending before the first instruction.
        """
        self._inject = inject
        self.raise_rx_if_needed()

    def queue_rx(self, data: bytes | bytearray) -> None:
        """Append bytes to RX. An empty-to-non-empty transition latches ``rx_irq``."""
        blob = _as_bytes(data, what=f"{self.name} rx")
        if not blob:
            return
        if not self.rx:
            self.rx_irq_armed = False
        self.rx.extend(blob)
        self.raise_rx_if_needed()

    def raise_rx_if_needed(self) -> None:
        """Pend ``rx_irq`` if a rising edge is waiting and an injector is bound."""
        if self._inject is None:
            return
        irq = self.take_rx_irq_edge()
        if irq is not None:
            self._inject(irq)

    def take_rx_irq_edge(self) -> int | None:
        """Return ``rx_irq`` once per non-empty burst, else None.

        The instruction hook calls this so a queue that arrived before
        ``bind_rx_irq``, or a snapshot restored with the latch clear, still
        pends on the next instruction. An empty queue re-arms the latch.
        """
        if self.rx_irq is None:
            return None
        if not self.rx:
            self.rx_irq_armed = False
            return None
        if self.rx_irq_armed:
            return None
        self.rx_irq_armed = True
        return self.rx_irq

    def read(self, offset: int, size: int) -> int:
        if offset == self.data_offset:
            if self.rx:
                byte = self.rx.pop(0)
                # Edge mode re-arms only when the queue drains, so one burst is
                # one IRQ and the handler is expected to empty RX. Level mode
                # matches a ready bit that stays set: another IRQ is pended
                # on the next instruction while bytes remain.
                if not self.rx or self.rx_level:
                    self.rx_irq_armed = False
                return byte & access_mask(size)
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
        return {
            "tx": bytes(self.tx),
            "rx": bytes(self.rx),
            "tx_dropped": self.tx_dropped,
            "rx_irq_armed": self.rx_irq_armed,
        }

    def restore_state(self, state: dict[str, Any]) -> None:
        self.tx = bytearray(state["tx"])
        self.rx = bytearray(state["rx"])
        self.tx_dropped = int(state["tx_dropped"])
        self.rx_irq_armed = bool(state.get("rx_irq_armed", False))

    def debug_lines(self) -> list[str]:
        preview = bytes(self.tx[:32])
        extra = "" if len(self.tx) <= 32 else f" (+{len(self.tx) - 32} more)"
        shown = preview.hex() or "(empty)"
        lines = [f"{self.name} tx: {shown}{extra}"]
        if self.rx_irq is not None:
            lines.append(f"{self.name} rx_irq: {self.rx_irq}")
        return lines


def _parse_rx_irq(name: str, config: dict[str, Any]) -> int | None:
    has_rx = "rx_irq" in config
    has_irq = "irq" in config
    if not has_rx and not has_irq:
        return None
    rx_irq = parse_u32(config["rx_irq"], what=f"{name} rx_irq") if has_rx else None
    irq = parse_u32(config["irq"], what=f"{name} irq") if has_irq else None
    if has_rx and has_irq and rx_irq != irq:
        raise ConfigError(f"{name} irq ({irq}) and rx_irq ({rx_irq}) disagree")
    chosen = rx_irq if rx_irq is not None else irq
    if chosen is None or not 0 <= chosen < NUM_EXTERNAL:
        raise ConfigError(f"{name} rx_irq must be an IRQ number from 0 to {NUM_EXTERNAL - 1}")
    return chosen


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
