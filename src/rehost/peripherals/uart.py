# SPDX-License-Identifier: MIT
"""Byte-oriented UART stub.

Not a 16550, and not a full vendor USART. Firmware that writes the data
register posts the low byte into ``tx``. A read of the data register pops one
byte from ``rx`` or returns 0. The status register reports transmitter-empty
and receiver-ready bits from config. Any other offset is logged and returns
``read_default``, unless it is listed in ``control_offsets`` / ``cr1_offset``.

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
with any other NVIC line. ``RXNEIE`` is not consulted. A sticky CR1 bit reads
back, and the RX latch stays the one above.

Transmit interrupts need ``cr1_offset``. ``tx_irq`` selects the line; omitted,
it is ``rx_irq``, because an STM32 USART has one vector for RX and TX. The
plugin pends that line on a rising edge of ``TXE && TXEIE`` and, separately,
of ``TC && TCIE``. Clearing the enable drops that edge so a later tick does
not pend. With ``cr1_offset`` or a non-zero ``tx_complete_mask``, status
follows a two-step transmitter paced by the instruction hook: a data write
clears TXE and TC, the next hook sets TXE, and the one after that sets TC.
Maps that set neither key keep the old status word, with ``tx_empty_mask``
set on every read.
"""

from __future__ import annotations

from typing import Any, Callable

from rehost.config import parse_u32
from rehost.errors import ConfigError
from rehost.memory import access_mask
from rehost.nvic import NUM_EXTERNAL
from rehost.peripherals.base import Peripheral, extract_field, insert_field
from rehost.peripherals.registry import register

_TX_IDLE = "idle"
_TX_STAGED = "staged"
_TX_SHIFTING = "shifting"
_TX_PHASES = (_TX_IDLE, _TX_STAGED, _TX_SHIFTING)


@register("uart")
class Uart(Peripheral):
    config_keys = frozenset(
        {
            "read_default",
            "data_offset",
            "status_offset",
            "tx_empty_mask",
            "tx_complete_mask",
            "rx_ready_mask",
            "rx",
            "rx_irq",
            "irq",
            "rx_level",
            "tx_irq",
            "cr1_offset",
            "txeie_mask",
            "tcie_mask",
            "control_offsets",
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
        self.tx_complete_mask = parse_u32(
            self.config.get("tx_complete_mask", 0), what=f"{self.name} tx_complete_mask"
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
        self.cr1_offset = _parse_cr1_offset(self.name, self.config)
        self.txeie_mask = _parse_enable_mask(
            self.name, self.config, "txeie_mask", self.cr1_offset, 0x80
        )
        self.tcie_mask = _parse_enable_mask(
            self.name, self.config, "tcie_mask", self.cr1_offset, 0x40
        )
        self._controls = _parse_control_offsets(
            self.name,
            self.config,
            cr1_offset=self.cr1_offset,
            size=self.size,
            data_offset=self.data_offset,
            status_offset=self.status_offset,
        )
        self.tx_irq = _parse_tx_irq(self.name, self.config, self.rx_irq, self.cr1_offset)
        # Shift timing is opt-in. Existing maps keep TXE set across a data write.
        self._tx_model = self.cr1_offset is not None or self.tx_complete_mask != 0
        self.tx = bytearray()
        self.tx_dropped = 0
        self.rx = bytearray(_as_bytes(self.config.get("rx", b""), what=f"{self.name} rx"))
        # True after the rising edge has been reported for the current burst.
        self.rx_irq_armed = False
        self._phase = _TX_IDLE
        self._txe = True
        self._tc = True
        # High after that source's rising edge has been pended.
        self._txe_line = False
        self._tc_line = False
        self._inject: Callable[[int], None] | None = None

    def _require_offset(self, offset: int, *, what: str) -> None:
        if offset >= self.size:
            raise ConfigError(
                f"{self.name} {what} at {offset:#x} does not fit in a {self.size:#x}-byte region"
            )

    def bind_rx_irq(self, inject: Callable[[int], None]) -> None:
        """Connect RX and TX latches to ``Machine.inject_irq`` (or a test double).

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

    def consume_tx(self) -> int | None:
        """Advance the transmitter one instruction hook.

        Returns ``tx_irq`` when this step raises TXE+TXEIE or TC+TCIE, and
        pends that line when an injector is bound. Maps without
        ``cr1_offset`` and without ``tx_complete_mask`` return None and leave
        status unchanged. The machine calls this from the instruction hook,
        before that instruction is retired.
        """
        if not self._tx_model:
            return None
        if self._phase == _TX_STAGED:
            self._phase = _TX_SHIFTING
            self._txe = True
        elif self._phase == _TX_SHIFTING:
            self._phase = _TX_IDLE
            self._tc = True
        return self._raise_tx_irq()

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
            return self._status_flags() & access_mask(size)
        word = self._control_word(offset, size)
        if word is not None:
            return extract_field(self._controls[word], offset, size, word)
        self.log_unhandled("read", offset, size, None)
        return self.read_default & access_mask(size)

    def write(self, offset: int, size: int, value: int) -> None:
        if offset == self.data_offset:
            if len(self.tx) < self._TX_CAP:
                self.tx.append(value & 0xFF)
            else:
                self.tx_dropped += 1
            if self._tx_model:
                self._txe = False
                self._tc = False
                self._phase = _TX_STAGED
                self._raise_tx_irq()
            return
        if offset == self.status_offset:
            self._write_status(size, value)
            return
        word = self._control_word(offset, size)
        if word is not None:
            merged = insert_field(self._controls[word], offset, size, word, value) & 0xFFFFFFFF
            self._controls[word] = merged
            if word == self.cr1_offset:
                self._raise_tx_irq()
            return
        self.log_unhandled("write", offset, size, value)

    def snapshot_state(self) -> dict[str, Any]:
        return {
            "tx": bytes(self.tx),
            "rx": bytes(self.rx),
            "tx_dropped": self.tx_dropped,
            "rx_irq_armed": self.rx_irq_armed,
            "tx_phase": self._phase,
            "txe": self._txe,
            "tc": self._tc,
            "txe_line": self._txe_line,
            "tc_line": self._tc_line,
            "controls": {f"{offset:#x}": value for offset, value in sorted(self._controls.items())},
        }

    def restore_state(self, state: dict[str, Any]) -> None:
        self.tx = bytearray(state["tx"])
        self.rx = bytearray(state["rx"])
        self.tx_dropped = int(state["tx_dropped"])
        self.rx_irq_armed = bool(state.get("rx_irq_armed", False))
        phase = state.get("tx_phase", _TX_IDLE)
        if phase not in _TX_PHASES:
            raise ConfigError(f"{self.name} snapshot tx_phase {phase!r} is not a transmitter phase")
        self._phase = phase
        self._txe = bool(state.get("txe", True))
        self._tc = bool(state.get("tc", True))
        self._txe_line = bool(state.get("txe_line", False))
        self._tc_line = bool(state.get("tc_line", False))
        raw = state.get("controls", {})
        if not isinstance(raw, dict):
            raise ConfigError(f"{self.name} snapshot controls must be a mapping")
        self._controls = {offset: 0 for offset in self._controls}
        for key, value in raw.items():
            offset = parse_u32(key, what=f"{self.name} snapshot control")
            if offset not in self._controls:
                continue
            self._controls[offset] = int(value) & 0xFFFFFFFF

    def debug_lines(self) -> list[str]:
        preview = bytes(self.tx[:32])
        extra = "" if len(self.tx) <= 32 else f" (+{len(self.tx) - 32} more)"
        shown = preview.hex() or "(empty)"
        lines = [f"{self.name} tx: {shown}{extra}"]
        if self.rx_irq is not None:
            lines.append(f"{self.name} rx_irq: {self.rx_irq}")
        if self.cr1_offset is not None:
            irq = "none" if self.tx_irq is None else str(self.tx_irq)
            lines.append(f"{self.name} tx_irq: {irq}")
        return lines

    def _status_flags(self) -> int:
        if self._tx_model:
            flags = self.tx_empty_mask if self._txe else 0
            if self._tc:
                flags |= self.tx_complete_mask
        else:
            flags = self.tx_empty_mask
        if self.rx:
            flags |= self.rx_ready_mask
        return flags

    def _write_status(self, size: int, value: int) -> None:
        """STM32 clears TC by writing 0 to that bit. Other status bits stick to the model."""
        if self.tx_complete_mask == 0:
            return
        covered = access_mask(size)
        if (self.tx_complete_mask & covered) and (value & self.tx_complete_mask) == 0:
            self._tc = False
            self._raise_tx_irq()

    def _control_word(self, offset: int, size: int) -> int | None:
        if size not in (1, 2, 4) or not self._controls:
            return None
        for base in self._controls:
            if base <= offset and offset + size <= base + 4:
                return base
        return None

    def _cr1(self) -> int:
        if self.cr1_offset is None:
            return 0
        return self._controls.get(self.cr1_offset, 0)

    def _txe_request(self) -> bool:
        if self.tx_irq is None or self.txeie_mask == 0:
            return False
        return self._txe and bool(self._cr1() & self.txeie_mask)

    def _tc_request(self) -> bool:
        if self.tx_irq is None or self.tcie_mask == 0:
            return False
        return self._tc and bool(self._cr1() & self.tcie_mask)

    def _raise_tx_irq(self) -> int | None:
        """Pend ``tx_irq`` on a rising TXEIE or TCIE edge. A held line does not repeat."""
        if not self._tx_model:
            return None
        pend = False
        txe_req = self._txe_request()
        tc_req = self._tc_request()
        if txe_req and not self._txe_line:
            self._txe_line = True
            pend = True
        elif not txe_req:
            self._txe_line = False
        if tc_req and not self._tc_line:
            self._tc_line = True
            pend = True
        elif not tc_req:
            self._tc_line = False
        if not pend or self.tx_irq is None:
            return None
        if self._inject is not None:
            self._inject(self.tx_irq)
        return self.tx_irq


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


def _parse_irq_number(name: str, value: object, *, what: str) -> int:
    irq = parse_u32(value, what=f"{name} {what}")
    if not 0 <= irq < NUM_EXTERNAL:
        raise ConfigError(f"{name} {what} must be an IRQ number from 0 to {NUM_EXTERNAL - 1}")
    return irq


def _parse_cr1_offset(name: str, config: dict[str, Any]) -> int | None:
    if "cr1_offset" not in config:
        return None
    offset = parse_u32(config["cr1_offset"], what=f"{name} cr1_offset")
    return offset


def _parse_enable_mask(
    name: str,
    config: dict[str, Any],
    key: str,
    cr1_offset: int | None,
    default: int,
) -> int:
    if key in config and cr1_offset is None:
        raise ConfigError(f"{name} {key} requires cr1_offset")
    if cr1_offset is None:
        return 0
    return parse_u32(config.get(key, default), what=f"{name} {key}")


def _parse_tx_irq(
    name: str,
    config: dict[str, Any],
    rx_irq: int | None,
    cr1_offset: int | None,
) -> int | None:
    if "tx_irq" in config and cr1_offset is None:
        raise ConfigError(f"{name} tx_irq requires cr1_offset")
    if cr1_offset is None:
        return None
    if "tx_irq" in config:
        return _parse_irq_number(name, config["tx_irq"], what="tx_irq")
    return rx_irq


def _parse_control_offsets(
    name: str,
    config: dict[str, Any],
    *,
    cr1_offset: int | None,
    size: int,
    data_offset: int,
    status_offset: int,
) -> dict[int, int]:
    raw = config.get("control_offsets", [])
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise ConfigError(f"{name} control_offsets must be a list of offsets")
    offsets: list[int] = []
    for item in raw:
        offsets.append(parse_u32(item, what=f"{name} control_offsets"))
    if cr1_offset is not None and cr1_offset not in offsets:
        offsets.append(cr1_offset)
    seen: set[int] = set()
    controls: dict[int, int] = {}
    for offset in offsets:
        if offset % 4 != 0:
            raise ConfigError(f"{name} control register {offset:#x} must be 4-byte aligned")
        if offset < 0 or offset + 4 > size:
            raise ConfigError(
                f"{name} control register at {offset:#x} does not fit in a {size:#x}-byte region"
            )
        if offset in seen:
            raise ConfigError(f"{name} control register {offset:#x} is duplicated")
        for other in (data_offset, status_offset):
            if offset <= other < offset + 4:
                raise ConfigError(
                    f"{name} control register {offset:#x} overlaps data or status at {other:#x}"
                )
        seen.add(offset)
        controls[offset] = 0
    return controls


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
