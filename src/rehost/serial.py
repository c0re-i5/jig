# SPDX-License-Identifier: MIT
"""Line-oriented text on the existing UART plugin.

This queues bytes with ``Uart.queue_rx``. It does not open a TTY, speak a
protocol, or replace the UART model. A chunk is either queued before
``run`` or handed to a small feed that watches the instruction stream:

* ``after_instructions`` waits until that many instructions have retired in
  the current ``run``.
* ``idle_instructions`` waits until TX has been quiet for that many
  instructions. The first chunk also waits until TX has grown at least once,
  so a banner can finish before the first line. Each later chunk waits until
  the guest has made progress on the previous one (RX shrank, or TX grew)
  and TX is quiet again.

``run_lines`` is the scripted exchange. It is the text counterpart of
``rehost.modbus.run_exchange``.
"""

from __future__ import annotations

from rehost.errors import SerialError
from rehost.peripherals.uart import Uart


def resolve_uart(machine, name: str | None = None) -> Uart:
    """The named UART, or the only UART on ``machine``."""
    if name:
        try:
            plugin = machine.peripheral(name)
        except KeyError as exc:
            raise SerialError(str(exc)) from exc
        if not isinstance(plugin, Uart):
            raise SerialError(f"{name} is not a uart peripheral")
        return plugin
    uarts = [plugin for plugin in machine.peripherals if isinstance(plugin, Uart)]
    if len(uarts) == 1:
        return uarts[0]
    found = ", ".join(plugin.name for plugin in uarts) or "(none)"
    raise SerialError(
        f"expected one UART to queue serial into, found {len(uarts)} ({found}); pass uart="
    )


def deliver(machine, data: bytes | bytearray, *, uart: str | None = None) -> Uart:
    """Append ``data`` to the UART RX queue now."""
    if not isinstance(data, (bytes, bytearray)):
        raise SerialError("serial data must be bytes")
    plugin = resolve_uart(machine, uart)
    plugin.queue_rx(bytes(data))
    return plugin


def decode_escapes(text: str) -> bytes:
    """ASCII text with ``\\n``, ``\\r``, ``\\t``, ``\\\\``, and ``\\xHH``."""
    if not isinstance(text, str):
        raise SerialError("serial text must be a string")
    out = bytearray()
    index = 0
    while index < len(text):
        char = text[index]
        if char != "\\":
            _append_ascii(out, char)
            index += 1
            continue
        if index + 1 >= len(text):
            raise SerialError("serial text has a trailing backslash")
        nxt = text[index + 1]
        if nxt == "n":
            out.append(0x0A)
        elif nxt == "r":
            out.append(0x0D)
        elif nxt == "t":
            out.append(0x09)
        elif nxt == "\\":
            out.append(0x5C)
        elif nxt == "x":
            hexes = text[index + 2 : index + 4]
            if len(hexes) != 2 or any(c not in "0123456789abcdefABCDEF" for c in hexes):
                raise SerialError("serial text \\x escape needs two hex digits")
            out.append(int(hexes, 16))
            index += 4
            continue
        else:
            raise SerialError(f"serial text has unknown escape \\{nxt}")
        index += 2
    return bytes(out)


def normalize_line(line: str | bytes | bytearray) -> bytes:
    """Bytes unchanged. A str is ASCII and gains a newline if it has no line ending."""
    if isinstance(line, str):
        raw = line.encode("ascii")
    elif isinstance(line, (bytes, bytearray)):
        raw = bytes(line)
    else:
        raise SerialError("a serial line must be bytes or ASCII text")
    if raw and raw[-1] in (0x0A, 0x0D):
        return raw
    return raw + b"\n"


class SerialFeed:
    """Queue RX chunks from the instruction hook.

    One machine has one feed. Attaching another replaces it. Chunks already
    queued on the UART stay there.
    """

    def __init__(
        self,
        uart: Uart,
        chunks: list[bytes],
        *,
        after_instructions: int | None = None,
        idle_instructions: int | None = None,
        settle_before: list[int] | None = None,
    ) -> None:
        if after_instructions is None and idle_instructions is None:
            raise SerialError("serial feed needs after_instructions or idle_instructions")
        if after_instructions is not None and after_instructions < 0:
            raise SerialError("after_instructions must be >= 0")
        if idle_instructions is not None and idle_instructions < 1:
            raise SerialError("idle_instructions must be >= 1")
        settles = [0] * len(chunks) if settle_before is None else list(settle_before)
        if len(settles) != len(chunks):
            raise SerialError("settle_before must have one delay per chunk")
        pending: list[tuple[bytes, int]] = []
        for chunk, settle in zip(chunks, settles):
            if isinstance(settle, bool) or not isinstance(settle, int) or settle < 0:
                raise SerialError("settle_before delays must be >= 0")
            blob = bytes(chunk)
            if blob:
                pending.append((blob, settle))
        self.uart = uart
        self.pending = pending
        self.after_instructions = after_instructions
        self.idle_instructions = idle_instructions
        self.sent: list[bytes] = []
        self.tx_len = len(uart.tx)
        self.quiet = 0
        self.seen_tx = len(uart.tx) > 0
        self._holding = False
        self._progress = False
        self._settling = False
        self._wait = 0
        self._tx_at_send = self.tx_len
        self._rx_at_send = len(uart.rx)

    def on_retired(self, instructions: int) -> None:
        """Called once per retired instruction with the run's instruction count."""
        tx_len = len(self.uart.tx)
        if tx_len != self.tx_len:
            self.tx_len = tx_len
            self.quiet = 0
            self.seen_tx = True
        else:
            self.quiet += 1
        if not self.pending:
            return
        if self._settling:
            self._wait -= 1
            if self._wait <= 0:
                self._settling = False
                self._emit()
            return
        if self.after_instructions is not None and instructions < self.after_instructions:
            return
        if self.idle_instructions is None:
            self._flush()
            return
        if self._holding:
            if not self._progress:
                if len(self.uart.rx) < self._rx_at_send or tx_len != self._tx_at_send:
                    self._progress = True
                    self.quiet = 0
                return
            if self.quiet >= self.idle_instructions:
                self._send_next()
            return
        # First chunk: a banner (or any earlier TX) has gone quiet.
        if self.seen_tx and self.quiet >= self.idle_instructions:
            self._send_next()

    def _flush(self) -> None:
        blob = b"".join(chunk for chunk, _settle in self.pending)
        self.pending.clear()
        if blob:
            self.uart.queue_rx(blob)
            self.sent.append(blob)

    def _send_next(self) -> None:
        _chunk, settle = self.pending[0]
        if settle:
            self._settling = True
            self._wait = settle
            return
        self._emit()

    def _emit(self) -> None:
        chunk, _settle = self.pending.pop(0)
        self.uart.queue_rx(chunk)
        self.sent.append(chunk)
        self._holding = bool(self.pending)
        self._progress = False
        self._tx_at_send = len(self.uart.tx)
        self._rx_at_send = len(self.uart.rx)
        self.quiet = 0


def attach_feed(
    machine,
    chunks: list[bytes],
    *,
    uart: str | None = None,
    after_instructions: int | None = None,
    idle_instructions: int | None = None,
    settle_before: list[int] | None = None,
) -> SerialFeed:
    """Arm ``machine`` so ``run`` queues ``chunks`` on the UART."""
    plugin = resolve_uart(machine, uart)
    feed = SerialFeed(
        plugin,
        chunks,
        after_instructions=after_instructions,
        idle_instructions=idle_instructions,
        settle_before=settle_before,
    )
    machine._rx_feed = feed
    return feed


def run_lines(
    machine,
    lines: list[str | bytes | bytearray],
    *,
    uart: str | None = None,
    idle_instructions: int = 64,
    after_instructions: int | None = None,
    settle_before: list[int] | None = None,
    harness=None,
):
    """Queue each line when TX goes quiet, run, and return ``(result, tx, new)``.

    Pass a ``PersistentHarness`` to restore its boot checkpoint first. The
    feed is attached after that restore. A ``str`` line is ASCII and is given
    a newline when it does not already end in ``\\n`` or ``\\r``. ``tx`` is
    the whole UART capture. ``new`` is the bytes appended during this run.
    ``settle_before`` is one non-negative delay per line: that many extra
    instructions after the idle gap and before that line is queued.
    """
    if harness is not None:
        harness.reset_to_checkpoint()
    chunks = [normalize_line(line) for line in lines]
    plugin = resolve_uart(machine, uart)
    before = len(plugin.tx)
    attach_feed(
        machine,
        chunks,
        uart=plugin.name,
        after_instructions=after_instructions,
        idle_instructions=idle_instructions,
        settle_before=settle_before,
    )
    result = machine.run()
    return result, bytes(plugin.tx), bytes(plugin.tx[before:])


def _append_ascii(out: bytearray, char: str) -> None:
    try:
        encoded = char.encode("ascii")
    except UnicodeEncodeError as exc:
        raise SerialError("serial text must be ASCII") from exc
    if len(encoded) != 1:
        raise SerialError("serial text must be ASCII")
    out.append(encoded[0])
