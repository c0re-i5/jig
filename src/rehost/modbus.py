# SPDX-License-Identifier: MIT
"""Modbus RTU framing on top of the existing UART plugin.

This builds and checks RTU frames. It is not a Modbus TCP stack, not a
slave implementation, and not EtherNet/IP, DNP3, or OPC-UA. Function codes
covered as builders are Read Holding Registers (0x03) and Write Single
Register (0x06), plus a generic exception response. The CRC is the Modbus
RTU CRC-16 (reflected polynomial 0xA001, initial value 0xFFFF), transmitted
low byte first.

Bytes are queued on a ``uart`` plugin with ``queue_rx``. The guest still
owns TX; after a run, ``parse_frame`` checks the CRC on whatever the plugin
captured. Timing (the 3.5-character silent gap), multi-drop scheduling, and
function codes other than the ones above are out of scope.
"""

from __future__ import annotations

from dataclasses import dataclass

from rehost.errors import ModbusError
from rehost.peripherals.uart import Uart

_MAX_SLAVE = 247
_MAX_HOLDING = 125


def crc16(data: bytes) -> int:
    """Return the Modbus RTU CRC-16 of ``data`` as an integer 0..65535."""
    if not isinstance(data, (bytes, bytearray)):
        raise ModbusError("CRC input must be bytes")
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def read_holding_registers(slave: int, address: int, count: int) -> bytes:
    """RTU request: function 0x03, starting ``address``, ``count`` registers."""
    _check_slave(slave)
    _check_u16(address, "address")
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= _MAX_HOLDING:
        raise ModbusError(f"holding-register count must be 1..{_MAX_HOLDING}")
    return _frame(bytes((slave, 0x03)) + address.to_bytes(2, "big") + count.to_bytes(2, "big"))


def write_single_register(slave: int, address: int, value: int) -> bytes:
    """RTU request: function 0x06, write ``value`` to ``address``."""
    _check_slave(slave)
    _check_u16(address, "address")
    _check_u16(value, "value")
    return _frame(bytes((slave, 0x06)) + address.to_bytes(2, "big") + value.to_bytes(2, "big"))


def exception_response(slave: int, function: int, code: int) -> bytes:
    """RTU exception: ``function | 0x80`` and a one-byte exception ``code``."""
    _check_slave(slave)
    if isinstance(function, bool) or not isinstance(function, int) or not 1 <= function <= 0xFF:
        raise ModbusError("function must be 1..255")
    if isinstance(code, bool) or not isinstance(code, int) or not 0 <= code <= 0xFF:
        raise ModbusError("exception code must be 0..255")
    return _frame(bytes((slave, function | 0x80, code)))


@dataclass(frozen=True)
class ModbusFrame:
    """One CRC-checked RTU frame. ``pdu`` is the bytes after the function code."""

    slave: int
    function: int
    pdu: bytes
    crc: int
    raw: bytes

    @property
    def exception(self) -> bool:
        return bool(self.function & 0x80)


def parse_frame(frame: bytes) -> ModbusFrame:
    """Split an RTU frame and reject a bad CRC or a short buffer."""
    if not isinstance(frame, (bytes, bytearray)):
        raise ModbusError("frame must be bytes")
    raw = bytes(frame)
    if len(raw) < 4:
        raise ModbusError(f"Modbus frame is {len(raw)} bytes; the minimum is 4")
    body = raw[:-2]
    got = raw[-2] | (raw[-1] << 8)
    expect = crc16(body)
    if got != expect:
        raise ModbusError(f"Modbus CRC is {got:#06x}, expected {expect:#06x}")
    return ModbusFrame(slave=body[0], function=body[1], pdu=body[2:], crc=expect, raw=raw)


def exception_code(frame: ModbusFrame) -> int:
    """The single exception-code byte of an exception response."""
    if not frame.exception:
        raise ModbusError(f"function {frame.function:#04x} is not an exception")
    if len(frame.pdu) != 1:
        raise ModbusError("exception response must carry one code byte")
    return frame.pdu[0]


def read_holding_values(frame: ModbusFrame) -> list[int]:
    """Big-endian register values from a function 0x03 response."""
    if frame.function != 0x03:
        raise ModbusError(f"function {frame.function:#04x} is not Read Holding Registers")
    if not frame.pdu:
        raise ModbusError("Read Holding Registers response has no byte count")
    count = frame.pdu[0]
    data = frame.pdu[1:]
    if count != len(data) or count % 2:
        raise ModbusError(
            f"Read Holding Registers byte count {count} does not match {len(data)} data bytes"
        )
    return [int.from_bytes(data[index : index + 2], "big") for index in range(0, count, 2)]


def resolve_uart(machine, name: str | None = None) -> Uart:
    """The named UART, or the only UART on ``machine``."""
    if name:
        try:
            plugin = machine.peripheral(name)
        except KeyError as exc:
            raise ModbusError(str(exc)) from exc
        if not isinstance(plugin, Uart):
            raise ModbusError(f"{name} is not a uart peripheral")
        return plugin
    uarts = [plugin for plugin in machine.peripherals if isinstance(plugin, Uart)]
    if len(uarts) == 1:
        return uarts[0]
    found = ", ".join(plugin.name for plugin in uarts) or "(none)"
    raise ModbusError(
        f"expected one UART to queue Modbus into, found {len(uarts)} ({found}); pass uart="
    )


def deliver(machine, frame: bytes, *, uart: str | None = None) -> Uart:
    """Queue an RTU ``frame`` on the machine's UART RX."""
    if not isinstance(frame, (bytes, bytearray)) or len(frame) < 4:
        raise ModbusError("Modbus frame must be at least 4 bytes")
    plugin = resolve_uart(machine, uart)
    plugin.queue_rx(bytes(frame))
    return plugin


def run_exchange(machine, frame: bytes, *, uart: str | None = None, harness=None):
    """Queue ``frame``, run the guest, and parse the UART TX buffer.

    Pass a ``PersistentHarness`` to restore its boot checkpoint first. Queue
    the frame after that restore: ``exec_one`` would drop bytes queued before
    it. The returned pair is ``(RunResult, ModbusFrame)``.
    """
    if harness is not None:
        harness.reset_to_checkpoint()
    plugin = deliver(machine, frame, uart=uart)
    result = machine.run()
    return result, parse_frame(bytes(plugin.tx))


def _frame(body: bytes) -> bytes:
    crc = crc16(body)
    return body + bytes((crc & 0xFF, (crc >> 8) & 0xFF))


def _check_slave(slave: int) -> None:
    if isinstance(slave, bool) or not isinstance(slave, int) or not 0 <= slave <= _MAX_SLAVE:
        raise ModbusError(f"slave address must be 0..{_MAX_SLAVE}")


def _check_u16(value: int, what: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFF:
        raise ModbusError(f"{what} must be an integer 0..65535")
