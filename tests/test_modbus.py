# SPDX-License-Identifier: MIT
"""Modbus RTU framing, the synthetic slave, and fuzz-iteration hygiene."""

from __future__ import annotations

import pytest

from rehost.config import FuzzBufferConfig, FuzzConfig
from rehost.errors import ModbusError
from rehost.fuzz import PersistentHarness
from rehost.machine import Machine
from rehost.modbus import (
    crc16,
    deliver,
    exception_code,
    exception_response,
    parse_frame,
    read_holding_registers,
    read_holding_values,
    run_exchange,
    write_single_register,
)
from rehost.nvic import EXC_SYSTICK

# The fixture's one holding register, at address 0.
_HOLDING = 0x1234


def test_crc16_matches_the_published_read_holding_vector():
    # Slave 1, FC 0x03, address 0, quantity 10. CRC low byte first is C5 CD.
    frame = read_holding_registers(1, 0, 10)
    assert frame == bytes.fromhex("01030000000ac5cd")
    assert crc16(frame[:-2]) == 0xCDC5
    parsed = parse_frame(frame)
    assert parsed.slave == 1
    assert parsed.function == 0x03
    assert parsed.pdu == b"\x00\x00\x00\x0a"


def test_builders_reject_out_of_range_fields():
    with pytest.raises(ModbusError):
        read_holding_registers(248, 0, 1)
    with pytest.raises(ModbusError):
        read_holding_registers(1, 0, 0)
    with pytest.raises(ModbusError):
        write_single_register(1, 0, 0x10000)
    with pytest.raises(ModbusError, match="CRC"):
        parse_frame(b"\x01\x03\x00\x00\x00\x01\x00\x00")


def test_exception_response_sets_the_high_bit():
    frame = exception_response(1, 0x03, 0x02)
    parsed = parse_frame(frame)
    assert parsed.exception
    assert parsed.function == 0x83
    assert exception_code(parsed) == 0x02


def _harness(machine: Machine) -> PersistentHarness:
    """Boot-checkpoint harness. The fixture has no fuzz section of its own."""
    machine.config.fuzz = FuzzConfig(
        mode="buffer",
        buffer=FuzzBufferConfig(address=0x20000100, max_size=16),
    )
    return PersistentHarness(machine)


def test_modbus_fixture_ignores_a_different_slave():
    machine = Machine.from_fixture("modbus-rtu")
    deliver(machine, read_holding_registers(2, 0, 1))
    result = machine.run()
    assert result.status == "halted", result.detail
    assert bytes(machine.peripheral("uart0").tx) == b""
    assert bytes(machine.peripheral("uart0").rx) == b""


def test_modbus_fixture_answers_read_holding_and_rejects_a_write():
    machine = Machine.from_fixture("modbus-rtu")
    harness = _harness(machine)
    result, frame = run_exchange(machine, read_holding_registers(1, 0, 1), harness=harness)
    assert result.status == "halted", result.detail
    assert read_holding_values(frame) == [_HOLDING]
    assert machine.backend.pending_irqs == []

    result, frame = run_exchange(machine, write_single_register(1, 0, 0x0003), harness=harness)
    assert result.status == "halted", result.detail
    assert frame.function == 0x86
    assert exception_code(frame) == 0x01
    assert bytes(machine.peripheral("uart0").tx) == frame.raw

    result, frame = run_exchange(machine, read_holding_registers(1, 5, 1), harness=harness)
    assert exception_code(frame) == 0x02
    result, frame = run_exchange(machine, read_holding_registers(1, 0, 2), harness=harness)
    assert exception_code(frame) == 0x03


def test_modbus_uart_and_tick_state_does_not_leak_across_exec_one():
    machine = Machine.from_fixture("modbus-rtu")
    harness = _harness(machine)
    result, frame = run_exchange(machine, read_holding_registers(1, 0, 1), harness=harness)
    assert read_holding_values(frame) == [_HOLDING]
    uart = machine.peripheral("uart0")
    tick = machine.peripheral("systick")
    uart.queue_rx(b"\xff\xff")
    machine.inject_irq(0)
    machine.backend.pend_exception(EXC_SYSTICK)
    tick.val = 0x123
    tick.irq_pending = True
    tick.countflag = True
    assert uart.rx
    assert uart.tx
    assert 0 in machine.backend.pending_irqs
    assert machine.backend.nvic.systick_pending

    second = harness.exec_one(b"\x11\x22")
    assert second.status == "halted", second.detail
    assert bytes(uart.tx) == b""
    assert bytes(uart.rx) == b""
    assert uart.rx_irq_armed is False
    assert machine.backend.pending_irqs == []
    assert machine.backend.nvic.systick_pending is False
    assert tick.val == 0
    assert tick.irq_pending is False
    assert tick.countflag is False
    assert machine.read_memory(0x20000100, 2) == b"\x11\x22"
