# SPDX-License-Identifier: MIT
"""STM32-shaped beachhead: one SysTick, one Modbus RTU reply, one planted bucket."""

from __future__ import annotations

import json
from pathlib import Path

from rehost.cli import main
from rehost.fixtures import build_fixture
from rehost.fuzz import PersistentHarness
from rehost.machine import Machine
from rehost.modbus import (
    deliver,
    exception_code,
    parse_frame,
    read_holding_registers,
    read_holding_values,
    run_exchange,
    write_single_register,
)
from rehost.nvic import EXC_SYSTICK

_HOLDING = 0x1234
_MAGIC = b"JIG!"
_FLASH = 0x08000000


def test_plant_floor_image_vectors_point_at_flash():
    image = build_fixture("plant-floor")
    assert len(image) < 0x1000
    assert int.from_bytes(image[0:4], "little") == 0x20004000
    reset = int.from_bytes(image[4:8], "little")
    systick = int.from_bytes(image[60:64], "little")
    usart = int.from_bytes(image[54 * 4 : 54 * 4 + 4], "little")
    for vector in (reset, systick, usart):
        assert vector & 1
        assert _FLASH <= (vector & ~1) < _FLASH + len(image)


def test_plant_floor_ticks_once_and_answers_one_modbus_read():
    machine = Machine.from_fixture("plant-floor")
    harness = PersistentHarness(machine)
    result, frame = run_exchange(
        machine, read_holding_registers(1, 0, 1), harness=harness
    )
    assert result.status == "halted", result.detail
    assert result.pc >= _FLASH
    assert read_holding_values(frame) == [_HOLDING]
    assert machine.read_u32(0x20000000) == 1
    assert machine.peripheral("gpioa").odr == 0x3
    assert machine.peripheral("systick").ctrl == 0x7
    assert machine.peripheral("systick").load == 0xFFFF
    assert machine.read_mmio(0x40023C00, 4) == 2
    assert machine.read_mmio(0x40023800, 4) & 0x2 == 0x2
    assert machine.backend.pending_irqs == []
    assert machine.backend.nvic.systick_pending is False

    result, frame = run_exchange(
        machine, write_single_register(1, 0, 0x0003), harness=harness
    )
    assert result.status == "halted", result.detail
    assert frame.function == 0x86
    assert exception_code(frame) == 0x01

    result, frame = run_exchange(
        machine, read_holding_registers(1, 5, 1), harness=harness
    )
    assert exception_code(frame) == 0x02
    result, frame = run_exchange(
        machine, read_holding_registers(1, 0, 2), harness=harness
    )
    assert exception_code(frame) == 0x03

    # A different slave is consumed and produces no TX. run_exchange would try to
    # parse that empty buffer, so deliver and run directly.
    harness.reset_to_checkpoint()
    deliver(machine, read_holding_registers(2, 0, 1))
    quiet = machine.run()
    assert quiet.status == "halted", quiet.detail
    uart = machine.peripheral("usart2")
    assert bytes(uart.tx) == b""
    assert bytes(uart.rx) == b""
    assert machine.read_u32(0x20000000) == 1


def test_plant_floor_answers_before_the_planted_fetch():
    """The maintenance oracle runs after the USART handler, so TX is already posted."""
    machine = Machine.from_fixture("plant-floor")
    harness = PersistentHarness(machine)
    harness.reset_to_checkpoint()
    deliver(machine, read_holding_registers(1, 0, 1))
    machine.write_memory(0x20000100, _MAGIC)
    result = machine.run()
    assert result.status == "fault"
    assert result.detail == "unmapped fetch at 0x60000000"
    frame_bytes = bytes(machine.peripheral("usart2").tx)
    assert read_holding_values(parse_frame(frame_bytes)) == [_HOLDING]
    assert machine.read_u32(0x20000000) == 1


def test_plant_floor_checkpoint_clears_uart_systick_and_nvic():
    machine = Machine.from_fixture("plant-floor")
    harness = PersistentHarness(machine)
    result, frame = run_exchange(
        machine, read_holding_registers(1, 0, 1), harness=harness
    )
    assert read_holding_values(frame) == [_HOLDING]
    uart = machine.peripheral("usart2")
    tick = machine.peripheral("systick")
    gpio = machine.peripheral("gpioa")
    uart.queue_rx(b"\xff\xff")
    machine.inject_irq(38)
    machine.backend.pend_exception(EXC_SYSTICK)
    tick.val = 0x123
    tick.irq_pending = True
    tick.countflag = True
    gpio.odr = 0xFFFF
    machine.write_u32(0x20000000, 0xFFFFFFFF)
    assert uart.tx
    assert 38 in machine.backend.pending_irqs

    harness.reset_to_checkpoint()
    assert bytes(uart.tx) == b""
    assert bytes(uart.rx) == b""
    assert uart.rx_irq_armed is False
    assert machine.backend.pending_irqs == []
    assert machine.backend.nvic.systick_pending is False
    assert tick.val == 0
    assert tick.ctrl == 0
    assert tick.irq_pending is False
    assert tick.countflag is False
    assert gpio.odr == 0
    assert machine.read_u32(0x20000000) == 0

    second = harness.exec_one(b"\x00\x00\x00\x00")
    assert second.status == "halted", second.detail
    assert bytes(uart.tx) == b""
    assert bytes(uart.rx) == b""
    assert machine.backend.pending_irqs == []
    assert machine.read_u32(0x20000000) == 1
    assert machine.read_memory(0x20000100, 4) == b"\x00\x00\x00\x00"


def test_plant_floor_fuzz_writes_one_unmapped_fetch_bucket(tmp_path: Path):
    out = tmp_path / "out"
    code = main(
        [
            "fuzz",
            "--fixture",
            "plant-floor",
            "--out",
            str(out),
            "--max-execs",
            "4000",
            "--stop-on-crash",
            "--rng-seed",
            "1",
        ]
    )
    assert code == 0
    crashes = list((out / "crashes").iterdir())
    assert len(crashes) == 1
    assert crashes[0].read_bytes() == _MAGIC
    index = json.loads((out / "buckets" / "index.json").read_text(encoding="utf-8"))
    assert index["version"] == 1
    assert len(index["buckets"]) == 1
    bucket_id, entry = next(iter(index["buckets"].items()))
    assert entry["fault_class"] == "unmapped_fetch"
    representative = Path(entry["representative"])
    assert representative.is_file()
    assert representative.read_bytes() == _MAGIC
    report = Path(entry["report"])
    report_json = Path(entry["report_json"])
    assert report.is_file()
    assert report_json.is_file()
    text = report.read_text(encoding="utf-8")
    body = json.loads(report_json.read_text(encoding="utf-8"))
    assert text.startswith(f"# unmapped_fetch `{bucket_id}`")
    assert "plant-floor" in text
    assert "jig-emu run" in text
    assert "--fixture plant-floor" in text
    assert body["fault_class"] == "unmapped_fetch"
    assert body["machine"] == "plant-floor"
    assert body["detail"] == "unmapped fetch at 0x60000000"
    assert not (out / "hangs").exists() or list((out / "hangs").iterdir()) == []

