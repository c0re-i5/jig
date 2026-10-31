# SPDX-License-Identifier: MIT
"""Snapshot round-trip of registers, RAM, and peripheral state."""

from __future__ import annotations

from rehost.machine import Machine
from rehost.snapshot import Snapshot
from tests.helpers import machine_from_asm


def test_snapshot_restores_registers_ram_and_uart():
    machine = machine_from_asm(
        "bkpt #0",
        regions=[
            {
                "name": "uart0",
                "base": 0x40000000,
                "size": 0x100,
                "perms": "rw",
                "peripheral": "uart",
            }
        ],
    )
    machine.boot()
    machine.backend.write_register("r0", 0x12345678)
    machine.write_u32(0x20000000, 0xAABBCCDD)
    machine.peripheral("uart0").write(0, 1, ord("Z"))
    snap = machine.snapshot()

    machine.backend.write_register("r0", 0)
    machine.write_u32(0x20000000, 0)
    machine.peripheral("uart0").tx.clear()
    machine.restore(snap)

    assert machine.backend.read_register("r0") == 0x12345678
    assert machine.read_u32(0x20000000) == 0xAABBCCDD
    assert bytes(machine.peripheral("uart0").tx) == b"Z"
    assert snap.registers["r0"] == 0x12345678


def test_json_snapshot_round_trip(tmp_path):
    machine = machine_from_asm("movs r0, #1\n    bkpt #0")
    machine.boot()
    machine.write_u32(0x20000010, 0x10)
    original = machine.snapshot()
    path = tmp_path / "snap.json"
    original.write_json(path)
    loaded = Snapshot.read_json(path)
    machine.write_u32(0x20000010, 0)
    machine.backend.write_register("r0", 0x55)
    machine.restore(loaded)
    assert machine.read_u32(0x20000010) == 0x10
    assert machine.backend.read_register("pc") == original.registers["pc"]


def test_restore_then_run_matches_a_fresh_execution():
    source = "movs r0, #4\n    movw r1, #0\n    movt r1, #0x2000\n    str r0, [r1, #0]\n    bkpt #0"
    first = machine_from_asm(source)
    first.boot()
    snap = first.snapshot()
    first.write_u32(0x20000000, 0xFFFFFFFF)
    first.restore(snap)
    result = first.run()
    assert result.status == "halted"
    assert first.read_u32(0x20000000) == 4

    second = machine_from_asm(source)
    assert second.run().status == "halted"
    assert second.read_u32(0x20000000) == first.read_u32(0x20000000)


def test_fixture_machine_snapshot_type():
    machine = Machine.from_fixture("uart-gpio")
    machine.boot()
    snap = machine.snapshot()
    assert snap.arch == "cortex-m"
    assert "sram" in snap.memory
    assert "flash" not in snap.memory
    assert set(snap.peripherals) == {"uart0", "gpioa", "systick"}
