# SPDX-License-Identifier: MIT
"""Plugin behavior and CPU-side dispatch into those plugins."""

from __future__ import annotations

import logging

from rehost.fuzz import FuzzHarness, encode_mmio_script
from rehost.peripherals import Gpio, RegisterBlock, SysTick, Uart, Unimplemented
from tests.helpers import machine_from_asm


def test_uart_posts_tx_and_pops_rx():
    uart = Uart(name="uart0", base=0x40000000, size=0x100, config={"rx": "Hi", "read_default": 0})
    assert uart.read(4, 4) & 0x80
    assert uart.read(4, 4) & 0x01
    assert uart.read(0, 1) == ord("H")
    uart.write(0, 4, 0x141)
    assert bytes(uart.tx) == b"A"
    uart.write(0x10, 4, 1)
    assert uart.read(0x10, 4) == 0


def test_gpio_latch_and_loopback():
    gpio = Gpio(name="gpioa", base=0x40001000, size=0x100, config={"idr": 0x4, "loopback": False})
    gpio.write(0, 4, 0x3)
    assert gpio.odr == 0x3
    assert gpio.read(4, 4) == 0x4
    gpio.loopback = True
    assert gpio.read(4, 4) == 0x3
    gpio.write(1, 1, 0xFF)
    assert gpio.odr == 0xFF03


def test_systick_poll_reloads_and_sets_countflag():
    tick = SysTick(name="systick", base=0xE000E010, size=0x10, config={})
    tick.write(0x4, 4, 5)
    tick.write(0x0, 4, 0x3)  # ENABLE | TICKINT
    tick.write(0x8, 4, 0x99)  # any VAL write clears
    assert tick.val == 0
    assert tick.read(0x8, 4) == 0
    assert tick.irq_pending is True
    assert tick.read(0x0, 4) & (1 << 16)
    assert tick.read(0x0, 4) & (1 << 16) == 0
    assert tick.read(0x8, 4) == 5
    assert tick.read(0x8, 4) == 4


def test_register_block_and_unimplemented_defaults():
    block = RegisterBlock(
        name="dev",
        base=0x40000000,
        size=0x100,
        config={
            "read_default": 0x5A,
            "registers": {"0x0": {"reset": 0x11}, "0x4": {"reset": 0x22, "writable": False}},
        },
    )
    assert block.read(0, 4) == 0x11
    block.write(0, 1, 0xAB)
    assert block.read(0, 4) == 0xAB
    block.write(4, 4, 0x7)
    assert block.read(4, 4) == 0x22
    assert block.read(8, 4) == 0x5A

    spare = Unimplemented(name="spare", base=0x40002000, size=0x100, config={"read_default": 0xA5})
    assert spare.read(0, 1) == 0xA5
    spare.write(0, 4, 1)
    assert spare.writes == 1


def test_cpu_dispatches_register_block_and_logs_unimplemented(caplog):
    source = """
        movw r0, #0
        movt r0, #0x4000
        ldr  r1, [r0, #0]
        movw r2, #0
        movt r2, #0x2000
        str  r1, [r2, #0]
        ldr  r1, [r0, #4]
        str  r1, [r2, #4]
        movs r3, #7
        str  r3, [r0, #4]
        ldr  r1, [r0, #4]
        str  r1, [r2, #8]
        ldr  r1, [r0, #8]
        str  r1, [r2, #12]
        bkpt #0
    """
    machine = machine_from_asm(
        source,
        regions=[
            {
                "name": "dev",
                "base": 0x40000000,
                "size": 0x1000,
                "perms": "rw",
                "peripheral": "register_block",
                "read_default": 0x5A,
                "config": {
                    "registers": {
                        "0x0": {"reset": 0x11, "writable": True},
                        "0x4": {"reset": 0x22, "writable": False},
                    }
                },
            }
        ],
    )
    with caplog.at_level(logging.INFO, logger="rehost.peripherals.base"):
        result = machine.run()
    assert result.status == "halted"
    assert machine.read_u32(0x20000000) == 0x11
    assert machine.read_u32(0x20000004) == 0x22
    assert machine.read_u32(0x20000008) == 0x22
    assert machine.read_u32(0x2000000C) == 0x5A
    assert any("unhandled MMIO" in rec.message for rec in caplog.records)


def test_mmio_script_reaches_the_plugin_before_the_cpu_reads_it():
    machine = machine_from_asm(
        """
        movw r0, #0
        movt r0, #0x4000
        ldr  r1, [r0, #0]
        movw r2, #0
        movt r2, #0x2000
        str  r1, [r2, #0]
        bkpt #0
        """,
        regions=[
            {
                "name": "dev",
                "base": 0x40000000,
                "size": 0x100,
                "perms": "rw",
                "peripheral": "register_block",
                "config": {"registers": {"0x0": {"reset": 0, "writable": True}}},
            }
        ],
        fuzz={"mode": "mmio"},
    )
    FuzzHarness(machine).apply(encode_mmio_script([(0x40000000, 0x99, 4)]))
    result = machine.run()
    assert result.status == "halted"
    assert machine.read_u32(0x20000000) == 0x99
