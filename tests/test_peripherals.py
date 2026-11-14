# SPDX-License-Identifier: MIT
"""Plugin behavior and CPU-side dispatch into those plugins."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from rehost.errors import ConfigError
from rehost.fuzz import FuzzHarness, encode_mmio_script
from rehost.machine import Machine
from rehost.peripherals import Gpio, RegisterBlock, SysTick, Uart, Unimplemented
from tests.helpers import machine_from_asm


def test_uart_rx_irq_latches_once_per_burst():
    seen: list[int] = []
    uart = Uart(
        name="uart0",
        base=0x40000000,
        size=0x100,
        config={"rx_irq": 4, "irq": 4},
    )
    assert uart.rx_irq == 4
    uart.bind_rx_irq(seen.append)
    assert seen == []
    uart.queue_rx(b"\x01\x02")
    assert seen == [4]
    uart.queue_rx(b"\x03")
    assert seen == [4]
    assert uart.read(0, 1) == 1
    assert uart.read(0, 1) == 2
    assert uart.read(0, 1) == 3
    assert uart.take_rx_irq_edge() is None
    uart.queue_rx(b"\x04")
    assert seen == [4, 4]

    quiet = Uart(name="uart0", base=0x40000000, size=0x100, config={"rx": "A"})
    quiet.bind_rx_irq(seen.append)
    assert seen == [4, 4]
    assert quiet.take_rx_irq_edge() is None

    primed = Uart(name="uart0", base=0x40000000, size=0x100, config={"rx": [0x11], "rx_irq": 7})
    primed.bind_rx_irq(seen.append)
    assert seen == [4, 4, 7]

    with pytest.raises(ConfigError, match="disagree"):
        Uart(name="uart0", base=0x40000000, size=0x100, config={"irq": 1, "rx_irq": 2})
    with pytest.raises(ConfigError, match="rx_irq"):
        Uart(name="uart0", base=0x40000000, size=0x100, config={"rx_irq": 256})
    with pytest.raises(ConfigError, match="does not accept"):
        Uart(name="uart0", base=0x40000000, size=0x100, config={"rx_interrupt": 1})


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


def test_uart_rx_irq_enters_the_handler_when_a_byte_is_queued():
    lines = [".word 0x20001000", ".thumb_word reset"]
    lines.extend(".word 0" for _ in range(14))
    lines.append(".thumb_word irq0")
    source = "\n".join(lines) + """
        reset:
            movw r0, #0xe100
            movt r0, #0xe000
            movs r1, #1
            str r1, [r0, #0]
            wfi
            bkpt #0
        irq0:
            movw r0, #0
            movt r0, #0x4000
            ldr r1, [r0, #0]
            movw r2, #0
            movt r2, #0x2000
            str r1, [r2, #0]
            bx lr
    """
    machine = machine_from_asm(
        source,
        regions=[
            {
                "name": "uart0",
                "base": 0x40000000,
                "size": 0x100,
                "perms": "rw",
                "peripheral": "uart",
                "config": {"rx_irq": 0},
            }
        ],
        boot={"mode": "vector", "vector_base": 0},
    )
    machine.peripheral("uart0").queue_rx(b"\x5a")
    assert machine.backend.pending_irqs == [0]
    result = machine.run()
    assert result.status == "halted", result.detail
    assert machine.read_u32(0x20000000) == 0x5A
    assert machine.backend.pending_irqs == []


def test_preloaded_rx_without_irq_does_not_pend():
    machine = machine_from_asm(
        """
        movw r0, #0
        movt r0, #0x4000
        ldr r1, [r0, #0]
        bkpt #0
        """,
        regions=[
            {
                "name": "uart0",
                "base": 0x40000000,
                "size": 0x100,
                "perms": "rw",
                "peripheral": "uart",
                "config": {"rx": [0x41]},
            }
        ],
    )
    assert machine.backend.pending_irqs == []
    result = machine.run()
    assert result.status == "halted"
    assert result.registers["r1"] == 0x41
    assert machine.backend.pending_irqs == []


def test_register_block_ready_bits_survive_writes_and_unknown_fields_fail():
    block = RegisterBlock(
        name="rcc",
        base=0x40023800,
        size=0x100,
        config={
            "registers": {
                "0x0": {"reset": 0x83, "read_set": 0x20000},
                "0x8": {"reset": 0, "writable": True, "read_mask": 0xC, "read_bits": 0x8},
            }
        },
    )
    block.write(0, 4, 0)
    assert block.read(0, 4) & 0x20000
    block.write(8, 4, 0)
    assert block.read(8, 4) & 0xC == 0x8
    with pytest.raises(ConfigError, match="unknown field"):
        RegisterBlock(
            name="rcc",
            base=0x40023800,
            size=0x100,
            config={"registers": {"0x0": {"reset": 1, "ready": True}}},
        )
    with pytest.raises(ConfigError, match="subset"):
        RegisterBlock(
            name="rcc",
            base=0x40023800,
            size=0x100,
            config={"registers": {"0x0": {"read_mask": 0x1, "read_bits": 0x2}}},
        )


def test_stm32f4_clock_template_returns_ready_bits():
    root = Path(__file__).resolve().parents[1]
    machine = Machine.from_path(root / "examples" / "stm32f4_clock.yaml")
    cr = 0x40023800
    cfgr = 0x40023808
    sr = 0x40023C0C
    machine.write_mmio(cr, 0, 4)
    assert machine.read_mmio(cr, 4) & 0x0A020002 == 0x0A020002
    machine.write_mmio(cfgr, 0, 4)
    assert machine.read_mmio(cfgr, 4) & 0xC == 0x8
    machine.write_mmio(sr, 0xFFFFFFFF, 4)
    assert machine.read_mmio(sr, 4) & 0x00010000 == 0
    assert machine.peripheral("usart2").rx_irq == 38


def test_ready_bits_load_from_toml(tmp_path: Path):
    path = tmp_path / "rcc.toml"
    path.write_text(
        """
        name = "rcc-toml"
        arch = "cortex-m"
        [[memory]]
        name = "rcc"
        base = 0x40023800
        size = 0x100
        perms = "rw"
        peripheral = "register_block"
        read_default = 0

        [memory.config.registers."0x00"]
        reset = 0x83
        writable = true
        read_set = 0x20000
        """,
        encoding="utf-8",
    )
    machine = Machine.from_path(path)
    machine.write_mmio(0x40023800, 0, 4)
    assert machine.read_mmio(0x40023800, 4) & 0x20000 == 0x20000
