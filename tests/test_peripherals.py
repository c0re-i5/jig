# SPDX-License-Identifier: MIT
"""Plugin behavior and CPU-side dispatch into those plugins."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from rehost.config import load_config
from rehost.errors import ConfigError
from rehost.fuzz import FuzzHarness, encode_mmio_script
from rehost.machine import Machine
from rehost.peripherals import Gpio, RegisterBlock, SysTick, Timer, Uart, Unimplemented
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


def test_uart_rx_level_pends_again_while_bytes_remain():
    seen: list[int] = []
    uart = Uart(
        name="uart0",
        base=0x4006A000,
        size=0x100,
        config={"rx_irq": 31, "rx_level": True, "data_offset": 0, "status_offset": 4},
    )
    uart.bind_rx_irq(seen.append)
    uart.queue_rx(b"hi")
    assert seen == [31]
    assert uart.read(0, 1) == ord("h")
    assert uart.take_rx_irq_edge() == 31
    assert uart.read(0, 1) == ord("i")
    assert uart.take_rx_irq_edge() is None


def test_uart_byte_offsets_match_a_kinetis_layout():
    # Status at +4 and data at +7, the Kinetis UART map. Word alignment is
    # not required; a byte access at the data offset is the data register.
    uart = Uart(
        name="uart0",
        base=0x4006A000,
        size=0x1000,
        config={
            "data_offset": 0x07,
            "status_offset": 0x04,
            "tx_empty_mask": 0xC0,
            "rx_ready_mask": 0x20,
            "rx": b"Z",
        },
    )
    assert uart.read(0x04, 1) & 0xE0 == 0xE0
    assert uart.read(0x07, 1) == ord("Z")
    uart.write(0x07, 1, 0x141)
    assert bytes(uart.tx) == b"A"
    assert uart.read(0x04, 1) & 0x20 == 0
    with pytest.raises(ConfigError, match="does not fit"):
        Uart(
            name="uart0",
            base=0x4006A000,
            size=0x10,
            config={"data_offset": 0x10, "status_offset": 0x04},
        )


def test_uart_posts_tx_and_pops_rx():
    uart = Uart(name="uart0", base=0x40000000, size=0x100, config={"rx": "Hi", "read_default": 0})
    assert uart.read(4, 4) & 0x80
    assert uart.read(4, 4) & 0x01
    assert uart.read(0, 1) == ord("H")
    uart.write(0, 4, 0x141)
    assert bytes(uart.tx) == b"A"
    # No cr1_offset: TXE stays set across the data write, and other offsets do not stick.
    assert uart.read(4, 4) & 0x80
    assert uart.consume_tx() is None
    uart.write(0x10, 4, 1)
    assert uart.read(0x10, 4) == 0


def _stm32_uart(**extra):
    config = {
        "data_offset": 4,
        "status_offset": 0,
        "tx_empty_mask": 0x80,
        "tx_complete_mask": 0x40,
        "rx_ready_mask": 0x20,
        "rx_irq": 37,
        "cr1_offset": 0x0C,
        "control_offsets": [0x08, 0x0C, 0x10, 0x14, 0x18],
    }
    config.update(extra)
    return Uart(name="usart1", base=0x40011000, size=0x400, config=config)


def test_uart_txeie_pends_when_txe_is_ready_and_clearing_it_stops():
    seen: list[int] = []
    uart = _stm32_uart()
    uart.bind_rx_irq(seen.append)
    assert uart.tx_irq == 37
    assert uart.read(0, 4) & 0xC0 == 0xC0
    # UE | RXNEIE | TE | RE. TXEIE is added by a read-modify-write below.
    cr = (1 << 13) | (1 << 5) | (1 << 3) | (1 << 2)
    uart.write(0x0C, 4, cr)
    assert seen == []
    uart.write(0x0C, 4, uart.read(0x0C, 4) | 0x80)
    assert seen == [37]
    uart.write(4, 1, ord("A"))
    assert bytes(uart.tx) == b"A"
    assert uart.read(0, 4) & 0xC0 == 0
    assert uart.consume_tx() == 37
    assert uart.read(0, 4) & 0xC0 == 0x80
    assert seen == [37, 37]
    uart.write(0x0C, 4, cr)
    uart.write(4, 1, ord("B"))
    assert uart.consume_tx() is None
    assert uart.consume_tx() is None
    assert seen == [37, 37]
    assert uart.read(0, 4) & 0xC0 == 0xC0


def test_uart_tcie_pends_on_tc_and_the_hal_handoff_is_one_store():
    seen: list[int] = []
    uart = _stm32_uart()
    uart.bind_rx_irq(seen.append)
    cr = (1 << 13) | (1 << 3) | (1 << 2)
    # TC is set at reset, so enabling TCIE pends before any data write.
    uart.write(0x0C, 4, cr | 0x40)
    assert seen == [37]
    uart.write(0x0C, 4, cr)
    uart.write(4, 1, ord("Z"))
    assert uart.read(0, 4) & 0x40 == 0
    # TXE rises on the first step. TXEIE is clear, so that step stays quiet.
    uart.write(0x0C, 4, cr | 0x40)
    assert uart.consume_tx() is None
    assert uart.read(0, 4) & 0x80
    assert uart.read(0, 4) & 0x40 == 0
    assert uart.consume_tx() == 37
    assert uart.read(0, 4) & 0x40
    assert seen == [37, 37]
    # Writing 0 to TC clears it and drops the request. Writing 1 does not.
    uart.write(0, 4, 0xC0)
    assert uart.read(0, 4) & 0x40
    uart.write(0, 4, 0x80)
    assert uart.read(0, 4) & 0x40 == 0
    assert seen == [37, 37]
    # One store that clears TXEIE (already clear) and sets TCIE while TC is 0
    # waits for the shift. The same store once TC is set pends immediately,
    # which is the HAL Transmit_IT handoff from TXEIE to TCIE.
    uart.write(4, 1, ord("Y"))
    uart.write(0x0C, 4, cr | 0x80)
    assert uart.consume_tx() == 37
    assert uart.read(0, 4) & 0x40 == 0
    uart.write(0x0C, 4, (uart.read(0x0C, 4) & ~0x80) | 0x40)
    assert seen == [37, 37, 37]
    assert uart.consume_tx() == 37
    assert seen == [37, 37, 37, 37]
    # TC is already set. One store that drops TXEIE and raises TCIE pends now.
    uart.write(0x0C, 4, cr | 0x80)
    uart.write(0x0C, 4, (uart.read(0x0C, 4) & ~0x80) | 0x40)
    assert seen == [37, 37, 37, 37, 37, 37]


def test_uart_cr_registers_read_back_including_enable_bits():
    uart = _stm32_uart()
    cr = (1 << 13) | (1 << 5) | (1 << 3) | (1 << 2)
    uart.write(0x0C, 4, cr)
    assert uart.read(0x0C, 4) == cr
    uart.write(0x0C, 4, uart.read(0x0C, 4) | 0x80 | 0x40)
    assert uart.read(0x0C, 4) == cr | 0xC0
    uart.write(0x0C, 1, 0xFF)
    assert uart.read(0x0C, 4) & 0xFF == 0xFF
    assert uart.read(0x0C, 4) & (1 << 13)
    uart.write(0x08, 4, 0x123)
    uart.write(0x10, 2, 0x2000)
    uart.write(0x14, 4, 0x1)
    uart.write(0x18, 4, 0x5)
    assert uart.read(0x08, 4) == 0x123
    assert uart.read(0x10, 4) == 0x2000
    assert uart.read(0x14, 4) == 1
    assert uart.read(0x18, 4) == 5
    assert uart.read(0x1C, 4) == 0
    saved = uart.snapshot_state()
    uart.write(0x0C, 4, 0)
    uart.write(0x08, 4, 0)
    uart.restore_state(saved)
    assert uart.read(0x0C, 4) == 0x20FF
    assert uart.read(0x08, 4) == 0x123


def test_uart_rx_path_does_not_follow_rxneie():
    seen: list[int] = []
    uart = _stm32_uart()
    uart.bind_rx_irq(seen.append)
    assert uart.read(0x0C, 4) == 0
    uart.queue_rx(b"\x11\x22")
    assert seen == [37]
    uart.queue_rx(b"\x33")
    assert seen == [37]
    assert uart.read(4, 1) == 0x11
    assert uart.read(4, 1) == 0x22
    assert uart.read(4, 1) == 0x33
    assert uart.take_rx_irq_edge() is None
    uart.write(0x0C, 4, 1 << 5)
    uart.queue_rx(b"\x44")
    assert seen == [37, 37]
    assert uart.read(0x0C, 4) == 1 << 5


def test_uart_tx_irq_defaults_to_the_shared_vector_unless_set():
    shared = _stm32_uart()
    assert shared.tx_irq == 37
    seen: list[int] = []
    split = _stm32_uart(tx_irq=39)
    split.bind_rx_irq(seen.append)
    assert split.tx_irq == 39
    split.write(0x0C, 4, 0x80)
    assert seen == [39]
    split.queue_rx(b"A")
    assert seen == [39, 37]
    with pytest.raises(ConfigError, match="tx_irq"):
        Uart(name="uart0", base=0x40000000, size=0x100, config={"tx_irq": 1})
    with pytest.raises(ConfigError, match="txeie_mask"):
        Uart(name="uart0", base=0x40000000, size=0x100, config={"txeie_mask": 1})
    with pytest.raises(ConfigError, match="overlaps"):
        Uart(
            name="uart0",
            base=0x40000000,
            size=0x100,
            config={"data_offset": 4, "status_offset": 0, "cr1_offset": 4},
        )
    with pytest.raises(ConfigError, match="tx_irq"):
        _stm32_uart(tx_irq=256)
    with pytest.raises(ConfigError, match="control_offsets"):
        Uart(
            name="uart0",
            base=0x40000000,
            size=0x100,
            config={"data_offset": 4, "status_offset": 0, "cr1_offset": 0x0C, "control_offsets": 0x0C},
        )


def test_gpio_latch_and_loopback():
    gpio = Gpio(name="gpioa", base=0x40001000, size=0x100, config={"idr": 0x4, "loopback": False})
    gpio.write(0, 4, 0x3)
    assert gpio.odr == 0x3
    assert gpio.read(4, 4) == 0x4
    gpio.loopback = True
    assert gpio.read(4, 4) == 0x3
    gpio.write(1, 1, 0xFF)
    assert gpio.odr == 0xFF03


def test_timer_update_sets_sr_and_reports_irq():
    timer = Timer(
        name="tim2",
        base=0x40000000,
        size=0x400,
        config={"irq": 28, "tick_every": 3},
    )
    timer.cpu_clock = True
    timer.write(0x0C, 4, 0x1)
    assert timer.consume_cpu_tick() is None
    timer.write(0x00, 4, 0x1)
    assert timer.consume_cpu_tick() is None
    assert timer.consume_cpu_tick() is None
    assert timer.consume_cpu_tick() == 28
    assert timer.read(0x10, 4) & 0x1
    # The update flag is still set, so another period does not start.
    assert timer.consume_cpu_tick() is None
    timer.write(0x10, 4, 0)
    timer.write(0x34, 4, 0x10)
    assert timer.consume_cpu_tick() is None
    assert timer.consume_cpu_tick() is None
    assert timer.consume_cpu_tick() == 28
    assert timer.read(0x10, 4) & 0x3 == 0x3
    # Read-modify-write clear of the update flag, the pattern TIM2_IRQHandler uses.
    sr = timer.read(0x10, 4)
    timer.write(0x10, 4, sr & ~1)
    assert timer.read(0x10, 4) & 0x1 == 0
    assert timer.read(0x10, 4) & 0x2
    restored = timer.snapshot_state()
    timer.write(0x00, 4, 0)
    timer.restore_state(restored)
    assert timer.read(0x00, 4) & 0x1
    assert timer.events == restored["events"]


def test_timer_irq_reaches_the_handler():
    lines = [".word 0x20001000", ".thumb_word reset"]
    lines.extend(".word 0" for _ in range(14))
    lines.append(".thumb_word tim")
    source = "\n".join(lines) + """
        reset:
            movw r4, #0xe100
            movt r4, #0xe000
            movs r1, #1
            str r1, [r4, #0]
            movw r0, #0
            movt r0, #0x4000
            str r1, [r0, #0xc]
            str r1, [r0, #0]
            movw r2, #0
            movt r2, #0x2000
        wait:
            ldr r3, [r2, #0]
            cmp r3, #1
            bne wait
            bkpt #0
        tim:
            movw r2, #0
            movt r2, #0x2000
            movs r1, #1
            str r1, [r2, #0]
            movw r0, #0
            movt r0, #0x4000
            movs r1, #0
            str r1, [r0, #0x10]
            bx lr
    """
    machine = machine_from_asm(
        source,
        regions=[
            {
                "name": "tim2",
                "base": 0x40000000,
                "size": 0x400,
                "perms": "rw",
                "peripheral": "timer",
                "config": {"irq": 0, "tick_every": 32},
            }
        ],
        boot={"mode": "vector", "vector_base": 0},
    )
    result = machine.run()
    assert result.status == "halted", result.detail
    assert machine.read_u32(0x20000000) == 1
    assert machine.peripheral("tim2").events >= 1


def test_gpio_bsrr_sets_and_resets_odr():
    gpio = Gpio(
        name="gpioe",
        base=0x40021000,
        size=0x400,
        config={"odr_offset": 0x14, "idr_offset": 0x10, "bsrr_offset": 0x18, "idr": 0xFFFF},
    )
    gpio.write(0x18, 2, 0x0005)
    assert gpio.odr == 0x0005
    gpio.write(0x1A, 2, 0x0001)
    assert gpio.odr == 0x0004
    # Both halves in one word: reset wins on the overlap.
    gpio.write(0x18, 4, 0x0004000F)
    assert gpio.odr == 0x000B
    assert gpio.read(0x18, 4) == 0
    assert gpio.read(0x10, 4) == 0xFFFF


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


def test_uart_interrupt_driven_tx_drains_a_buffer_without_a_helper():
    """HAL-shaped TX: TXEIE drains the buffer, then one TCIE store completes it.

    The handler is the only thing that pends the USART vector. Nothing outside
    the plugin writes ISPR.
    """
    lines = [".word 0x20001000", ".thumb_word reset"]
    lines.extend(".word 0" for _ in range(14))
    lines.append(".thumb_word irq0")
    source = "\n".join(lines) + """
        reset:
            movw r0, #0xe100
            movt r0, #0xe000
            movs r1, #1
            str r1, [r0, #0]
            movw r4, #0
            movt r4, #0x2000
            movs r1, #0x41
            str r1, [r4, #0]
            movs r1, #0x42
            str r1, [r4, #4]
            movs r1, #0x43
            str r1, [r4, #8]
            movw r1, #0
            movt r1, #0x2000
            str r1, [r4, #0x0c]
            movs r1, #3
            str r1, [r4, #0x10]
            movs r1, #0
            str r1, [r4, #0x14]
            movw r0, #0
            movt r0, #0x4000
            movw r1, #0x123
            str r1, [r0, #8]
            movs r1, #0x20
            str r1, [r0, #0x10]
            movw r1, #0x200c
            str r1, [r0, #0x0c]
            ldr r2, [r0, #0x0c]
            str r2, [r4, #0x18]
            movs r3, #0x80
            orrs r2, r3
            str r2, [r0, #0x0c]
        wait:
            ldr r1, [r4, #0x14]
            cmp r1, #1
            bne wait
            bkpt #0
        irq0:
            movw r0, #0
            movt r0, #0x4000
            movw r2, #0
            movt r2, #0x2000
            ldr r3, [r2, #0x10]
            cmp r3, #0
            beq end_or_tc
            ldr r1, [r0, #0]
            movs r3, #0x80
            ands r1, r3
            cmp r1, #0
            beq irq_ret
            ldr r1, [r2, #0x0c]
            ldr r3, [r1, #0]
            str r3, [r0, #4]
            adds r1, #4
            str r1, [r2, #0x0c]
            ldr r3, [r2, #0x10]
            subs r3, #1
            str r3, [r2, #0x10]
            b irq_ret
        end_or_tc:
            ldr r1, [r0, #0x0c]
            mov r3, r1
            movs r2, #0x80
            ands r3, r2
            cmp r3, #0
            beq tc_check
            eors r1, r2
            movs r2, #0x40
            orrs r1, r2
            str r1, [r0, #0x0c]
            b irq_ret
        tc_check:
            ldr r3, [r0, #0]
            movs r2, #0x40
            ands r3, r2
            cmp r3, #0
            beq irq_ret
            ldr r1, [r0, #0x0c]
            eors r1, r2
            str r1, [r0, #0x0c]
            movw r2, #0
            movt r2, #0x2000
            movs r1, #1
            str r1, [r2, #0x14]
        irq_ret:
            bx lr
    """
    machine = machine_from_asm(
        source,
        regions=[
            {
                "name": "usart1",
                "base": 0x40000000,
                "size": 0x400,
                "perms": "rw",
                "peripheral": "uart",
                "config": {
                    "data_offset": 4,
                    "status_offset": 0,
                    "tx_empty_mask": 0x80,
                    "tx_complete_mask": 0x40,
                    "rx_ready_mask": 0x20,
                    "rx_irq": 0,
                    "cr1_offset": 0x0C,
                    "txeie_mask": 0x80,
                    "tcie_mask": 0x40,
                    "control_offsets": [0x08, 0x0C, 0x10, 0x14, 0x18],
                },
            }
        ],
        boot={"mode": "vector", "vector_base": 0},
    )
    result = machine.run()
    uart = machine.peripheral("usart1")
    assert result.status == "halted", result.detail
    assert bytes(uart.tx) == b"ABC"
    assert machine.read_u32(0x20000014) == 1
    assert machine.read_u32(0x20000018) == 0x200C
    assert uart.read(0x0C, 4) == 0x200C
    assert uart.read(0x08, 4) == 0x123
    assert uart.read(0x10, 4) == 0x20
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


def test_follow_bits_track_enable_and_clear_when_disabled():
    block = RegisterBlock(
        name="rcc",
        base=0x40023800,
        size=0x100,
        config={
            "registers": {
                "0x0": {
                    "reset": 0x83,
                    "follow": [
                        {"src": 0, "dst": 1},
                        {"src": 16, "dst": 17},
                        {"src": 24, "dst": 25},
                    ],
                },
                "0x8": {
                    "reset": 0,
                    "follow": [{"src": 0, "dst": 2, "width": 2}],
                },
            }
        },
    )
    # Reset HSION is set, so HSIRDY reads set. HSE and PLL are not.
    assert block.read(0, 4) & 0x3 == 0x3
    assert block.read(0, 4) & 0x02020000 == 0
    block.write(0, 4, 0)
    assert block.read(0, 4) & 0x02020002 == 0
    # Writing the ready bit alone does not stick while the enable is clear.
    block.write(0, 4, 1 << 17)
    assert block.read(0, 4) & (1 << 17) == 0
    block.write(0, 4, 1 << 16)
    assert block.read(0, 4) & (1 << 17)
    block.write(0, 4, 0)
    assert block.read(0, 4) & (1 << 17) == 0
    block.write(8, 4, 0)
    assert block.read(8, 4) & 0xC == 0
    block.write(8, 4, 0x2)
    assert block.read(8, 4) & 0xC == 0x8
    block.write(8, 4, 0x1)
    assert block.read(8, 4) & 0xC == 0x4
    state = block.snapshot_state()
    block.write(0, 4, 0)
    block.restore_state(state)
    assert block.read(8, 4) & 0xC == 0x4
    with pytest.raises(ConfigError, match="overlap"):
        RegisterBlock(
            name="rcc",
            base=0x40023800,
            size=0x100,
            config={"registers": {"0x0": {"follow": [{"src": 0, "dst": 1}, {"src": 2, "dst": 1}]}}},
        )
    with pytest.raises(ConfigError, match="follow must be a list"):
        RegisterBlock(
            name="rcc",
            base=0x40023800,
            size=0x100,
            config={"registers": {"0x0": {"follow": {"src": 0, "dst": 1}}}},
        )


def test_follow_can_read_another_register_and_override_a_field():
    # Status in the second word tracks an enable in the first. A later rule
    # forces a constant into that field only while its own enable is set.
    block = RegisterBlock(
        name="mcg",
        base=0x40064000,
        size=0x1000,
        config={
            "registers": {
                "0x0": {"reset": 0, "writable": True},
                "0x4": {
                    "reset": 0,
                    "writable": True,
                    "follow": [
                        {"from": 0, "src": 6, "dst": 18, "width": 2},
                        {"src": 14, "dst": 18, "width": 2, "value": 3},
                        {"from": 0, "src": 2, "dst": 20},
                    ],
                },
            }
        },
    )
    assert block.read(0x6, 1) == 0
    block.write(0x0, 1, 1 << 2)
    assert block.read(0x6, 1) & 0x10
    block.write(0x0, 1, 0x80)
    assert block.read(0x6, 1) & 0x0C == 0x08
    block.write(0x5, 1, 1 << 6)
    assert block.read(0x6, 1) & 0x0C == 0x0C
    block.write(0x5, 1, 0)
    assert block.read(0x6, 1) & 0x0C == 0x08
    with pytest.raises(ConfigError, match="not a register"):
        RegisterBlock(
            name="mcg",
            base=0x40064000,
            size=0x1000,
            config={"registers": {"0x4": {"follow": [{"from": 0x10, "src": 0, "dst": 1}]}}},
        )


def test_guest_poll_sees_ready_follow_enable():
    """The HAL off-then-on wait, and SWS following SW, as the CPU observes them."""
    source = """
        movw r0, #0x3800
        movt r0, #0x4002
        movs r1, #0
        str r1, [r0]
    hse_off:
        ldr r1, [r0]
        lsrs r1, r1, #17
        movs r2, #1
        ands r1, r2
        bne hse_off
        movs r1, #1
        lsls r1, r1, #16
        str r1, [r0]
    hse_on:
        ldr r1, [r0]
        lsrs r1, r1, #17
        movs r2, #1
        ands r1, r2
        beq hse_on
        movw r3, #0x3808
        movt r3, #0x4002
        movs r1, #0
        str r1, [r3]
    sws_hsi:
        ldr r1, [r3]
        lsrs r1, r1, #2
        movs r2, #3
        ands r1, r2
        bne sws_hsi
        movs r1, #2
        str r1, [r3]
    sws_pll:
        ldr r1, [r3]
        lsrs r1, r1, #2
        movs r2, #3
        ands r1, r2
        cmp r1, #2
        bne sws_pll
        bkpt #0
    """
    machine = machine_from_asm(
        source,
        regions=[
            {
                "name": "rcc",
                "base": 0x40023800,
                "size": 0x100,
                "perms": "rw",
                "peripheral": "register_block",
                "config": {
                    "registers": {
                        "0x0": {
                            "reset": 0x83,
                            "follow": [{"src": 16, "dst": 17}],
                        },
                        "0x8": {"follow": [{"src": 0, "dst": 2, "width": 2}]},
                    }
                },
            }
        ],
    )
    result = machine.run()
    assert result.status == "halted", result.detail
    assert result.instructions < 80
    assert machine.read_mmio(0x40023800, 4) & (1 << 17)
    assert machine.read_mmio(0x40023808, 4) & 0xC == 0x8


def test_bitband_round_trip_updates_register_block_and_sram():
    source = """
        movw r0, #0x60
        movt r0, #0x4200
        movs r1, #1
        str r1, [r0]
        movw r2, #0
        movt r2, #0x4000
        ldr r3, [r2]
        ldr r4, [r0]
        movs r1, #0
        str r1, [r0]
        ldr r5, [r2]
        ldr r6, [r0]
        movw r0, #0x200
        movt r0, #0x2200
        movs r1, #1
        str r1, [r0]
        movw r2, #0x10
        movt r2, #0x2000
        ldrb r7, [r2]
        bkpt #0
    """
    machine = machine_from_asm(
        source,
        regions=[
            {
                "name": "rcc",
                "base": 0x40000000,
                "size": 0x100,
                "perms": "rw",
                "peripheral": "register_block",
                "config": {
                    "registers": {
                        "0x0": {"reset": 0, "follow": [{"src": 24, "dst": 25}]},
                    }
                },
            },
            {
                "name": "peripheral_bitband",
                "base": 0x42000000,
                "size": 0x1000,
                "perms": "rw",
                "peripheral": "bitband",
                "config": {"target": 0x40000000},
            },
            {
                "name": "sram_bitband",
                "base": 0x22000000,
                "size": 0x1000,
                "perms": "rw",
                "peripheral": "bitband",
                "config": {"target": 0x20000000},
            },
        ],
    )
    # Alias of bit 24 (byte 3, bit 0) before the guest runs.
    machine.write_mmio(0x42000060, 1, 4)
    shown = machine.read_mmio(0x40000000, 4)
    assert shown & (1 << 24)
    assert shown & (1 << 25)
    assert machine.read_mmio(0x42000060, 4) == 1
    machine.write_mmio(0x42000060, 0, 4)
    assert machine.read_mmio(0x40000000, 4) & (1 << 25) == 0
    result = machine.run()
    assert result.status == "halted", result.detail
    assert result.registers["r4"] == 1
    assert result.registers["r3"] & (1 << 24)
    assert result.registers["r3"] & (1 << 25)
    assert result.registers["r6"] == 0
    assert result.registers["r5"] & (1 << 25) == 0
    # Bit 0 of SRAM byte 0x20000010. The alias word is base + 0x10 * 32.
    assert result.registers["r7"] == 1
    assert machine.read_u32(0x20000010) & 1 == 1
    with pytest.raises(ConfigError, match="overlaps its target"):
        from rehost.peripherals.bitband import Bitband

        Bitband(name="bb", base=0x20000000, size=0x1000, config={"target": 0x20000000})


def test_stm32f4_clock_template_returns_ready_bits():
    root = Path(__file__).resolve().parents[1]
    machine = Machine.from_path(root / "examples" / "stm32f4_clock.yaml")
    cr = 0x40023800
    cfgr = 0x40023808
    sr = 0x40023C0C
    # Reset HSION implies HSIRDY. The other ready bits follow disabled clocks.
    assert machine.read_mmio(cr, 4) & 0x3 == 0x3
    assert machine.read_mmio(cr, 4) & 0x0A020000 == 0
    machine.write_mmio(cr, 0, 4)
    assert machine.read_mmio(cr, 4) & 0x0A020002 == 0
    machine.write_mmio(cr, 1 << 16, 4)
    assert machine.read_mmio(cr, 4) & (1 << 17)
    machine.write_mmio(cfgr, 0, 4)
    assert machine.read_mmio(cfgr, 4) & 0xC == 0
    machine.write_mmio(cfgr, 0x2, 4)
    assert machine.read_mmio(cfgr, 4) & 0xC == 0x8
    # __HAL_RCC_PLL_ENABLE() stores 1 at the PLLON bit-band alias.
    pllon = 0x42470060
    machine.write_mmio(pllon, 1, 4)
    enabled = machine.read_mmio(cr, 4)
    assert enabled & (1 << 24)
    assert enabled & (1 << 25)
    assert machine.read_mmio(pllon, 4) == 1
    machine.write_mmio(pllon, 0, 4)
    assert machine.read_mmio(cr, 4) & (1 << 25) == 0
    machine.write_mmio(sr, 0xFFFFFFFF, 4)
    assert machine.read_mmio(sr, 4) & 0x00010000 == 0
    assert machine.peripheral("peripheral_bitband").target == 0x40000000
    assert machine.peripheral("sram_bitband").target == 0x20000000
    usart = machine.peripheral("usart2")
    assert usart.rx_irq == 38
    assert usart.tx_empty_mask == 0xC0
    assert usart.rx_ready_mask == 0x20
    gpioa = machine.peripheral("gpioa")
    assert gpioa.odr_offset == 0x14
    assert gpioa.idr_offset == 0x10
    # The long tail is an unimplemented window, not a second HAL.
    assert machine.peripheral("gpiob").read(0x14, 4) == 0
    assert machine.peripheral("usart6").read(0, 4) == 0
    flash = next(region for region in machine.config.memory if region.name == "flash")
    sram = next(region for region in machine.config.memory if region.name == "sram")
    assert flash.base == 0x08000000
    assert sram.base == 0x20000000
    assert machine.config.boot.vector_base == 0x08000000
    assert not any(region.base == 0xE000E000 for region in machine.config.memory)


def test_cnc_p2im_map_extends_the_clock_template():
    """The CNC example keeps the F4 map and adds the Grbl session peripherals.

    The firmware binary stays out of the tree. TIM2 is a timer and GPIO A-E
    gain BSRR; every other region still matches the template.
    """
    root = Path(__file__).resolve().parents[1]
    clock = load_config(root / "examples" / "stm32f4_clock.yaml")
    cnc = load_config(root / "examples" / "cnc-p2im.yaml")
    assert cnc.name == "p2im-cnc"
    assert "not in this repository" in cnc.description
    assert cnc.arch == clock.arch
    assert cnc.endian == clock.endian
    assert cnc.load_base == clock.load_base == 0x08000000
    assert cnc.boot == clock.boot
    assert cnc.unmapped == clock.unmapped
    assert clock.fuzz is None
    # USART2 RX, snapshotted after the Grbl banner. The ELF is still not in the tree.
    assert cnc.fuzz is not None and cnc.fuzz.mode == "uart"
    assert cnc.fuzz.uart is not None and cnc.fuzz.uart.name == "usart2"
    assert cnc.fuzz.checkpoint.mode == "banner"
    assert cnc.fuzz.checkpoint.contains == "Grbl 0.8c"
    assert cnc.fuzz.hang_on_limit is False
    assert cnc.run.timeout_ms == 0
    assert cnc.run.max_instructions == 2_400_000
    assert cnc.run.trace_limit == 128
    assert cnc.run.halt_on_bkpt == clock.run.halt_on_bkpt
    assert cnc.run.halt_addresses == clock.run.halt_addresses
    assert cnc.run.collect_coverage == clock.run.collect_coverage
    assert clock.run.timeout_ms == 2000

    clock_by_name = {region.name: region for region in clock.memory}
    cnc_by_name = {region.name: region for region in cnc.memory}
    assert set(clock_by_name) == set(cnc_by_name)
    promoted = {"tim2", "gpioa", "gpiob", "gpioc", "gpiod", "gpioe"}
    for name, region in cnc_by_name.items():
        template = clock_by_name[name]
        assert region.base == template.base
        assert region.size == template.size
        assert region.perms == template.perms
        if name not in promoted:
            assert region == template
    assert cnc_by_name["tim2"].peripheral == "timer"
    assert cnc_by_name["tim2"].peripheral_config["irq"] == 28
    for name in ("gpioa", "gpiob", "gpioc", "gpiod", "gpioe"):
        region = cnc_by_name[name]
        assert region.peripheral == "gpio"
        assert region.peripheral_config["bsrr_offset"] == 0x18
        assert region.peripheral_config["odr_offset"] == 0x14
        assert region.peripheral_config["idr_offset"] == 0x10


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

        [memory.config.registers."0x08"]
        reset = 0
        writable = true

        [[memory.config.registers."0x08".follow]]
        src = 0
        dst = 2
        width = 2
        """,
        encoding="utf-8",
    )
    machine = Machine.from_path(path)
    machine.write_mmio(0x40023800, 0, 4)
    assert machine.read_mmio(0x40023800, 4) & 0x20000 == 0x20000
    machine.write_mmio(0x40023808, 1, 4)
    assert machine.read_mmio(0x40023808, 4) & 0xC == 0x4
