# SPDX-License-Identifier: MIT
"""Cortex-M exception entry, NVIC priority, SysTick, and external IRQs."""

from __future__ import annotations

import struct

from rehost.nvic import (
    EXC_SYSTICK,
    NUM_EXTERNAL,
    REDIRECT,
    SKIP,
    Nvic,
)
from rehost.snapshot import Snapshot
from tests.helpers import machine_from_asm

_SYSTICK = {
    "name": "systick",
    "base": 0xE000E010,
    "size": 0x10,
    "perms": "rw",
    "peripheral": "systick",
}


class FakeCore:
    """Register file and sparse memory for entry/exit tests without Unicorn."""

    def __init__(self) -> None:
        self.regs = {f"r{index}": 0 for index in range(13)}
        self.regs.update(
            {
                "sp": 0,
                "lr": 0,
                "pc": 0,
                "xpsr": 1 << 24,
                "msp": 0,
                "psp": 0,
                "control": 0,
                "primask": 0,
                "basepri": 0,
                "faultmask": 0,
            }
        )
        self.mem: dict[int, int] = {}

    def read_reg(self, name: str) -> int:
        return self.regs[name]

    def write_reg(self, name: str, value: int) -> None:
        self.regs[name] = value & 0xFFFFFFFF

    def read_mem(self, address: int, size: int) -> bytes:
        return bytes(self.mem.get((address + index) & 0xFFFFFFFF, 0) for index in range(size))

    def write_mem(self, address: int, data: bytes) -> None:
        for index, byte in enumerate(data):
            self.mem[(address + index) & 0xFFFFFFFF] = byte

    def w32(self, address: int, value: int) -> None:
        self.write_mem(address, struct.pack("<I", value & 0xFFFFFFFF))

    def r32(self, address: int) -> int:
        return int.from_bytes(self.read_mem(address, 4), "little")


def _vector_table(*handlers: tuple[int, str]) -> str:
    by_exc = dict(handlers)
    lines = [".word 0x20001000", ".thumb_word reset"]
    for exc in range(2, 18):
        handler = by_exc.get(exc)
        lines.append(f".thumb_word {handler}" if handler else ".word 0")
    return "\n".join(lines) + "\n"


def test_entry_stacks_frame_aligns_and_returns():
    core = FakeCore()
    nvic = Nvic(core)
    core.regs["msp"] = 0x20001000
    core.regs["sp"] = 0x20001000
    core.regs["r0"] = 0x11
    core.regs["r1"] = 0x22
    core.regs["lr"] = 0xFFFFFFFF
    core.regs["pc"] = 0x40
    core.w32(EXC_SYSTICK * 4, 0x81)
    nvic.systick_pending = True
    nvic.enter(EXC_SYSTICK, 0x40)
    assert nvic.fault is None
    frame = 0x20001000 - 32
    assert core.regs["sp"] == frame
    assert core.regs["lr"] == 0xFFFFFFF9
    assert core.regs["pc"] & ~1 == 0x80
    assert core.regs["xpsr"] & 0x1FF == EXC_SYSTICK
    assert (core.regs["control"] & 0x2) == 0
    assert core.r32(frame) == 0x11
    assert core.r32(frame + 4) == 0x22
    assert core.r32(frame + 20) == 0xFFFFFFFF
    assert core.r32(frame + 24) == 0x40
    stacked = core.r32(frame + 28)
    assert stacked & (1 << 24)
    assert (stacked & 0x1FF) == 0
    assert (stacked & (1 << 9)) == 0
    assert not nvic.systick_pending
    assert EXC_SYSTICK in nvic.active

    core.regs["r0"] = 0x99
    nvic.exception_return(0xFFFFFFF9)
    assert nvic.fault is None
    assert core.regs["r0"] == 0x11
    assert core.regs["r1"] == 0x22
    assert core.regs["lr"] == 0xFFFFFFFF
    assert core.regs["pc"] & ~1 == 0x40
    assert core.regs["sp"] == 0x20001000
    assert (core.regs["xpsr"] & 0x1FF) == 0
    assert EXC_SYSTICK not in nvic.active


def test_stkalign_sets_stacked_xpsr_bit9_and_psp_uses_thread_stack():
    core = FakeCore()
    nvic = Nvic(core)
    core.regs["msp"] = 0x20001000
    core.regs["psp"] = 0x20000804
    core.regs["sp"] = 0x20000804
    core.regs["control"] = 2
    core.regs["pc"] = 0x20
    core.w32(EXC_SYSTICK * 4, 0x101)
    nvic.enter(EXC_SYSTICK, 0x20)
    assert nvic.fault is None
    assert core.regs["lr"] == 0xFFFFFFFD
    assert core.regs["msp"] == 0x20001000
    assert core.regs["sp"] == 0x20001000
    frame = 0x20000804 - 4 - 32
    assert core.regs["psp"] == frame
    assert core.r32(frame + 28) & (1 << 9)
    assert core.r32(frame + 24) == 0x20

    # Return to thread mode on PSP and undo the alignment word.
    core.regs["xpsr"] = (1 << 24) | EXC_SYSTICK
    nvic.exception_return(0xFFFFFFFD)
    assert nvic.fault is None
    assert core.regs["sp"] == 0x20000804
    assert core.regs["psp"] == 0x20000804
    assert core.regs["control"] & 0x2
    assert core.regs["pc"] & ~1 == 0x20


def test_nested_entry_writes_return_to_handler():
    core = FakeCore()
    nvic = Nvic(core)
    core.regs["msp"] = core.regs["sp"] = 0x20001000
    core.w32(16 * 4, 0x201)
    core.w32(17 * 4, 0x301)
    nvic.enter(16, 0x40)
    assert core.regs["lr"] == 0xFFFFFFF9
    nvic.enter(17, 0x200)
    assert nvic.fault is None
    assert core.regs["lr"] == 0xFFFFFFF1
    assert core.regs["xpsr"] & 0x1FF == 17
    assert nvic.active == {16, 17}


def test_priority_primask_and_basepri_select_the_exception():
    core = FakeCore()
    nvic = Nvic(core)
    nvic.external_enabled[0] = True
    nvic.external_enabled[1] = True
    nvic.external_pending[0] = True
    nvic.external_pending[1] = True
    assert nvic.select_exception() == 16

    nvic.external_priority[0] = 0x20
    assert nvic.select_exception() == 17

    nvic.external_priority[0] = 0x80
    nvic.external_priority[1] = 0x80
    core.regs["basepri"] = 0x40
    assert nvic.select_exception() is None
    nvic.external_priority[1] = 0x00
    assert nvic.select_exception() == 17

    core.regs["basepri"] = 0
    core.regs["primask"] = 1
    assert nvic.select_exception() is None
    nvic.nmi_pending = True
    assert nvic.select_exception() == 2


def test_nvic_mmio_set_clear_and_icsr():
    nvic = Nvic(FakeCore())
    assert nvic.io_read(0xE000ED00, 4, ipsr=0) == 0x410FC231
    assert nvic.io_write(0xE000E100, 4, 0x1) is True
    assert nvic.external_enabled[0] is True
    assert nvic.io_read(0xE000E100, 4, ipsr=0) == 1
    assert nvic.io_write(0xE000E180, 4, 0x1) is True
    assert nvic.external_enabled[0] is False
    assert nvic.io_write(0xE000E400, 4, 0x80) is True
    assert nvic.external_priority[0] == 0x80
    assert nvic.io_read(0xE000E400, 1, ipsr=0) == 0x80
    assert nvic.io_write(0xE000ED04, 4, 1 << 26) is True
    assert nvic.systick_pending is True
    assert nvic.io_read(0xE000ED04, 4, ipsr=0) & (1 << 26)
    assert nvic.io_write(0xE000ED04, 4, 1 << 25) is True
    assert nvic.systick_pending is False
    assert nvic.io_write(0xE000ED20, 4, 0x40 << 24) is True
    assert nvic.shpr[EXC_SYSTICK] == 0x40
    assert nvic.io_write(0xE000ED0C, 4, (0x05FA << 16) | (3 << 8)) is True
    assert nvic.prigroup == 3
    assert nvic.io_write(0xE000ED0C, 4, (0x1234 << 16) | (1 << 8)) is True
    assert nvic.prigroup == 3
    assert nvic.io_read(0xE000E010, 4, ipsr=0) is None


def test_pop_and_wfi_use_the_same_return_path():
    core = FakeCore()
    nvic = Nvic(core)
    frame = 0x20000100
    core.regs["xpsr"] = (1 << 24) | EXC_SYSTICK
    core.regs["msp"] = core.regs["sp"] = frame - 4
    core.w32(frame - 4, 0xFFFFFFF9)
    core.w32(frame + 0, 0x11)
    core.w32(frame + 24, 0x50)
    core.w32(frame + 28, 1 << 24)
    core.mem[0x80] = 0x00
    core.mem[0x81] = 0xBD  # pop {pc}
    nvic.active.add(EXC_SYSTICK)
    assert nvic.service(0x80, 2) == REDIRECT
    assert nvic.fault is None
    assert core.regs["r0"] == 0x11
    assert core.regs["pc"] & ~1 == 0x50
    assert core.regs["sp"] == frame + 32

    core.regs["pc"] = 0
    core.regs["xpsr"] = 1 << 24
    core.mem[0] = 0x30
    core.mem[1] = 0xBF
    assert nvic.service(0, 2) == SKIP
    assert core.regs["pc"] & ~1 == 2

    core.regs["pc"] = 0
    core.regs["msp"] = core.regs["sp"] = 0x20001000
    core.w32(EXC_SYSTICK * 4, 0x101)
    nvic.systick_pending = True
    assert nvic.service(0, 2) == REDIRECT
    assert core.r32(core.regs["sp"] + 24) == 2
    assert core.regs["lr"] == 0xFFFFFFF9


def test_thumb2_pop_restores_a_high_register_then_returns():
    core = FakeCore()
    nvic = Nvic(core)
    frame = 0x20000100
    core.regs["xpsr"] = (1 << 24) | 16
    core.regs["msp"] = core.regs["sp"] = frame - 8
    core.w32(frame - 8, 0x44)
    core.w32(frame - 4, 0xFFFFFFF9)
    core.w32(frame, 0x11)
    core.w32(frame + 24, 0x60)
    core.w32(frame + 28, 1 << 24)
    for index, byte in enumerate(bytes.fromhex("bde81080")):  # pop.w {r4, pc}
        core.mem[0x100 + index] = byte
    nvic.active.add(16)
    assert nvic.service(0x100, 4) == REDIRECT
    assert nvic.fault is None
    assert core.regs["r4"] == 0x44
    assert core.regs["r0"] == 0x11
    assert core.regs["pc"] & ~1 == 0x60
    assert core.regs["sp"] == frame + 32


def test_extended_frame_exc_return_is_rejected():
    core = FakeCore()
    nvic = Nvic(core)
    core.regs["xpsr"] = (1 << 24) | EXC_SYSTICK
    nvic.active.add(EXC_SYSTICK)
    nvic.exception_return(0xFFFFFFE9)
    assert nvic.fault is not None
    assert "floating-point" in nvic.fault


def test_snapshot_round_trip_of_nvic_state():
    nvic = Nvic(FakeCore())
    nvic.vtor = 0x20000000
    nvic.external_enabled[4] = True
    nvic.external_pending[4] = True
    nvic.external_priority[4] = 0xA0
    nvic.shpr[14] = 0xFF
    nvic.systick_pending = True
    nvic.active.add(EXC_SYSTICK)
    restored = Nvic(FakeCore())
    restored.restore_state(nvic.snapshot_state())
    assert restored.vtor == 0x20000000
    assert restored.external_enabled[4] is True
    assert restored.external_pending[4] is True
    assert restored.external_priority[4] == 0xA0
    assert restored.shpr[14] == 0xFF
    assert restored.systick_pending is True
    assert EXC_SYSTICK in restored.active
    assert len(restored.external_priority) == NUM_EXTERNAL


def test_systick_tickint_runs_the_handler_and_unstacks():
    source = _vector_table((EXC_SYSTICK, "systick")) + """
        reset:
            movs r0, #0x11
            movw r3, #0xe010
            movt r3, #0xe000
            movs r1, #0xff
            str r1, [r3, #4]
            movs r1, #0
            str r1, [r3, #8]
            movs r1, #7
            str r1, [r3, #0]
        after_enable:
            nop
            movw r2, #0
            movt r2, #0x2000
            str r0, [r2, #24]
            bkpt #0
        systick:
            add r3, sp, #0
            movw r2, #0
            movt r2, #0x2000
            ldr r1, [r3, #0]
            str r1, [r2, #4]
            ldr r1, [r3, #24]
            str r1, [r2, #8]
            ldr r1, [r3, #28]
            str r1, [r2, #12]
            mrs r1, ipsr
            str r1, [r2, #16]
            mov r1, lr
            str r1, [r2, #20]
            str r3, [r2, #28]
            movs r1, #1
            str r1, [r2, #0]
            movs r0, #0x99
            bx lr
    """
    machine = machine_from_asm(
        source,
        regions=[_SYSTICK],
        boot={"mode": "vector", "vector_base": 0},
    )
    result = machine.run()
    assert result.status == "halted", result.detail
    assert machine.read_u32(0x20000000) == 1
    assert machine.read_u32(0x20000004) == 0x11
    assert machine.read_u32(0x20000008) == machine.labels["after_enable"]
    stacked = machine.read_u32(0x2000000C)
    assert stacked & (1 << 24)
    assert (stacked & 0x1FF) == 0
    assert machine.read_u32(0x20000010) == EXC_SYSTICK
    assert machine.read_u32(0x20000014) == 0xFFFFFFF9
    assert machine.read_u32(0x20000018) == 0x11
    assert machine.read_u32(0x2000001C) == 0x20001000 - 32


def test_inject_irq_enters_the_vector_after_it_is_enabled():
    source = _vector_table((16, "irq0")) + """
        reset:
            movw r2, #0
            movt r2, #0x2000
            movs r3, #2
            str r3, [r2, #4]
            movw r0, #0xe100
            movt r0, #0xe000
            movs r1, #1
            str r1, [r0, #0]
        after_enable:
            wfi
        after_wfi:
            bkpt #0
        irq0:
            add r3, sp, #0
            movw r2, #0
            movt r2, #0x2000
            ldr r1, [r3, #24]
            str r1, [r2, #12]
            ldr r1, [r2, #4]
            str r1, [r2, #8]
            movs r1, #1
            str r1, [r2, #0]
            bx lr
    """
    machine = machine_from_asm(source, boot={"mode": "vector", "vector_base": 0})
    machine.inject_irq(0)
    result = machine.run()
    assert result.status == "halted", result.detail
    assert machine.read_u32(0x20000000) == 1
    assert machine.read_u32(0x20000008) == 2
    assert machine.read_u32(0x2000000C) == machine.labels["after_wfi"]
    assert 0 not in machine.backend.pending_irqs


def test_disabled_irq_stays_pending():
    machine = machine_from_asm("movs r0, #1\n    bkpt #0")
    # No vector table in this image; delivery would fault. The IRQ is disabled.
    machine.inject_irq(3)
    result = machine.run()
    assert result.status == "halted"
    assert result.registers["r0"] == 1
    assert machine.backend.pending_irqs == [3]


def test_primask_defers_an_external_irq():
    source = _vector_table((16, "irq0")) + """
        reset:
            cpsid i
            movw r0, #0xe100
            movt r0, #0xe000
            movs r1, #1
            str r1, [r0, #0]
            movw r0, #0xe200
            movt r0, #0xe000
            movs r1, #1
            str r1, [r0, #0]
            nop
            movw r2, #0
            movt r2, #0x2000
            ldr r3, [r2, #0]
            str r3, [r2, #4]
            cpsie i
            nop
            bkpt #0
        irq0:
            movw r2, #0
            movt r2, #0x2000
            ldr r1, [r2, #0]
            adds r1, #1
            str r1, [r2, #0]
            bx lr
    """
    machine = machine_from_asm(source, boot={"mode": "vector", "vector_base": 0})
    result = machine.run()
    assert result.status == "halted", result.detail
    assert machine.read_u32(0x20000004) == 0
    assert machine.read_u32(0x20000000) == 1


def test_basepri_masks_a_less_urgent_irq():
    source = _vector_table((16, "irq0")) + """
        reset:
            movw r0, #0xe400
            movt r0, #0xe000
            movs r1, #0x80
            str r1, [r0, #0]
            movs r1, #0x40
            msr basepri, r1
            movw r0, #0xe100
            movt r0, #0xe000
            movs r1, #1
            str r1, [r0, #0]
            movw r0, #0xe200
            movt r0, #0xe000
            movs r1, #1
            str r1, [r0, #0]
            nop
            movw r2, #0
            movt r2, #0x2000
            ldr r3, [r2, #0]
            str r3, [r2, #4]
            movs r1, #0
            msr basepri, r1
            nop
            bkpt #0
        irq0:
            movw r2, #0
            movt r2, #0x2000
            ldr r1, [r2, #0]
            adds r1, #1
            str r1, [r2, #0]
            bx lr
    """
    machine = machine_from_asm(source, boot={"mode": "vector", "vector_base": 0})
    result = machine.run()
    assert result.status == "halted", result.detail
    assert machine.read_u32(0x20000004) == 0
    assert machine.read_u32(0x20000000) == 1


def test_wfi_with_primask_set_does_not_hang_or_enter():
    source = _vector_table((16, "irq0")) + """
        reset:
            cpsid i
            movw r0, #0xe100
            movt r0, #0xe000
            movs r1, #1
            str r1, [r0, #0]
            movw r0, #0xe200
            movt r0, #0xe000
            movs r1, #1
            str r1, [r0, #0]
            wfi
            movw r2, #0
            movt r2, #0x2000
            movs r3, #1
            str r3, [r2, #4]
            bkpt #0
        irq0:
            movw r2, #0
            movt r2, #0x2000
            movs r1, #1
            str r1, [r2, #0]
            bx lr
    """
    machine = machine_from_asm(source, boot={"mode": "vector", "vector_base": 0})
    result = machine.run()
    assert result.status == "halted", result.detail
    assert machine.read_u32(0x20000000) == 0
    assert machine.read_u32(0x20000004) == 1


def test_svc_stacks_the_following_instruction():
    source = _vector_table((11, "svcall")) + """
        reset:
            movs r0, #5
            svc #0
            movw r2, #0
            movt r2, #0x2000
            str r0, [r2, #4]
            bkpt #0
        svcall:
            movw r2, #0
            movt r2, #0x2000
            movs r1, #1
            str r1, [r2, #0]
            movs r0, #9
            bx lr
    """
    machine = machine_from_asm(source, boot={"mode": "vector", "vector_base": 0})
    result = machine.run()
    assert result.status == "halted", result.detail
    assert machine.read_u32(0x20000000) == 1
    assert machine.read_u32(0x20000004) == 5


def test_higher_priority_irq_preempts_and_returns_to_the_handler():
    source = _vector_table((16, "irq0"), (17, "irq1")) + """
        reset:
            movw r0, #0xe400
            movt r0, #0xe000
            movs r1, #0x80
            str r1, [r0, #0]
            movw r0, #0xe100
            movt r0, #0xe000
            movs r1, #3
            str r1, [r0, #0]
            movw r0, #0xe200
            movt r0, #0xe000
            movs r1, #1
            str r1, [r0, #0]
            nop
            bkpt #0
        irq0:
            movw r0, #0xe200
            movt r0, #0xe000
            movs r1, #2
            str r1, [r0, #0]
            nop
            bx lr
        irq1:
            mov r1, lr
            movw r2, #0
            movt r2, #0x2000
            str r1, [r2, #0]
            movs r1, #1
            str r1, [r2, #4]
            bx lr
    """
    machine = machine_from_asm(source, boot={"mode": "vector", "vector_base": 0})
    result = machine.run()
    assert result.status == "halted", result.detail
    assert machine.read_u32(0x20000000) == 0xFFFFFFF1
    assert machine.read_u32(0x20000004) == 1


def test_thread_psp_stacks_on_psp_and_returns_with_exc_return_fd():
    source = _vector_table((16, "irq0")) + """
        reset:
            movw r0, #0x0800
            movt r0, #0x2000
            msr psp, r0
            movs r0, #2
            msr control, r0
            movs r1, #0x55
            movw r0, #0xe100
            movt r0, #0xe000
            movs r2, #1
            str r2, [r0, #0]
            movw r0, #0xe200
            movt r0, #0xe000
            str r2, [r0, #0]
            nop
            movw r3, #0
            movt r3, #0x2000
            str r1, [r3, #4]
            bkpt #0
        irq0:
            mov r1, lr
            movw r3, #0
            movt r3, #0x2000
            str r1, [r3, #0]
            movs r1, #0
            bx lr
    """
    machine = machine_from_asm(source, boot={"mode": "vector", "vector_base": 0})
    result = machine.run()
    assert result.status == "halted", result.detail
    assert machine.read_u32(0x20000000) == 0xFFFFFFFD
    assert machine.read_u32(0x20000004) == 0x55


def test_aircr_sysresetreq_stops_the_run():
    source = """
        movw r0, #0xed0c
        movt r0, #0xe000
        movw r1, #4
        movt r1, #0x05fa
        str r1, [r0, #0]
        movs r0, #1
        bkpt #0
    """
    machine = machine_from_asm(source)
    result = machine.run()
    assert result.status == "fault"
    assert "SYSRESETREQ" in result.detail
    assert result.registers["r0"] != 1


def test_restored_nvic_pending_bit_is_delivered():
    source = _vector_table((16, "irq0")) + """
        reset:
            movw r0, #0xe100
            movt r0, #0xe000
            movs r1, #1
            str r1, [r0, #0]
            wfi
            bkpt #0
        irq0:
            movw r2, #0
            movt r2, #0x2000
            movs r1, #1
            str r1, [r2, #0]
            bx lr
    """
    machine = machine_from_asm(source, boot={"mode": "vector", "vector_base": 0})
    machine.boot()
    machine.inject_irq(0)
    snap = machine.snapshot()
    machine.backend.reset_cpu_state()
    assert machine.backend.pending_irqs == []
    cloned = Snapshot.from_dict(snap.to_dict())
    machine.restore(cloned)
    assert machine.backend.nvic.external_pending[0] is True
    result = machine.run()
    assert result.status == "halted", result.detail
    assert machine.read_u32(0x20000000) == 1
