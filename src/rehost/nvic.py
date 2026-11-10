# SPDX-License-Identifier: MIT
"""ARMv7-M NVIC, system control, and exception entry/exit.

This is the architectural model the Unicorn backend drives. It is deliberately
an ARMv7-M integer profile, which is also enough for the ARMv6-M subset
(PRIMASK, the same basic stack frame, the same EXC_RETURN values).

Modeled
    Exception numbers follow the architecture: SysTick is 15, external IRQ ``n``
    is exception ``16 + n``. VTOR supplies the vector table. On entry the
    processor stacks r0-r3, r12, lr, the return PC, and xPSR (with bit 9 set
    when CCR.STKALIGN forced 8-byte alignment), selects MSP for the handler,
    and writes LR with EXC_RETURN. On return it unstacks that frame.
    ``0xFFFFFFF1`` returns to Handler mode on MSP, ``0xFFFFFFF9`` to Thread
    mode on MSP, and ``0xFFFFFFFD`` to Thread mode on PSP.

    Priority uses all eight implemented bits. AIRCR.PRIGROUP splits group
    priority from subpriority. A pending exception is taken only when it is
    enabled, not already active, and its group priority is strictly more urgent
    than the execution priority. Execution priority is the most urgent of the
    active exceptions, PRIMASK (boost to 0), FAULTMASK (boost to -1), and
    BASEPRI. BASEPRI compares group priority and is disabled when its group
    field is 0. NMI is -2, HardFault is -1, and both are fixed.

Not modeled
    Tail-chaining and late arrival. A new exception taken as another returns is
    unstacked and then stacked again, so register state matches the architecture
    and the stack pointer briefly moves back up.
    Lazy floating-point stacking. An EXC_RETURN with bit 4 clear stops the run.
    v8-M stack-limit registers and security extensions.
    Priority bits narrower than 8. Unimplemented low bits on a real core read
    as zero; here all eight bits are writable.
"""

from __future__ import annotations

import struct
from typing import Protocol

from rehost.errors import BackendError, MachineError

EXC_NMI = 2
EXC_HARDFAULT = 3
EXC_SVCALL = 11
EXC_PENDSV = 14
EXC_SYSTICK = 15
EXC_EXTERNAL = 16
NUM_EXTERNAL = 256

RETIRE = "retire"
SKIP = "skip"
REDIRECT = "redirect"
STOP = "stop"

_FIXED_PRIORITY = {EXC_NMI: -2, EXC_HARDFAULT: -1}
_SHPR_EXCEPTIONS = (4, 5, 6, 11, 12, 14, 15)
_IT_MASK = (0x3 << 25) | (0x3F << 10)
_CCR_MASK = (1 << 9) | (1 << 8) | (1 << 4) | (1 << 3) | (1 << 1) | (1 << 0)
_SCR_MASK = (1 << 4) | (1 << 2) | (1 << 1)
_SHCSR_ENABLE = (1 << 18) | (1 << 17) | (1 << 16)
_WFI = 0xBF30
_WFE = 0xBF20

_ICTR = 0xE000E004
_ISER = 0xE000E100
_ICER = 0xE000E180
_ISPR = 0xE000E200
_ICPR = 0xE000E280
_IABR = 0xE000E300
_IPR = 0xE000E400
_CPUID = 0xE000ED00
_ICSR = 0xE000ED04
_VTOR = 0xE000ED08
_AIRCR = 0xE000ED0C
_SCR = 0xE000ED10
_CCR = 0xE000ED14
_SHPR1 = 0xE000ED18
_SHPR2 = 0xE000ED1C
_SHPR3 = 0xE000ED20
_SHCSR = 0xE000ED24
_STIR = 0xE000EF00
_SYSTICK_LO = 0xE000E010
_SYSTICK_HI = 0xE000E020
_CPUID_VALUE = 0x410FC231  # Cortex-M3 r0p1, a generic v7-M identity.

_SHPR_BYTES = {
    1: (4, 5, 6, None),
    2: (None, None, None, 11),
    3: (12, None, 14, 15),
}
_SHPR_BASE = {1: _SHPR1, 2: _SHPR2, 3: _SHPR3}
_WORD_OWNERS = {
    "ictr",
    "cpuid",
    "icsr",
    "vtor",
    "aircr",
    "scr",
    "ccr",
    "shpr1",
    "shpr2",
    "shpr3",
    "shcsr",
    "stir",
}


class CoreView(Protocol):
    """Register and memory operations exception entry needs from a CPU."""

    def read_reg(self, name: str) -> int: ...

    def write_reg(self, name: str, value: int) -> None: ...

    def read_mem(self, address: int, size: int) -> bytes: ...

    def write_mem(self, address: int, data: bytes) -> None: ...


class Nvic:
    """NVIC plus the SCB registers that exception delivery consults."""

    def __init__(self, core: CoreView) -> None:
        self.core = core
        self.fault: str | None = None
        self.reset()

    def reset(self) -> None:
        """Architectural reset values for the registers this model owns."""
        self.external_enabled = [False] * NUM_EXTERNAL
        self.external_pending = [False] * NUM_EXTERNAL
        self.external_priority = [0] * NUM_EXTERNAL
        self.shpr = {exc: 0 for exc in _SHPR_EXCEPTIONS}
        self.active: set[int] = set()
        self.nmi_pending = False
        self.pendsv_pending = False
        self.systick_pending = False
        self.vtor = 0
        self.prigroup = 0
        self.ccr = 1 << 9  # STKALIGN
        self.scr = 0
        self.shcsr = 0
        self.fault = None

    def snapshot_state(self) -> dict:
        """Plain data for a machine snapshot. Keys stay JSON-friendly."""
        return {
            "vtor": self.vtor,
            "prigroup": self.prigroup,
            "ccr": self.ccr,
            "scr": self.scr,
            "shcsr": self.shcsr,
            "systick_pending": self.systick_pending,
            "pendsv_pending": self.pendsv_pending,
            "nmi_pending": self.nmi_pending,
            "enabled": [irq for irq, flag in enumerate(self.external_enabled) if flag],
            "pending": [irq for irq, flag in enumerate(self.external_pending) if flag],
            "active": sorted(self.active),
            "priority": list(self.external_priority),
            "shpr": {str(exc): self.shpr[exc] for exc in _SHPR_EXCEPTIONS},
        }

    def restore_state(self, state: dict) -> None:
        """Replace NVIC state. An empty mapping is a reset."""
        if not state:
            self.reset()
            return
        if not isinstance(state, dict):
            raise MachineError("nvic snapshot state must be an object")
        self.reset()
        self.vtor = int(state.get("vtor", 0)) & 0xFFFFFF80
        self.prigroup = int(state.get("prigroup", 0)) & 7
        self.ccr = int(state.get("ccr", 1 << 9)) & _CCR_MASK
        self.scr = int(state.get("scr", 0)) & _SCR_MASK
        self.shcsr = int(state.get("shcsr", 0)) & _SHCSR_ENABLE
        self.systick_pending = bool(state.get("systick_pending", False))
        self.pendsv_pending = bool(state.get("pendsv_pending", False))
        self.nmi_pending = bool(state.get("nmi_pending", False))
        for irq in _irq_list(state.get("enabled", []), "enabled"):
            self.external_enabled[irq] = True
        for irq in _irq_list(state.get("pending", []), "pending"):
            self.external_pending[irq] = True
        priority = state.get("priority", [0] * NUM_EXTERNAL)
        if not isinstance(priority, list) or len(priority) != NUM_EXTERNAL:
            raise MachineError("nvic priority must be 256 bytes")
        self.external_priority = [int(value) & 0xFF for value in priority]
        raw_shpr = state.get("shpr", {})
        if not isinstance(raw_shpr, dict):
            raise MachineError("nvic shpr must be an object")
        for key, value in raw_shpr.items():
            exc = int(key)
            if exc not in self.shpr:
                raise MachineError(f"nvic shpr exception {exc} is not configurable")
            self.shpr[exc] = int(value) & 0xFF
        active = state.get("active", [])
        if not isinstance(active, list):
            raise MachineError("nvic active set must be a list")
        for exc in active:
            number = int(exc)
            if not 0 <= number <= 0x1FF:
                raise MachineError(f"nvic active exception {number} is out of range")
            if number:
                self.active.add(number)

    def pend(self, exc: int) -> None:
        """Latch a system exception, or an external exception number."""
        if exc == EXC_NMI:
            self.nmi_pending = True
        elif exc == EXC_PENDSV:
            self.pendsv_pending = True
        elif exc == EXC_SYSTICK:
            self.systick_pending = True
        elif EXC_EXTERNAL <= exc < EXC_EXTERNAL + NUM_EXTERNAL:
            self.external_pending[exc - EXC_EXTERNAL] = True
        else:
            raise ValueError(f"exception {exc} cannot be pended")

    def pend_external(self, irq: int) -> None:
        if not 0 <= irq < NUM_EXTERNAL:
            raise ValueError(f"irq {irq} is outside 0..{NUM_EXTERNAL - 1}")
        self.external_pending[irq] = True

    def service(self, address: int, size: int) -> str:
        """Deliver a pending exception or complete an exception return.

        Called before the instruction at ``address`` retires. ``skip`` means a
        WFI/WFE was retired without letting the engine execute it. ``redirect``
        means PC now points at a handler or a restored instruction.
        """
        if self.fault:
            return STOP
        try:
            first = self._half(address)
        except BackendError as exc:
            self.fault = f"could not read instruction at {address:#x}: {exc}"
            return STOP
        if first in (_WFI, _WFE):
            exc_num = self.select_exception()
            if exc_num is not None:
                # The hint completes; the stacked PC is the following instruction.
                self.enter(exc_num, (address + 2) & 0xFFFFFFFF)
                return STOP if self.fault else REDIRECT
            self._write_pc((address + 2) & 0xFFFFFFFF)
            return SKIP
        exc_num = self.select_exception()
        if exc_num is not None:
            self.enter(exc_num, address & ~1)
            return STOP if self.fault else REDIRECT
        outcome = self._try_exception_return(address, first)
        if self.fault:
            return STOP
        if outcome is not None:
            return outcome
        return RETIRE

    def request_exception(self, exc: int, return_pc: int) -> None:
        """Take a synchronous exception, escalating to HardFault or lockup."""
        if self._can_take_now(exc):
            self.enter(exc, return_pc)
            return
        if exc != EXC_HARDFAULT and self._can_take_now(EXC_HARDFAULT):
            self.enter(EXC_HARDFAULT, return_pc)
            return
        self.fault = f"exception {exc} escalated to lockup"

    def enter(self, exc: int, return_pc: int) -> None:
        """Stack the integer frame and branch to the vector."""
        if exc in self.active:
            self.fault = f"lockup: exception {exc} is already active"
            return
        xpsr = self.core.read_reg("xpsr") & 0xFFFFFFFF
        ipsr = xpsr & 0x1FF
        control = self.core.read_reg("control") & 0xFFFFFFFF
        in_handler = ipsr != 0
        use_psp = (not in_handler) and ((control >> 1) & 1) == 1
        if in_handler:
            exc_return = 0xFFFFFFF1
        elif use_psp:
            exc_return = 0xFFFFFFFD
        else:
            exc_return = 0xFFFFFFF9
        bank = "psp" if use_psp else "msp"
        sp = self.core.read_reg(bank) & 0xFFFFFFFF
        if sp & 0x3:
            self.fault = f"exception {exc} entry with misaligned stack pointer {sp:#x}"
            return
        vector = self._read_vector(exc)
        if vector is None:
            return
        align = 1 if (self.ccr & (1 << 9)) and (sp & 0x4) else 0
        frame = (sp - (4 * align) - 32) & 0xFFFFFFFF
        stacked_xpsr = (xpsr & ~(1 << 9)) | (align << 9)
        blob = struct.pack(
            "<8I",
            self._gpr(0),
            self._gpr(1),
            self._gpr(2),
            self._gpr(3),
            self._gpr(12),
            self._gpr(14),
            return_pc & ~1,
            stacked_xpsr & 0xFFFFFFFF,
        )
        try:
            self.core.write_mem(frame, blob)
        except BackendError as exc_err:
            self.fault = f"exception {exc} could not stack at {frame:#x}: {exc_err}"
            return
        if use_psp:
            self.core.write_reg("psp", frame)
            handler_sp = self.core.read_reg("msp") & 0xFFFFFFFF
        else:
            handler_sp = frame
            self.core.write_reg("msp", frame)
        self.core.write_reg("control", control & ~0x2)
        self.core.write_reg("msp", handler_sp)
        self.core.write_reg("sp", handler_sp)
        new_xpsr = (xpsr & ~0x1FF & ~_IT_MASK) | (1 << 24) | (exc & 0x1FF)
        self.core.write_reg("xpsr", new_xpsr)
        self.core.write_reg("lr", exc_return)
        self.active.add(exc)
        self._clear_pending(exc)
        self._write_pc(vector & ~1)

    def exception_return(self, exc_return: int) -> None:
        """Unstack a basic frame described by ``exc_return``."""
        reason = self.exc_return_error(exc_return)
        if reason is not None:
            self.fault = reason
            return
        to_thread = bool(exc_return & 0x8)
        to_psp = bool(exc_return & 0x4)
        current = self.core.read_reg("xpsr") & 0x1FF
        if current == 0:
            self.fault = "EXC_RETURN used outside handler mode"
            return
        if to_thread and (self.ccr & 1) == 0:
            others = [item for item in self.active if item != current]
            if others:
                self.fault = (
                    f"exception return to thread while exception {others[0]} is still active"
                )
                return
        bank = "psp" if to_psp else "msp"
        sp = self.core.read_reg(bank) & 0xFFFFFFFF
        if sp & 0x3:
            self.fault = f"exception return with misaligned stack pointer {sp:#x}"
            return
        try:
            blob = self.core.read_mem(sp, 32)
        except BackendError as exc:
            self.fault = f"exception return could not unstack at {sp:#x}: {exc}"
            return
        if len(blob) != 32:
            self.fault = f"exception return could not unstack at {sp:#x}"
            return
        r0, r1, r2, r3, r12, lr, ret_pc, stacked = struct.unpack("<8I", blob)
        if (stacked & (1 << 24)) == 0:
            self.fault = "exception return stacked xPSR.T is clear"
            return
        new_sp = (sp + 32 + (4 if (stacked & (1 << 9)) else 0)) & 0xFFFFFFFF
        for name, value in (
            ("r0", r0),
            ("r1", r1),
            ("r2", r2),
            ("r3", r3),
            ("r12", r12),
            ("lr", lr),
        ):
            self.core.write_reg(name, value)
        self.active.discard(current)
        control = self.core.read_reg("control") & 0xFFFFFFFF
        if to_psp:
            control |= 0x2
            self.core.write_reg("control", control)
            self.core.write_reg("psp", new_sp)
        else:
            control &= ~0x2
            self.core.write_reg("control", control)
            self.core.write_reg("msp", new_sp)
        self.core.write_reg("sp", new_sp)
        if current != EXC_NMI:
            self.core.write_reg("faultmask", 0)
        self.core.write_reg("xpsr", (stacked & ~(1 << 9)) | (1 << 24))
        self._write_pc(ret_pc & ~1)

    def select_exception(self) -> int | None:
        """Most urgent exception that can preempt, or None."""
        exec_pri = self._execution_priority()
        best: int | None = None
        best_key: tuple[int, int, int] | None = None
        for exc in self._pending_enabled():
            if self.group_priority(exc) >= exec_pri:
                continue
            key = (self.group_priority(exc), self.subpriority(exc), exc)
            if best_key is None or key < best_key:
                best, best_key = exc, key
        return best

    def group_priority(self, exc: int) -> int:
        fixed = _FIXED_PRIORITY.get(exc)
        if fixed is not None:
            return fixed
        raw = self.priority_byte(exc)
        shift = self.prigroup + 1
        if shift >= 8:
            return 0
        return raw >> shift

    def subpriority(self, exc: int) -> int:
        if exc in _FIXED_PRIORITY:
            return 0
        raw = self.priority_byte(exc)
        shift = self.prigroup + 1
        if shift >= 8:
            return raw
        return raw & ((1 << shift) - 1)

    def priority_byte(self, exc: int) -> int:
        if EXC_EXTERNAL <= exc < EXC_EXTERNAL + NUM_EXTERNAL:
            return self.external_priority[exc - EXC_EXTERNAL]
        return self.shpr.get(exc, 0) & 0xFF

    def vectpending(self) -> int:
        """Highest pending enabled exception, ignoring PRIMASK and BASEPRI."""
        best: int | None = None
        best_key: tuple[int, int, int] | None = None
        for exc in self._pending_enabled():
            key = (self.group_priority(exc), self.subpriority(exc), exc)
            if best_key is None or key < best_key:
                best, best_key = exc, key
        return 0 if best is None else best

    def io_read(self, address: int, size: int, *, ipsr: int) -> int | None:
        """Read a modeled SCS register. None means this access is not ours."""
        if not self._claim(address, size):
            return None
        owner = self._owner(address)
        if owner in _WORD_OWNERS:
            word = self._read_word(owner, ipsr)
            shift = 8 * (address & 3)
            return (word >> shift) & _mask(size)
        value = 0
        for offset in range(size):
            value |= self._read_byte(address + offset) << (8 * offset)
        return value

    def io_write(self, address: int, size: int, value: int) -> bool:
        """Apply a guest store. False means the access is not ours."""
        if not self._claim(address, size):
            return False
        owner = self._owner(address)
        if owner in _WORD_OWNERS:
            self._write_word(owner, address, size, value)
            return True
        for offset in range(size):
            self._write_byte(address + offset, (value >> (8 * offset)) & 0xFF)
        return True

    def exc_return_error(self, value: int) -> str | None:
        """None when ``value`` is a basic integer EXC_RETURN we can perform."""
        if (value & 0xFFFFFFE0) != 0xFFFFFFE0:
            return f"invalid EXC_RETURN {value:#x}"
        if (value & 0x10) == 0:
            return (
                "EXC_RETURN requests an extended floating-point stack frame, "
                "which is not modeled"
            )
        if (value & 0x1) == 0 or (value & 0x2):
            return f"invalid EXC_RETURN {value:#x}"
        if (value & 0x8) == 0 and (value & 0x4):
            return f"invalid EXC_RETURN {value:#x}"
        return None

    def _execution_priority(self) -> int:
        primask = self.core.read_reg("primask") & 1
        basepri = self.core.read_reg("basepri") & 0xFF
        faultmask = self.core.read_reg("faultmask") & 1
        ipsr = self.core.read_reg("xpsr") & 0x1FF
        priority = 256
        for exc in self.active:
            priority = min(priority, self.group_priority(exc))
        if ipsr and ipsr not in self.active:
            priority = min(priority, self.group_priority(ipsr))
        if faultmask:
            priority = min(priority, -1)
        elif primask:
            priority = min(priority, 0)
        boosted = self._basepri_group(basepri)
        if boosted is not None:
            priority = min(priority, boosted)
        return priority

    def _basepri_group(self, basepri: int) -> int | None:
        if basepri == 0:
            return None
        shift = self.prigroup + 1
        if shift >= 8:
            return None
        group = (basepri & 0xFF) >> shift
        if group == 0:
            return None
        return group

    def _can_take_now(self, exc: int) -> bool:
        if exc in self.active:
            return False
        return self.group_priority(exc) < self._execution_priority()

    def _pending_enabled(self):
        if self.nmi_pending and EXC_NMI not in self.active:
            yield EXC_NMI
        if self.pendsv_pending and EXC_PENDSV not in self.active:
            yield EXC_PENDSV
        if self.systick_pending and EXC_SYSTICK not in self.active:
            yield EXC_SYSTICK
        for irq, pending in enumerate(self.external_pending):
            exc = EXC_EXTERNAL + irq
            if pending and self.external_enabled[irq] and exc not in self.active:
                yield exc

    def _clear_pending(self, exc: int) -> None:
        if exc == EXC_NMI:
            self.nmi_pending = False
        elif exc == EXC_PENDSV:
            self.pendsv_pending = False
        elif exc == EXC_SYSTICK:
            self.systick_pending = False
        elif exc >= EXC_EXTERNAL:
            irq = exc - EXC_EXTERNAL
            if 0 <= irq < NUM_EXTERNAL:
                self.external_pending[irq] = False

    def _read_vector(self, exc: int) -> int | None:
        address = (self.vtor + exc * 4) & 0xFFFFFFFF
        try:
            blob = self.core.read_mem(address, 4)
        except BackendError as exc_err:
            self.fault = f"exception {exc} vector fetch at {address:#x} failed: {exc_err}"
            return None
        if len(blob) != 4:
            self.fault = f"exception {exc} vector fetch at {address:#x} failed"
            return None
        vector = int.from_bytes(blob, "little")
        if (vector & 1) == 0:
            self.fault = f"exception {exc} vector {vector:#010x} is not a Thumb address"
            return None
        return vector

    def _try_exception_return(self, address: int, first: int) -> str | None:
        target = self._return_target(address, first)
        if self.fault:
            return STOP
        if target is None:
            return None
        _kind, value, action = target
        if not _looks_like_exc_return(value):
            return None
        ipsr = self.core.read_reg("xpsr") & 0x1FF
        if ipsr == 0:
            self.fault = "EXC_RETURN used outside handler mode"
            return STOP
        if action is not None:
            action()
            if self.fault:
                return STOP
        self.exception_return(value)
        if self.fault:
            return STOP
        return REDIRECT

    def _return_target(self, address: int, first: int):
        """Peek a PC load that might be EXC_RETURN. The action commits a pop."""
        if (first & 0xFF87) in (0x4700, 0x4780):
            rm = (first >> 3) & 0xF
            return ("bx", self._gpr(rm), None)
        if (first & 0xFF00) == 0x4600:
            rd = (((first >> 7) & 1) << 3) | (first & 7)
            rm = (first >> 3) & 0xF
            if rd == 15:
                return ("mov", self._gpr(rm), None)
            return None
        if (first & 0xFE00) == 0xBC00 and (first & 0x0100):
            regs = [index for index in range(8) if first & (1 << index)]
            regs.append(15)
            return self._peek_pop(regs, self.core.read_reg("sp") & 0xFFFFFFFF, 13)
        if _is_thumb32(first) and (first & 0xFFD0) == 0xE890:
            try:
                second = self._half(address + 2)
            except BackendError as exc:
                self.fault = f"could not read instruction at {address:#x}: {exc}"
                return None
            if (second & (1 << 15)) == 0:
                return None
            rn = first & 0xF
            regs = [index for index in range(13) if second & (1 << index)]
            if second & (1 << 14):
                regs.append(14)
            regs.append(15)
            writeback = rn if ((first >> 5) & 1) else None
            return self._peek_pop(regs, self._gpr(rn), writeback)
        return None

    def _peek_pop(self, regs: list[int], base: int, writeback: int | None):
        if 15 not in regs:
            return None
        pc_index = regs.index(15)
        try:
            raw = self.core.read_mem((base + 4 * pc_index) & 0xFFFFFFFF, 4)
        except BackendError:
            return None
        if len(raw) != 4:
            return None
        pc_val = int.from_bytes(raw, "little")
        if not _looks_like_exc_return(pc_val):
            return None

        def commit() -> None:
            try:
                blob = self.core.read_mem(base & 0xFFFFFFFF, 4 * len(regs))
            except BackendError as exc:
                self.fault = f"could not pop exception return at {base:#x}: {exc}"
                return
            if len(blob) != 4 * len(regs):
                self.fault = f"could not pop exception return at {base:#x}"
                return
            words = struct.unpack("<" + "I" * len(regs), blob)
            for reg, word in zip(regs, words):
                if reg != 15:
                    self._write_gpr(reg, word)
            if writeback is not None:
                self._write_gpr(writeback, (base + 4 * len(regs)) & 0xFFFFFFFF)

        return ("pop", pc_val, commit)

    def _write_pc(self, address: int) -> None:
        xpsr = self.core.read_reg("xpsr") & 0xFFFFFFFF
        self.core.write_reg("xpsr", xpsr | (1 << 24))
        self.core.write_reg("pc", (address & ~1) | 1)

    def _gpr(self, index: int) -> int:
        if index == 13:
            return self.core.read_reg("sp") & 0xFFFFFFFF
        if index == 14:
            return self.core.read_reg("lr") & 0xFFFFFFFF
        if index == 15:
            return self.core.read_reg("pc") & 0xFFFFFFFF
        return self.core.read_reg(f"r{index}") & 0xFFFFFFFF

    def _write_gpr(self, index: int, value: int) -> None:
        value &= 0xFFFFFFFF
        if index == 13:
            self._write_sp(value)
            return
        if index == 14:
            self.core.write_reg("lr", value)
            return
        if index == 15:
            self._write_pc(value)
            return
        self.core.write_reg(f"r{index}", value)

    def _write_sp(self, value: int) -> None:
        ipsr = self.core.read_reg("xpsr") & 0x1FF
        control = self.core.read_reg("control")
        self.core.write_reg("sp", value)
        if ipsr == 0 and (control & 0x2):
            self.core.write_reg("psp", value)
        else:
            self.core.write_reg("msp", value)

    def _half(self, address: int) -> int:
        blob = self.core.read_mem(address & 0xFFFFFFFF, 2)
        if len(blob) != 2:
            raise BackendError(f"short instruction read at {address:#x}")
        return int.from_bytes(blob, "little")

    def _claim(self, address: int, size: int) -> bool:
        if size not in (1, 2, 4):
            return False
        if address < _SYSTICK_HI and address + size > _SYSTICK_LO:
            return False
        owners = {self._owner(address + offset) for offset in range(size)}
        return len(owners) == 1 and None not in owners

    def _owner(self, address: int) -> str | None:
        if _ISER <= address < _ISER + 0x20:
            return "iser"
        if _ICER <= address < _ICER + 0x20:
            return "icer"
        if _ISPR <= address < _ISPR + 0x20:
            return "ispr"
        if _ICPR <= address < _ICPR + 0x20:
            return "icpr"
        if _IABR <= address < _IABR + 0x20:
            return "iabr"
        if _IPR <= address < _IPR + NUM_EXTERNAL:
            return "ipr"
        if _ICTR <= address < _ICTR + 4:
            return "ictr"
        if _CPUID <= address < _CPUID + 4:
            return "cpuid"
        if _ICSR <= address < _ICSR + 4:
            return "icsr"
        if _VTOR <= address < _VTOR + 4:
            return "vtor"
        if _AIRCR <= address < _AIRCR + 4:
            return "aircr"
        if _SCR <= address < _SCR + 4:
            return "scr"
        if _CCR <= address < _CCR + 4:
            return "ccr"
        if _SHPR1 <= address < _SHPR1 + 4:
            return "shpr1"
        if _SHPR2 <= address < _SHPR2 + 4:
            return "shpr2"
        if _SHPR3 <= address < _SHPR3 + 4:
            return "shpr3"
        if _SHCSR <= address < _SHCSR + 4:
            return "shcsr"
        if _STIR <= address < _STIR + 4:
            return "stir"
        return None

    def _read_word(self, owner: str, ipsr: int) -> int:
        if owner == "ictr":
            return (NUM_EXTERNAL // 32) - 1
        if owner == "cpuid":
            return _CPUID_VALUE
        if owner == "icsr":
            return self._read_icsr(ipsr)
        if owner == "vtor":
            return self.vtor
        if owner == "aircr":
            return 0xFA050000 | ((self.prigroup & 7) << 8)
        if owner == "scr":
            return self.scr & _SCR_MASK
        if owner == "ccr":
            return self.ccr & _CCR_MASK
        if owner == "shcsr":
            return self._read_shcsr()
        if owner == "stir":
            return 0
        if owner in {"shpr1", "shpr2", "shpr3"}:
            which = {"shpr1": 1, "shpr2": 2, "shpr3": 3}[owner]
            word = 0
            for index, exc in enumerate(_SHPR_BYTES[which]):
                if exc is not None:
                    word |= (self.shpr.get(exc, 0) & 0xFF) << (8 * index)
            return word
        return 0

    def _read_icsr(self, ipsr: int) -> int:
        value = ipsr & 0x1FF
        if self.nmi_pending:
            value |= 1 << 31
        if self.pendsv_pending:
            value |= 1 << 28
        if self.systick_pending:
            value |= 1 << 26
        if any(self.external_pending):
            value |= 1 << 22
        value |= (self.vectpending() & 0x1FF) << 12
        if ipsr and len(self.active) <= 1:
            value |= 1 << 11
        return value

    def _read_shcsr(self) -> int:
        value = self.shcsr & _SHCSR_ENABLE
        active_bits = {
            15: 11,
            14: 10,
            12: 8,
            11: 7,
            6: 3,
            5: 1,
            4: 0,
        }
        for exc, bit in active_bits.items():
            if exc in self.active:
                value |= 1 << bit
        return value

    def _write_word(self, owner: str, address: int, size: int, value: int) -> None:
        if owner in {"ictr", "cpuid"}:
            return
        if owner == "stir":
            self._write_masked(_STIR, address, size, value, self._apply_stir)
            return
        if owner == "icsr":
            self._write_masked(_ICSR, address, size, value, self._apply_icsr)
            return
        if owner == "vtor":
            self._write_masked(_VTOR, address, size, value, self._apply_vtor)
            return
        if owner == "aircr":
            if address == _AIRCR and size == 4 and ((value >> 16) & 0xFFFF) == 0x05FA:
                self.prigroup = (value >> 8) & 7
                if value & (1 << 2):
                    self.fault = "AIRCR.SYSRESETREQ"
            return
        if owner == "scr":
            self._write_masked(_SCR, address, size, value, self._apply_scr)
            return
        if owner == "ccr":
            self._write_masked(_CCR, address, size, value, self._apply_ccr)
            return
        if owner == "shcsr":
            self._write_masked(_SHCSR, address, size, value, self._apply_shcsr)
            return
        if owner in {"shpr1", "shpr2", "shpr3"}:
            which = {"shpr1": 1, "shpr2": 2, "shpr3": 3}[owner]
            self._write_shpr(which, address, size, value)

    def _write_masked(self, base: int, address: int, size: int, value: int, apply) -> None:
        shift = 8 * (address - base)
        mask = _mask(size) << shift
        bits = (value & _mask(size)) << shift
        apply(bits, mask)

    def _apply_stir(self, bits: int, mask: int) -> None:
        irq = bits & 0x1FF
        if mask & 0x1FF and irq < NUM_EXTERNAL:
            self.external_pending[irq] = True

    def _apply_icsr(self, bits: int, mask: int) -> None:
        if mask & (1 << 31) and bits & (1 << 31):
            self.nmi_pending = True
        if mask & (1 << 28) and bits & (1 << 28):
            self.pendsv_pending = True
        elif mask & (1 << 27) and bits & (1 << 27):
            self.pendsv_pending = False
        if mask & (1 << 26) and bits & (1 << 26):
            self.systick_pending = True
        elif mask & (1 << 25) and bits & (1 << 25):
            self.systick_pending = False

    def _apply_vtor(self, bits: int, mask: int) -> None:
        writable = mask & 0xFFFFFF80
        self.vtor = (self.vtor & ~writable) | (bits & writable)

    def _apply_scr(self, bits: int, mask: int) -> None:
        writable = mask & _SCR_MASK
        self.scr = (self.scr & ~writable) | (bits & writable)

    def _apply_ccr(self, bits: int, mask: int) -> None:
        writable = mask & _CCR_MASK
        self.ccr = (self.ccr & ~writable) | (bits & writable)

    def _apply_shcsr(self, bits: int, mask: int) -> None:
        writable = mask & _SHCSR_ENABLE
        self.shcsr = (self.shcsr & ~writable) | (bits & writable)

    def _write_shpr(self, which: int, address: int, size: int, value: int) -> None:
        base = _SHPR_BASE[which]
        shift = 8 * (address - base)
        mask = _mask(size) << shift
        bits = (value & _mask(size)) << shift
        for index, exc in enumerate(_SHPR_BYTES[which]):
            if exc is None or (mask & (0xFF << (8 * index))) == 0:
                continue
            self.shpr[exc] = (bits >> (8 * index)) & 0xFF

    def _read_byte(self, address: int) -> int:
        owner = self._owner(address)
        if owner == "ipr":
            return self.external_priority[address - _IPR] & 0xFF
        if owner in {"iser", "icer", "ispr", "icpr", "iabr"}:
            base = {"iser": _ISER, "icer": _ICER, "ispr": _ISPR, "icpr": _ICPR, "iabr": _IABR}[owner]
            return self._flag_byte(address - base, owner)
        return 0

    def _write_byte(self, address: int, byte: int) -> None:
        owner = self._owner(address)
        if owner == "ipr":
            self.external_priority[address - _IPR] = byte & 0xFF
            return
        if owner == "iabr":
            return
        if owner in {"iser", "icer", "ispr", "icpr"}:
            self._flag_store(address, owner, byte)

    def _flag_byte(self, delta: int, owner: str) -> int:
        irq = delta * 8
        value = 0
        for bit in range(8):
            number = irq + bit
            if number >= NUM_EXTERNAL:
                break
            if owner in {"iser", "icer"} and self.external_enabled[number]:
                value |= 1 << bit
            elif owner in {"ispr", "icpr"} and self.external_pending[number]:
                value |= 1 << bit
            elif owner == "iabr" and (EXC_EXTERNAL + number) in self.active:
                value |= 1 << bit
        return value

    def _flag_store(self, address: int, owner: str, byte: int) -> None:
        base = {"iser": _ISER, "icer": _ICER, "ispr": _ISPR, "icpr": _ICPR}[owner]
        irq = (address - base) * 8
        for bit in range(8):
            if (byte & (1 << bit)) == 0:
                continue
            number = irq + bit
            if number >= NUM_EXTERNAL:
                break
            if owner == "iser":
                self.external_enabled[number] = True
            elif owner == "icer":
                self.external_enabled[number] = False
            elif owner == "ispr":
                self.external_pending[number] = True
            elif owner == "icpr":
                self.external_pending[number] = False

def _looks_like_exc_return(value: int) -> bool:
    return (value & 0xF0000000) == 0xF0000000


def _is_thumb32(first: int) -> bool:
    return (first >> 11) >= 0x1D


def _mask(size: int) -> int:
    return (1 << (8 * size)) - 1


def _irq_list(value: object, what: str) -> list[int]:
    if not isinstance(value, list):
        raise MachineError(f"nvic {what} must be a list")
    irqs: list[int] = []
    for item in value:
        irq = int(item)
        if not 0 <= irq < NUM_EXTERNAL:
            raise MachineError(f"nvic {what} irq {irq} is out of range")
        irqs.append(irq)
    return irqs
