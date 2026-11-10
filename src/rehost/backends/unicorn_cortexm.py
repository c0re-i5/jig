# SPDX-License-Identifier: MIT
"""Unicorn Engine backend for Cortex-M (Thumb and Thumb-2, little-endian).

The CPU is Unicorn's. This module only maps the backend interface onto it:
page mapping, register names, and hooks. Peripheral behavior lives in plugins.
"""

from __future__ import annotations

import logging

from unicorn import (
    UC_ARCH_ARM,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_UNMAPPED,
    UC_HOOK_MEM_WRITE,
    UC_MODE_LITTLE_ENDIAN,
    UC_MODE_MCLASS,
    UC_MODE_THUMB,
    UC_PROT_EXEC,
    UC_PROT_READ,
    UC_PROT_WRITE,
    UC_QUERY_TIMEOUT,
    Uc,
    UcError,
)
from unicorn.arm_const import (
    UC_ARM_REG_BASEPRI,
    UC_ARM_REG_CONTROL,
    UC_ARM_REG_FAULTMASK,
    UC_ARM_REG_LR,
    UC_ARM_REG_MSP,
    UC_ARM_REG_PC,
    UC_ARM_REG_PRIMASK,
    UC_ARM_REG_PSP,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_R4,
    UC_ARM_REG_R5,
    UC_ARM_REG_R6,
    UC_ARM_REG_R7,
    UC_ARM_REG_R8,
    UC_ARM_REG_R9,
    UC_ARM_REG_R10,
    UC_ARM_REG_R11,
    UC_ARM_REG_R12,
    UC_ARM_REG_SP,
    UC_ARM_REG_XPSR,
)
from unicorn.unicorn_const import (
    UC_MEM_FETCH_UNMAPPED,
    UC_MEM_READ_UNMAPPED,
    UC_MEM_WRITE_UNMAPPED,
)

from rehost.backends.base import CpuBackend, MemAccess
from rehost.backends.registry import register_backend
from rehost.errors import BackendError
from rehost.memory import PERM_EXEC, PERM_READ, PERM_WRITE
from rehost.nvic import EXC_SVCALL, Nvic

logger = logging.getLogger(__name__)

# QEMU exception numbers, surfaced by Unicorn as the interrupt-hook vector.
BKPT_VECTOR = 7
SVC_VECTOR = 2

_SCS_PAGE = 0xE000E000

_REGISTERS: tuple[tuple[str, int], ...] = (
    ("r0", UC_ARM_REG_R0),
    ("r1", UC_ARM_REG_R1),
    ("r2", UC_ARM_REG_R2),
    ("r3", UC_ARM_REG_R3),
    ("r4", UC_ARM_REG_R4),
    ("r5", UC_ARM_REG_R5),
    ("r6", UC_ARM_REG_R6),
    ("r7", UC_ARM_REG_R7),
    ("r8", UC_ARM_REG_R8),
    ("r9", UC_ARM_REG_R9),
    ("r10", UC_ARM_REG_R10),
    ("r11", UC_ARM_REG_R11),
    ("r12", UC_ARM_REG_R12),
    ("sp", UC_ARM_REG_SP),
    ("lr", UC_ARM_REG_LR),
    ("pc", UC_ARM_REG_PC),
    ("xpsr", UC_ARM_REG_XPSR),
    ("msp", UC_ARM_REG_MSP),
    ("psp", UC_ARM_REG_PSP),
    ("control", UC_ARM_REG_CONTROL),
    ("primask", UC_ARM_REG_PRIMASK),
    ("basepri", UC_ARM_REG_BASEPRI),
    ("faultmask", UC_ARM_REG_FAULTMASK),
)
_REG_INDEX = {name: ident for name, ident in _REGISTERS}

_UNMAPPED = {
    UC_MEM_READ_UNMAPPED: "read_unmapped",
    UC_MEM_WRITE_UNMAPPED: "write_unmapped",
    UC_MEM_FETCH_UNMAPPED: "fetch_unmapped",
}


@register_backend("cortex-m")
class UnicornCortexM(CpuBackend):
    """Cortex-M via ``UC_ARCH_ARM`` + ``UC_MODE_THUMB | UC_MODE_MCLASS``."""

    arch = "cortex-m"

    def __init__(self) -> None:
        super().__init__()
        # The C API times out in microseconds. The Python docstring that says
        # milliseconds does not match Unicorn 2.1 (uc_emu_start).
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS | UC_MODE_LITTLE_ENDIAN)
        self.nvic = Nvic(_UnicornCore(self))
        self._scs_ready = False

    def map_memory(self, address: int, size: int, perms: int) -> None:
        self._check_pages(address, size)
        try:
            self.uc.mem_map(address, size, self._perms(perms))
        except UcError as exc:
            raise BackendError(f"mem_map {address:#x} size {size:#x} failed: {exc}") from exc

    def protect_memory(self, address: int, size: int, perms: int) -> None:
        self._check_pages(address, size)
        try:
            self.uc.mem_protect(address, size, self._perms(perms))
        except UcError as exc:
            raise BackendError(f"mem_protect {address:#x} failed: {exc}") from exc

    def write_memory(self, address: int, data: bytes) -> None:
        try:
            self.uc.mem_write(address, bytes(data))
        except UcError as exc:
            raise BackendError(f"mem_write {address:#x} size {len(data)} failed: {exc}") from exc

    def read_memory(self, address: int, size: int) -> bytes:
        try:
            return bytes(self.uc.mem_read(address, size))
        except UcError as exc:
            raise BackendError(f"mem_read {address:#x} size {size} failed: {exc}") from exc

    def read_register(self, name: str) -> int:
        ident = self._ident(name)
        try:
            return self._u32(self.uc.reg_read(ident))
        except UcError as exc:
            raise BackendError(f"cannot read {name}: {exc}") from exc

    def write_register(self, name: str, value: int) -> None:
        ident = self._ident(name)
        try:
            self.uc.reg_write(ident, value & 0xFFFFFFFF)
        except UcError as exc:
            raise BackendError(f"cannot write {name}: {exc}") from exc

    def read_registers(self) -> dict[str, int]:
        values: dict[str, int] = {}
        for name, ident in _REGISTERS:
            try:
                values[name] = self._u32(self.uc.reg_read(ident))
            except UcError:
                logger.debug("unicorn has no readable register %s", name)
        return values

    def write_registers(self, values: dict[str, int]) -> None:
        for name, value in values.items():
            self.write_register(name, value)

    def start(self, pc: int, *, until: int, timeout_us: int, count: int) -> bool:
        # Odd entry address selects Thumb when the CPSR.T bit is clear.
        begin = pc | 1
        try:
            self.uc.emu_start(begin, until, timeout=timeout_us, count=count)
        except UcError as exc:
            raise BackendError(f"unicorn: {exc}", pc=self._safe_pc()) from exc
        try:
            return bool(self.uc.query(UC_QUERY_TIMEOUT))
        except UcError:
            return False

    def stop(self) -> None:
        try:
            self.uc.emu_stop()
        except UcError as exc:
            raise BackendError(f"emu_stop failed: {exc}") from exc

    def hook_code(self, callback) -> None:
        def inner(_uc, address, size, _user) -> None:
            callback(address, size)

        self.uc.hook_add(UC_HOOK_CODE, inner)

    def hook_interrupt(self, callback) -> None:
        def inner(_uc, vector, _user) -> None:
            callback(vector)

        self.uc.hook_add(UC_HOOK_INTR, inner)

    def hook_memory_read(self, callback, start: int, end: int) -> None:
        def inner(_uc, _access, address, size, value, _user) -> None:
            callback(address, size, value)

        self.uc.hook_add(UC_HOOK_MEM_READ, inner, begin=start, end=end)

    def hook_memory_write(self, callback, start: int, end: int) -> None:
        def inner(_uc, _access, address, size, value, _user) -> None:
            callback(address, size, value)

        self.uc.hook_add(UC_HOOK_MEM_WRITE, inner, begin=start, end=end)

    def hook_unmapped(self, callback) -> None:
        def inner(_uc, access, address, size, value, _user) -> bool:
            kind = _UNMAPPED.get(access, f"unmapped_{access}")
            event = MemAccess(kind=kind, address=address, size=size, value=value & 0xFFFFFFFF)
            return bool(callback(event))

        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, inner)

    def inject_irq(self, irq: int) -> None:
        self._check_irq(irq)
        self.nvic.pend_external(irq)
        self._sync_pending_irqs()

    def pend_exception(self, number: int) -> None:
        self.nvic.pend(number)
        self._sync_pending_irqs()

    def service_interrupts(self, address: int, size: int) -> str:
        effect = self.nvic.service(address, size)
        self._sync_pending_irqs()
        if self.nvic.fault:
            self.cpu_fault = self.nvic.fault
        return effect

    def take_svc(self) -> None:
        # Unicorn has already moved PC past the SVC instruction.
        self.nvic.request_exception(EXC_SVCALL, self.read_register("pc") & ~1)
        self._sync_pending_irqs()
        if self.nvic.fault:
            self.cpu_fault = self.nvic.fault

    def prepare_run(self) -> None:
        super().prepare_run()
        self.nvic.fault = None

    def reset_cpu_state(self) -> None:
        self.nvic.reset()
        self._sync_pending_irqs()
        self.cpu_fault = None

    def set_vector_table(self, address: int) -> None:
        self.nvic.vtor = address & 0xFFFFFF80

    def ensure_system_control(self) -> None:
        """Map the SCS page and answer NVIC/SCB accesses from the model."""
        if self._scs_ready:
            return
        try:
            self.uc.mem_map(_SCS_PAGE, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
        except UcError:
            try:
                self.uc.mem_read(_SCS_PAGE, 1)
            except UcError as exc:
                raise BackendError(f"cannot map system control space: {exc}") from exc
        self.hook_memory_read(self._on_scs_read, _SCS_PAGE, _SCS_PAGE + 0xFFF)
        self.hook_memory_write(self._on_scs_write, _SCS_PAGE, _SCS_PAGE + 0xFFF)
        self._scs_ready = True

    def snapshot_cpu_state(self) -> dict:
        return self.nvic.snapshot_state()

    def restore_cpu_state(self, state: dict) -> None:
        self.nvic.restore_state(state or {})
        self._sync_pending_irqs()
        self.cpu_fault = None

    def _on_scs_read(self, address: int, size: int, _value: int) -> None:
        data = self.nvic.io_read(address, size, ipsr=self.read_register("xpsr") & 0x1FF)
        if data is None:
            return
        width = 8 * size
        self.write_memory(address, (data & ((1 << width) - 1)).to_bytes(size, "little"))

    def _on_scs_write(self, address: int, size: int, value: int) -> None:
        if not self.nvic.io_write(address, size, value):
            return
        self._sync_pending_irqs()
        if self.nvic.fault:
            self.cpu_fault = self.nvic.fault
            self.stop()

    def _sync_pending_irqs(self) -> None:
        self.pending_irqs = [
            irq for irq, pending in enumerate(self.nvic.external_pending) if pending
        ]

    def _ident(self, name: str) -> int:
        try:
            return _REG_INDEX[name]
        except KeyError as exc:
            known = ", ".join(name for name, _ident in _REGISTERS)
            raise BackendError(f"unknown register {name!r}; known: {known}") from exc

    def _check_pages(self, address: int, size: int) -> None:
        page = self.page_size
        if address % page or size % page or size <= 0:
            raise BackendError(
                f"mapping address {address:#x} size {size:#x} is not aligned to {page:#x}"
            )

    @staticmethod
    def _perms(perms: int) -> int:
        value = 0
        if perms & PERM_READ:
            value |= UC_PROT_READ
        if perms & PERM_WRITE:
            value |= UC_PROT_WRITE
        if perms & PERM_EXEC:
            value |= UC_PROT_EXEC
        if value == 0:
            raise BackendError("refusing to map a page with empty permissions")
        return value

    def _safe_pc(self) -> int | None:
        try:
            return self._u32(self.uc.reg_read(UC_ARM_REG_PC))
        except UcError:
            return None

    @staticmethod
    def _u32(value: int) -> int:
        return value & 0xFFFFFFFF


class _UnicornCore:
    """Register and memory view the NVIC uses to stack and unstack."""

    def __init__(self, backend: UnicornCortexM) -> None:
        self._backend = backend

    def read_reg(self, name: str) -> int:
        return self._backend.read_register(name)

    def write_reg(self, name: str, value: int) -> None:
        self._backend.write_register(name, value & 0xFFFFFFFF)

    def read_mem(self, address: int, size: int) -> bytes:
        return self._backend.read_memory(address, size)

    def write_mem(self, address: int, data: bytes) -> None:
        self._backend.write_memory(address, data)
