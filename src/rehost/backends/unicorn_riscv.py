# SPDX-License-Identifier: MIT
"""Unicorn Engine backend for RV32.

The CPU is Unicorn's RISC-V32 engine (``UC_ARCH_RISCV`` + ``UC_MODE_RISCV32``).
This module maps the ``CpuBackend`` interface onto it: page mapping, register
names, and hooks. Peripheral behavior stays in the plugins.

``EBREAK`` is the breakpoint. Unicorn 2.1 reports that opcode as an invalid
instruction rather than an interrupt, so the code hook recognizes the
encoding ``0x00100073`` and delivers it as vector 7, the same breakpoint
vector the Cortex-M backend uses for ``BKPT``. Halt addresses, the
instruction cap, and memory faults stay on the hooks ``Machine`` already
installs.

There is no CLINT, PLIC, or NVIC. ``inject_irq`` only records the number.
"""

from __future__ import annotations

import logging

from unicorn import (
    UC_ARCH_RISCV,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
    UC_HOOK_MEM_PROT,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_UNMAPPED,
    UC_HOOK_MEM_WRITE,
    UC_MODE_LITTLE_ENDIAN,
    UC_MODE_RISCV32,
    UC_PROT_EXEC,
    UC_PROT_READ,
    UC_PROT_WRITE,
    UC_QUERY_TIMEOUT,
    Uc,
    UcError,
)
from unicorn.riscv_const import (
    UC_RISCV_REG_A0,
    UC_RISCV_REG_A1,
    UC_RISCV_REG_A2,
    UC_RISCV_REG_A3,
    UC_RISCV_REG_A4,
    UC_RISCV_REG_A5,
    UC_RISCV_REG_A6,
    UC_RISCV_REG_A7,
    UC_RISCV_REG_GP,
    UC_RISCV_REG_PC,
    UC_RISCV_REG_RA,
    UC_RISCV_REG_S0,
    UC_RISCV_REG_S1,
    UC_RISCV_REG_S10,
    UC_RISCV_REG_S11,
    UC_RISCV_REG_S2,
    UC_RISCV_REG_S3,
    UC_RISCV_REG_S4,
    UC_RISCV_REG_S5,
    UC_RISCV_REG_S6,
    UC_RISCV_REG_S7,
    UC_RISCV_REG_S8,
    UC_RISCV_REG_S9,
    UC_RISCV_REG_SP,
    UC_RISCV_REG_T0,
    UC_RISCV_REG_T1,
    UC_RISCV_REG_T2,
    UC_RISCV_REG_T3,
    UC_RISCV_REG_T4,
    UC_RISCV_REG_T5,
    UC_RISCV_REG_T6,
    UC_RISCV_REG_TP,
    UC_RISCV_REG_X0,
)
from unicorn.unicorn_const import (
    UC_MEM_FETCH_PROT,
    UC_MEM_FETCH_UNMAPPED,
    UC_MEM_READ_PROT,
    UC_MEM_READ_UNMAPPED,
    UC_MEM_WRITE_PROT,
    UC_MEM_WRITE_UNMAPPED,
)

from rehost.backends.base import CpuBackend, MemAccess
from rehost.backends.registry import register_backend
from rehost.backends.unicorn_cortexm import BKPT_VECTOR
from rehost.errors import BackendError
from rehost.memory import PERM_EXEC, PERM_READ, PERM_WRITE

logger = logging.getLogger(__name__)

# RV32 ``EBREAK``: ``SYSTEM`` funct3=0, imm 1. Unicorn 2.1 does not raise
# this through ``UC_HOOK_INTR``; the code hook matches the word instead.
EBREAK_WORD = 0x00100073

# RISC-V exception codes. Breakpoint is rewritten to ``BKPT_VECTOR`` so
# ``halt_on_bkpt`` applies. The others must not be forwarded raw: code 2 is
# the ARM SVC vector and code 7 is the ARM BKPT vector.
_EXCP_BREAKPOINT = 3
_RISCV_EXCEPTIONS = {
    0: "instruction address misaligned",
    1: "instruction access fault",
    2: "illegal instruction",
    3: "breakpoint",
    4: "load address misaligned",
    5: "load access fault",
    6: "store address misaligned",
    7: "store access fault",
    8: "environment call from U-mode",
    9: "environment call from S-mode",
    11: "environment call from M-mode",
}

# One name per architectural register, in ABI order. ``xN`` and ``fp`` are
# accepted by read/write and are not repeated here.
_REGISTERS: tuple[tuple[str, int], ...] = (
    ("zero", UC_RISCV_REG_X0),
    ("ra", UC_RISCV_REG_RA),
    ("sp", UC_RISCV_REG_SP),
    ("gp", UC_RISCV_REG_GP),
    ("tp", UC_RISCV_REG_TP),
    ("t0", UC_RISCV_REG_T0),
    ("t1", UC_RISCV_REG_T1),
    ("t2", UC_RISCV_REG_T2),
    ("s0", UC_RISCV_REG_S0),
    ("s1", UC_RISCV_REG_S1),
    ("a0", UC_RISCV_REG_A0),
    ("a1", UC_RISCV_REG_A1),
    ("a2", UC_RISCV_REG_A2),
    ("a3", UC_RISCV_REG_A3),
    ("a4", UC_RISCV_REG_A4),
    ("a5", UC_RISCV_REG_A5),
    ("a6", UC_RISCV_REG_A6),
    ("a7", UC_RISCV_REG_A7),
    ("s2", UC_RISCV_REG_S2),
    ("s3", UC_RISCV_REG_S3),
    ("s4", UC_RISCV_REG_S4),
    ("s5", UC_RISCV_REG_S5),
    ("s6", UC_RISCV_REG_S6),
    ("s7", UC_RISCV_REG_S7),
    ("s8", UC_RISCV_REG_S8),
    ("s9", UC_RISCV_REG_S9),
    ("s10", UC_RISCV_REG_S10),
    ("s11", UC_RISCV_REG_S11),
    ("t3", UC_RISCV_REG_T3),
    ("t4", UC_RISCV_REG_T4),
    ("t5", UC_RISCV_REG_T5),
    ("t6", UC_RISCV_REG_T6),
    ("pc", UC_RISCV_REG_PC),
)
_REG_INDEX = {name: ident for name, ident in _REGISTERS}
_REG_INDEX["fp"] = UC_RISCV_REG_S0
# x0..x31 share the unicorn ids stored under the ABI names.
_XN = {
    0: "zero",
    1: "ra",
    2: "sp",
    3: "gp",
    4: "tp",
    5: "t0",
    6: "t1",
    7: "t2",
    8: "s0",
    9: "s1",
    10: "a0",
    11: "a1",
    12: "a2",
    13: "a3",
    14: "a4",
    15: "a5",
    16: "a6",
    17: "a7",
    18: "s2",
    19: "s3",
    20: "s4",
    21: "s5",
    22: "s6",
    23: "s7",
    24: "s8",
    25: "s9",
    26: "s10",
    27: "s11",
    28: "t3",
    29: "t4",
    30: "t5",
    31: "t6",
}
for _number, _abi in _XN.items():
    _REG_INDEX[f"x{_number}"] = _REG_INDEX[_abi]

_ZERO_NAMES = frozenset({"zero", "x0"})

_UNMAPPED = {
    UC_MEM_READ_UNMAPPED: "read_unmapped",
    UC_MEM_WRITE_UNMAPPED: "write_unmapped",
    UC_MEM_FETCH_UNMAPPED: "fetch_unmapped",
}
_PROT = {
    UC_MEM_READ_PROT: "read_prot",
    UC_MEM_WRITE_PROT: "write_prot",
    UC_MEM_FETCH_PROT: "fetch_prot",
}


@register_backend("riscv")
@register_backend("riscv32")
class UnicornRiscv(CpuBackend):
    """RV32 via ``UC_ARCH_RISCV`` + ``UC_MODE_RISCV32``.

    Unicorn Cortex-M stays the default (``arch: cortex-m``). Select this
    backend with ``--backend riscv`` or with ``arch: riscv`` /
    ``arch: riscv32``. ``boot_isa`` tells ``Machine`` to load ``sp`` and
    ``pc`` from ``boot.mode: entry`` instead of a Cortex-M vector table.
    """

    arch = "riscv"
    boot_isa = "rv32"
    # CmpLog decodes Thumb. The campaign and the forkserver stay on Cortex-M.
    supports_fuzz = False

    def __init__(self) -> None:
        super().__init__()
        # Same microsecond timeout convention as the Cortex-M Unicorn engine.
        self.uc = Uc(UC_ARCH_RISCV, UC_MODE_RISCV32 | UC_MODE_LITTLE_ENDIAN)
        self._intr_callback = None

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
        if name in _ZERO_NAMES:
            # x0 is hardwired zero. A raw Unicorn reg_write can stick until
            # the next instruction; the architectural read is always 0.
            return 0
        ident = self._ident(name)
        try:
            return self._u32(self.uc.reg_read(ident))
        except UcError as exc:
            raise BackendError(f"cannot read {name}: {exc}") from exc

    def write_register(self, name: str, value: int) -> None:
        ident = self._ident(name)
        stored = 0 if name in _ZERO_NAMES else value & 0xFFFFFFFF
        try:
            self.uc.reg_write(ident, stored)
        except UcError as exc:
            raise BackendError(f"cannot write {name}: {exc}") from exc

    def read_registers(self) -> dict[str, int]:
        values: dict[str, int] = {}
        for name, ident in _REGISTERS:
            if name in _ZERO_NAMES:
                values[name] = 0
                continue
            try:
                values[name] = self._u32(self.uc.reg_read(ident))
            except UcError:
                logger.debug("unicorn has no readable register %s", name)
        return values

    def write_registers(self, values: dict[str, int]) -> None:
        for name, value in values.items():
            self.write_register(name, value)

    def start(self, pc: int, *, until: int, timeout_us: int, count: int) -> bool:
        # RV32 has no Thumb bit. The address is used as written.
        begin = pc & 0xFFFFFFFF
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
            # After the machine has counted this instruction (or stopped for
            # a halt address / cap). EBREAK never retires: Unicorn treats
            # the encoding as an invalid instruction.
            if self._intr_callback is not None and self._is_ebreak(address, size):
                self._intr_callback(BKPT_VECTOR)

        self.uc.hook_add(UC_HOOK_CODE, inner)

    def hook_interrupt(self, callback) -> None:
        self._intr_callback = callback

        def inner(_uc, vector, _user) -> None:
            self._deliver_exception(vector)

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

    def hook_prot(self, callback) -> None:
        def inner(_uc, access, address, size, value, _user) -> bool:
            kind = _PROT.get(access, f"prot_{access}")
            event = MemAccess(kind=kind, address=address, size=size, value=value & 0xFFFFFFFF)
            return bool(callback(event))

        self.uc.hook_add(UC_HOOK_MEM_PROT, inner)

    def _deliver_exception(self, vector: int) -> None:
        callback = self._intr_callback
        if callback is None:
            return
        if vector == _EXCP_BREAKPOINT:
            callback(BKPT_VECTOR)
            return
        label = _RISCV_EXCEPTIONS.get(vector, "exception")
        self.cpu_fault = f"riscv {label} ({vector})"
        # 0x20 + code is neither the BKPT vector (7) nor the SVC vector (2).
        callback(0x20 + (vector & 0xFF))

    def _is_ebreak(self, address: int, size: int) -> bool:
        if size != 4:
            return False
        try:
            word = int.from_bytes(self.read_memory(address, 4), "little")
        except BackendError:
            return False
        return word == EBREAK_WORD

    def _ident(self, name: str) -> int:
        try:
            return _REG_INDEX[name]
        except KeyError as exc:
            known = ", ".join(name for name, _ident in _REGISTERS)
            raise BackendError(
                f"unknown register {name!r}; known: {known} (and x0-x31, fp)"
            ) from exc

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
            return self._u32(self.uc.reg_read(UC_RISCV_REG_PC))
        except UcError:
            return None

    @staticmethod
    def _u32(value: int) -> int:
        return value & 0xFFFFFFFF
