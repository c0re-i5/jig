# SPDX-License-Identifier: MIT
"""CPU backend interface.

``UnicornCortexM`` is the first implementation. A QEMU system adapter or a
Renode adapter should implement the same methods so ``Machine`` does not grow
a second control path. The backend does not know about YAML, plugins, or
fuzz input.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

# Until-address that a 32-bit PC cannot equal. Passing 0 makes Unicorn stop
# immediately when the reset vector lives at address 0.
UNTIL_NEVER = 0x1_0000_0000


@dataclass(frozen=True)
class MemAccess:
    """Guest memory event, already translated out of backend-specific enums."""

    kind: str
    address: int
    size: int
    value: int


class CpuBackend(ABC):
    """Operations ``Machine`` needs from any CPU engine.

    Planned adapters (not implemented): ``qemu-cortex-m``, ``renode``, and a
    RISC-V engine. ``inject_irq`` is part of the contract even when the engine
    cannot deliver the interrupt yet.
    """

    arch: str
    page_size: int = 0x1000

    def __init__(self) -> None:
        self.pending_irqs: list[int] = []

    @abstractmethod
    def map_memory(self, address: int, size: int, perms: int) -> None:
        """Map ``size`` bytes at ``address``. Both must be page aligned."""

    @abstractmethod
    def protect_memory(self, address: int, size: int, perms: int) -> None:
        """Replace permissions on an existing mapping."""

    @abstractmethod
    def write_memory(self, address: int, data: bytes) -> None:
        """Write guest memory. Does not invoke guest MMIO callbacks."""

    @abstractmethod
    def read_memory(self, address: int, size: int) -> bytes:
        """Read guest memory. Does not invoke guest MMIO callbacks."""

    @abstractmethod
    def read_register(self, name: str) -> int:
        """Read one architectural register by the name used in snapshots."""

    @abstractmethod
    def write_register(self, name: str, value: int) -> None:
        """Write one architectural register."""

    @abstractmethod
    def read_registers(self) -> dict[str, int]:
        """Read the snapshot register set. Missing engine registers are omitted."""

    @abstractmethod
    def write_registers(self, values: dict[str, int]) -> None:
        """Restore registers previously returned by ``read_registers``."""

    @abstractmethod
    def start(self, pc: int, *, until: int, timeout_us: int, count: int) -> bool:
        """Execute from ``pc``.

        Returns True when the engine stopped because ``timeout_us`` elapsed.
        ``timeout_us`` is microseconds; 0 means no time limit. ``count`` is an
        instruction cap; 0 means no cap. Thumb backends set the ISA bit.
        """

    @abstractmethod
    def stop(self) -> None:
        """Stop the current ``start`` from inside a hook."""

    @abstractmethod
    def hook_code(self, callback) -> None:
        """Call ``callback(address, size)`` before each instruction."""

    @abstractmethod
    def hook_interrupt(self, callback) -> None:
        """Call ``callback(vector)`` on a CPU exception. Vector 7 is BKPT."""

    @abstractmethod
    def hook_memory_read(self, callback, start: int, end: int) -> None:
        """Call ``callback(address, size, value)`` on reads in ``[start, end]``.

        ``end`` is inclusive. On Unicorn 2 the callback runs before the load
        retires, so writing the address updates the value the instruction sees.
        """

    @abstractmethod
    def hook_memory_write(self, callback, start: int, end: int) -> None:
        """Call ``callback(address, size, value)`` on writes in ``[start, end]``."""

    @abstractmethod
    def hook_unmapped(self, callback) -> None:
        """Call ``callback(access) -> bool``. True asks the engine to retry."""

    def inject_irq(self, irq: int) -> None:
        """Queue an interrupt request.

        The Unicorn Cortex-M backend records the request and does not deliver
        it through NVIC. A future backend can override this and take the IRQ.
        """
        if not isinstance(irq, int) or isinstance(irq, bool) or not 0 <= irq <= 255:
            raise ValueError(f"irq must be an integer from 0 to 255, not {irq!r}")
        self.pending_irqs.append(irq)
