# SPDX-License-Identifier: MIT
"""CPU backends.

Importing this package registers the Unicorn Cortex-M engine, the QEMU
Cortex-M adapter, the Renode Cortex-M adapter, and the Unicorn RV32 engine.
Cortex-M Unicorn stays the default.
"""

from rehost.backends.base import UNTIL_NEVER, CpuBackend, MemAccess
from rehost.backends.qemu_cortexm import QemuCortexM
from rehost.backends.registry import available_backends, create_backend, register_backend
from rehost.backends.renode_cortexm import RenodeCortexM
from rehost.backends.unicorn_cortexm import BKPT_VECTOR, SVC_VECTOR, UnicornCortexM
from rehost.backends.unicorn_riscv import UnicornRiscv

__all__ = [
    "BKPT_VECTOR",
    "SVC_VECTOR",
    "UNTIL_NEVER",
    "CpuBackend",
    "MemAccess",
    "QemuCortexM",
    "RenodeCortexM",
    "UnicornCortexM",
    "UnicornRiscv",
    "available_backends",
    "create_backend",
    "register_backend",
]
