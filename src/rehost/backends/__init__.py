# SPDX-License-Identifier: MIT
"""CPU backends.

Importing this package registers the Unicorn Cortex-M engine, the QEMU
Cortex-M adapter, and the Renode Cortex-M adapter. RISC-V is still a name
in the planned set.
"""

from rehost.backends.base import UNTIL_NEVER, CpuBackend, MemAccess
from rehost.backends.qemu_cortexm import QemuCortexM
from rehost.backends.registry import available_backends, create_backend, register_backend
from rehost.backends.renode_cortexm import RenodeCortexM
from rehost.backends.unicorn_cortexm import BKPT_VECTOR, SVC_VECTOR, UnicornCortexM

__all__ = [
    "BKPT_VECTOR",
    "SVC_VECTOR",
    "UNTIL_NEVER",
    "CpuBackend",
    "MemAccess",
    "QemuCortexM",
    "RenodeCortexM",
    "UnicornCortexM",
    "available_backends",
    "create_backend",
    "register_backend",
]
