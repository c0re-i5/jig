# SPDX-License-Identifier: MIT
"""CPU backends. Importing this package registers the Unicorn Cortex-M engine."""

from rehost.backends.base import UNTIL_NEVER, CpuBackend, MemAccess
from rehost.backends.registry import available_backends, create_backend, register_backend
from rehost.backends.unicorn_cortexm import BKPT_VECTOR, SVC_VECTOR, UnicornCortexM

__all__ = [
    "BKPT_VECTOR",
    "SVC_VECTOR",
    "UNTIL_NEVER",
    "CpuBackend",
    "MemAccess",
    "UnicornCortexM",
    "available_backends",
    "create_backend",
    "register_backend",
]
