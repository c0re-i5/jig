# SPDX-License-Identifier: MIT
"""Jig, a machine shop for plant-controller firmware.

The import package is still ``rehost``. The researcher supplies the firmware
image. This package supplies the CPU backend interface, config-driven MMIO
plugins, snapshots, and a fuzz harness.
"""

from rehost.backends import available_backends, register_backend
from rehost.errors import (
    AssembleError,
    BackendError,
    ConfigError,
    FuzzInputError,
    MachineError,
    ModbusError,
    RehostError,
    SerialError,
)
from rehost.fuzz import FuzzHarness, PersistentHarness, encode_mmio_script, parse_mmio_script
from rehost.machine import Machine
from rehost.peripherals import Peripheral, available_plugins, register

__version__ = "0.1.0"

__all__ = [
    "AssembleError",
    "BackendError",
    "ConfigError",
    "FuzzHarness",
    "FuzzInputError",
    "Machine",
    "MachineError",
    "ModbusError",
    "Peripheral",
    "PersistentHarness",
    "RehostError",
    "SerialError",
    "__version__",
    "available_backends",
    "available_plugins",
    "encode_mmio_script",
    "parse_mmio_script",
    "register",
    "register_backend",
]
