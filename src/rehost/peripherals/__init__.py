# SPDX-License-Identifier: MIT
"""Built-in MMIO plugins and the registry used to add more."""

from rehost.peripherals.base import Peripheral
from rehost.peripherals.gpio import Gpio
from rehost.peripherals.register_block import RegisterBlock
from rehost.peripherals.registry import available_plugins, create_peripheral, register
from rehost.peripherals.systick import SysTick
from rehost.peripherals.uart import Uart
from rehost.peripherals.unimplemented import Unimplemented

__all__ = [
    "Gpio",
    "Peripheral",
    "RegisterBlock",
    "SysTick",
    "Uart",
    "Unimplemented",
    "available_plugins",
    "create_peripheral",
    "register",
]
