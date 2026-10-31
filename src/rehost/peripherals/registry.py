# SPDX-License-Identifier: MIT
"""Name → peripheral class registry.

Plugins register at import time. A machine file names the class; the machine
constructs it. Users add a device without editing the dispatcher:

.. code-block:: python

    from rehost.peripherals import Peripheral, register

    @register("led_bank")
    class LedBank(Peripheral):
        def read(self, offset: int, size: int) -> int:
            return 0

        def write(self, offset: int, size: int, value: int) -> None:
            self.last = value
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rehost.errors import ConfigError

if TYPE_CHECKING:
    from rehost.peripherals.base import Peripheral

_REGISTRY: dict[str, type[Peripheral]] = {}


def register(name: str):
    """Register ``name`` as it appears in a machine file's ``peripheral:`` field."""

    def decorate(cls: type[Peripheral]) -> type[Peripheral]:
        if not name or not name.replace("_", "").isalnum():
            raise ConfigError(f"peripheral plugin name {name!r} is not an identifier")
        existing = _REGISTRY.get(name)
        if existing is not None and existing is not cls:
            raise ConfigError(f"peripheral {name!r} is already registered")
        _REGISTRY[name] = cls
        cls.plugin_name = name
        return cls

    return decorate


def available_plugins() -> list[str]:
    return sorted(_REGISTRY)


def create_peripheral(kind: str, **kwargs: object) -> Peripheral:
    try:
        cls = _REGISTRY[kind]
    except KeyError as exc:
        known = ", ".join(available_plugins()) or "(none)"
        raise ConfigError(f"unknown peripheral {kind!r}. Registered plugins: {known}") from exc
    return cls(**kwargs)
