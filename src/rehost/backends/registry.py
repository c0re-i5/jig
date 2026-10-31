# SPDX-License-Identifier: MIT
"""CPU backend registry, parallel to the peripheral registry."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rehost.errors import ConfigError

if TYPE_CHECKING:
    from rehost.backends.base import CpuBackend

_BACKENDS: dict[str, type[CpuBackend]] = {}

_PLANNED = {
    "qemu",
    "qemu-cortex-m",
    "renode",
    "riscv",
    "riscv32",
}


def register_backend(arch: str):
    """Register ``arch`` as it appears in a machine file's ``arch:`` field."""

    def decorate(cls: type[CpuBackend]) -> type[CpuBackend]:
        existing = _BACKENDS.get(arch)
        if existing is not None and existing is not cls:
            raise ConfigError(f"backend {arch!r} is already registered")
        _BACKENDS[arch] = cls
        return cls

    return decorate


def available_backends() -> list[str]:
    return sorted(_BACKENDS)


def create_backend(arch: str) -> CpuBackend:
    try:
        cls = _BACKENDS[arch]
    except KeyError as exc:
        known = ", ".join(available_backends()) or "(none)"
        hint = ""
        if arch in _PLANNED:
            hint = " That backend is a planned adapter behind CpuBackend; it is not implemented."
        raise ConfigError(f"unknown arch {arch!r}. Available: {known}.{hint}") from exc
    return cls()
