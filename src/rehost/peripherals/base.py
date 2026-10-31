# SPDX-License-Identifier: MIT
"""Peripheral plugin contract.

A plugin owns the registers behind one memory region. The machine calls
``read`` and ``write`` with offsets from the region base. Sizes are 1, 2, or
4 bytes. Snapshot methods return plain data so they can be restored after a
fuzz iteration or written to JSON.
"""

from __future__ import annotations

import logging
from typing import Any

from rehost.errors import ConfigError
from rehost.memory import access_mask

logger = logging.getLogger(__name__)


def extract_field(word: int, offset: int, size: int, word_offset: int) -> int:
    shift = 8 * (offset - word_offset)
    return (word >> shift) & access_mask(size)


def insert_field(word: int, offset: int, size: int, word_offset: int, value: int) -> int:
    shift = 8 * (offset - word_offset)
    field = access_mask(size) << shift
    return (word & ~field) | ((value & access_mask(size)) << shift)


class Peripheral:
    """Base class. Subclasses override ``read`` and ``write``."""

    plugin_name: str = ""
    config_keys: frozenset[str] = frozenset({"read_default"})

    def __init__(
        self,
        *,
        name: str,
        base: int,
        size: int,
        config: dict[str, Any] | None = None,
        read_default: int = 0,
    ) -> None:
        self.name = name
        self.base = base
        self.size = size
        self.config = dict(config or {})
        unknown = sorted(set(self.config) - set(self.config_keys))
        if unknown:
            kind = self.plugin_name or self.__class__.__name__
            raise ConfigError(
                f"peripheral {kind} on region {name} does not accept config field(s): "
                + ", ".join(unknown)
            )
        if "read_default" in self.config:
            self.read_default = int(self.config["read_default"])
        else:
            self.read_default = int(read_default)
        self._logged: set[tuple[str, int, int]] = set()

    def read(self, offset: int, size: int) -> int:
        self.log_unhandled("read", offset, size, None)
        return self.read_default & access_mask(size)

    def write(self, offset: int, size: int, value: int) -> None:
        self.log_unhandled("write", offset, size, value)

    def snapshot_state(self) -> dict[str, Any]:
        return {}

    def restore_state(self, state: dict[str, Any]) -> None:
        return None

    def debug_lines(self) -> list[str]:
        return []

    def require_aligned(self, offset: int, *, what: str) -> None:
        if offset % 4 != 0:
            raise ConfigError(f"{self.name} {what} offset {offset:#x} must be 4-byte aligned")
        if offset < 0 or offset + 4 > self.size:
            raise ConfigError(
                f"{self.name} {what} at {offset:#x} does not fit in a {self.size:#x}-byte region"
            )

    def log_unhandled(self, kind: str, offset: int, size: int, value: int | None) -> None:
        """Log an unimplemented access once at INFO, then at DEBUG."""
        key = (kind, offset, size)
        address = self.base + offset
        if kind == "read":
            message = (
                "unhandled MMIO read %s+%#x (%#x) size %d; returning default %#x"
            )
            args = (self.name, offset, address, size, self.read_default)
        else:
            message = "unhandled MMIO write %s+%#x (%#x) size %d value %s; ignored"
            args = (self.name, offset, address, size, None if value is None else hex(value))
        if key in self._logged:
            logger.debug(message, *args)
        else:
            self._logged.add(key)
            logger.info(message, *args)
