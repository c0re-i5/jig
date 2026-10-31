# SPDX-License-Identifier: MIT
"""Generic register block.

Each entry in ``registers`` is a 32-bit cell at a 4-byte-aligned offset, with
a reset value and a writable flag. Reads and writes of 1, 2, or 4 bytes merge
into that cell. Offsets that are not listed are logged and return
``read_default`` (writes are ignored). Readonly cells ignore writes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rehost.config import parse_u32
from rehost.errors import ConfigError
from rehost.memory import access_mask
from rehost.peripherals.base import Peripheral, extract_field, insert_field
from rehost.peripherals.registry import register


@dataclass
class _Cell:
    offset: int
    writable: bool
    value: int


@register("register_block")
class RegisterBlock(Peripheral):
    config_keys = frozenset({"read_default", "registers"})

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        raw = self.config.get("registers", {})
        if not isinstance(raw, dict):
            raise ConfigError(f"{self.name} registers must be a mapping of offset to spec")
        self.cells: dict[int, _Cell] = {}
        for key, spec in raw.items():
            offset = parse_u32(key, what=f"{self.name} register offset")
            if isinstance(spec, int) and not isinstance(spec, bool):
                spec = {"reset": spec}
            if not isinstance(spec, dict):
                raise ConfigError(f"{self.name} register {offset:#x} spec must be a mapping or integer")
            unknown = sorted(set(spec) - {"reset", "writable"})
            if unknown:
                raise ConfigError(
                    f"{self.name} register {offset:#x} has unknown field(s): {', '.join(unknown)}"
                )
            reset = parse_u32(spec.get("reset", 0), what=f"{self.name} register {offset:#x} reset")
            writable = spec.get("writable", True)
            if not isinstance(writable, bool):
                raise ConfigError(f"{self.name} register {offset:#x} writable must be true or false")
            self.require_aligned(offset, what=f"register {offset:#x}")
            if offset in self.cells:
                raise ConfigError(f"{self.name} register {offset:#x} is duplicated")
            self.cells[offset] = _Cell(offset=offset, writable=writable, value=reset)

    def read(self, offset: int, size: int) -> int:
        cell = self._cell_for(offset, size)
        if cell is None:
            self.log_unhandled("read", offset, size, None)
            return self.read_default & access_mask(size)
        return extract_field(cell.value, offset, size, cell.offset)

    def write(self, offset: int, size: int, value: int) -> None:
        cell = self._cell_for(offset, size)
        if cell is None:
            self.log_unhandled("write", offset, size, value)
            return
        if not cell.writable:
            return
        cell.value = insert_field(cell.value, offset, size, cell.offset, value) & 0xFFFFFFFF

    def snapshot_state(self) -> dict[str, Any]:
        return {"values": {str(offset): cell.value for offset, cell in self.cells.items()}}

    def restore_state(self, state: dict[str, Any]) -> None:
        values = state["values"]
        for offset, cell in self.cells.items():
            cell.value = int(values[str(offset)]) & 0xFFFFFFFF

    def _cell_for(self, offset: int, size: int) -> _Cell | None:
        for cell in self.cells.values():
            if cell.offset <= offset and offset + size <= cell.offset + 4:
                return cell
        return None
