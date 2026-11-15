# SPDX-License-Identifier: MIT
"""Generic register block.

Each entry in ``registers`` is a 32-bit cell at a 4-byte-aligned offset, with
a reset value and a writable flag. Reads and writes of 1, 2, or 4 bytes merge
into that cell. Offsets that are not listed are logged and return
``read_default`` (writes are ignored). Readonly cells ignore writes.

Optional read-time overlays model status bits without a new peripheral.
They are config, not snapshot state, so a fuzz restore cannot clear them by
replaying a write of zero. A read is built in this order:

1. ``follow`` copies bits onto this word, in list order. Each entry is
   ``{src, dst, width}`` (``width`` defaults to 1). The source is a stored
   value, so a ready bit clears when its enable bit clears. ``from`` names
   another register in this block; omitted, the source is this register.
   ``value`` with ``src_width`` (default 1) is an override: a non-zero source
   field writes that constant into the destination, and a zero source leaves
   the destination as earlier rules left it. Plain copies must not overlap
   each other. A ``value`` rule may overlap an earlier destination.
2. ``read_set`` is ORed in, which forces those bits high on every read.
3. ``read_mask`` / ``read_bits`` then replace those bits (``read_bits`` must
   be a subset of ``read_mask``). ``read_mask`` wins where it overlaps the
   earlier overlays.

``follow`` is the HAL clock-tree case: HSERDY tracks HSEON, and a multi-bit
field such as SWS can track SW. ``from`` is the same idea when the enable and
the ready bit are in different registers. ``value`` covers a status field
that takes one encoding when an enable is set and otherwise keeps the copy
from an earlier rule. ``read_set`` remains the "stuck ready" stub.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rehost.config import parse_int, parse_u32
from rehost.errors import ConfigError
from rehost.memory import access_mask
from rehost.peripherals.base import Peripheral, extract_field, insert_field
from rehost.peripherals.registry import register


@dataclass(frozen=True)
class _Follow:
    src: int
    dst: int
    width: int
    from_offset: int | None = None
    value: int | None = None
    src_width: int = 1


@dataclass
class _Cell:
    offset: int
    writable: bool
    value: int
    read_set: int
    read_mask: int
    read_bits: int
    follow: tuple[_Follow, ...]


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
            unknown = sorted(
                set(spec) - {"reset", "writable", "read_set", "read_mask", "read_bits", "follow"}
            )
            if unknown:
                raise ConfigError(
                    f"{self.name} register {offset:#x} has unknown field(s): {', '.join(unknown)}"
                )
            reset = parse_u32(spec.get("reset", 0), what=f"{self.name} register {offset:#x} reset")
            writable = spec.get("writable", True)
            if not isinstance(writable, bool):
                raise ConfigError(f"{self.name} register {offset:#x} writable must be true or false")
            read_set = parse_u32(
                spec.get("read_set", 0), what=f"{self.name} register {offset:#x} read_set"
            )
            if "read_bits" in spec and "read_mask" not in spec:
                raise ConfigError(
                    f"{self.name} register {offset:#x} read_bits requires read_mask"
                )
            read_mask = parse_u32(
                spec.get("read_mask", 0), what=f"{self.name} register {offset:#x} read_mask"
            )
            read_bits = parse_u32(
                spec.get("read_bits", 0), what=f"{self.name} register {offset:#x} read_bits"
            )
            if read_bits & ~read_mask:
                raise ConfigError(
                    f"{self.name} register {offset:#x} read_bits must be a subset of read_mask"
                )
            follow = _parse_follow(self.name, offset, spec.get("follow", []))
            self.require_aligned(offset, what=f"register {offset:#x}")
            if offset in self.cells:
                raise ConfigError(f"{self.name} register {offset:#x} is duplicated")
            self.cells[offset] = _Cell(
                offset=offset,
                writable=writable,
                value=reset,
                read_set=read_set,
                read_mask=read_mask,
                read_bits=read_bits,
                follow=follow,
            )
        for cell in self.cells.values():
            for rule in cell.follow:
                if rule.from_offset is None or rule.from_offset in self.cells:
                    continue
                raise ConfigError(
                    f"{self.name} register {cell.offset:#x} follow source "
                    f"{rule.from_offset:#x} is not a register in this block"
                )

    def read(self, offset: int, size: int) -> int:
        cell = self._cell_for(offset, size)
        if cell is None:
            self.log_unhandled("read", offset, size, None)
            return self.read_default & access_mask(size)
        return extract_field(self._shown(cell), offset, size, cell.offset)

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

    def _shown(self, cell: _Cell) -> int:
        value = self._apply_follow(cell)
        value = (value | cell.read_set) & 0xFFFFFFFF
        if cell.read_mask:
            value = (value & ~cell.read_mask) | cell.read_bits
        return value & 0xFFFFFFFF

    def _apply_follow(self, cell: _Cell) -> int:
        """Apply follow rules in order. Sources are stored values, not overlays."""
        updated = cell.value & 0xFFFFFFFF
        for rule in cell.follow:
            source_cell = cell if rule.from_offset is None else self.cells[rule.from_offset]
            field = (source_cell.value >> rule.src) & ((1 << rule.src_width) - 1)
            if rule.value is None:
                written = field
            elif field == 0:
                continue
            else:
                written = rule.value
            dst_mask = ((1 << rule.width) - 1) << rule.dst
            updated = (updated & ~dst_mask) | ((written & ((1 << rule.width) - 1)) << rule.dst)
        return updated & 0xFFFFFFFF

    def _cell_for(self, offset: int, size: int) -> _Cell | None:
        for cell in self.cells.values():
            if cell.offset <= offset and offset + size <= cell.offset + 4:
                return cell
        return None


def _parse_follow(name: str, offset: int, raw: Any) -> tuple[_Follow, ...]:
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise ConfigError(f"{name} register {offset:#x} follow must be a list of {{src, dst, width}}")
    rules: list[_Follow] = []
    covered = 0
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ConfigError(f"{name} register {offset:#x} follow[{index}] must be a mapping")
        unknown = sorted(set(item) - {"src", "dst", "width", "from", "value", "src_width"})
        if unknown:
            raise ConfigError(
                f"{name} register {offset:#x} follow[{index}] has unknown field(s): {', '.join(unknown)}"
            )
        what = f"{name} register {offset:#x} follow[{index}]"
        if "src" not in item or "dst" not in item:
            raise ConfigError(f"{what} requires src and dst")
        src = _parse_bit(item["src"], f"{what} src")
        dst = _parse_bit(item["dst"], f"{what} dst")
        width = 1 if "width" not in item else parse_int(item["width"], what=f"{what} width")
        if "value" in item and "src_width" not in item:
            src_width = 1
        elif "src_width" in item:
            src_width = parse_int(item["src_width"], what=f"{what} src_width")
        else:
            src_width = width
        if "src_width" in item and "value" not in item:
            raise ConfigError(f"{what} src_width is only used with value")
        value = None if "value" not in item else parse_u32(item["value"], what=f"{what} value")
        from_offset = None
        if "from" in item:
            from_offset = parse_u32(item["from"], what=f"{what} from")
            if from_offset % 4 != 0:
                raise ConfigError(f"{what} from {from_offset:#x} must be 4-byte aligned")
        if width < 1 or src_width < 1 or src + src_width > 32 or dst + width > 32:
            raise ConfigError(
                f"{what} width {width} src_width {src_width} does not fit at src {src} dst {dst}"
            )
        if value is not None and value >= (1 << width):
            raise ConfigError(f"{what} value {value:#x} does not fit in {width} destination bits")
        mask = ((1 << width) - 1) << dst
        if covered & mask and value is None:
            raise ConfigError(f"{name} register {offset:#x} follow destination bits overlap")
        covered |= mask
        rules.append(
            _Follow(
                src=src,
                dst=dst,
                width=width,
                from_offset=from_offset,
                value=value,
                src_width=src_width,
            )
        )
    return tuple(rules)


def _parse_bit(value: Any, what: str) -> int:
    number = parse_int(value, what=what)
    if not 0 <= number <= 31:
        raise ConfigError(f"{what} must be a bit number from 0 to 31")
    return number
