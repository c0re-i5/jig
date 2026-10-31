# SPDX-License-Identifier: MIT
"""Memory map: named regions, permission flags, and page spans.

The map is firmware-agnostic. Addresses come from the researcher's machine
config; nothing here embeds a vendor layout.
"""

from __future__ import annotations

from dataclasses import dataclass

from rehost.errors import ConfigError

PERM_READ = 1
PERM_WRITE = 2
PERM_EXEC = 4

PAGE_SIZE = 0x1000


def parse_perms(text: str) -> int:
    """Turn ``rwx`` text into permission bits."""
    if not isinstance(text, str) or not text:
        raise ConfigError("perms must be a string such as 'rw' or 'rx'")
    unknown = sorted(set(text) - set("rwx"))
    if unknown:
        raise ConfigError(f"perms {text!r} has unknown flag(s): {''.join(unknown)}")
    value = 0
    if "r" in text:
        value |= PERM_READ
    if "w" in text:
        value |= PERM_WRITE
    if "x" in text:
        value |= PERM_EXEC
    if value == 0:
        raise ConfigError("perms must include at least one of r, w, x")
    return value


def format_perms(value: int) -> str:
    parts = []
    if value & PERM_READ:
        parts.append("r")
    if value & PERM_WRITE:
        parts.append("w")
    if value & PERM_EXEC:
        parts.append("x")
    return "".join(parts)


def pages_touched(base: int, size: int, page_size: int = PAGE_SIZE) -> list[int]:
    """Page-aligned starts covered by ``[base, base + size)``."""
    if size <= 0:
        return []
    if page_size <= 0 or page_size & (page_size - 1):
        raise ConfigError(f"page size {page_size:#x} is not a power of two")
    start = base & ~(page_size - 1)
    end_addr = base + size
    end_page = (end_addr + page_size - 1) & ~(page_size - 1)
    return list(range(start, end_page, page_size))


def access_mask(size: int) -> int:
    if size not in (1, 2, 4):
        raise ConfigError(f"access size must be 1, 2, or 4 bytes, not {size}")
    return (1 << (8 * size)) - 1


@dataclass
class Region:
    """One contiguous mapping. ``peripheral`` is filled in when the machine is built."""

    name: str
    base: int
    size: int
    perms: int
    peripheral: object | None = None
    save: bool = False

    @property
    def end(self) -> int:
        return self.base + self.size

    def contains(self, address: int) -> bool:
        return self.base <= address < self.end

    def contains_access(self, address: int, size: int) -> bool:
        return size >= 0 and self.base <= address and address + size <= self.end


class MemoryMap:
    """Non-overlapping regions, kept in address order for lookup."""

    def __init__(self, regions: list[Region]) -> None:
        names = [region.name for region in regions]
        if len(names) != len(set(names)):
            raise ConfigError("memory region names must be unique")
        self.regions = sorted(regions, key=lambda region: (region.base, region.name))
        self._check_overlap()

    def _check_overlap(self) -> None:
        for prev, nxt in zip(self.regions, self.regions[1:]):
            if prev.end > nxt.base:
                raise ConfigError(
                    f"memory regions {prev.name!r} [{prev.base:#x}, {prev.end:#x}) "
                    f"and {nxt.name!r} [{nxt.base:#x}, {nxt.end:#x}) overlap"
                )

    def region_at(self, address: int) -> Region | None:
        for region in self.regions:
            if region.contains(address):
                return region
            if region.base > address:
                break
        return None

    def regions_covering(self, address: int, size: int) -> list[Region]:
        """Regions that together cover ``[address, address + size)``.

        Raises:
            MachineError: a gap or an unmapped address is in the span.
        """
        from rehost.errors import MachineError

        if size < 0:
            raise MachineError("negative memory span")
        if size == 0:
            return []
        end = address + size
        cursor = address
        found: list[Region] = []
        while cursor < end:
            region = self.region_at(cursor)
            if region is None:
                raise MachineError(f"address {cursor:#x} is outside the memory map")
            found.append(region)
            nxt = min(end, region.end)
            if nxt <= cursor:
                raise MachineError(f"region {region.name!r} does not advance the walk")
            cursor = nxt
        return found

    def savable(self) -> list[Region]:
        return [region for region in self.regions if region.save]

    def get(self, name: str) -> Region:
        for region in self.regions:
            if region.name == name:
                return region
        raise KeyError(name)
