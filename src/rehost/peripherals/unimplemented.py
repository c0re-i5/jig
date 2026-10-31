# SPDX-License-Identifier: MIT
"""MMIO that has no model yet.

Reads log once and return ``read_default``. Writes log once and are ignored.
Use it for a spare window, or set ``mmio: true`` on a region with no
``peripheral`` (the loader selects this plugin).
"""

from __future__ import annotations

from typing import Any

from rehost.memory import access_mask
from rehost.peripherals.base import Peripheral
from rehost.peripherals.registry import register


@register("unimplemented")
class Unimplemented(Peripheral):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.reads = 0
        self.writes = 0

    def read(self, offset: int, size: int) -> int:
        self.reads += 1
        self.log_unhandled("read", offset, size, None)
        return self.read_default & access_mask(size)

    def write(self, offset: int, size: int, value: int) -> None:
        self.writes += 1
        self.log_unhandled("write", offset, size, value)

    def snapshot_state(self) -> dict[str, Any]:
        return {"reads": self.reads, "writes": self.writes}

    def restore_state(self, state: dict[str, Any]) -> None:
        self.reads = int(state["reads"])
        self.writes = int(state["writes"])

    def debug_lines(self) -> list[str]:
        return [f"{self.name} unhandled: {self.reads} read(s), {self.writes} write(s)"]
