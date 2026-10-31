# SPDX-License-Identifier: MIT
"""Cortex-M SysTick stub at the standard offsets (CTRL, LOAD, VAL, CALIB).

This is a functional model for firmware that polls ``VAL``, not a cycle timer.
While ``ENABLE`` is set, each read of ``VAL`` returns the current count and
then decrements it. A read that observes 0 reloads from ``LOAD``, sets
``COUNTFLAG``, and if ``TICKINT`` is set records ``irq_pending``. Nothing
delivers that interrupt: NVIC injection is a separate extension point
(``Machine.inject_irq`` only queues the request on the Unicorn backend).

A write to ``VAL`` clears it, matching the architecture. ``CALIB`` is read-only.
"""

from __future__ import annotations

from typing import Any

from rehost.config import parse_u32
from rehost.memory import access_mask
from rehost.peripherals.base import Peripheral, extract_field, insert_field
from rehost.peripherals.registry import register

CTRL = 0x00
LOAD = 0x04
VAL = 0x08
CALIB = 0x0C

ENABLE = 1
TICKINT = 2
COUNTFLAG = 1 << 16


@register("systick")
class SysTick(Peripheral):
    config_keys = frozenset({"read_default", "calib"})

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.calib = parse_u32(self.config.get("calib", 0x00FFFFFF), what=f"{self.name} calib")
        for offset, what in ((CTRL, "CTRL"), (LOAD, "LOAD"), (VAL, "VAL"), (CALIB, "CALIB")):
            self.require_aligned(offset, what=what)
        self.ctrl = 0
        self.load = 0
        self.val = 0
        self.countflag = False
        self.irq_pending = False

    def read(self, offset: int, size: int) -> int:
        word = self._word_for(offset)
        if word is None:
            self.log_unhandled("read", offset, size, None)
            return self.read_default & access_mask(size)
        if word == CTRL:
            value = self.ctrl
            if self.countflag:
                value |= COUNTFLAG
                self.countflag = False
            return extract_field(value, offset, size, CTRL)
        if word == LOAD:
            return extract_field(self.load, offset, size, LOAD)
        if word == VAL:
            current = self.val
            if self.ctrl & ENABLE:
                if self.val == 0:
                    self.countflag = True
                    self.val = self.load & 0xFFFFFF
                    if self.ctrl & TICKINT:
                        self.irq_pending = True
                else:
                    self.val = (self.val - 1) & 0xFFFFFF
            return extract_field(current, offset, size, VAL)
        return extract_field(self.calib, offset, size, CALIB)

    def write(self, offset: int, size: int, value: int) -> None:
        word = self._word_for(offset)
        if word is None or offset + size > word + 4:
            self.log_unhandled("write", offset, size, value)
            return
        if word == CTRL:
            merged = insert_field(self.ctrl, offset, size, CTRL, value)
            self.ctrl = merged & 0x7
            return
        if word == LOAD:
            merged = insert_field(self.load, offset, size, LOAD, value)
            self.load = merged & 0xFFFFFF
            return
        if word == VAL:
            self.val = 0
            return
        # CALIB is read-only.
        return

    def snapshot_state(self) -> dict[str, Any]:
        return {
            "ctrl": self.ctrl,
            "load": self.load,
            "val": self.val,
            "countflag": self.countflag,
            "irq_pending": self.irq_pending,
        }

    def restore_state(self, state: dict[str, Any]) -> None:
        self.ctrl = int(state["ctrl"]) & 0x7
        self.load = int(state["load"]) & 0xFFFFFF
        self.val = int(state["val"]) & 0xFFFFFF
        self.countflag = bool(state["countflag"])
        self.irq_pending = bool(state["irq_pending"])

    def debug_lines(self) -> list[str]:
        return [
            f"{self.name} ctrl: {self.ctrl:#x} load: {self.load:#x} val: {self.val:#x}"
        ]

    def _word_for(self, offset: int) -> int | None:
        for word in (CTRL, LOAD, VAL, CALIB):
            if word <= offset < word + 4 and offset + 0 <= word + 4:
                return word
        return None
