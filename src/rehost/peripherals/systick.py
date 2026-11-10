# SPDX-License-Identifier: MIT
"""Cortex-M SysTick at the standard offsets (CTRL, LOAD, VAL, CALIB).

Two clocks share one counter step. A direct ``read`` of ``VAL`` (the original
polling stub) returns the current count and then steps. When a ``Machine``
owns the peripheral it sets ``cpu_clock`` and steps once per instruction
instead, so a handler can run without firmware polling ``VAL``. ``CLKSOURCE``
does not select a second clock; there is no external reference, and an enabled
counter advances on the instruction stream either way.

A step that observes 0 reloads from ``LOAD``, sets ``COUNTFLAG``, and, when
``TICKINT`` is set, reports an interrupt edge. The machine pends exception 15
for that edge. ``irq_pending`` stays set after the first such edge so existing
polling tests can observe it. Delivery itself lives in the NVIC pending bit,
which is cleared when the exception is taken.

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
        self.cpu_clock = False

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
            if (self.ctrl & ENABLE) and not self.cpu_clock:
                self._step()
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

    def consume_cpu_tick(self) -> bool:
        """Step once if ``Machine`` is clocking this counter.

        Returns True on the edge that should pend the SysTick exception.
        """
        if not self.cpu_clock or not (self.ctrl & ENABLE):
            return False
        return self._step()

    def _step(self) -> bool:
        if self.val == 0:
            self.val = self.load & 0xFFFFFF
            self.countflag = True
            if self.ctrl & TICKINT:
                self.irq_pending = True
                return True
            return False
        self.val = (self.val - 1) & 0xFFFFFF
        return False

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
