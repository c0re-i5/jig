# SPDX-License-Identifier: MIT
"""Instruction-paced counter that can pend an NVIC line.

This is not a cycle-accurate timer and not a vendor TIM block. While the
enable bit is set, every ``tick_every`` retired instructions is one update
event: the update flag is set, compare flags are set for compare registers
that hold a non-zero value, and if any of those flags is also enabled in the
interrupt-enable word the plugin returns its ``irq`` so the machine can pend
it. ``tick_every`` is an instruction count, not a prescaler. ARR, CNT, and the
compare registers are latches the guest can read back. They do not pace the
event.

Defaults match the STM32 general-purpose timer offsets (CR1, DIER, SR, CNT,
ARR, CCR1..). A map that only needs "the counter is running, so deliver the
IRQ" sets ``irq`` and leaves the offsets alone. Status flags are a plain
latch, so a read-modify-write that clears one bit leaves the others in place.
"""

from __future__ import annotations

from typing import Any

from rehost.config import parse_u32
from rehost.errors import ConfigError
from rehost.memory import access_mask
from rehost.nvic import NUM_EXTERNAL
from rehost.peripherals.base import Peripheral, extract_field, insert_field
from rehost.peripherals.registry import register


@register("timer")
class Timer(Peripheral):
    config_keys = frozenset(
        {
            "read_default",
            "irq",
            "tick_every",
            "cr_offset",
            "dier_offset",
            "sr_offset",
            "cnt_offset",
            "arr_offset",
            "ccr_offset",
            "ccr_count",
            "enable_bit",
            "update_bit",
        }
    )

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.irq = _parse_irq(self.name, self.config.get("irq"))
        self.tick_every = parse_u32(self.config.get("tick_every", 64), what=f"{self.name} tick_every")
        if self.tick_every < 1:
            raise ConfigError(f"{self.name} tick_every must be >= 1")
        self.cr_offset = parse_u32(self.config.get("cr_offset", 0x00), what=f"{self.name} cr_offset")
        self.dier_offset = parse_u32(self.config.get("dier_offset", 0x0C), what=f"{self.name} dier_offset")
        self.sr_offset = parse_u32(self.config.get("sr_offset", 0x10), what=f"{self.name} sr_offset")
        self.cnt_offset = parse_u32(self.config.get("cnt_offset", 0x24), what=f"{self.name} cnt_offset")
        self.arr_offset = parse_u32(self.config.get("arr_offset", 0x2C), what=f"{self.name} arr_offset")
        self.ccr_offset = parse_u32(self.config.get("ccr_offset", 0x34), what=f"{self.name} ccr_offset")
        self.ccr_count = parse_u32(self.config.get("ccr_count", 4), what=f"{self.name} ccr_count")
        self.enable_bit = parse_u32(self.config.get("enable_bit", 0), what=f"{self.name} enable_bit")
        self.update_bit = parse_u32(self.config.get("update_bit", 0), what=f"{self.name} update_bit")
        if self.ccr_count < 1 or self.ccr_count > 8:
            raise ConfigError(f"{self.name} ccr_count must be 1..8")
        if not 0 <= self.enable_bit <= 31 or not 0 <= self.update_bit <= 31:
            raise ConfigError(f"{self.name} enable_bit and update_bit must be 0..31")
        if self.update_bit + self.ccr_count > 32:
            raise ConfigError(f"{self.name} compare flags do not fit above update_bit")
        offsets = [
            self.cr_offset,
            self.dier_offset,
            self.sr_offset,
            self.cnt_offset,
            self.arr_offset,
        ]
        offsets.extend(self.ccr_offset + 4 * index for index in range(self.ccr_count))
        if len(set(offsets)) != len(offsets):
            raise ConfigError(f"{self.name} timer registers must not alias each other")
        for offset in offsets:
            self.require_aligned(offset, what="register")
        self.words: dict[int, int] = {}
        self._div = 0
        self._event_mask = 0
        self.events = 0
        self.cpu_clock = False

    def read(self, offset: int, size: int) -> int:
        word = self._word_base(offset, size)
        if word is None:
            self.log_unhandled("read", offset, size, None)
            return self.read_default & access_mask(size)
        return extract_field(self.words.get(word, 0), offset, size, word)

    def write(self, offset: int, size: int, value: int) -> None:
        word = self._word_base(offset, size)
        if word is None:
            self.log_unhandled("write", offset, size, value)
            return
        merged = insert_field(self.words.get(word, 0), offset, size, word, value) & 0xFFFFFFFF
        if merged == 0:
            self.words.pop(word, None)
        else:
            self.words[word] = merged
        if word == self.cr_offset and (merged & (1 << self.enable_bit)) == 0:
            self._div = 0

    def consume_cpu_tick(self) -> int | None:
        """Count one instruction. Return ``irq`` when an enabled flag is newly set.

        The machine pends that line. A timer with no ``irq`` still sets flags
        so firmware can poll them. The enable bit gates the counter.
        """
        if not self.cpu_clock:
            return None
        if (self._reg(self.cr_offset) & (1 << self.enable_bit)) == 0:
            return None
        # Hold the next event until the guest clears the flags from the last
        # one. Otherwise a handler longer than tick_every re-pends before it
        # returns, and the thread instruction never gets to retire.
        if self._reg(self.sr_offset) & self._reg(self.dier_offset) & self._event_mask:
            self._div = 0
            return None
        self._div += 1
        if self._div < self.tick_every:
            return None
        self._div = 0
        return self._event()

    def _event(self) -> int | None:
        flags = 1 << self.update_bit
        for index in range(self.ccr_count):
            if self._reg(self.ccr_offset + 4 * index) != 0:
                flags |= 1 << (self.update_bit + 1 + index)
        self._event_mask = flags
        sr = self._reg(self.sr_offset) | flags
        self._set_reg(self.sr_offset, sr)
        cnt = (self._reg(self.cnt_offset) + 1) & 0xFFFFFFFF
        arr = self._reg(self.arr_offset)
        if arr and cnt > arr:
            cnt = 0
        self._set_reg(self.cnt_offset, cnt)
        self.events += 1
        if self.irq is None:
            return None
        if sr & self._reg(self.dier_offset) & flags:
            return self.irq
        return None

    def snapshot_state(self) -> dict[str, Any]:
        return {
            "words": {f"{offset:#x}": value for offset, value in sorted(self.words.items())},
            "div": self._div,
            "event_mask": self._event_mask,
            "events": self.events,
        }

    def restore_state(self, state: dict[str, Any]) -> None:
        raw = state.get("words", {})
        if not isinstance(raw, dict):
            raise ConfigError(f"{self.name} snapshot words must be a mapping")
        self.words = {}
        for key, value in raw.items():
            offset = parse_u32(key, what=f"{self.name} snapshot word")
            self.words[offset] = int(value) & 0xFFFFFFFF
        self._div = int(state.get("div", 0))
        self._event_mask = int(state.get("event_mask", 0)) & 0xFFFFFFFF
        self.events = int(state.get("events", 0))

    def debug_lines(self) -> list[str]:
        cr = self._reg(self.cr_offset)
        dier = self._reg(self.dier_offset)
        sr = self._reg(self.sr_offset)
        irq = "none" if self.irq is None else str(self.irq)
        return [
            f"{self.name} cr: {cr:#x} dier: {dier:#x} sr: {sr:#x} events: {self.events} irq: {irq}"
        ]

    def _word_base(self, offset: int, size: int) -> int | None:
        if size not in (1, 2, 4):
            return None
        if offset < 0 or offset + size > self.size:
            return None
        word = offset & ~3
        if offset + size > word + 4:
            return None
        return word

    def _reg(self, offset: int) -> int:
        return self.words.get(offset, 0)

    def _set_reg(self, offset: int, value: int) -> None:
        value &= 0xFFFFFFFF
        if value == 0:
            self.words.pop(offset, None)
        else:
            self.words[offset] = value


def _parse_irq(name: str, value: object) -> int | None:
    if value is None:
        return None
    irq = parse_u32(value, what=f"{name} irq")
    if not 0 <= irq < NUM_EXTERNAL:
        raise ConfigError(f"{name} irq must be an IRQ number from 0 to {NUM_EXTERNAL - 1}")
    return irq
