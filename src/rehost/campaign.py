# SPDX-License-Identifier: MIT
"""In-process coverage-guided campaign.

``jig-emu fuzz`` uses this when it is not attached to an AFL++ forkserver.
Each iteration calls ``PersistentHarness.exec_one``, so guest CPU, RAM,
plugin, and NVIC state come from the boot checkpoint. The coverage map and
the crash decision are the same ones the forkserver reports to afl-fuzz.

The schedule is deliberately small: a deterministic byte walk on short
corpus items (so a 4-byte magic value is reachable from a zero seed), then
stacked havoc. It is not AFL's full power schedule.
"""

from __future__ import annotations

import os
import random
import sys
from dataclasses import dataclass, field
from pathlib import Path

from rehost.coverage import MAP_SIZE, CoverageMap
from rehost.errors import FuzzInputError
from rehost.fuzz import PersistentHarness, is_fuzz_crash
from rehost.result import STATUS_LIMIT, STATUS_TIMEOUT

# Byte-walk inputs longer than this only in havoc. The planted fixture's
# interesting prefix is 4 bytes, and the walk is what makes that demo finish
# without depending on a lucky random mutation.
_DETERMINISTIC_MAX_LEN = 16
_HAVOC_ENERGY = 16
_HAVOC_STACK = 4
_INTERESTING_8 = (0, 1, 16, 32, 64, 100, 127, 128, 255)
_HANG_CAP = 8
_CRASH_CAP = 64


@dataclass
class CampaignResult:
    execs: int
    corpus: int
    crashes: int
    hangs: int
    rng_seed: int
    crash_paths: list[Path] = field(default_factory=list)

    def format(self) -> str:
        lines = [
            f"execs: {self.execs}",
            f"corpus: {self.corpus}",
            f"crashes: {self.crashes}",
            f"hangs: {self.hangs}",
            f"rng-seed: {self.rng_seed}",
        ]
        if self.crash_paths:
            lines.append(f"crash: {self.crash_paths[0]}")
        return "\n".join(lines)


@dataclass
class _Item:
    data: bytes
    deterministic_done: bool = False


class Campaign:
    """Grow a corpus from edge coverage and write crashes under ``out``."""

    def __init__(
        self,
        machine,
        *,
        out: Path,
        seed_files: list[Path] | None = None,
        extra_inputs: list[bytes] | None = None,
        max_execs: int = 1_000_000,
        rng_seed: int | None = None,
        stop_on_crash: bool = False,
    ) -> None:
        if max_execs < 1:
            raise ValueError("max_execs must be >= 1")
        fuzz = machine.config.fuzz
        if fuzz is not None and fuzz.mode == "buffer" and fuzz.buffer is not None:
            self.max_len = fuzz.buffer.max_size
        else:
            self.max_len = 4096
        self.machine = machine
        self.out = out
        self.seed_files = list(seed_files or [])
        self.extra_inputs = list(extra_inputs or [])
        self.max_execs = max_execs
        self.stop_on_crash = stop_on_crash
        self.rng_seed = random.SystemRandom().randrange(1 << 32) if rng_seed is None else rng_seed
        self.rng = random.Random(self.rng_seed)
        self.coverage = CoverageMap(size=MAP_SIZE)
        machine.attach_coverage(self.coverage)
        self.harness = PersistentHarness(machine)
        self.best = bytearray(MAP_SIZE)
        self.queue: list[_Item] = []
        self.execs = 0
        self.crash_count = 0
        self.hang_count = 0
        self.crash_paths: list[Path] = []
        self._stopped = False

    def run(self) -> CampaignResult:
        self.out.mkdir(parents=True, exist_ok=True)
        for seed in self._initial_seeds():
            self._consider(seed)
            if self._stopped:
                return self._result()
        cursor = 0
        while cursor < len(self.queue) and self.execs < self.max_execs and not self._stopped:
            item = self.queue[cursor]
            cursor += 1
            if item.deterministic_done or not 0 < len(item.data) <= _DETERMINISTIC_MAX_LEN:
                continue
            item.deterministic_done = True
            self._deterministic(item.data)
        cursor = 0
        while self.execs < self.max_execs and self.queue and not self._stopped:
            item = self.queue[cursor % len(self.queue)]
            cursor += 1
            self._havoc_round(item.data)
        return self._result()

    def _result(self) -> CampaignResult:
        return CampaignResult(
            execs=self.execs,
            corpus=len(self.queue),
            crashes=self.crash_count,
            hangs=self.hang_count,
            rng_seed=self.rng_seed,
            crash_paths=list(self.crash_paths),
        )

    def _initial_seeds(self) -> list[bytes]:
        seeds: list[bytes] = []
        for path in self.seed_files:
            seeds.append(self._clip(path.read_bytes()))
        seeds.extend(self._clip(blob) for blob in self.extra_inputs)
        if seeds:
            return seeds
        width = 4
        fuzz = self.machine.config.fuzz
        if fuzz is not None and fuzz.buffer is not None:
            width = min(4, fuzz.buffer.max_size)
        return [bytes(width)]

    def _clip(self, data: bytes) -> bytes:
        if self.machine.config.fuzz is not None and self.machine.config.fuzz.mode == "mmio":
            data = data[: len(data) - (len(data) % 12)]
        if len(data) > self.max_len:
            return data[: self.max_len]
        return data

    def _consider(self, data: bytes) -> str:
        if self.execs >= self.max_execs:
            return "skip"
        data = self._clip(data)
        self.execs += 1
        try:
            result = self.harness.exec_one(data)
        except FuzzInputError:
            self._progress()
            return "boring"
        fuzz = self.machine.config.fuzz
        if is_fuzz_crash(result, fuzz):
            self._save_crash(data, result)
            if self.stop_on_crash:
                self._stopped = True
            self._progress()
            return "crash"
        if result.status in (STATUS_TIMEOUT, STATUS_LIMIT):
            self._save_hang(data, result)
            self._progress()
            return "hang"
        if self.coverage.absorb(self.best):
            self.queue.append(_Item(data))
            self._write(self.out / "queue", f"id:{len(self.queue) - 1:06d}", data)
            self._progress()
            return "new"
        self._progress()
        return "boring"

    def _progress(self) -> None:
        if self.execs == 1 or self.execs % 1000 == 0:
            print(
                f"execs: {self.execs} corpus: {len(self.queue)} crashes: {self.crash_count}",
                file=sys.stderr,
            )

    def _deterministic(self, base: bytes, depth: int = 0) -> None:
        """Walk each byte. A new edge is extended before the rest of this input.

        Depth-first means a matched prefix (the thing that just grew the map)
        is mutated next. Finishing the uninteresting values of the parent
        first would spend the whole budget before a 4-byte magic is reached.
        """
        for pos in range(len(base)):
            if self._stopped or self.execs >= self.max_execs:
                return
            original = base[pos]
            trial = bytearray(base)
            for value in range(256):
                if value == original:
                    continue
                if self._stopped or self.execs >= self.max_execs:
                    return
                trial[pos] = value
                before = len(self.queue)
                self._consider(bytes(trial))
                if self._stopped or self.execs >= self.max_execs:
                    return
                if len(self.queue) > before and depth < 32:
                    discovered = self.queue[-1]
                    if (
                        not discovered.deterministic_done
                        and 0 < len(discovered.data) <= _DETERMINISTIC_MAX_LEN
                    ):
                        discovered.deterministic_done = True
                        self._deterministic(discovered.data, depth + 1)

    def _havoc_round(self, base: bytes) -> None:
        corpus = [item.data for item in self.queue]
        for _ in range(_HAVOC_ENERGY):
            if self._stopped or self.execs >= self.max_execs:
                return
            self._consider(havoc(base, self.rng, corpus, self.max_len))

    def _save_crash(self, data: bytes, result) -> None:
        self.crash_count += 1
        if len(self.crash_paths) >= _CRASH_CAP:
            return
        name = f"id:{self.crash_count - 1:06d},sig:11,pc:{result.pc & ~1:08x}"
        path = self._write(self.out / "crashes", name, data)
        self.crash_paths.append(path)
        print(f"crash: {path}", file=sys.stderr)

    def _save_hang(self, data: bytes, result) -> None:
        self.hang_count += 1
        if self.hang_count > _HANG_CAP:
            return
        name = f"id:{self.hang_count - 1:06d},status:{result.status}"
        self._write(self.out / "hangs", name, data)

    @staticmethod
    def _write(directory: Path, name: str, data: bytes) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / name
        with path.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        return path


def havoc(data: bytes, rng: random.Random, corpus: list[bytes], max_len: int) -> bytes:
    """Stack a handful of AFL-style havoc mutations.

    The set is bit flips, random and interesting bytes, small arithmetic,
    insert, delete, splice, and a short overwrite. It is not the full AFL
    havoc catalog (no dictionary stage, no effectors).
    """
    buf = bytearray(data)
    if not buf and max_len > 0:
        buf.append(0)
    rounds = 1 << rng.randrange(_HAVOC_STACK)
    for _ in range(rounds):
        if not buf:
            if max_len > 0:
                buf.append(rng.randrange(256))
            continue
        kind = rng.randrange(8)
        if kind == 0:
            index = rng.randrange(len(buf))
            buf[index] ^= 1 << rng.randrange(8)
        elif kind == 1:
            buf[rng.randrange(len(buf))] = rng.randrange(256)
        elif kind == 2:
            buf[rng.randrange(len(buf))] = rng.choice(_INTERESTING_8)
        elif kind == 3:
            index = rng.randrange(len(buf))
            buf[index] = (buf[index] + rng.randint(-35, 35)) & 0xFF
        elif kind == 4:
            if len(buf) < max_len:
                buf.insert(rng.randrange(len(buf) + 1), rng.randrange(256))
        elif kind == 5:
            if len(buf) > 1:
                del buf[rng.randrange(len(buf))]
        elif kind == 6 and len(corpus) > 1:
            other = rng.choice(corpus)
            if other and buf:
                cut = rng.randrange(len(buf))
                other_cut = rng.randrange(len(other))
                buf = buf[:cut] + other[other_cut:]
        else:
            start = rng.randrange(len(buf))
            end = min(len(buf), start + rng.randint(1, 4))
            for index in range(start, end):
                buf[index] = rng.randrange(256)
        if len(buf) > max_len:
            del buf[max_len:]
    return bytes(buf)
