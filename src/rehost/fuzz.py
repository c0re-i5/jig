# SPDX-License-Identifier: MIT
"""Fuzz-harness input sinks.

Three sinks are configured per machine:

* ``buffer`` copies bytes into a RAM window (and optionally stores the length).
* ``mmio`` replays a sequence of writes into peripheral plugins.
* ``uart`` replaces the UART RX queue with the testcase. That is the serial
  line a shell or a Grbl parser reads.

Input can come from a file, stdin, or an AFL++ shared-memory fuzz region
(``__AFL_SHM_FUZZ_ID`` / ``__AFL_SHM_FUZZ_FD``). The region layout matches
AFL++: a little-endian ``u32`` length followed by the testcase bytes.

``PersistentHarness.exec_one`` restores a checkpoint, applies one testcase,
and runs. The checkpoint is the reset state, or, when
``fuzz.checkpoint.mode`` is ``banner``, the state after the UART has
transmitted and gone quiet. ``jig-emu fuzz`` drives that hook from an
in-process campaign (``rehost.campaign``) or, when spawned by afl-fuzz,
from an AFL++ persistent-mode forkserver (``rehost.forkserver``).
"""

from __future__ import annotations

import ctypes
import logging
import mmap
import os
import struct
import sys
import time
from pathlib import Path
from typing import BinaryIO

from rehost.errors import ConfigError, FuzzInputError, RehostError
from rehost.memory import access_mask
from rehost.result import STATUS_HALTED, STATUS_LIMIT, STATUS_TIMEOUT, RunResult

logger = logging.getLogger(__name__)

# AFL++'s default MAX_FILE is 1 MiB; the fuzz map adds the leading u32.
_DEFAULT_AFL_MAP = (1 << 20) + 4
_MMIO_RECORD = struct.Struct("<IIB3x")


def ensure_fuzz_backend(machine: object) -> None:
    """Refuse a campaign on a backend that does not support fuzzing.

    CmpLog decodes Thumb, and the forkserver is wired to that same Unicorn
    Cortex-M path. The RV32 backend sets ``supports_fuzz`` false.
    """
    backend = getattr(machine, "backend", None)
    if getattr(backend, "supports_fuzz", True):
        return
    arch = getattr(backend, "arch", "this CPU")
    raise RehostError(
        f"fuzzing, CmpLog, and the AFL++ forkserver are not implemented on {arch}. "
        "They stay on the Unicorn Cortex-M backend."
    )


def encode_mmio_script(records: list[tuple[int, int, int]]) -> bytes:
    """Pack ``(address, value, size)`` records.

    Each record is 12 bytes: ``u32`` address, ``u32`` value, ``u8`` size, 3
    bytes of padding. ``size`` is 1, 2, or 4. The value is masked to ``size``
    when it is applied.
    """
    out = bytearray()
    for address, value, size in records:
        if size not in (1, 2, 4):
            raise FuzzInputError(f"MMIO record size must be 1, 2, or 4, not {size}")
        out += _MMIO_RECORD.pack(address & 0xFFFFFFFF, value & 0xFFFFFFFF, size)
    return bytes(out)


def parse_mmio_script(data: bytes) -> list[tuple[int, int, int]]:
    """Inverse of ``encode_mmio_script``. A partial trailing record is an error."""
    if len(data) % _MMIO_RECORD.size != 0:
        raise FuzzInputError(
            f"MMIO script length {len(data)} is not a multiple of {_MMIO_RECORD.size} bytes"
        )
    records: list[tuple[int, int, int]] = []
    for address, value, size in _MMIO_RECORD.iter_unpack(data):
        if size not in (1, 2, 4):
            raise FuzzInputError(f"MMIO record size must be 1, 2, or 4, not {size}")
        records.append((address, value & access_mask(size), size))
    return records


def parse_afl_fuzz_region(blob: bytes) -> bytes:
    """Split an AFL++ fuzz map into the testcase it currently holds."""
    if len(blob) < 4:
        raise FuzzInputError("AFL++ fuzz region is shorter than the 4-byte length")
    length = int.from_bytes(blob[:4], "little")
    available = len(blob) - 4
    if length > available:
        raise FuzzInputError(
            f"AFL++ fuzz length {length} exceeds the mapped region ({available} bytes available)"
        )
    return bytes(blob[4 : 4 + length])


def read_afl_shmem() -> bytes | None:
    """Read the AFL++ shared fuzz testcase, or return None if the env is unset.

    Honors ``__AFL_SHM_FUZZ_FD`` (mmap of an inherited descriptor) and
    ``__AFL_SHM_FUZZ_ID`` (System V ``shmat``). ``__AFL_SHM_FUZZ_MAP_SIZE``
    selects the map size; otherwise 1 MiB + 4 is used, matching AFL++'s
    default ``MAX_FILE``.
    """
    fd_env = os.environ.get("__AFL_SHM_FUZZ_FD")
    id_env = os.environ.get("__AFL_SHM_FUZZ_ID")
    if fd_env is None and id_env is None:
        return None
    size_env = os.environ.get("__AFL_SHM_FUZZ_MAP_SIZE")
    try:
        size = int(size_env) if size_env else _DEFAULT_AFL_MAP
    except ValueError as exc:
        raise FuzzInputError("__AFL_SHM_FUZZ_MAP_SIZE is not an integer") from exc
    if size < 4:
        raise FuzzInputError("__AFL_SHM_FUZZ_MAP_SIZE must be at least 4")
    if fd_env is not None:
        try:
            fd = int(fd_env)
        except ValueError as exc:
            raise FuzzInputError("__AFL_SHM_FUZZ_FD is not an integer") from exc
        return _read_afl_fd(fd, size)
    try:
        shm_id = int(id_env or "")
    except ValueError as exc:
        raise FuzzInputError("__AFL_SHM_FUZZ_ID is not an integer") from exc
    return _read_afl_sysv(shm_id, size)


def read_input(*, path: str | Path | None = None, stdin: BinaryIO | None = None) -> bytes:
    """Resolve one testcase.

    Priority: explicit ``path``, AFL++ shared memory, ``REHOST_INPUT_FILE``,
    then ``stdin`` when it is not a terminal. An unset source yields ``b""``.
    """
    if path is not None:
        return _read_path(Path(path), "fuzz input")
    shared = read_afl_shmem()
    if shared is not None:
        return shared
    env_file = os.environ.get("REHOST_INPUT_FILE")
    if env_file:
        return _read_path(Path(env_file), "REHOST_INPUT_FILE")
    if stdin is None:
        return b""
    if hasattr(stdin, "isatty") and stdin.isatty():
        return b""
    data = stdin.read()
    if isinstance(data, str):
        return data.encode("utf-8")
    return bytes(data)


class FuzzHarness:
    """Apply one testcase to a machine using its ``fuzz:`` config."""

    def __init__(self, machine) -> None:
        if machine.config.fuzz is None:
            raise ConfigError(
                "machine config has no fuzz: section; add one to choose a buffer or MMIO sink"
            )
        self.machine = machine
        self.config = machine.config.fuzz

    def apply(self, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise FuzzInputError("fuzz input must be bytes")
        blob = bytes(data)
        if self.config.mode == "buffer":
            self._apply_buffer(blob)
        elif self.config.mode == "mmio":
            for address, value, size in parse_mmio_script(blob):
                self.machine.write_mmio(address, value, size)
        elif self.config.mode == "uart":
            self._apply_uart(blob)
        else:
            raise ConfigError(f"unknown fuzz mode {self.config.mode!r}")

    def _apply_buffer(self, data: bytes) -> None:
        window = self.config.buffer
        if window is None:
            raise ConfigError("fuzz.mode buffer requires fuzz.buffer")
        if len(data) > window.max_size:
            logger.warning(
                "fuzz input truncated from %d to %d bytes", len(data), window.max_size
            )
            data = data[: window.max_size]
        self.machine.ensure_ram(window.address, window.max_size)
        self.machine.write_memory(window.address, bytes(window.max_size))
        if data:
            self.machine.write_memory(window.address, data)
        if window.length_address is not None:
            self.machine.write_u32(window.length_address, len(data))

    def _apply_uart(self, data: bytes) -> None:
        """Replace UART RX with the testcase. A restored queue is cleared first."""
        window = self.config.uart
        if window is None:
            raise ConfigError("fuzz.mode uart requires fuzz.uart")
        if len(data) > window.max_size:
            logger.warning(
                "fuzz input truncated from %d to %d bytes", len(data), window.max_size
            )
            data = data[: window.max_size]
        from rehost.serial import resolve_uart

        uart = resolve_uart(self.machine, window.name)
        uart.rx.clear()
        uart.rx_irq_armed = False
        if data:
            uart.queue_rx(data)


def is_fuzz_crash(result: RunResult, fuzz) -> bool:
    """True when the fuzzer should keep this input and signal a crash.

    A fault is always a crash. A halt whose PC is listed in
    ``fuzz.crash_addresses`` is a crash too (the low bit of both addresses is
    ignored). Timeouts and the instruction limit are hangs, not crashes: AFL++
    has its own timeout, and a clean ``BKPT`` is a normal exit unless the
    machine file says that PC is the bug.
    """
    if result.faulted:
        return True
    if fuzz is None:
        return False
    pc = result.pc & ~1
    return any((address & ~1) == pc for address in fuzz.crash_addresses)


def is_fuzz_hang(result: RunResult, fuzz) -> bool:
    """True when this stop should be saved as a hang and kept out of the corpus.

    A wall-clock timeout is always a hang. The instruction cap is a hang
    for a buffer or MMIO sink, which is expected to reach ``BKPT`` or a
    halt address. ``fuzz.hang_on_limit: false`` (the UART default) means
    the guest is a command loop: hitting the cap is a finished execution,
    and the campaign still records its edges. afl-fuzz has its own ``-t``
    and does not use this helper.
    """
    if result.status == STATUS_TIMEOUT:
        return True
    if result.status == STATUS_LIMIT:
        if fuzz is None:
            return True
        return bool(fuzz.hang_on_limit)
    return False


class _BannerWatch:
    """Stop once the UART has transmitted and then stayed quiet.

    Quiet time before the first transmitted byte does not count, so reset
    is not mistaken for the banner. When ``contains`` is set, quiet time
    also waits until that ASCII text is already in TX.
    """

    def __init__(self, machine, uart, idle: int, contains: bytes) -> None:
        self.machine = machine
        self.uart = uart
        self.idle = idle
        self.contains = contains
        self.tx_len = len(uart.tx)
        self.quiet = 0
        self.seen = self.tx_len > 0
        self.reached = False

    def on_retired(self, _instructions: int) -> None:
        if self.reached:
            return
        tx_len = len(self.uart.tx)
        if tx_len != self.tx_len:
            self.tx_len = tx_len
            self.quiet = 0
            self.seen = True
            return
        if not self.seen:
            return
        if self.contains and self.contains not in self.uart.tx:
            self.quiet = 0
            return
        self.quiet += 1
        if self.quiet >= self.idle:
            self.reached = True
            self.machine.request_stop(
                STATUS_HALTED,
                f"uart {self.uart.name} tx quiet for {self.idle} instructions",
            )


class _ExecQuiet:
    """End one UART case once RX is empty and TX has settled.

    Quiet time does not accumulate while RX still holds bytes, so a pause
    before the guest has taken the line is not the end of the case. TX
    growth resets the counter, so a long reply is not cut off. A line the
    guest accepts and then does not answer (a partial line with no newline,
    or homing with no prompt yet) ends after ``idle`` quiet instructions
    instead of burning the instruction cap. A guest that never drains RX
    still runs to the cap.
    """

    def __init__(self, machine, uart, idle: int) -> None:
        self.machine = machine
        self.uart = uart
        self.idle = idle
        self.tx_len = len(uart.tx)
        self.quiet = 0

    def on_retired(self, _instructions: int) -> None:
        tx_len = len(self.uart.tx)
        if tx_len != self.tx_len:
            self.tx_len = tx_len
            self.quiet = 0
            return
        if self.uart.rx:
            self.quiet = 0
            return
        self.quiet += 1
        if self.quiet >= self.idle:
            self.machine.request_stop(
                STATUS_HALTED,
                f"uart {self.uart.name} rx empty and tx quiet for {self.idle} instructions",
            )


class PersistentHarness:
    """Snapshot, apply one input, run, and restore on the next call.

    Take the checkpoint at boot, before any fuzzer bytes are applied, so each
    ``exec_one`` starts from the same CPU, RAM, peripheral, and NVIC state.
    The in-tree campaign and the AFL++ forkserver both call ``exec_one``.
    ``reset_to_checkpoint`` is the same restore without a testcase, and it
    does not require a ``fuzz:`` section. When a coverage map is attached to
    the machine, ``run`` clears it for this execution only.
    """

    def __init__(self, machine) -> None:
        self.machine = machine
        self._fuzz = None
        self._snapshot = None
        self.checkpoint_mode = "boot"
        self.checkpoint_instructions = 0
        self.checkpoint_pc = 0
        self.checkpoint_tx = b""
        self.checkpoint_uart: str | None = None
        self.checkpoint_seconds = 0.0

    @property
    def fuzz(self):
        """The input sink. Built on first use so a restore-only harness needs no ``fuzz:`` section."""
        if self._fuzz is None:
            self._fuzz = FuzzHarness(self.machine)
        return self._fuzz

    def checkpoint(self):
        """Snapshot the baseline. Banner mode runs the guest once to get there.

        A second call returns the same snapshot. It does not run again, so
        a testcase cannot move the baseline.
        """
        if self._snapshot is not None:
            return self._snapshot
        started = time.perf_counter()
        fuzz = self.machine.config.fuzz
        if fuzz is not None and fuzz.checkpoint.mode == "banner":
            self._reach_banner(fuzz)
        elif not self.machine.booted:
            self.machine.boot()
        self._snapshot = self.machine.snapshot()
        self.checkpoint_seconds = time.perf_counter() - started
        self._remember_checkpoint(fuzz)
        return self._snapshot

    def _reach_banner(self, fuzz) -> None:
        """Boot, run until TX goes quiet, and leave the machine there."""
        from rehost.serial import resolve_uart

        spec = fuzz.checkpoint
        if spec.idle_instructions is None:
            raise ConfigError("fuzz.checkpoint mode banner requires idle_instructions")
        uart_name = None if fuzz.uart is None else fuzz.uart.name
        uart = resolve_uart(self.machine, uart_name)
        if not self.machine.booted:
            self.machine.boot()
        contains = b"" if spec.contains is None else spec.contains.encode("ascii")
        watch = _BannerWatch(self.machine, uart, spec.idle_instructions, contains)
        run = self.machine.config.run
        saved = run.max_instructions
        if spec.max_instructions is not None:
            run.max_instructions = spec.max_instructions
        self.machine._retire_hook = watch.on_retired
        try:
            result = self.machine.run()
        finally:
            self.machine._retire_hook = None
            run.max_instructions = saved
        if not watch.reached:
            marker = f" containing {spec.contains!r}" if spec.contains else ""
            raise FuzzInputError(
                f"banner checkpoint did not see {uart.name} go quiet{marker} "
                f"({result.status}: {result.detail}; tx {len(uart.tx)} bytes). "
                "Raise fuzz.checkpoint.max_instructions, or lower idle_instructions "
                "if the banner never pauses."
            )

    def _remember_checkpoint(self, fuzz) -> None:
        registers = self.machine.backend.read_registers()
        self.checkpoint_pc = int(registers.get("pc", 0))
        self.checkpoint_mode = "boot" if fuzz is None else fuzz.checkpoint.mode
        self.checkpoint_uart = None
        self.checkpoint_tx = b""
        if fuzz is None or fuzz.checkpoint.mode != "banner":
            self.checkpoint_instructions = 0
            return
        from rehost.serial import resolve_uart

        uart_name = None if fuzz.uart is None else fuzz.uart.name
        uart = resolve_uart(self.machine, uart_name)
        self.checkpoint_uart = uart.name
        self.checkpoint_tx = bytes(uart.tx)
        # The warmup run's instruction count is not guest state. Read it
        # back from the last result by asking the machine, which still
        # holds the counter until the next run() clears it.
        self.checkpoint_instructions = self.machine._instructions
        preview = self.checkpoint_tx[:80].decode("ascii", errors="replace")
        preview = preview.replace("\r", "\\r").replace("\n", "\\n")
        print(
            "checkpoint: banner "
            f"pc: {self.checkpoint_pc:#010x} "
            f"instructions: {self.checkpoint_instructions} "
            f"uart: {uart.name} "
            f"tx: {len(self.checkpoint_tx)} bytes "
            f"warmup: {self.checkpoint_seconds:.2f}s "
            f"preview: {preview!r}",
            file=sys.stderr,
            flush=True,
        )

    def reset_to_checkpoint(self) -> None:
        """Restore the boot checkpoint, taking it on the first call.

        RAM, plugin state (UART RX/TX, SysTick), and the NVIC image all come
        back from that checkpoint. A later case cannot replace the baseline:
        this does not snapshot the machine again.
        """
        if self._snapshot is None:
            self.checkpoint()
            return
        self.machine.restore(self._snapshot)

    def exec_one(self, data: bytes):
        self.reset_to_checkpoint()
        self.fuzz.apply(data)
        run = self.machine.config.run
        limits = self.fuzz.config.exec
        saved = (run.max_instructions, run.timeout_ms)
        if limits.max_instructions is not None:
            run.max_instructions = limits.max_instructions
        if limits.timeout_ms is not None:
            run.timeout_ms = limits.timeout_ms
        watch = self._arm_exec_quiet(limits.idle_instructions)
        try:
            return self.machine.run()
        finally:
            if watch is not None:
                self.machine._retire_hook = None
            run.max_instructions, run.timeout_ms = saved

    def _arm_exec_quiet(self, idle: int | None):
        if not idle or self.fuzz.config.mode != "uart":
            return None
        from rehost.serial import resolve_uart

        uart = resolve_uart(self.machine, self.fuzz.config.uart.name if self.fuzz.config.uart else None)
        watch = _ExecQuiet(self.machine, uart, idle)
        self.machine._retire_hook = watch.on_retired
        return watch


def _read_path(path: Path, what: str) -> bytes:
    """Read a regular file or a pipe such as a shell process substitution."""
    if not path.exists() or path.is_dir():
        raise FuzzInputError(f"{what} not found: {path}")
    return path.read_bytes()


def _read_afl_fd(fd: int, size: int) -> bytes:
    try:
        with mmap.mmap(fd, size, prot=mmap.PROT_READ) as mapped:
            return parse_afl_fuzz_region(mapped)
    except (OSError, ValueError, BufferError) as exc:
        raise FuzzInputError(f"cannot map __AFL_SHM_FUZZ_FD {fd}: {exc}") from exc


def _read_afl_sysv(shm_id: int, size: int) -> bytes:
    libc = ctypes.CDLL(None, use_errno=True)
    shmat = libc.shmat
    shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
    shmat.restype = ctypes.c_void_p
    shmdt = libc.shmdt
    shmdt.argtypes = [ctypes.c_void_p]
    shmdt.restype = ctypes.c_int
    addr = shmat(shm_id, None, 0)
    failed = addr is None or addr == ctypes.c_void_p(-1).value
    if failed:
        err = ctypes.get_errno()
        raise FuzzInputError(f"shmat({shm_id}) failed: {os.strerror(err) if err else 'unknown error'}")
    try:
        blob = ctypes.string_at(addr, size)
    finally:
        shmdt(ctypes.c_void_p(addr))
    return parse_afl_fuzz_region(blob)
