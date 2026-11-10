# SPDX-License-Identifier: MIT
"""Fuzz-harness input sinks.

Two sinks are configured per machine:

* ``buffer`` copies bytes into a RAM window (and optionally stores the length).
* ``mmio`` replays a sequence of writes into peripheral plugins.

Input can come from a file, stdin, or an AFL++ shared-memory fuzz region
(``__AFL_SHM_FUZZ_ID`` / ``__AFL_SHM_FUZZ_FD``). The region layout matches
AFL++: a little-endian ``u32`` length followed by the testcase bytes.

``PersistentHarness.exec_one`` restores a boot checkpoint, applies one
testcase, and runs. ``jig-emu fuzz`` drives that hook from an in-process
campaign (``rehost.campaign``) or, when spawned by afl-fuzz, from an AFL++
persistent-mode forkserver (``rehost.forkserver``).
"""

from __future__ import annotations

import ctypes
import logging
import mmap
import os
import struct
from pathlib import Path
from typing import BinaryIO

from rehost.errors import ConfigError, FuzzInputError
from rehost.memory import access_mask
from rehost.result import RunResult

logger = logging.getLogger(__name__)

# AFL++'s default MAX_FILE is 1 MiB; the fuzz map adds the leading u32.
_DEFAULT_AFL_MAP = (1 << 20) + 4
_MMIO_RECORD = struct.Struct("<IIB3x")


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


class PersistentHarness:
    """Snapshot, apply one input, run, and restore on the next call.

    Take the checkpoint at boot, before any fuzzer bytes are applied, so each
    ``exec_one`` starts from the same CPU, RAM, peripheral, and NVIC state.
    The in-tree campaign and the AFL++ forkserver both call ``exec_one``.
    When a coverage map is attached to the machine, ``run`` clears it for
    this execution only.
    """

    def __init__(self, machine) -> None:
        self.machine = machine
        self.fuzz = FuzzHarness(machine)
        self._snapshot = None

    def checkpoint(self):
        if not self.machine.booted:
            self.machine.boot()
        self._snapshot = self.machine.snapshot()
        return self._snapshot

    def exec_one(self, data: bytes):
        if self._snapshot is None:
            self.checkpoint()
        else:
            self.machine.restore(self._snapshot)
        self.fuzz.apply(data)
        return self.machine.run()


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
