# SPDX-License-Identifier: MIT
"""AFL++ v1 forkserver: a clean iteration stops, a planted crash is SIGSEGV."""

from __future__ import annotations

import ctypes
import os
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from rehost.coverage import MAP_SIZE
from rehost.forkserver import FS_NEW_OPT_MAPSIZE, FS_NEW_OPT_SHDMEM_FUZZ, FS_VERSION

_MAGIC = b"JIG!"


def test_forkserver_stops_for_a_clean_input_and_signals_the_crash(tmp_path):
    fuzz_size = 64
    coverage_id = _shmget(MAP_SIZE)
    fuzz_id = _shmget(fuzz_size)
    if coverage_id is None or fuzz_id is None:
        pytest.skip("System V shared memory is not available")
    ctl_read, ctl_write = os.pipe()
    status_read, status_write = os.pipe()
    control_fd, status_fd = _consecutive_fds()
    os.dup2(ctl_read, control_fd)
    os.dup2(status_write, status_fd)
    out = tmp_path / "out"
    env = os.environ.copy()
    root = Path(__file__).resolve().parents[1]
    env["PYTHONPATH"] = str(root / "src") + os.pathsep + env.get("PYTHONPATH", "")
    env["AFL_FORKSRV_FD"] = str(control_fd)
    env["__AFL_SHM_ID"] = str(coverage_id)
    env["AFL_MAP_SIZE"] = str(MAP_SIZE)
    env["__AFL_SHM_FUZZ_ID"] = str(fuzz_id)
    env["__AFL_SHM_FUZZ_MAP_SIZE"] = str(fuzz_size)
    env.pop("__AFL_SHM_FD", None)
    env.pop("__AFL_SHM_FUZZ_FD", None)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "rehost",
            "fuzz",
            "--fixture",
            "fuzz-crash",
            "--out",
            str(out),
            "--persistent-iters",
            "20",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        pass_fds=(control_fd, status_fd),
        close_fds=True,
    )
    os.close(control_fd)
    os.close(status_fd)
    os.close(ctl_read)
    os.close(status_write)
    try:
        version = _read_u32(status_read, 20)
        assert version == FS_VERSION
        _write_u32(ctl_write, FS_VERSION ^ 0xFFFFFFFF)
        options = _read_u32(status_read, 5)
        assert options & FS_NEW_OPT_MAPSIZE
        assert options & FS_NEW_OPT_SHDMEM_FUZZ
        assert _read_u32(status_read, 5) == MAP_SIZE
        assert _read_u32(status_read, 5) == FS_VERSION

        _write_fuzz(fuzz_id, fuzz_size, b"\x00\x00\x00\x00")
        _write_u32(ctl_write, 0)
        _read_u32(status_read, 20)  # child pid
        clean_status = _read_u32(status_read, 20)
        assert os.WIFSTOPPED(clean_status)
        assert os.WSTOPSIG(clean_status) == signal.SIGSTOP
        clean_map = _read_shm(coverage_id, MAP_SIZE)
        assert any(clean_map[1:])

        _write_fuzz(fuzz_id, fuzz_size, _MAGIC)
        _write_u32(ctl_write, 0)
        _read_u32(status_read, 20)
        crash_status = _read_u32(status_read, 20)
        assert os.WIFSIGNALED(crash_status)
        assert os.WTERMSIG(crash_status) == signal.SIGSEGV
        crash_map = _read_shm(coverage_id, MAP_SIZE)
        assert crash_map != clean_map
        assert _read_shm(fuzz_id, fuzz_size)[4 : 4 + len(_MAGIC)] == _MAGIC
        crashes = list((out / "crashes").iterdir())
        assert len(crashes) == 1
        assert crashes[0].read_bytes() == _MAGIC
    finally:
        os.close(ctl_write)
        os.close(status_read)
        if proc.poll() is None:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        stderr = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
        if proc.returncode not in (0, None) and proc.returncode < 0:
            pytest.fail(f"forkserver died by signal {-proc.returncode}: {stderr}")
        _shmctl_rmid(coverage_id)
        _shmctl_rmid(fuzz_id)


def _consecutive_fds() -> tuple[int, int]:
    """Two consecutive descriptors, so the status pipe can be control + 1."""
    opened: list[int] = []
    while True:
        fd = os.open("/dev/null", os.O_RDONLY)
        if opened and fd == opened[-1] + 1:
            first = opened[-1]
            for extra in opened[:-1]:
                os.close(extra)
            return first, fd
        opened.append(fd)
        if len(opened) > 8:
            last = opened[-1]
            for extra in opened[:-1]:
                os.close(extra)
            opened = [last]


def _shmget(size: int) -> int | None:
    libc = ctypes.CDLL(None, use_errno=True)
    shmget = libc.shmget
    shmget.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.c_int]
    shmget.restype = ctypes.c_int
    shm_id = shmget(0, size, 0o1000 | 0o600)
    if shm_id < 0:
        return None
    return shm_id


def _shmctl_rmid(shm_id: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    shmctl = libc.shmctl
    shmctl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    shmctl.restype = ctypes.c_int
    shmctl(shm_id, 0, None)


def _attach(shm_id: int, size: int) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    shmat = libc.shmat
    shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
    shmat.restype = ctypes.c_void_p
    addr = shmat(shm_id, None, 0)
    if addr in (None, ctypes.c_void_p(-1).value):
        raise OSError(f"shmat({shm_id}) failed")
    return addr


def _detach(addr: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    shmdt = libc.shmdt
    shmdt.argtypes = [ctypes.c_void_p]
    shmdt.restype = ctypes.c_int
    shmdt(ctypes.c_void_p(addr))


def _read_shm(shm_id: int, size: int) -> bytes:
    addr = _attach(shm_id, size)
    try:
        return ctypes.string_at(addr, size)
    finally:
        _detach(addr)


def _write_fuzz(shm_id: int, size: int, payload: bytes) -> None:
    region = len(payload).to_bytes(4, "little") + payload
    region = region.ljust(size, b"\x00")
    addr = _attach(shm_id, size)
    try:
        ctypes.memmove(addr, region, size)
    finally:
        _detach(addr)


def _read_u32(fd: int, timeout: float) -> int:
    return int.from_bytes(_read_exact(fd, 4, timeout), "little")


def _read_exact(fd: int, size: int, timeout: float) -> bytes:
    chunks: list[bytes] = []
    got = 0
    deadline = time.monotonic() + timeout
    while got < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError("timed out waiting for the forkserver")
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            raise AssertionError("timed out waiting for the forkserver")
        part = os.read(fd, size - got)
        if not part:
            raise AssertionError("forkserver closed the status pipe")
        chunks.append(part)
        got += len(part)
    return b"".join(chunks)


def _write_u32(fd: int, value: int) -> None:
    os.write(fd, (value & 0xFFFFFFFF).to_bytes(4, "little"))
