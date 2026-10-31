# SPDX-License-Identifier: MIT
"""Buffer sink, MMIO script, persistent loop, and AFL++ shared-memory layout."""

from __future__ import annotations

import ctypes

import pytest

from rehost.errors import FuzzInputError
from rehost.fuzz import (
    PersistentHarness,
    encode_mmio_script,
    parse_afl_fuzz_region,
    parse_mmio_script,
    read_afl_shmem,
    read_input,
)
from rehost.machine import Machine
from tests.helpers import machine_from_asm


def test_mmio_script_rejects_a_partial_record():
    script = encode_mmio_script([(0x40000000, 0x11, 1), (0x40000004, 0x2233, 2)])
    assert parse_mmio_script(script) == [(0x40000000, 0x11, 1), (0x40000004, 0x2233, 2)]
    with pytest.raises(FuzzInputError):
        parse_mmio_script(script[:-1])
    with pytest.raises(FuzzInputError):
        encode_mmio_script([(0x40000000, 1, 3)])


def test_fuzz_echo_fixture_is_independent_across_iterations(tmp_path):
    machine = Machine.from_fixture("fuzz-echo")
    harness = PersistentHarness(machine)
    first = harness.exec_one(b"Z")
    second = harness.exec_one(b"Y")
    assert first.status == "halted"
    assert second.status == "halted"
    assert bytes(machine.peripheral("uart0").tx) == b"Y"
    # A third empty input must not keep the previous byte.
    harness.exec_one(b"")
    assert bytes(machine.peripheral("uart0").tx) == b"\x00"


def test_buffer_length_and_truncation():
    machine = machine_from_asm(
        "bkpt #0",
        fuzz={
            "mode": "buffer",
            "buffer": {"address": 0x20000100, "max_size": 4, "length_address": 0x20000000},
        },
    )
    from rehost.fuzz import FuzzHarness

    FuzzHarness(machine).apply(b"abcdef")
    assert machine.read_memory(0x20000100, 4) == b"abcd"
    assert machine.read_u32(0x20000000) == 4


def test_afl_region_parser_and_sysv_shm(monkeypatch):
    assert parse_afl_fuzz_region((3).to_bytes(4, "little") + b"xyz!!!!") == b"xyz"
    with pytest.raises(FuzzInputError):
        parse_afl_fuzz_region(b"\x00\x00")
    with pytest.raises(FuzzInputError):
        parse_afl_fuzz_region((9).to_bytes(4, "little") + b"short")

    monkeypatch.delenv("__AFL_SHM_FUZZ_ID", raising=False)
    monkeypatch.delenv("__AFL_SHM_FUZZ_FD", raising=False)
    monkeypatch.delenv("__AFL_SHM_FUZZ_MAP_SIZE", raising=False)
    assert read_afl_shmem() is None

    payload = b"Hi"
    region = len(payload).to_bytes(4, "little") + payload + b"\x00" * 8
    libc = ctypes.CDLL(None, use_errno=True)
    shmget = libc.shmget
    shmget.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.c_int]
    shmget.restype = ctypes.c_int
    shm_id = shmget(0, len(region), 0o1000 | 0o600)
    if shm_id < 0:
        pytest.skip("System V shared memory is not available")
    try:
        shmat = libc.shmat
        shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        shmat.restype = ctypes.c_void_p
        addr = shmat(shm_id, None, 0)
        assert addr not in (None, ctypes.c_void_p(-1).value)
        try:
            ctypes.memmove(addr, region, len(region))
        finally:
            libc.shmdt(ctypes.c_void_p(addr))
        monkeypatch.setenv("__AFL_SHM_FUZZ_ID", str(shm_id))
        monkeypatch.setenv("__AFL_SHM_FUZZ_MAP_SIZE", str(len(region)))
        assert read_afl_shmem() == payload
    finally:
        shmctl = libc.shmctl
        shmctl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        shmctl.restype = ctypes.c_int
        shmctl(shm_id, 0, None)


def test_read_input_file_and_stdin(tmp_path, monkeypatch):
    monkeypatch.delenv("__AFL_SHM_FUZZ_ID", raising=False)
    monkeypatch.delenv("__AFL_SHM_FUZZ_FD", raising=False)
    path = tmp_path / "case.bin"
    path.write_bytes(b"from-file")
    monkeypatch.setenv("REHOST_INPUT_FILE", str(path))
    assert read_input() == b"from-file"
    monkeypatch.delenv("REHOST_INPUT_FILE")
    assert read_input(stdin=FakeStdin(b"pipe")) == b"pipe"
    assert read_input(stdin=FakeStdin(b"ignored", tty=True)) == b""


class FakeStdin:
    def __init__(self, data: bytes, tty: bool = False) -> None:
        self._data = data
        self._tty = tty

    def read(self) -> bytes:
        return self._data

    def isatty(self) -> bool:
        return self._tty
