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


def test_exec_one_drops_an_irq_pended_after_the_checkpoint():
    machine = Machine.from_fixture("fuzz-echo")
    harness = PersistentHarness(machine)
    harness.exec_one(b"A")
    machine.backend.inject_irq(3)
    assert 3 in machine.backend.pending_irqs
    harness.exec_one(b"B")
    assert machine.backend.pending_irqs == []
    assert machine.backend.nvic.external_pending[3] is False


def test_crash_address_is_a_halt_the_fuzzer_keeps():
    from rehost.fuzz import is_fuzz_crash

    machine = machine_from_asm(
        "bkpt #0",
        fuzz={
            "mode": "buffer",
            "buffer": {"address": 0x20000100, "max_size": 4},
            "crash_addresses": [0],
        },
    )
    result = PersistentHarness(machine).exec_one(b"")
    assert result.status == "halted"
    assert is_fuzz_crash(result, machine.config.fuzz)
    machine.config.fuzz.crash_addresses = ()
    assert is_fuzz_crash(result, machine.config.fuzz) is False


_UART_POLL = """
movw r2, #0x0000
movt r2, #0x4000
movs r0, #0x48
str r0, [r2, #0]
loop:
ldr r1, [r2, #4]
cmp r1, #0xA0
bne loop
ldrb r1, [r2, #0]
str r1, [r2, #0]
cmp r1, #0x58
bne done
movw r3, #0x0001
movt r3, #0x6000
bx r3
done:
bkpt #0
"""


def _uart_machine(**fuzz_extra):
    fuzz = {
        "mode": "uart",
        "uart": {"name": "uart0", "max_size": 8},
        "checkpoint": {
            "mode": "banner",
            "idle_instructions": 16,
            "contains": "H",
            "max_instructions": 5000,
        },
        "exec": {"max_instructions": 2000},
        "hang_on_limit": False,
    }
    fuzz.update(fuzz_extra)
    return machine_from_asm(
        _UART_POLL,
        regions=[
            {
                "name": "uart0",
                "base": 0x40000000,
                "size": 0x100,
                "perms": "rw",
                "peripheral": "uart",
                "config": {
                    "data_offset": 0,
                    "status_offset": 4,
                    "tx_empty_mask": 0x80,
                    "rx_ready_mask": 0x20,
                },
            }
        ],
        run={"timeout_ms": 1000, "max_instructions": 5000, "halt_on_bkpt": True},
        fuzz=fuzz,
    )


def test_uart_banner_checkpoint_restores_rx_and_tx():
    machine = _uart_machine()
    harness = PersistentHarness(machine)
    harness.checkpoint()
    assert harness.checkpoint_mode == "banner"
    assert harness.checkpoint_tx == b"H"
    assert bytes(machine.peripheral("uart0").rx) == b""
    first = harness.exec_one(b"A")
    assert first.status == "halted", first.detail
    assert bytes(machine.peripheral("uart0").tx) == b"HA"
    second = harness.exec_one(b"X")
    assert second.status == "fault"
    assert bytes(machine.peripheral("uart0").tx) == b"HX"
    # The crash must not stick to the next case.
    third = harness.exec_one(b"B")
    assert third.status == "halted"
    assert bytes(machine.peripheral("uart0").tx) == b"HB"


def test_exec_idle_ends_a_command_loop_before_the_cap():
    source = _UART_POLL.replace("bkpt #0", "b loop")
    fuzz = {
        "mode": "uart",
        "uart": {"name": "uart0", "max_size": 8},
        "checkpoint": {
            "mode": "banner",
            "idle_instructions": 16,
            "contains": "H",
            "max_instructions": 5000,
        },
        "exec": {"max_instructions": 5000, "idle_instructions": 48},
        "hang_on_limit": False,
    }
    machine = machine_from_asm(
        source,
        regions=[
            {
                "name": "uart0",
                "base": 0x40000000,
                "size": 0x100,
                "perms": "rw",
                "peripheral": "uart",
                "config": {
                    "data_offset": 0,
                    "status_offset": 4,
                    "tx_empty_mask": 0x80,
                    "rx_ready_mask": 0x20,
                },
            }
        ],
        run={"timeout_ms": 1000, "max_instructions": 5000, "halt_on_bkpt": True},
        fuzz=fuzz,
    )
    harness = PersistentHarness(machine)
    answered = harness.exec_one(b"A")
    assert answered.status == "halted"
    assert "tx quiet" in answered.detail
    assert answered.instructions < 1000
    assert bytes(machine.peripheral("uart0").tx) == b"HA"
    fault = harness.exec_one(b"X")
    assert fault.status == "fault"


def test_banner_checkpoint_reports_a_marker_the_image_never_sends():
    machine = _uart_machine(
        checkpoint={
            "mode": "banner",
            "idle_instructions": 8,
            "contains": "NOPE",
            "max_instructions": 200,
        }
    )
    with pytest.raises(FuzzInputError, match="did not see"):
        PersistentHarness(machine).checkpoint()


def test_instruction_limit_is_a_hang_only_when_configured(tmp_path):
    from rehost.campaign import Campaign

    spinning = machine_from_asm(
        "spin:\n    b spin\n",
        run={"timeout_ms": 1000, "max_instructions": 40, "halt_on_bkpt": True},
        fuzz={
            "mode": "buffer",
            "buffer": {"address": 0x20000000, "max_size": 4},
            "hang_on_limit": False,
        },
    )
    finished = Campaign(
        spinning,
        out=tmp_path / "normal",
        max_execs=8,
        rng_seed=1,
    ).run()
    assert finished.hangs == 0
    assert finished.corpus >= 1
    assert finished.edges >= 1

    hanging = machine_from_asm(
        "spin:\n    b spin\n",
        run={"timeout_ms": 1000, "max_instructions": 40, "halt_on_bkpt": True},
        fuzz={
            "mode": "buffer",
            "buffer": {"address": 0x20000000, "max_size": 4},
            "hang_on_limit": True,
        },
    )
    stopped = Campaign(
        hanging,
        out=tmp_path / "hangs",
        max_execs=8,
        rng_seed=1,
    ).run()
    assert stopped.hangs >= 1
    assert stopped.corpus == 0
    assert "hangs: " in stopped.format()
    assert "execs/sec: " in stopped.format()


def test_uart_campaign_finds_the_planted_serial_fault(tmp_path):
    from rehost.campaign import Campaign

    machine = _uart_machine()
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "letter.txt").write_bytes(b"A")
    result = Campaign(
        machine,
        out=tmp_path / "out",
        seed_files=[seeds / "letter.txt"],
        max_execs=400,
        rng_seed=1,
        stop_on_crash=True,
    ).run()
    assert result.crashes == 1
    assert result.buckets == 1
    assert result.crash_paths[0].read_bytes().startswith(b"X")


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
