# SPDX-License-Identifier: MIT
"""Edge map, planted crash, and the in-process campaign."""

from __future__ import annotations

from rehost.cli import main
from rehost.coverage import CoverageMap
from rehost.fuzz import PersistentHarness
from rehost.machine import Machine

_MAGIC = b"JIG!"


def _execute(data: bytes):
    machine = Machine.from_fixture("fuzz-crash")
    coverage = CoverageMap()
    machine.attach_coverage(coverage)
    result = PersistentHarness(machine).exec_one(data)
    return result, coverage.snapshot_bytes()


def test_magic_prefix_grows_the_edge_map_and_does_not_accumulate():
    halted, zeros = _execute(b"\x00\x00\x00\x00")
    assert halted.status == "halted"
    prefixes = []
    previous = zeros
    for size in range(1, 4):
        result, bitmap = _execute(_MAGIC[:size] + bytes(4 - size))
        assert result.status == "halted"
        assert bitmap != previous
        prefixes.append(bitmap)
        previous = bitmap
    crashed, crash_map = _execute(_MAGIC)
    assert crashed.status == "fault"
    assert crash_map != previous
    assert any(byte for byte in crash_map[1:])

    machine = Machine.from_fixture("fuzz-crash")
    coverage = CoverageMap()
    machine.attach_coverage(coverage)
    harness = PersistentHarness(machine)
    harness.exec_one(b"\x00\x00\x00\x00")
    first = coverage.snapshot_bytes()
    harness.exec_one(b"\x00\x00\x00\x00")
    second = coverage.snapshot_bytes()
    assert first == second
    assert sum(first) == sum(second)


def test_fuzz_without_out_is_usage(capsys):
    code = main(["fuzz", "--fixture", "fuzz-crash", "--max-execs", "1"])
    assert code == 4
    assert "--out" in capsys.readouterr().err


def test_cli_fuzz_finds_the_planted_crash(tmp_path, capsys):
    out = tmp_path / "out"
    code = main(
        [
            "fuzz",
            "--fixture",
            "fuzz-crash",
            "--out",
            str(out),
            "--max-execs",
            "3000",
            "--stop-on-crash",
            "--rng-seed",
            "1",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert "crashes: 1" in captured.out
    crashes = list((out / "crashes").iterdir())
    assert len(crashes) == 1
    assert crashes[0].read_bytes() == _MAGIC
    assert len(list((out / "queue").iterdir())) >= 2
