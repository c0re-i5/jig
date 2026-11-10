# SPDX-License-Identifier: MIT
"""Run limits, unmapped policy, coverage, and the IRQ extension point."""

from __future__ import annotations

import pytest

from rehost.errors import ConfigError
from rehost.machine import Machine
from tests.helpers import machine_from_asm


def test_instruction_limit_and_halt_address():
    limited = machine_from_asm("self:\n    b self", run={"max_instructions": 10, "timeout_ms": 1000})
    result = limited.run()
    assert result.status == "instruction_limit"
    assert result.instructions == 10

    halted = machine_from_asm(
        """
        movs r0, #1
        movs r0, #2
        bkpt #0
        """,
        run={"halt_addresses": [2]},
    )
    result = halted.run()
    assert result.status == "halted"
    assert result.detail == "halt address 0x2"
    assert result.registers["r0"] == 1


def test_timeout_on_a_branch_to_self():
    machine = machine_from_asm(
        "self:\n    b self",
        run={"timeout_ms": 30, "max_instructions": 0},
    )
    result = machine.run()
    assert result.status == "timeout"
    assert result.instructions > 0


def test_unmapped_fault_and_log_default():
    fault = machine_from_asm(
        """
        movw r0, #0
        movt r0, #0x5000
        ldr r1, [r0, #0]
        bkpt #0
        """
    )
    result = fault.run()
    assert result.status == "fault"
    assert "unmapped" in result.detail

    logged = machine_from_asm(
        """
        movw r0, #0x2000
        movt r0, #0x5000
        ldr r1, [r0, #0]
        movw r2, #0
        movt r2, #0x2000
        str r1, [r2, #0]
        bkpt #0
        """,
        unmapped={"action": "log", "read_default": 0xA5A5A5A5, "log": True},
    )
    result = logged.run()
    assert result.status == "halted"
    assert logged.read_u32(0x20000000) == 0xA5A5A5A5


def test_invalid_instruction_is_a_fault():
    from rehost.config import parse_config

    machine = Machine(
        parse_config(
            {
                "name": "bad",
                "arch": "cortex-m",
                "memory": [
                    {"name": "flash", "base": 0, "size": 0x1000, "perms": "rx"},
                    {"name": "sram", "base": 0x20000000, "size": 0x1000, "perms": "rw"},
                ],
                "boot": {"mode": "entry", "sp": 0x20001000, "entry": 0},
                "run": {"timeout_ms": 200, "max_instructions": 10, "halt_on_bkpt": True},
            }
        )
    )
    machine.load_image(b"\xff\xff")
    result = machine.run()
    assert result.status == "fault"


def test_coverage_includes_the_entry_and_unknown_backend_is_named():
    machine = machine_from_asm(
        "movs r0, #1\n    bkpt #0",
        run={"collect_coverage": True},
    )
    result = machine.run()
    assert result.coverage is not None
    assert 0 in result.coverage
    with pytest.raises(ConfigError, match="planned adapter"):
        Machine(
            parse_config_arch("qemu-cortex-m"),
        )


def test_wfi_loop_still_hits_the_instruction_limit():
    machine = machine_from_asm(
        "loop:\n    wfi\n    b loop",
        run={"max_instructions": 20, "timeout_ms": 1000},
    )
    result = machine.run()
    assert result.status == "instruction_limit"
    assert result.instructions == 20


def test_wfi_loop_still_times_out():
    machine = machine_from_asm(
        "loop:\n    wfi\n    b loop",
        run={"timeout_ms": 50, "max_instructions": 0},
    )
    result = machine.run()
    assert result.status == "timeout"
    assert result.instructions > 0


def parse_config_arch(arch: str):
    from rehost.config import parse_config

    return parse_config(
        {
            "name": "later",
            "arch": arch,
            "memory": [{"name": "flash", "base": 0, "size": 0x1000, "perms": "rx"}],
        }
    )
