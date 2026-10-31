# SPDX-License-Identifier: MIT
"""Thumb fixture assembler: encodings and a couple of executed programs."""

from __future__ import annotations

import pytest

from rehost.errors import AssembleError
from rehost.fixtures.assemble import assemble
from tests.helpers import machine_from_asm


def test_movw_movt_and_memory_encodings():
    assert assemble("movw r0, #0") == bytes.fromhex("40f20000")
    assert assemble("movt r0, #0x4000") == bytes.fromhex("c4f20000")
    assert assemble("movs r1, #0x41") == bytes.fromhex("4121")
    assert assemble("str r1, [r0, #0]") == bytes.fromhex("0160")
    assert assemble("ldr r1, [r0, #4]") == bytes.fromhex("4168")
    assert assemble("bkpt #0") == bytes.fromhex("00be")
    assert assemble("nop") == bytes.fromhex("00bf")
    # `b .` is the well-known Thumb encoding fe e7.
    assert assemble("self:\n    b self") == bytes.fromhex("fee7")


def test_thumb_word_sets_the_low_bit():
    blob = assemble(".thumb_word reset\nreset:\n    bkpt #0")
    # The label sits at byte 4; the vector must set the Thumb bit.
    assert blob[:4] == (4 | 1).to_bytes(4, "little")
    assert blob[4:] == bytes.fromhex("00be")


def test_branch_skips_the_following_instruction():
    machine = machine_from_asm(
        """
        b skip
        bkpt #0
        skip:
            movs r0, #7
            bkpt #0
        """
    )
    result = machine.run()
    assert result.status == "halted"
    assert result.registers["r0"] == 7


def test_movw_movt_builds_a_peripheral_address():
    machine = machine_from_asm(
        """
        movw r0, #0x1000
        movt r0, #0x4000
        bkpt #0
        """
    )
    result = machine.run()
    assert result.status == "halted"
    assert result.registers["r0"] == 0x40001000


def test_unknown_instruction_and_far_branch_fail():
    with pytest.raises(AssembleError, match="unknown instruction"):
        assemble("svc #0")
    padding = "\n".join(".word 0" for _ in range(600))
    with pytest.raises(AssembleError, match="out of range"):
        assemble(f"b far\n{padding}\nfar:\n    bkpt #0\n")
    with pytest.raises(AssembleError, match="duplicate label"):
        assemble("reset:\nreset:\n    nop")
