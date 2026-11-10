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
    assert assemble("wfi") == bytes.fromhex("30bf")
    assert assemble("wfe") == bytes.fromhex("20bf")
    assert assemble("cpsid i") == bytes.fromhex("72b6")
    assert assemble("cpsie i") == bytes.fromhex("62b6")
    assert assemble("bx lr") == bytes.fromhex("7047")
    assert assemble("adds r1, #1") == bytes.fromhex("0131")
    assert assemble("mov r0, lr") == bytes.fromhex("7046")
    assert assemble("add r0, sp, #0") == bytes.fromhex("00a8")
    assert assemble("svc #0") == bytes.fromhex("00df")
    assert assemble("mrs r0, ipsr") == bytes.fromhex("eff30580")
    assert assemble("msr basepri, r1") == bytes.fromhex("81f31188")
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


def test_cmp_ldrb_and_conditional_branch_execute():
    assert assemble("cmp r1, #0x4A") == bytes.fromhex("4a29")
    assert assemble("ldrb r1, [r0, #0]") == bytes.fromhex("0178")
    assert assemble("ldrb r1, [r0, #1]") == bytes.fromhex("4178")
    taken = machine_from_asm(
        """
        movs r0, #0
        cmp r0, #1
        bne skip
        movs r1, #1
        b done
        skip:
            movs r1, #2
        done:
            bkpt #0
        """
    )
    result = taken.run()
    assert result.status == "halted"
    assert result.registers["r1"] == 2
    not_taken = machine_from_asm(
        """
        movs r0, #1
        cmp r0, #1
        bne skip
        movs r1, #1
        b done
        skip:
            movs r1, #2
        done:
            bkpt #0
        """
    )
    result = not_taken.run()
    assert result.registers["r1"] == 1
    machine = machine_from_asm(
        """
        movw r0, #0
        movt r0, #0x2000
        ldrb r1, [r0, #1]
        bkpt #0
        """
    )
    machine.write_memory(0x20000000, b"\x11\x22\x33\x44")
    assert machine.run().registers["r1"] == 0x22


def test_unknown_instruction_and_far_branch_fail():
    with pytest.raises(AssembleError, match="unknown instruction"):
        assemble("udf #0")
    padding = "\n".join(".word 0" for _ in range(600))
    with pytest.raises(AssembleError, match="out of range"):
        assemble(f"b far\n{padding}\nfar:\n    bkpt #0\n")
    with pytest.raises(AssembleError, match="duplicate label"):
        assemble("reset:\nreset:\n    nop")
