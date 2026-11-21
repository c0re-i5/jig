# SPDX-License-Identifier: MIT
"""CmpLog shadow runs and input-to-state replacement on a synthetic gate.

The program is assembled with the in-repo Thumb assembler. It is not
firmware. A 4-byte word compare hides the checksum, so a one-byte walk
never reaches the guarded BKPT inside the budget. ``--cmplog`` does.
"""

from __future__ import annotations

from pathlib import Path

from rehost.cli import main
from rehost.cmplog import CmpLog, Comparison, input_to_state, thumb_expand_imm
from rehost.fixtures.assemble import assemble_image
from rehost.fuzz import PersistentHarness, is_fuzz_crash
from tests.helpers import machine_from_asm

# 0xA1B2C3D4 as a little-endian word, then three data bytes and a checksum.
# The checksum byte must equal (b4 + b5 + b6 + 0x3C) & 0xFF. Zeros fail both
# checks: the word is not the magic, and a zero checksum is not 0x3C.
_MAGIC = (0xA1B2C3D4).to_bytes(4, "little")
_SOLUTION = _MAGIC + bytes(3) + bytes([0x3C])
_BUDGET = 80

_GATE = """
movw r0, #0x0100
movt r0, #0x2000
movw r2, #0xC3D4
movt r2, #0xA1B2
ldr r1, [r0, #0]
cmp r1, r2
bne fail
ldrb r3, [r0, #4]
ldrb r4, [r0, #5]
adds r3, r4
ldrb r4, [r0, #6]
adds r3, r4
adds r3, #0x3C
ldrb r4, [r0, #7]
cmp r3, r4
bne fail
guarded:
bkpt #1
fail:
bkpt #0
"""

# Thumb-2 encodings executed below. The branch after each one fails if
# Unicorn did not actually compare, so a decoder-only match is not enough.
_CMP_REG = 0x0F01EBB0  # cmp r0, r1
_CMP_LSL4 = 0x1F01EBB0  # cmp r0, r1, lsl #4
_CMP_IMM_4A = 0x0F4AF1B0  # cmp r0, #0x4A
_CMP_IMM_ROT = 0x4F00F1B0  # cmp r0, #0x80000000


def _gate_machine():
    _image, labels = assemble_image(_GATE)
    return machine_from_asm(
        _GATE,
        fuzz={
            "mode": "buffer",
            "buffer": {"address": 0x20000100, "max_size": 16},
            "crash_addresses": [labels["guarded"]],
        },
        name="cmplog-gate",
    )


def _summary_value(text: str, key: str) -> int:
    for line in text.splitlines():
        if line.startswith(f"{key}: "):
            return int(line.split(":", 1)[1].strip())
    raise AssertionError(f"{key} missing from summary:\n{text}")


def test_thumb_expand_imm_matches_the_arm_rules():
    assert thumb_expand_imm(0x04A) == 0x4A
    assert thumb_expand_imm(0x101) == 0x00010001
    assert thumb_expand_imm(0x202) == 0x02000200
    assert thumb_expand_imm(0x303) == 0x03030303
    assert thumb_expand_imm(0x400) == 0x80000000
    assert thumb_expand_imm(0x100) is None


def test_wide_compares_execute_and_are_logged():
    source = f"""
        movs r0, #1
        movs r1, #3
        cmp r0, r0
        .word {_CMP_LSL4}
        beq bad
        movs r1, #2
        cmp r0, r0
        .word {_CMP_REG}
        beq bad
        cmp r0, r0
        .word {_CMP_IMM_4A}
        beq bad
        cmp r0, r0
        .word {_CMP_IMM_ROT}
        beq bad
        movs r3, #9
        b done
        bad:
            movs r3, #0
        done:
            bkpt #0
    """
    machine = machine_from_asm(source)
    log = CmpLog()
    log.active = True
    machine.attach_cmplog(log)
    result = machine.run()
    assert result.status == "halted", result.detail
    assert result.registers["r3"] == 9
    observed = {(item.left, item.right) for item in log.pairs}
    assert (1, 48) in observed
    assert (1, 2) in observed
    assert (1, 0x4A) in observed
    assert (1, 0x80000000) in observed


def test_load_and_compare_logs_the_loaded_width():
    machine = machine_from_asm(
        """
        movw r0, #0x0100
        movt r0, #0x2000
        movs r3, #1
        ldrb r1, [r0, #0]
        cmp r1, #0x4A
        ldr r2, [r0, #0]
        cmp r2, r3
        bkpt #0
        """,
        fuzz={
            "mode": "buffer",
            "buffer": {"address": 0x20000100, "max_size": 4},
        },
    )
    log = CmpLog()
    machine.attach_cmplog(log)
    harness = PersistentHarness(machine)
    log.active = False
    harness.exec_one(b"\x00\x00\x00\x00")
    assert log.pairs == []
    log.active = True
    harness.exec_one(b"\x00\x00\x00\x00")
    kinds = {(item.kind, item.left, item.right, item.widths) for item in log.pairs}
    assert ("cmp", 0, 0x4A, (1,)) in kinds
    # The word load is the instruction before the second compare, so width 4
    # is recorded even though both values fit in a byte.
    word = [item for item in log.pairs if item.left == 0 and item.right == 1]
    assert word and 4 in word[0].widths


def test_input_to_state_substitutes_endian_and_neighbors():
    data = bytes(8)
    pairs = [Comparison(0, 0x11223344, (4,), "cmp", 0)]
    candidates = input_to_state(data, pairs, limit=100)
    assert candidates[0].startswith((0x11223344).to_bytes(4, "little"))
    assert any(item.startswith((0x11223344).to_bytes(4, "big")) for item in candidates)
    assert any(item.startswith((0x11223345).to_bytes(4, "little")) for item in candidates)
    assert any(item.startswith((0x11223343).to_bytes(4, "little")) for item in candidates)
    assert all(len(item) == len(data) for item in candidates)
    assert data not in candidates


def test_subs_and_cmn_log_the_pre_instruction_operands():
    machine = machine_from_asm(
        """
        movs r0, #5
        movs r1, #3
        cmn r0, r1
        subs r0, r1
        bkpt #0
        """
    )
    log = CmpLog()
    log.active = True
    machine.attach_cmplog(log)
    result = machine.run()
    assert result.status == "halted"
    assert result.registers["r0"] == 2
    observed = [(item.kind, item.left, item.right) for item in log.pairs]
    assert ("cmn", 5, 3) in observed
    assert ("subs", 5, 3) in observed


def test_solution_reaches_the_guard_and_zeros_do_not():
    machine = _gate_machine()
    harness = PersistentHarness(machine)
    opened = harness.exec_one(_SOLUTION)
    assert is_fuzz_crash(opened, machine.config.fuzz)
    closed = harness.exec_one(bytes(8))
    assert closed.status == "halted"
    assert not is_fuzz_crash(closed, machine.config.fuzz)
    # A one-byte change of the zero seed cannot satisfy the word compare.
    almost = bytearray(8)
    almost[0] = _MAGIC[0]
    missed = harness.exec_one(bytes(almost))
    assert not is_fuzz_crash(missed, machine.config.fuzz)


def test_cmplog_reaches_the_guard_and_the_same_budget_does_not(tmp_path, capsys):
    """Same budget: CmpLog reaches the guard, the byte walk does not."""
    image, labels = assemble_image(_GATE)
    image_path = tmp_path / "gate.bin"
    image_path.write_bytes(image)
    config = tmp_path / "gate.yaml"
    config.write_text(
        "\n".join(
            [
                "name: cmplog-gate",
                "description: synthetic word-and-checksum gate for the CmpLog test",
                "arch: cortex-m",
                "endian: little",
                "memory:",
                "  - {name: flash, base: 0, size: 0x1000, perms: rx}",
                "  - {name: sram, base: 0x20000000, size: 0x1000, perms: rw}",
                "boot: {mode: entry, sp: 0x20001000, entry: 0}",
                "run: {timeout_ms: 200, max_instructions: 1000, halt_on_bkpt: true}",
                "fuzz:",
                "  mode: buffer",
                "  buffer: {address: 0x20000100, max_size: 16}",
                f"  crash_addresses: [{labels['guarded']}]",
                "",
            ]
        ),
        encoding="utf-8",
    )
    seed = tmp_path / "zero.bin"
    seed.write_bytes(bytes(8))

    def invoke(out: Path, cmplog: bool) -> str:
        argv = [
            "fuzz",
            "--config",
            str(config),
            "--firmware",
            str(image_path),
            "--input",
            str(seed),
            "--out",
            str(out),
            "--max-execs",
            str(_BUDGET),
            "--stop-on-crash",
            "--rng-seed",
            "1",
        ]
        if cmplog:
            argv.append("--cmplog")
        code = main(argv)
        captured = capsys.readouterr()
        assert code == 0, captured.err
        return captured.out

    opened = invoke(tmp_path / "on", True)
    assert _summary_value(opened, "crashes") == 1
    assert _summary_value(opened, "execs") < _BUDGET
    crashes = list((tmp_path / "on" / "crashes").iterdir())
    assert len(crashes) == 1
    assert crashes[0].read_bytes() == _SOLUTION

    closed = invoke(tmp_path / "off", False)
    assert _summary_value(closed, "crashes") == 0
    assert _summary_value(closed, "execs") == _BUDGET
    assert not (tmp_path / "off" / "crashes").exists()
