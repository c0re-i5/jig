# SPDX-License-Identifier: MIT
"""Fault classes, bucket ids, and the crash report written by a campaign."""

from __future__ import annotations

import hashlib
import json
import shlex

from rehost.cli import main
from rehost.coverage import MAP_SIZE, edge_location
from rehost.fuzz import PersistentHarness
from rehost.machine import Machine
from rehost.result import RunResult
from rehost.triage import (
    ReplayTarget,
    TriageStore,
    bucket_id,
    bucket_material,
    classify,
    guest_reader,
)
from tests.helpers import machine_from_asm

_FUZZ = {
    "mode": "buffer",
    "buffer": {"address": 0x20000100, "max_size": 16},
}


def test_fuzz_crash_bucket_matches_the_readme():
    """The README quotes this material line. It is the whole path of ``JIG!``."""
    machine = Machine.from_fixture("fuzz-crash")
    classification = classify(PersistentHarness(machine).exec_one(b"JIG!"), memory=machine.memory)
    assert classification.fault_class == "unmapped_fetch"
    assert classification.fault_address == 0x60000000
    assert (
        classification.material
        == "unmapped_fetch|fetch|60000000|-|00000026,00000028,0000002c,00000030|-|26,29,28,19"
    )
    assert classification.bucket_id == "e14172fe0db2ca7e"


def test_bucket_material_is_the_documented_line():
    material = bucket_material(
        fault_class="unmapped_fetch",
        reason="fetch",
        fault_pc=0x60000001,
        lr_fingerprint=None,
        preceding_pcs=(0x10, 0x14),
        handler_frame=None,
        edges=(9, 3, 1),
    )
    assert material == "unmapped_fetch|fetch|60000000|-|00000010,00000014|-|9,3,1"
    assert bucket_id(material) == hashlib.sha256(material.encode("ascii")).hexdigest()[:16]


def test_retired_tail_matches_the_coverage_edge_update():
    result = machine_from_asm("movs r0, #1\n    movs r0, #2\n    bkpt #0").run()
    assert result.status == "halted"
    assert len(result.recent_pcs) == result.instructions == 3
    prev = 0
    expected = []
    for pc in result.recent_pcs:
        cur = edge_location(pc, MAP_SIZE - 1)
        expected.append(cur ^ prev)
        prev = cur >> 1
    assert list(result.recent_edges) == expected


def test_two_faults_bucket_apart_and_two_inputs_share_one(tmp_path):
    machine = machine_from_asm(
        """
        movw r0, #0x0100
        movt r0, #0x2000
        ldrb r1, [r0, #0]
        cmp r1, #1
        beq do_fetch
        cmp r1, #2
        beq do_read
        bkpt #0
        do_fetch:
        movw r2, #0x0001
        movt r2, #0x6000
        bx r2
        do_read:
        movw r2, #0x0000
        movt r2, #0x5000
        ldr r3, [r2, #0]
        bkpt #0
        """,
        fuzz=_FUZZ,
        name="two-fault",
    )
    harness = PersistentHarness(machine)
    first = classify(harness.exec_one(b"\x01\xff\xff"), memory=machine.memory)
    second = classify(harness.exec_one(b"\x01"), memory=machine.memory)
    other = classify(harness.exec_one(b"\x02"), memory=machine.memory)
    assert first.fault_class == "unmapped_fetch"
    assert second.fault_class == "unmapped_fetch"
    assert first.bucket_id == second.bucket_id
    assert first.material == second.material
    assert other.fault_class == "unmapped_read"
    assert other.bucket_id != first.bucket_id
    assert "not in the machine map" in first.explanation
    assert "BusFault" in first.explanation

    store = TriageStore(tmp_path, replay=ReplayTarget(("--fixture", "two-fault")))
    longer = store.record(
        b"\x01\xff\xff",
        harness.exec_one(b"\x01\xff\xff"),
        memory=machine.memory,
        machine_name="two-fault",
    )
    shorter = store.record(
        b"\x01",
        harness.exec_one(b"\x01"),
        memory=machine.memory,
        machine_name="two-fault",
    )
    distinct = store.record(
        b"\x02",
        harness.exec_one(b"\x02"),
        memory=machine.memory,
        machine_name="two-fault",
    )
    assert longer.created and longer.bucket_id == first.bucket_id
    assert shorter.replaced and shorter.seen == 2
    assert distinct.created and distinct.bucket_id == other.bucket_id
    representative = tmp_path / "buckets" / first.bucket_id / "representative"
    assert representative.read_bytes() == b"\x01"
    report = (tmp_path / "reports" / f"{first.bucket_id}.md").read_text(encoding="utf-8")
    sidecar = json.loads((tmp_path / "reports" / f"{first.bucket_id}.json").read_text(encoding="utf-8"))
    assert "Seen: 2" in report
    assert sidecar["seen"] == 2
    assert sidecar["fault_class"] == "unmapped_fetch"
    assert sidecar["material"] == first.material
    assert report.count("## Replay") == 1
    assert len(list((tmp_path / "reports").glob("*.md"))) == 2


def test_same_instruction_with_different_pointers_shares_a_bucket():
    wild = classify(_result("unmapped read_unmapped at 0x50000000 size 4"))
    other = classify(_result("unmapped read_unmapped at 0x50001000 size 4"))
    null = classify(_result("unmapped read_unmapped at 0x10 size 4"))
    assert wild.fault_class == other.fault_class == "unmapped_read"
    assert wild.bucket_id == other.bucket_id
    assert wild.fault_address != other.fault_address
    assert null.fault_class == "null_deref"
    assert null.bucket_id != wild.bucket_id


def test_architectural_faults_and_the_unicorn_bkpt_vector():
    assert classify(_result("exception 4 vector 0x00000000 is not a Thumb address")).fault_class == "memmanage"
    bus = classify(_result("exception 5 vector fetch at 0x14 failed: mem_read"))
    assert bus.fault_class == "bus_fault"
    assert bus.reason == "vector-fetch"
    lockup = classify(_result("exception 11 escalated to lockup"))
    assert lockup.fault_class == "hardfault"
    assert lockup.reason == "lockup"
    assert "HardFault" in lockup.explanation
    # Unicorn's interrupt hook uses its own vector numbers. 6 is not UsageFault.
    assert classify(_result("exception 6")).fault_class == "other"
    assert classify(_result("exception 7")).fault_class == "bkpt"
    assert classify(_result("exception return stacked xPSR.T is clear")).fault_class == "usage_fault"
    assert classify(_result("AIRCR.SYSRESETREQ")).reason == "reset"
    stacked = classify(
        _result("exception 11 could not stack at 0x1fffffe0: mem_write failed")
    )
    assert stacked.fault_class == "bad_sp"


def test_live_stops_use_the_hook_and_the_nvic_model():
    null = machine_from_asm(
        """
        movs r0, #0
        movs r1, #1
        str r1, [r0, #0]
        bkpt #0
        """
    ).run()
    null_class = classify(null)
    assert null_class.fault_class == "null_deref"
    assert null_class.access == "write"
    assert null_class.fault_address == 0
    assert null.detail.startswith("prot write")

    protected = machine_from_asm(
        """
        movw r0, #0x200
        movs r1, #1
        str r1, [r0, #0]
        bkpt #0
        """
    ).run()
    assert classify(protected).fault_class == "prot_write"
    assert classify(protected).fault_address == 0x200

    fetch = machine_from_asm(
        """
        movw r2, #0x0001
        movt r2, #0x2000
        bx r2
        """
    ).run()
    fetch_class = classify(fetch)
    assert fetch_class.fault_class == "prot_fetch"
    assert "MemManage" in fetch_class.explanation

    undefined = machine_from_asm("bkpt #0")
    undefined.load_image(b"\x00\xde")
    undefined_class = classify(undefined.run())
    assert undefined_class.fault_class == "usage_fault"
    assert undefined_class.reason == "undef"

    masked = machine_from_asm(
        """
        movs r0, #1
        msr faultmask, r0
        svc #1
        bkpt #0
        """
    ).run()
    assert classify(masked).fault_class == "hardfault"
    assert classify(masked).reason == "lockup"

    crooked = machine_from_asm(
        """
        movs r0, #1
        msr msp, r0
        svc #1
        bkpt #0
        """
    ).run()
    assert classify(crooked).fault_class == "bad_sp"
    assert classify(crooked).reason == "misaligned"

    overflow_machine = machine_from_asm(
        _vectors((11, "handler"))
        + """
        reset:
            movw r0, #0
            movt r0, #0x2000
            msr msp, r0
            svc #1
            bkpt #0
        handler:
            bkpt #1
        """,
        boot={"mode": "vector", "vector_base": 0},
    )
    overflow = overflow_machine.run()
    overflow_class = classify(overflow, memory=overflow_machine.memory)
    assert overflow.detail.startswith("exception 11 could not stack")
    assert overflow_class.fault_class == "stack_overflow"

    entered = machine_from_asm(
        _vectors((3, "hard"), (11, "svch"))
        + """
        reset:
            cpsid i
            svc #1
            bkpt #0
        svch:
            bkpt #2
        hard:
            bkpt #3
        """,
        boot={"mode": "vector", "vector_base": 0},
    )
    entered_result = entered.run()
    assert entered_result.registers["xpsr"] & 0x1FF == 3
    entered_class = classify(
        entered_result,
        memory=entered.memory,
        read_memory=guest_reader(entered),
    )
    assert entered_class.handler_frame is not None
    assert entered_class.ipsr == 3

    halted = machine_from_asm(
        "bkpt #0",
        fuzz={
            "mode": "buffer",
            "buffer": {"address": 0x20000100, "max_size": 4},
            "crash_addresses": [0],
        },
    )
    crash = PersistentHarness(halted).exec_one(b"")
    assert classify(crash).fault_class == "bkpt"


def test_campaign_report_replays_and_triage_rebuilds(tmp_path):
    seed = tmp_path / "crash.bin"
    seed.write_bytes(b"JIG!plus")
    out = tmp_path / "out"
    code = main(
        [
            "fuzz",
            "--fixture",
            "fuzz-crash",
            "--out",
            str(out),
            "--input",
            str(seed),
            "--max-execs",
            "1",
            "--stop-on-crash",
        ]
    )
    assert code == 0
    reports = list((out / "reports").glob("*.md"))
    assert len(reports) == 1
    text = reports[0].read_text(encoding="utf-8")
    assert "unmapped_fetch" in text
    assert "4a494721706c7573" in text
    command = _replay_line(text)
    assert command.startswith("jig-emu run ")
    assert "--fixture" in command and "fuzz-crash" in command
    assert main(shlex.split(command)[1:]) == 1

    longer = out / "crashes" / "id:000000,sig:11,pc:60000000"
    assert longer.is_file()
    short = out / "crashes" / "id:000001,sig:11,pc:60000000"
    short.write_bytes(b"JIG!")
    assert main(["triage", "--fixture", "fuzz-crash", "--out", str(out)]) == 0
    rebuilt = list((out / "reports").glob("*.md"))
    assert len(rebuilt) == 1
    body = rebuilt[0].read_text(encoding="utf-8")
    sidecar = json.loads(rebuilt[0].with_suffix(".json").read_text(encoding="utf-8"))
    assert sidecar["seen"] == 2
    assert sidecar["fault_class"] == "unmapped_fetch"
    assert "Seen: 2" in body
    representative = out / "buckets" / sidecar["bucket_id"] / "representative"
    assert representative.read_bytes() == b"JIG!"
    assert main(shlex.split(_replay_line(body))[1:]) == 1


def _replay_line(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("jig-emu run "):
            return line
    raise AssertionError("report has no replay command")


def _result(detail: str, pc: int = 0x20) -> RunResult:
    registers = {"pc": pc, "sp": 0x20001000, "lr": 0xFFFFFFFF, "xpsr": 0x01000000}
    return RunResult(
        status="fault",
        detail=detail,
        pc=pc,
        sp=registers["sp"],
        lr=registers["lr"],
        registers=registers,
        instructions=1,
        trace=(),
        trace_total=0,
    )


def _vectors(*handlers: tuple[int, str]) -> str:
    by_exc = dict(handlers)
    lines = [".word 0x20001000", ".thumb_word reset"]
    for exc in range(2, 16):
        handler = by_exc.get(exc)
        lines.append(f".thumb_word {handler}" if handler else ".word 0")
    return "\n".join(lines) + "\n"

