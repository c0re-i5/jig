# SPDX-License-Identifier: MIT
"""UART RX injection: immediate, after N instructions, and after TX goes quiet."""

from __future__ import annotations

from rehost.cli import main
from rehost.errors import SerialError
from rehost.fixtures.assemble import assemble
from rehost.serial import attach_feed, decode_escapes, normalize_line, run_lines
from tests.helpers import machine_from_asm

_UART = {
    "name": "uart0",
    "base": 0x40000000,
    "size": 0x100,
    "perms": "rw",
    "peripheral": "uart",
    "config": {"tx_empty_mask": 0x80, "rx_ready_mask": 0x01},
}

_POLL = """
    movw r0, #0
    movt r0, #0x4000
poll:
    ldr r1, [r0, #4]
    cmp r1, #0x81
    bne poll
    ldr r1, [r0, #0]
    str r1, [r0, #0]
"""


def test_decode_and_normalize_lines():
    assert decode_escapes(r"$$\r\n") == b"$$\r\n"
    assert decode_escapes(r"\x3f") == b"?"
    assert normalize_line("G91 G0 X1") == b"G91 G0 X1\n"
    assert normalize_line(b"ok\r") == b"ok\r"
    try:
        decode_escapes("\u00e9")
    except SerialError:
        pass
    else:
        raise AssertionError("non-ASCII serial text should be rejected")


def test_serial_after_instructions_queues_once_the_count_is_reached():
    machine = machine_from_asm(
        _POLL + "bkpt #0\n",
        regions=[_UART],
        run={"timeout_ms": 1000, "max_instructions": 5000},
    )
    feed = attach_feed(machine, [b"A"], after_instructions=25)
    result = machine.run()
    assert result.status == "halted", result.detail
    assert result.instructions >= 25
    assert bytes(machine.peripheral("uart0").tx) == b"A"
    assert feed.sent == [b"A"]


def test_serial_idle_waits_for_tx_and_paces_lines():
    source = """
        movw r0, #0
        movt r0, #0x4000
        movs r1, #0x48
        str r1, [r0, #0]
        movs r4, #0
    """ + _POLL + """
        cmp r1, #10
        bne poll
        adds r4, #1
        cmp r4, #2
        bne poll
        bkpt #0
    """
    machine = machine_from_asm(
        source,
        regions=[_UART],
        run={"timeout_ms": 1000, "max_instructions": 20000},
    )
    result, tx, _new = run_lines(machine, ["AB", "C"], idle_instructions=8)
    assert result.status == "halted", result.detail
    assert tx == b"HABC\n\n" or tx == b"HAB\nC\n"
    assert b"AB\n" in tx and tx.endswith(b"C\n")
    assert tx.startswith(b"H")


def test_serial_settle_holds_the_next_chunk():
    source = """
        movw r0, #0
        movt r0, #0x4000
        movs r1, #0x48
        str r1, [r0, #0]
        movs r4, #0
    """ + _POLL + """
        cmp r1, #10
        bne poll
        adds r4, #1
        cmp r4, #2
        bne poll
        bkpt #0
    """
    machine = machine_from_asm(
        source,
        regions=[_UART],
        run={"timeout_ms": 1000, "max_instructions": 5000},
    )
    feed = attach_feed(
        machine,
        [b"A\n", b"B\n"],
        idle_instructions=4,
        settle_before=[0, 200],
    )
    result = machine.run()
    assert result.status == "halted", result.detail
    assert feed.sent == [b"A\n", b"B\n"]
    assert bytes(machine.peripheral("uart0").tx) == b"HA\nB\n"
    assert result.instructions >= 200


def test_serial_idle_does_not_send_before_the_first_tx_byte():
    machine = machine_from_asm(
        "bkpt #0\n",
        regions=[_UART],
        run={"timeout_ms": 200, "max_instructions": 20},
    )
    feed = attach_feed(machine, [b"A"], idle_instructions=4)
    result = machine.run()
    assert result.status == "halted"
    assert feed.sent == []
    assert bytes(machine.peripheral("uart0").rx) == b""


def test_cli_serial_in_and_after(tmp_path, capsys):
    image = tmp_path / "image.bin"
    image.write_bytes(assemble(_POLL + "bkpt #0\n"))
    config = tmp_path / "machine.yaml"
    config.write_text(
        """
        name: serial-demo
        arch: cortex-m
        memory:
          - {name: flash, base: 0, size: 0x1000, perms: rx}
          - {name: sram, base: 0x20000000, size: 0x1000, perms: rw}
          - name: uart0
            base: 0x40000000
            size: 0x100
            perms: rw
            peripheral: uart
            config: {tx_empty_mask: 0x80, rx_ready_mask: 0x01}
        boot: {mode: entry, sp: 0x20001000, entry: 0}
        run: {timeout_ms: 1000, max_instructions: 5000}
        """,
        encoding="utf-8",
    )
    code = main(
        [
            "run",
            "--config",
            str(config),
            "--firmware",
            str(image),
            "--serial-in",
            r"\x41",
            "--serial-after",
            "10",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert "status: halted" in captured.out
    assert "uart0 tx: 41" in captured.out

    code = main(["run", "--fixture", "uart-gpio", "--serial-in", r"\q"])
    err = capsys.readouterr().err
    assert code == 4
    assert "unknown escape" in err
