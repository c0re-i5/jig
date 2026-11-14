# SPDX-License-Identifier: MIT
"""CLI smoke tests against the synthetic fixtures."""

from __future__ import annotations

import subprocess
import sys

from rehost.cli import main


def test_fixture_run_halts(capsys):
    code = main(["run", "--fixture", "uart-gpio"])
    captured = capsys.readouterr()
    assert code == 0
    assert "status: halted" in captured.out
    assert "uart0 tx: 41" in captured.out
    assert "gpioa odr: 0x1" in captured.out
    assert captured.err == ""


def test_plugins_and_fixtures_list():
    assert main(["plugins"]) == 0
    assert main(["fixtures"]) == 0


def test_fuzz_input_and_snapshot(tmp_path, capsys):
    case = tmp_path / "case.bin"
    case.write_bytes(b"Z")
    snap = tmp_path / "after.json"
    code = main(
        [
            "run",
            "--fixture",
            "fuzz-echo",
            "--input",
            str(case),
            "--snapshot-out",
            str(snap),
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "uart0 tx: 5a" in out
    assert snap.is_file()
    assert '"arch": "cortex-m"' in snap.read_text(encoding="utf-8")


def test_plant_floor_demo_prints_tick_and_modbus():
    # The fixture has a fuzz buffer, so a non-tty stdin is a testcase. An empty
    # pipe is what a script feeds; it must not steal the Modbus exchange.
    proc = subprocess.run(
        [sys.executable, "-m", "rehost", "run", "--fixture", "plant-floor", "--modbus-read", "1:0:1"],
        input=b"",
        capture_output=True,
        check=False,
    )
    out = proc.stdout.decode()
    assert proc.returncode == 0, proc.stderr.decode()
    assert "status: halted" in out
    assert "usart2 tx: 0103021234b533" in out
    assert "gpioa odr: 0x3" in out
    assert "systick ctrl: 0x7 load: 0xffff" in out


def test_modbus_rtu_demo_prints_a_response(capsys):
    code = main(["run", "--fixture", "modbus-rtu", "--modbus-read", "1:0:1"])
    out = capsys.readouterr().out
    assert code == 0
    assert "status: halted" in out
    assert "uart0 tx: 0103021234" in out
    assert "uart0 rx_irq: 0" in out


def test_modbus_request_shape_is_usage(capsys):
    code = main(["run", "--fixture", "modbus-rtu", "--modbus-read", "1:0"])
    err = capsys.readouterr().err
    assert code == 4
    assert "SLAVE:ADDRESS:COUNT" in err


def test_firmware_without_config_is_usage(tmp_path, capsys):
    image = tmp_path / "image.bin"
    image.write_bytes(b"\x00\x00")
    code = main(["run", "--firmware", str(image)])
    err = capsys.readouterr().err
    assert code == 4
    assert "--firmware requires --config" in err


def test_unmapped_firmware_exits_nonzero(tmp_path, capsys):
    from rehost.fixtures.assemble import assemble

    image = tmp_path / "image.bin"
    image.write_bytes(
        assemble(
            """
            movw r0, #0
            movt r0, #0x6000
            ldr r1, [r0, #0]
            bkpt #0
            """
        )
    )
    config = tmp_path / "machine.yaml"
    config.write_text(
        """
        name: fault-demo
        arch: cortex-m
        memory:
          - {name: flash, base: 0, size: 0x1000, perms: rx}
          - {name: sram, base: 0x20000000, size: 0x1000, perms: rw}
        boot: {mode: entry, sp: 0x20001000, entry: 0}
        run: {timeout_ms: 200, max_instructions: 100}
        """,
        encoding="utf-8",
    )
    code = main(["run", "--config", str(config), "--firmware", str(image)])
    out = capsys.readouterr().out
    assert code == 1
    assert "status: fault" in out
