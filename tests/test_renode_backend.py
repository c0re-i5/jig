# SPDX-License-Identifier: MIT
"""Renode Cortex-M backend.

Parser and registry checks always run. Anything that spawns ``renode`` is
skipped when that binary is not on PATH, so the default suite stays green
on a machine that only has Unicorn.
"""

from __future__ import annotations

import os
import shutil
from contextlib import contextmanager

import pytest

from rehost.backends.renode_cortexm import (
    RENODE_PLATFORM,
    RenodeCortexM,
    parse_byte_list,
    parse_registration_points,
    resolve_renode,
)
from rehost.backends.registry import available_backends, create_backend
from rehost.cli import main
from rehost.config import parse_config
from rehost.errors import BackendError
from rehost.fixtures.assemble import assemble_image
from rehost.machine import Machine


def _renode_binary() -> str | None:
    path = os.environ.get("JIG_RENODE") or shutil.which("renode")
    if path and os.path.isfile(path) and os.access(path, os.X_OK):
        return path
    return None


requires_renode = pytest.mark.skipif(_renode_binary() is None, reason="renode is not installed")


def test_renode_names_are_registered():
    names = available_backends()
    assert "cortex-m" in names
    assert "renode" in names
    assert "renode-cortex-m" in names


def test_parse_registration_points_are_inclusive():
    flash = parse_registration_points("[\n<0x00000000, 0x000FFFFF>, \n]")
    assert flash == [(0x0, 0x100000)]
    ram = parse_registration_points("[<0x00800000, 0x0083FFFF>, <0x20000000, 0x2003FFFF>,]")
    assert ram == [(0x00800000, 0x40000), (0x20000000, 0x40000)]
    assert parse_registration_points("no ranges here") == []


def test_parse_byte_list_reads_a_monitor_dump():
    text = "[\n0x01, 0x20, 0x00, 0xBE,\n]"
    assert parse_byte_list(text) == bytes([0x01, 0x20, 0x00, 0xBE])


def test_missing_renode_binary_names_the_program(monkeypatch):
    monkeypatch.delenv("JIG_RENODE", raising=False)
    monkeypatch.setattr("rehost.backends.renode_cortexm.shutil.which", lambda _name: None)
    with pytest.raises(BackendError, match="renode"):
        resolve_renode()
    with pytest.raises(BackendError, match="renode"):
        RenodeCortexM(binary="/no/such/renode")


def test_cli_names_missing_renode(monkeypatch, capsys):
    monkeypatch.delenv("JIG_RENODE", raising=False)
    monkeypatch.setattr("rehost.backends.renode_cortexm.shutil.which", lambda _name: None)
    code = main(["run", "--backend", "renode", "--fixture", "uart-gpio"])
    err = capsys.readouterr().err
    assert code == 4
    assert "renode" in err


def test_plugins_list_renode(capsys):
    assert main(["plugins"]) == 0
    out = capsys.readouterr().out
    assert "\n  renode\n" in out or "\n  renode-cortex-m\n" in out
    assert "cortex-m" in out


@contextmanager
def _renode_machine(source: str, *, regions: list[dict] | None = None, run: dict | None = None):
    backend = RenodeCortexM()
    try:
        memory: list[dict] = [
            {"name": "flash", "base": 0, "size": 0x1000, "perms": "rx"},
            {"name": "sram", "base": 0x20000000, "size": 0x1000, "perms": "rw"},
        ]
        if regions:
            memory.extend(regions)
        run_cfg = {"timeout_ms": 5000, "max_instructions": 1000, "halt_on_bkpt": True}
        if run:
            run_cfg.update(run)
        machine = Machine(
            parse_config(
                {
                    "name": "renode-synth",
                    "arch": "cortex-m",
                    "memory": memory,
                    "boot": {"mode": "entry", "sp": 0x20001000, "entry": 0},
                    "run": run_cfg,
                }
            ),
            backend=backend,
        )
        image, _labels = assemble_image(source)
        machine.load_image(image)
        yield machine
    finally:
        backend.close()


@requires_renode
def test_registers_roundtrip_through_the_monitor():
    backend = create_backend("renode-cortex-m")
    try:
        assert isinstance(backend, RenodeCortexM)
        assert backend.arch == "renode-cortex-m"
        assert backend.platform == RENODE_PLATFORM
        backend.write_register("r0", 0x12345678)
        assert backend.read_register("r0") == 0x12345678
        backend.write_register("sp", 0x20000003)
        assert backend.read_register("sp") == 0x20000000
        backend.write_register("msp", 0x20002000)
        backend.write_register("psp", 0x20003000)
        backend.write_register("primask", 1)
        backend.write_register("control", 0)
        backend.write_register("xpsr", 1 << 24)
        values = backend.read_registers()
        assert values["msp"] == 0x20002000
        assert values["psp"] == 0x20003000
        assert values["primask"] == 1
        assert values["control"] == 0
        assert values["xpsr"] & (1 << 24)
    finally:
        backend.close()


@requires_renode
def test_synthetic_sram_program_runs_on_renode():
    source = """
        movs r0, #0x11
        movw r1, #0
        movt r1, #0x2000
        str r0, [r1, #0]
        adds r0, #1
        bkpt #0
    """
    with _renode_machine(source) as machine:
        result = machine.run()
        assert result.status == "halted", result.detail
        assert result.detail == "bkpt"
        assert result.registers["r0"] == 0x12
        assert machine.read_u32(0x20000000) == 0x11


@requires_renode
def test_uart_gpio_matches_unicorn():
    uni = Machine.from_fixture("uart-gpio")
    renode_backend = RenodeCortexM()
    try:
        renode = Machine.from_fixture("uart-gpio", backend=renode_backend)
        left = uni.run()
        right = renode.run()
        assert right.status == left.status == "halted", right.detail
        assert right.detail == left.detail == "bkpt"
        assert right.pc == left.pc == 0x42
        assert right.sp == left.sp == 0x20004000
        assert right.lr == left.lr
        assert right.instructions == left.instructions == 20
        assert bytes(renode.peripheral("uart0").tx) == bytes(uni.peripheral("uart0").tx) == b"A"
        assert renode.peripheral("gpioa").odr == uni.peripheral("gpioa").odr == 1
        assert renode.read_memory(0x20000000, 12) == uni.read_memory(0x20000000, 12)
    finally:
        renode_backend.close()


@requires_renode
def test_unmapped_load_and_flash_store_fault_like_the_hooks():
    unmapped = """
        movw r0, #0
        movt r0, #0x6000
        ldr r1, [r0, #0]
        bkpt #0
    """
    with _renode_machine(unmapped) as machine:
        result = machine.run()
    assert result.status == "fault"
    assert "unmapped" in result.detail

    store = """
        movs r1, #1
        movw r0, #0
        movt r0, #0
        str r1, [r0, #8]
        bkpt #0
    """
    with _renode_machine(store) as machine:
        result = machine.run()
    assert result.status == "fault"
    assert "prot" in result.detail


@requires_renode
def test_wfi_and_svc_do_not_block_or_enter_renode_vectoring():
    source = """
        wfi
        svc #1
        movs r0, #3
        bkpt #0
    """
    with _renode_machine(source) as machine:
        result = machine.run()
        assert result.status == "halted", result.detail
        assert result.detail == "bkpt"
        assert result.registers["r0"] == 3


@requires_renode
def test_free_window_outside_platform_ram_is_mapped():
    source = """
        movs r0, #0x5a
        movw r1, #0
        movt r1, #0x2100
        str r0, [r1, #0]
        ldr r2, [r1, #0]
        bkpt #0
    """
    regions = [{"name": "extra", "base": 0x21000000, "size": 0x1000, "perms": "rw"}]
    with _renode_machine(source, regions=regions) as machine:
        result = machine.run()
        assert result.status == "halted", result.detail
        assert result.registers["r2"] == 0x5A
        assert machine.read_u32(0x21000000) == 0x5A


@requires_renode
def test_cli_uart_gpio_under_renode(capsys):
    code = main(["run", "--backend", "renode", "--fixture", "uart-gpio"])
    out = capsys.readouterr().out
    assert code == 0, capsys.readouterr().err
    assert "status: halted" in out
    assert "detail: bkpt" in out
    assert "pc: 0x00000042" in out
    assert "uart0 tx: 41" in out
    assert "gpioa odr: 0x1" in out
    assert "instructions: 20" in out
