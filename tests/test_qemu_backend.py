# SPDX-License-Identifier: MIT
"""QEMU Cortex-M backend.

Decoder and registry checks always run. Anything that spawns
``qemu-system-arm`` is skipped when that binary is not on PATH, so the
default suite stays green on a machine that only has Unicorn.
"""

from __future__ import annotations

import os
import shutil
from contextlib import contextmanager

import pytest

from rehost.backends.qemu_cortexm import (
    QemuCortexM,
    decode_thumb,
    gdb_register_map,
    resolve_qemu,
    thumb2_memory_base,
)
from rehost.backends.registry import available_backends, create_backend
from rehost.cli import main
from rehost.config import parse_config
from rehost.errors import BackendError, ConfigError
from rehost.fixtures.assemble import assemble, assemble_image
from rehost.machine import Machine

_QEMU = os.environ.get("JIG_QEMU") or shutil.which("qemu-system-arm")
requires_qemu = pytest.mark.skipif(_QEMU is None, reason="qemu-system-arm is not installed")


def test_qemu_and_renode_names_are_registered_and_riscv_stays_planned():
    names = available_backends()
    assert "cortex-m" in names
    assert "qemu" in names
    assert "qemu-cortex-m" in names
    assert "renode" in names
    assert "renode-cortex-m" in names
    with pytest.raises(ConfigError, match="planned adapter"):
        create_backend("riscv")


def test_omitted_backend_stays_unicorn():
    machine = Machine.from_fixture("uart-gpio")
    assert machine.backend.arch == "cortex-m"


def test_explicit_unicorn_flag(capsys):
    code = main(["run", "--backend", "unicorn", "--fixture", "uart-gpio"])
    out = capsys.readouterr().out
    assert code == 0
    assert "status: halted" in out
    assert "uart0 tx: 41" in out
    assert "gpioa odr: 0x1" in out


def test_plugins_list_qemu(capsys):
    assert main(["plugins"]) == 0
    out = capsys.readouterr().out
    assert "\n  qemu\n" in out or "\n  qemu-cortex-m\n" in out
    assert "cortex-m" in out


def test_missing_qemu_binary_names_the_program(monkeypatch):
    monkeypatch.delenv("JIG_QEMU", raising=False)
    monkeypatch.setattr("rehost.backends.qemu_cortexm.shutil.which", lambda _name: None)
    with pytest.raises(BackendError, match="qemu-system-arm"):
        resolve_qemu()
    with pytest.raises(BackendError, match="qemu-system-arm"):
        QemuCortexM(binary="/no/such/qemu-system-arm")


def test_cli_names_missing_qemu(monkeypatch, capsys):
    monkeypatch.delenv("JIG_QEMU", raising=False)
    monkeypatch.setattr("rehost.backends.qemu_cortexm.shutil.which", lambda _name: None)
    code = main(["run", "--backend", "qemu", "--fixture", "uart-gpio"])
    err = capsys.readouterr().err
    assert code == 4
    assert "qemu-system-arm" in err


def test_decode_fixture_str_and_ldr():
    blob = assemble("str r1, [r0, #4]\nldr r2, [r0, #0]\n")
    store = int.from_bytes(blob[:2], "little")
    load = int.from_bytes(blob[2:4], "little")
    regs = {0: 0x40000000, 1: 0x41, 2: 0}

    def read_reg(number: int) -> int:
        return regs.get(number, 0)

    decoded = decode_thumb(store, 0, 0x1A, read_reg)
    assert decoded is not None
    assert decoded.size == 2
    assert decoded.ops[0].store
    assert decoded.ops[0].address == 0x40000004
    assert decoded.ops[0].width == 4
    assert decoded.ops[0].rt == 1
    assert decoded.ops[0].value == 0x41

    decoded = decode_thumb(load, 0, 0x1C, read_reg)
    assert decoded is not None
    assert not decoded.ops[0].store
    assert decoded.ops[0].address == 0x40000000
    assert decoded.ops[0].rt == 2


def test_decode_literal_ldrb_and_thumb2_imm12():
    def read_reg(number: int) -> int:
        return {1: 0x40001000, 3: 0x7}.get(number, 0)

    # LDR (literal) T1: 01001 Rd imm8. Rd = r3, imm8 = 1 -> pool at align(pc+4)+4.
    literal = 0x4800 | (3 << 8) | 1
    decoded = decode_thumb(literal, 0, 0x10, read_reg)
    assert decoded is not None
    assert decoded.ops[0].address == ((0x10 + 4) & ~3) + 4
    assert decoded.ops[0].rt == 3

    # LDRB (immediate) T1 at r1 + 2.
    ldrb = 0x7800 | (2 << 6) | (1 << 3) | 0
    decoded = decode_thumb(ldrb, 0, 0, read_reg)
    assert decoded is not None
    assert decoded.ops[0].address == 0x40001002
    assert decoded.ops[0].width == 1
    assert not decoded.ops[0].store

    # STR (immediate) T3: hw1 = 0xF8C0|Rn, hw2 = Rt<<12|imm12. r3 -> [r1, #8].
    decoded = decode_thumb(0xF8C1, (3 << 12) | 8, 0, read_reg)
    assert decoded is not None
    assert decoded.size == 4
    assert decoded.ops[0].store
    assert decoded.ops[0].address == 0x40001008
    assert decoded.ops[0].value == 0x7

    assert decode_thumb(0x2001, 0, 0, read_reg) is None  # movs r0, #1
    assert thumb2_memory_base(0xF240) is None  # movw
    assert thumb2_memory_base(0xF840) == 0  # Thumb-2 store we do not fully decode


def test_gdb_register_map_matches_m_profile_xml():
    core = """
    <feature name="org.gnu.gdb.arm.m-profile">
      <reg name="r0" bitsize="32"/>
      <reg name="sp" bitsize="32" regnum="13"/>
      <reg name="lr" bitsize="32"/>
      <reg name="pc" bitsize="32"/>
      <reg name="xpsr" bitsize="32" regnum="25"/>
    </feature>
    """
    system = """
    <feature name="org.gnu.gdb.arm.m-system">
      <reg name="msp" bitsize="32" regnum="26"/>
      <reg name="psp" bitsize="32" regnum="27"/>
      <reg name="primask" bitsize="32" regnum="28"/>
      <reg name="control" bitsize="32" regnum="29"/>
      <reg name="basepri" bitsize="32" regnum="30"/>
      <reg name="faultmask" bitsize="32" regnum="31"/>
    </feature>
    """
    names = gdb_register_map([core, system])
    assert names["r0"] == 0
    assert names["sp"] == 13
    assert names["lr"] == 14
    assert names["pc"] == 15
    assert names["xpsr"] == 25
    assert names["msp"] == 26
    assert names["control"] == 29
    assert names["basepri"] == 30
    assert names["faultmask"] == 31


@contextmanager
def _qemu_machine(source: str, *, regions: list[dict] | None = None, run: dict | None = None):
    backend = QemuCortexM()
    try:
        memory: list[dict] = [
            {"name": "flash", "base": 0, "size": 0x1000, "perms": "rx"},
            {"name": "sram", "base": 0x20000000, "size": 0x1000, "perms": "rw"},
        ]
        if regions:
            memory.extend(regions)
        run_cfg = {"timeout_ms": 2000, "max_instructions": 1000, "halt_on_bkpt": True}
        if run:
            run_cfg.update(run)
        machine = Machine(
            parse_config(
                {
                    "name": "qemu-synth",
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


@requires_qemu
def test_registers_roundtrip_through_the_gdbstub():
    created = create_backend("qemu-cortex-m")
    backend = QemuCortexM()
    try:
        assert isinstance(created, QemuCortexM)
        assert created.arch == "qemu-cortex-m"
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
        created.close()


@requires_qemu
def test_synthetic_sram_program_runs_on_qemu():
    source = """
        movs r0, #0x11
        movw r1, #0
        movt r1, #0x2000
        str r0, [r1, #0]
        adds r0, #1
        bkpt #0
    """
    with _qemu_machine(source) as machine:
        result = machine.run()
        assert result.status == "halted"
        assert result.detail == "bkpt"
        assert result.registers["r0"] == 0x12
        assert machine.read_u32(0x20000000) == 0x11


@requires_qemu
def test_uart_gpio_matches_unicorn():
    uni = Machine.from_fixture("uart-gpio")
    qemu_backend = QemuCortexM()
    try:
        qemu = Machine.from_fixture("uart-gpio", backend=qemu_backend)
        left = uni.run()
        right = qemu.run()
        assert right.status == left.status == "halted"
        assert right.detail == left.detail == "bkpt"
        assert right.pc == left.pc == 0x42
        assert right.sp == left.sp == 0x20004000
        assert right.lr == left.lr
        assert right.instructions == left.instructions == 20
        assert bytes(qemu.peripheral("uart0").tx) == bytes(uni.peripheral("uart0").tx) == b"A"
        assert qemu.peripheral("gpioa").odr == uni.peripheral("gpioa").odr == 1
        assert qemu.read_memory(0x20000000, 12) == uni.read_memory(0x20000000, 12)
    finally:
        qemu_backend.close()


@requires_qemu
def test_unmapped_load_and_flash_store_fault_like_the_hooks():
    unmapped = """
        movw r0, #0
        movt r0, #0x6000
        ldr r1, [r0, #0]
        bkpt #0
    """
    with _qemu_machine(unmapped) as machine:
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
    with _qemu_machine(store) as machine:
        result = machine.run()
    assert result.status == "fault"
    assert "prot" in result.detail


@requires_qemu
def test_wfi_and_svc_do_not_block_or_enter_qemu_vectoring():
    source = """
        wfi
        svc #1
        movs r0, #3
        bkpt #0
    """
    with _qemu_machine(source) as machine:
        result = machine.run()
        assert result.status == "halted"
        assert result.detail == "bkpt"
        assert result.registers["r0"] == 3


@requires_qemu
def test_cli_uart_gpio_under_qemu(capsys):
    code = main(["run", "--backend", "qemu", "--fixture", "uart-gpio"])
    out = capsys.readouterr().out
    assert code == 0, capsys.readouterr().err
    assert "status: halted" in out
    assert "detail: bkpt" in out
    assert "pc: 0x00000042" in out
    assert "uart0 tx: 41" in out
    assert "gpioa odr: 0x1" in out
    assert "instructions: 20" in out
