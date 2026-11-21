# SPDX-License-Identifier: MIT
"""Unicorn RV32 backend, the in-repo assembler, and the uart-gpio-rv32 fixture."""

from __future__ import annotations

import pytest

from rehost.backends import UNTIL_NEVER, available_backends, create_backend
from rehost.backends.unicorn_riscv import EBREAK_WORD, UnicornRiscv
from rehost.cli import main
from rehost.config import parse_config
from rehost.errors import AssembleError, BackendError, ConfigError, MachineError, RehostError
from rehost.fixtures import build_fixture
from rehost.fixtures.assemble_riscv import assemble
from rehost.machine import Machine
from rehost.memory import PERM_EXEC, PERM_READ, PERM_WRITE

# The fixture is 13 RV32I instructions: 12 before EBREAK, then EBREAK itself.
_FIXTURE_INSNS = 13
_FIXTURE_EBREAK = (_FIXTURE_INSNS - 1) * 4


def test_rv32_encodings_match_the_fixture_words():
    assert assemble("lui a0, 0x20000") == bytes.fromhex("37050020")
    assert assemble("addi a2, zero, 0x41") == bytes.fromhex("13061004")
    assert assemble("sb a2, 0(a1)") == bytes.fromhex("2380c500")
    assert assemble("sw a4, 0(a3)") == bytes.fromhex("23a0e600")
    assert assemble("lw a2, 4(a1)") == bytes.fromhex("03a64500")
    assert assemble("lui a5, 0xc10") == bytes.fromhex("b707c100")
    assert assemble("addi a5, a5, -18") == bytes.fromhex("9387e7fe")
    assert assemble("ebreak") == EBREAK_WORD.to_bytes(4, "little")
    assert assemble("ebreak") == bytes.fromhex("73001000")


def test_assembler_rejects_extensions_outside_the_slice():
    with pytest.raises(AssembleError, match="unknown instruction"):
        assemble("mul a0, a0, a1")
    with pytest.raises(AssembleError, match="unknown instruction"):
        assemble("c.nop")
    with pytest.raises(AssembleError, match="unknown instruction"):
        assemble("flw fa0, 0(a0)")
    with pytest.raises(AssembleError, match="signed 12"):
        assemble("addi a0, zero, 4096")


def test_riscv_names_are_registered_and_cortex_m_stays_default():
    names = available_backends()
    assert "cortex-m" in names
    assert "riscv" in names
    assert "riscv32" in names
    cpu = create_backend("riscv")
    assert isinstance(cpu, UnicornRiscv)
    assert cpu.arch == "riscv"
    assert create_backend("riscv32").arch == "riscv"
    machine = Machine.from_fixture("uart-gpio")
    assert machine.backend.arch == "cortex-m"
    with pytest.raises(ConfigError, match="unknown arch"):
        create_backend("mips")


def test_register_and_memory_round_trip_and_one_step():
    cpu = UnicornRiscv()
    cpu.map_memory(0, 0x1000, PERM_READ | PERM_WRITE | PERM_EXEC)
    image = assemble("addi a0, zero, 0x11\naddi a0, a0, 1\nebreak\n")
    cpu.write_memory(0, image)
    assert cpu.read_memory(0, len(image)) == image
    cpu.write_memory(0x100, b"\x11\x22\x33\x44")
    assert cpu.read_memory(0x100, 4) == b"\x11\x22\x33\x44"
    cpu.write_register("a0", 0xFFFFFFFF)
    assert cpu.read_register("a0") == 0xFFFFFFFF
    cpu.write_register("x10", 7)
    assert cpu.read_register("a0") == 7
    assert cpu.read_register("x10") == 7
    cpu.write_register("fp", 0x20)
    assert cpu.read_register("s0") == 0x20
    cpu.write_register("zero", 0x99)
    cpu.write_register("x0", 0x55)
    assert cpu.read_register("zero") == 0
    assert cpu.read_register("x0") == 0
    assert cpu.read_registers()["zero"] == 0
    cpu.write_register("pc", 0)
    cpu.write_register("sp", 0x20004000)
    assert cpu.start(0, until=UNTIL_NEVER, timeout_us=0, count=1) is False
    assert cpu.read_register("pc") == 4
    assert cpu.read_register("a0") == 0x11
    assert cpu.read_register("sp") == 0x20004000
    with pytest.raises(BackendError, match="unknown register"):
        cpu.read_register("r0")


def test_uart_gpio_rv32_fixture_contract():
    image = build_fixture("uart-gpio-rv32")
    assert len(image) == _FIXTURE_INSNS * 4
    assert image.endswith(EBREAK_WORD.to_bytes(4, "little"))

    machine = Machine.from_fixture("uart-gpio-rv32")
    assert machine.backend.arch == "riscv"
    assert machine.config.arch == "riscv"
    result = machine.run()

    assert result.status == "halted"
    assert result.detail == "bkpt"
    assert result.pc == _FIXTURE_EBREAK
    assert result.sp == 0x20004000
    assert result.instructions == _FIXTURE_INSNS
    assert result.lr == 0
    assert bytes(machine.peripheral("uart0").tx) == b"A"
    assert machine.peripheral("gpioa").odr == 1
    assert machine.read_u32(0x20000000) == 0x00C0FFEE
    assert machine.read_u32(0x20000008) == 0x80
    assert result.registers["a5"] == 0x00C0FFEE
    assert result.registers["a2"] == 0x80
    assert result.registers["a0"] == 0x20000000
    kinds = {(entry.kind, entry.address, entry.size, entry.value) for entry in result.trace}
    assert ("write", 0x40000000, 1, 0x41) in kinds
    assert ("write", 0x40001000, 4, 1) in kinds
    assert ("read", 0x40000004, 4, 0x80) in kinds


def test_cli_riscv_fixture_and_backend_flag(capsys):
    code = main(["run", "--fixture", "uart-gpio-rv32"])
    out = capsys.readouterr().out
    assert code == 0
    assert "status: halted" in out
    assert "detail: bkpt" in out
    assert "pc: 0x00000030" in out
    assert "sp: 0x20004000" in out
    assert "instructions: 13" in out
    assert "uart0 tx: 41" in out
    assert "gpioa odr: 0x1" in out

    code = main(["run", "--backend", "riscv", "--fixture", "uart-gpio-rv32"])
    out = capsys.readouterr().out
    assert code == 0
    assert "uart0 tx: 41" in out
    assert "instructions: 13" in out

    assert main(["plugins"]) == 0
    listed = capsys.readouterr().out
    assert "\n  riscv\n" in listed
    assert "\n  riscv32\n" in listed


def test_arch_riscv32_runs_the_same_program():
    source = "addi a0, zero, 3\nebreak\n"
    machine = _rv_machine(source, arch="riscv32")
    assert machine.backend.arch == "riscv"
    result = machine.run()
    assert result.status == "halted"
    assert result.detail == "bkpt"
    assert result.instructions == 2
    assert result.registers["a0"] == 3


def test_halt_address_and_instruction_limit():
    halted = _rv_machine(
        """
        addi a0, zero, 1
        addi a0, zero, 2
        ebreak
        """,
        run={"halt_addresses": [4]},
    )
    result = halted.run()
    assert result.status == "halted"
    assert result.detail == "halt address 0x4"
    assert result.instructions == 1
    assert result.registers["a0"] == 1

    limited = _rv_machine(
        """
        loop:
            addi a0, a0, 1
            j loop
        """,
        run={"max_instructions": 10, "timeout_ms": 1000},
    )
    result = limited.run()
    assert result.status == "instruction_limit"
    assert result.instructions == 10
    assert result.registers["a0"] == 5


def test_timeout_on_a_jump_to_self():
    machine = _rv_machine(
        """
        loop:
            j loop
        """,
        run={"timeout_ms": 50, "max_instructions": 0},
    )
    result = machine.run()
    assert result.status == "timeout"
    assert result.instructions > 0


def test_unmapped_load_and_permission_fault():
    unmapped = _rv_machine(
        """
        lui a0, 0x60000
        lw a1, 0(a0)
        ebreak
        """
    )
    result = unmapped.run()
    assert result.status == "fault"
    assert "unmapped" in result.detail

    store = _rv_machine(
        """
        addi a1, zero, 1
        sw a1, 0(zero)
        ebreak
        """
    )
    result = store.run()
    assert result.status == "fault"
    assert "prot" in result.detail

    fetch = _rv_machine("ebreak\n", boot={"mode": "entry", "sp": 0x20001000, "entry": 0x30000000})
    result = fetch.run()
    assert result.status == "fault"
    assert "unmapped fetch" in result.detail


def test_illegal_instruction_is_a_fault():
    machine = _rv_machine(".word 0xffffffff\n")
    result = machine.run()
    assert result.status == "fault"
    assert "illegal instruction" in result.detail


def test_vector_boot_is_rejected_and_irq_is_not_delivered():
    machine = _rv_machine("ebreak\n", boot={"mode": "vector", "vector_base": 0})
    with pytest.raises(MachineError, match="vector table"):
        machine.boot()

    machine = Machine.from_fixture("uart-gpio-rv32")
    machine.inject_irq(5)
    result = machine.run()
    assert result.status == "halted"
    assert result.detail == "bkpt"
    assert result.instructions == _FIXTURE_INSNS
    assert machine.backend.pending_irqs == [5]


def test_fuzz_refuses_riscv(tmp_path, capsys):
    code = main(
        ["fuzz", "--fixture", "uart-gpio-rv32", "--out", str(tmp_path), "--max-execs", "1"]
    )
    assert code == 4
    assert "not implemented" in capsys.readouterr().err

    from rehost.campaign import Campaign

    with pytest.raises(RehostError, match="not implemented"):
        Campaign(Machine.from_fixture("uart-gpio-rv32"), out=tmp_path, max_execs=1)


def _rv_machine(
    source: str,
    *,
    arch: str = "riscv",
    boot: dict | None = None,
    run: dict | None = None,
) -> Machine:
    run_cfg: dict = {"timeout_ms": 1000, "max_instructions": 10000, "halt_on_bkpt": True}
    if run:
        run_cfg.update(run)
    config = {
        "name": "rv-test",
        "arch": arch,
        "memory": [
            {"name": "flash", "base": 0, "size": 0x1000, "perms": "rx"},
            {"name": "sram", "base": 0x20000000, "size": 0x1000, "perms": "rw"},
        ],
        "boot": boot or {"mode": "entry", "sp": 0x20001000, "entry": 0},
        "run": run_cfg,
    }
    machine = Machine(parse_config(config))
    machine.load_image(assemble(source))
    return machine
