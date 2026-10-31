# SPDX-License-Identifier: MIT
"""Machine-file parsing: YAML, TOML, overlaps, and rejected fields."""

from __future__ import annotations

from pathlib import Path

import pytest

from rehost.config import load_config, parse_config
from rehost.errors import ConfigError
from rehost.memory import PERM_EXEC, PERM_READ, PERM_WRITE, pages_touched, parse_perms


def _minimal(**overrides):
    data = {
        "name": "demo",
        "arch": "cortex-m",
        "memory": [
            {"name": "flash", "base": 0, "size": 0x1000, "perms": "rx"},
            {"name": "sram", "base": 0x20000000, "size": 0x1000, "perms": "rw"},
        ],
    }
    data.update(overrides)
    return data


def test_yaml_hex_and_toml_round_trip(tmp_path: Path):
    yaml_path = tmp_path / "machine.yaml"
    yaml_path.write_text(
        """
        name: demo
        arch: cortex-m
        memory:
          - {name: flash, base: 0x00000000, size: 0x1000, perms: rx}
          - {name: sram, base: 0x20000000, size: 0x1000, perms: rw}
        """,
        encoding="utf-8",
    )
    toml_path = tmp_path / "machine.toml"
    toml_path.write_text(
        """
        name = "demo"
        arch = "cortex-m"
        [[memory]]
        name = "flash"
        base = 0x0
        size = 0x1000
        perms = "rx"
        [[memory]]
        name = "sram"
        base = 0x20000000
        size = 0x1000
        perms = "rw"
        """,
        encoding="utf-8",
    )
    from_yaml = load_config(yaml_path)
    from_toml = load_config(toml_path)
    assert [(r.name, r.base, r.size) for r in from_yaml.memory] == [
        (r.name, r.base, r.size) for r in from_toml.memory
    ]
    assert from_yaml.memory[1].base == 0x20000000
    assert from_yaml.memory[0].save is False
    assert from_yaml.memory[1].save is True


def test_overlap_unknown_field_and_big_endian_are_rejected():
    with pytest.raises(ConfigError, match="overlap"):
        parse_config(
            _minimal(
                memory=[
                    {"name": "a", "base": 0, "size": 0x2000, "perms": "rw"},
                    {"name": "b", "base": 0x1000, "size": 0x1000, "perms": "rw"},
                ]
            )
        )
    with pytest.raises(ConfigError, match="unknown machine field"):
        parse_config(_minimal(firmware="image.bin"))
    with pytest.raises(ConfigError, match="little-endian"):
        parse_config(_minimal(endian="big"))


def test_permission_flags_and_page_span():
    assert parse_perms("rx") == PERM_READ | PERM_EXEC
    assert parse_perms("rw") == PERM_READ | PERM_WRITE
    with pytest.raises(ConfigError):
        parse_perms("rwq")
    # SysTick's 16-byte window sits inside one page and is not page-aligned.
    assert pages_touched(0xE000E010, 0x10) == [0xE000E000]
    assert pages_touched(0, 0x1001) == [0, 0x1000]


def test_save_requires_a_writable_region():
    with pytest.raises(ConfigError, match="not writable"):
        parse_config(
            _minimal(
                memory=[
                    {
                        "name": "flash",
                        "base": 0,
                        "size": 0x1000,
                        "perms": "rx",
                        "save": True,
                    }
                ]
            )
        )


def test_entry_boot_requires_sp_and_entry():
    with pytest.raises(ConfigError, match="boot.sp"):
        parse_config(_minimal(boot={"mode": "entry"}))


def test_unlimited_run_is_rejected():
    with pytest.raises(ConfigError, match="cannot hang"):
        parse_config(_minimal(run={"timeout_ms": 0, "max_instructions": 0}))
