# SPDX-License-Identifier: MIT
"""Build a small Cortex-M machine around a snippet of fixture assembly."""

from __future__ import annotations

from rehost.config import parse_config
from rehost.fixtures.assemble import assemble
from rehost.machine import Machine


def machine_from_asm(
    source: str,
    *,
    regions: list[dict] | None = None,
    boot: dict | None = None,
    run: dict | None = None,
    unmapped: dict | None = None,
    fuzz: dict | None = None,
    name: str = "test",
) -> Machine:
    memory: list[dict] = [
        {"name": "flash", "base": 0, "size": 0x1000, "perms": "rx"},
        {"name": "sram", "base": 0x20000000, "size": 0x1000, "perms": "rw"},
    ]
    if regions:
        memory.extend(regions)
    run_cfg: dict = {"timeout_ms": 1000, "max_instructions": 10000, "halt_on_bkpt": True}
    if run:
        run_cfg.update(run)
    config: dict = {
        "name": name,
        "arch": "cortex-m",
        "memory": memory,
        "boot": boot or {"mode": "entry", "sp": 0x20001000, "entry": 0},
        "run": run_cfg,
    }
    if unmapped is not None:
        config["unmapped"] = unmapped
    if fuzz is not None:
        config["fuzz"] = fuzz
    machine = Machine(parse_config(config))
    machine.load_image(assemble(source))
    return machine
