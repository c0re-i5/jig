# SPDX-License-Identifier: MIT
"""Load a machine description from YAML or TOML.

The file names regions, plugin classes, and run limits. It does not name a
firmware image: the caller passes that path, or selects a built-in synthetic
fixture.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from rehost.errors import ConfigError
from rehost.memory import PERM_WRITE, Region, parse_perms

_ADDRESS_SPACE = 0x1_0000_0000
_MAX_FUZZ_BUFFER = 16 * 1024 * 1024

_TOP_KEYS = {
    "name",
    "arch",
    "endian",
    "description",
    "memory",
    "boot",
    "run",
    "unmapped",
    "fuzz",
    "load",
}
_REGION_KEYS = {
    "name",
    "base",
    "size",
    "perms",
    "peripheral",
    "config",
    "mmio",
    "read_default",
    "save",
}
_BOOT_KEYS = {"mode", "vector_base", "sp", "entry"}
_RUN_KEYS = {
    "timeout_ms",
    "max_instructions",
    "halt_on_bkpt",
    "halt_addresses",
    "trace_limit",
    "collect_coverage",
}
_UNMAPPED_KEYS = {"action", "read_default", "log"}
_FUZZ_KEYS = {"mode", "buffer"}
_BUFFER_KEYS = {"address", "max_size", "length_address"}
_LOAD_KEYS = {"base"}


def parse_int(value: Any, *, what: str) -> int:
    """Accept a JSON/YAML/TOML integer or a string such as ``0x20000000``."""
    if isinstance(value, bool) or value is None:
        raise ConfigError(f"{what} must be an integer, not {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise ConfigError(f"{what} is not an integer: {value!r}") from exc
    raise ConfigError(f"{what} must be an integer, not {type(value).__name__}")


def parse_u32(value: Any, *, what: str) -> int:
    number = parse_int(value, what=what)
    if number < 0 or number > 0xFFFFFFFF:
        raise ConfigError(f"{what} must fit in an unsigned 32-bit word")
    return number


def _check_keys(data: dict[str, Any], allowed: set[str], what: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ConfigError(f"unknown {what} field(s): {', '.join(unknown)}")


def _mapping(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{what} must be a mapping")
    return value


def _bool(value: Any, what: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{what} must be true or false")
    return value


@dataclass
class BootConfig:
    mode: str = "vector"
    vector_base: int = 0
    sp: int | None = None
    entry: int | None = None


@dataclass
class RunConfig:
    timeout_ms: int = 1000
    max_instructions: int = 1_000_000
    halt_on_bkpt: bool = True
    halt_addresses: tuple[int, ...] = ()
    trace_limit: int = 256
    collect_coverage: bool = False


@dataclass
class UnmappedConfig:
    action: str = "fault"
    read_default: int = 0
    log: bool = True


@dataclass
class FuzzBufferConfig:
    address: int
    max_size: int
    length_address: int | None = None


@dataclass
class FuzzConfig:
    mode: str
    buffer: FuzzBufferConfig | None = None


@dataclass
class RegionSpec:
    """Region as declared, before a live plugin object is attached."""

    name: str
    base: int
    size: int
    perms: str
    peripheral: str | None
    peripheral_config: dict[str, Any]
    mmio: bool
    read_default: int
    save: bool

    def to_region(self, peripheral: object | None = None) -> Region:
        return Region(
            name=self.name,
            base=self.base,
            size=self.size,
            perms=parse_perms(self.perms),
            peripheral=peripheral,
            save=self.save,
        )


@dataclass
class MachineConfig:
    name: str
    arch: str
    memory: tuple[RegionSpec, ...]
    description: str = ""
    endian: str = "little"
    boot: BootConfig = field(default_factory=BootConfig)
    run: RunConfig = field(default_factory=RunConfig)
    unmapped: UnmappedConfig = field(default_factory=UnmappedConfig)
    fuzz: FuzzConfig | None = None
    load_base: int = 0


def load_config(path: str | Path) -> MachineConfig:
    """Read ``.yaml``, ``.yml``, or ``.toml``."""
    file = Path(path)
    if not file.is_file():
        raise ConfigError(f"config not found: {file}")
    text = file.read_text(encoding="utf-8")
    suffix = file.suffix.lower()
    try:
        if suffix in {".yaml", ".yml"}:
            data = yaml.safe_load(text)
        elif suffix == ".toml":
            data = tomllib.loads(text)
        else:
            raise ConfigError(f"config {file} must be .yaml, .yml, or .toml")
    except yaml.YAMLError as exc:
        raise ConfigError(f"{file}: invalid YAML: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{file}: invalid TOML: {exc}") from exc
    if data is None:
        raise ConfigError(f"{file} is empty")
    try:
        return parse_config(data)
    except ConfigError as exc:
        raise ConfigError(f"{file}: {exc}") from exc


def parse_config(data: Any) -> MachineConfig:
    """Validate an already-decoded mapping."""
    root = _mapping(data, "machine config")
    _check_keys(root, _TOP_KEYS, "machine")
    name = root.get("name")
    arch = root.get("arch")
    if not isinstance(name, str) or not name:
        raise ConfigError("machine name must be a non-empty string")
    if not isinstance(arch, str) or not arch:
        raise ConfigError("machine arch must be a non-empty string")
    endian = root.get("endian", "little")
    if endian != "little":
        raise ConfigError("only little-endian machines are implemented")
    description = root.get("description", "")
    if not isinstance(description, str):
        raise ConfigError("description must be a string")
    memory = _parse_memory(root.get("memory"))
    boot = _parse_boot(root.get("boot"))
    run = _parse_run(root.get("run"))
    unmapped = _parse_unmapped(root.get("unmapped"))
    fuzz = _parse_fuzz(root.get("fuzz")) if "fuzz" in root and root.get("fuzz") is not None else None
    load_base = 0
    if "load" in root and root.get("load") is not None:
        load = _mapping(root["load"], "load")
        _check_keys(load, _LOAD_KEYS, "load")
        load_base = parse_u32(load.get("base", 0), what="load.base")
    if run.timeout_ms == 0 and run.max_instructions == 0:
        raise ConfigError("set run.timeout_ms or run.max_instructions so a run cannot hang")
    return MachineConfig(
        name=name,
        arch=arch,
        description=description.strip(),
        endian=endian,
        memory=tuple(memory),
        boot=boot,
        run=run,
        unmapped=unmapped,
        fuzz=fuzz,
        load_base=load_base,
    )


def _parse_memory(value: Any) -> list[RegionSpec]:
    if not isinstance(value, list) or not value:
        raise ConfigError("memory must be a non-empty list of regions")
    regions: list[RegionSpec] = []
    for index, item in enumerate(value):
        raw = _mapping(item, f"memory[{index}]")
        _check_keys(raw, _REGION_KEYS, f"memory region {raw.get('name', index)}")
        name = raw.get("name")
        if not isinstance(name, str) or not name:
            raise ConfigError(f"memory[{index}].name must be a non-empty string")
        base = parse_u32(raw.get("base"), what=f"region {name} base")
        size = parse_int(raw.get("size"), what=f"region {name} size")
        if size <= 0:
            raise ConfigError(f"region {name} size must be positive")
        if base + size > _ADDRESS_SPACE:
            raise ConfigError(f"region {name} extends past the 32-bit address space")
        perms_text = raw.get("perms", "rw")
        if not isinstance(perms_text, str):
            raise ConfigError(f"region {name} perms must be a string")
        perms = parse_perms(perms_text)
        peripheral = raw.get("peripheral")
        if peripheral is not None and (not isinstance(peripheral, str) or not peripheral):
            raise ConfigError(f"region {name} peripheral must be a plugin name")
        mmio = _bool(raw.get("mmio", False), f"region {name} mmio")
        if peripheral is None and mmio:
            peripheral = "unimplemented"
        read_default = parse_u32(raw.get("read_default", 0), what=f"region {name} read_default")
        plugin_config = raw.get("config", {})
        if plugin_config is None:
            plugin_config = {}
        plugin_config = dict(_mapping(plugin_config, f"region {name} config"))
        if "read_default" not in plugin_config:
            plugin_config["read_default"] = read_default
        if "save" in raw and raw["save"] is not None:
            save = _bool(raw["save"], f"region {name} save")
        else:
            save = bool(perms & PERM_WRITE) and peripheral is None
        if save and not (perms & PERM_WRITE):
            raise ConfigError(f"region {name} is marked save but is not writable")
        regions.append(
            RegionSpec(
                name=name,
                base=base,
                size=size,
                perms=perms_text,
                peripheral=peripheral,
                peripheral_config=plugin_config,
                mmio=mmio or peripheral is not None,
                read_default=read_default,
                save=save,
            )
        )
    # Construct a map so overlap and duplicate names fail at parse time.
    from rehost.memory import MemoryMap

    MemoryMap([spec.to_region() for spec in regions])
    return regions


def _parse_boot(value: Any) -> BootConfig:
    if value is None:
        return BootConfig()
    raw = _mapping(value, "boot")
    _check_keys(raw, _BOOT_KEYS, "boot")
    mode = raw.get("mode", "vector")
    if mode not in {"vector", "entry"}:
        raise ConfigError("boot.mode must be 'vector' or 'entry'")
    vector_base = parse_u32(raw.get("vector_base", 0), what="boot.vector_base")
    sp = parse_u32(raw["sp"], what="boot.sp") if "sp" in raw and raw["sp"] is not None else None
    entry = (
        parse_u32(raw["entry"], what="boot.entry")
        if "entry" in raw and raw["entry"] is not None
        else None
    )
    if mode == "entry" and (sp is None or entry is None):
        raise ConfigError("boot.mode entry requires boot.sp and boot.entry")
    return BootConfig(mode=mode, vector_base=vector_base, sp=sp, entry=entry)


def _parse_run(value: Any) -> RunConfig:
    if value is None:
        return RunConfig()
    raw = _mapping(value, "run")
    _check_keys(raw, _RUN_KEYS, "run")
    timeout_ms = parse_int(raw.get("timeout_ms", 1000), what="run.timeout_ms")
    max_instructions = parse_int(raw.get("max_instructions", 1_000_000), what="run.max_instructions")
    if timeout_ms < 0 or max_instructions < 0:
        raise ConfigError("run limits must be >= 0 (0 means unlimited for that limit)")
    halt_on_bkpt = _bool(raw.get("halt_on_bkpt", True), "run.halt_on_bkpt")
    addresses = raw.get("halt_addresses", [])
    if not isinstance(addresses, list):
        raise ConfigError("run.halt_addresses must be a list")
    halt_addresses = tuple(parse_u32(item, what="halt address") for item in addresses)
    trace_limit = parse_int(raw.get("trace_limit", 256), what="run.trace_limit")
    if trace_limit < 0:
        raise ConfigError("run.trace_limit must be >= 0")
    collect_coverage = _bool(raw.get("collect_coverage", False), "run.collect_coverage")
    return RunConfig(
        timeout_ms=timeout_ms,
        max_instructions=max_instructions,
        halt_on_bkpt=halt_on_bkpt,
        halt_addresses=halt_addresses,
        trace_limit=trace_limit,
        collect_coverage=collect_coverage,
    )


def _parse_unmapped(value: Any) -> UnmappedConfig:
    if value is None:
        return UnmappedConfig()
    raw = _mapping(value, "unmapped")
    _check_keys(raw, _UNMAPPED_KEYS, "unmapped")
    action = raw.get("action", "fault")
    if action not in {"fault", "log"}:
        raise ConfigError("unmapped.action must be 'fault' or 'log'")
    return UnmappedConfig(
        action=action,
        read_default=parse_u32(raw.get("read_default", 0), what="unmapped.read_default"),
        log=_bool(raw.get("log", True), "unmapped.log"),
    )


def _parse_fuzz(value: Any) -> FuzzConfig:
    raw = _mapping(value, "fuzz")
    _check_keys(raw, _FUZZ_KEYS, "fuzz")
    mode = raw.get("mode")
    if mode not in {"buffer", "mmio"}:
        raise ConfigError("fuzz.mode must be 'buffer' or 'mmio'")
    if mode == "mmio" and "buffer" in raw:
        raise ConfigError("fuzz.mode mmio does not use fuzz.buffer")
    buffer = None
    if mode == "buffer":
        if "buffer" not in raw:
            raise ConfigError("fuzz.mode buffer requires fuzz.buffer")
        spec = _mapping(raw["buffer"], "fuzz.buffer")
        _check_keys(spec, _BUFFER_KEYS, "fuzz.buffer")
        address = parse_u32(spec.get("address"), what="fuzz.buffer.address")
        max_size = parse_int(spec.get("max_size"), what="fuzz.buffer.max_size")
        if not 1 <= max_size <= _MAX_FUZZ_BUFFER:
            raise ConfigError("fuzz.buffer.max_size must be between 1 and 16 MiB")
        if address + max_size > _ADDRESS_SPACE:
            raise ConfigError("fuzz buffer extends past the 32-bit address space")
        length_address = None
        if "length_address" in spec and spec["length_address"] is not None:
            length_address = parse_u32(spec["length_address"], what="fuzz.buffer.length_address")
        buffer = FuzzBufferConfig(address=address, max_size=max_size, length_address=length_address)
    return FuzzConfig(mode=mode, buffer=buffer)
