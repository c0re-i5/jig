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
    "svc_nop",
}
_UNMAPPED_KEYS = {"action", "read_default", "log"}
_FUZZ_KEYS = {
    "mode",
    "buffer",
    "uart",
    "crash_addresses",
    "checkpoint",
    "exec",
    "hang_on_limit",
}
_BUFFER_KEYS = {"address", "max_size", "length_address"}
_UART_FUZZ_KEYS = {"name", "max_size"}
_CHECKPOINT_KEYS = {"mode", "idle_instructions", "max_instructions", "contains"}
_EXEC_KEYS = {"max_instructions", "timeout_ms", "idle_instructions"}
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
    # SVC immediates that retire as NOP. A research image can use one as a
    # harness hook (P2IM ``svc #63``) that must not enter the SVCall handler.
    svc_nop: frozenset[int] = frozenset()


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
class FuzzUartConfig:
    """UART RX is the testcase. ``name`` None means the machine's only UART."""

    max_size: int
    name: str | None = None


@dataclass
class FuzzCheckpointConfig:
    """Where ``PersistentHarness`` snapshots before the first testcase.

    ``boot`` is the reset state, before any guest instruction. ``banner``
    runs until the fuzz UART has transmitted and then gone quiet, and
    snapshots that state. Each later case restores it and queues RX, so
    the fuzzer does not pay for reset on every input.
    """

    mode: str = "boot"
    idle_instructions: int | None = None
    max_instructions: int | None = None
    # When set, a quiet gap counts only after the UART TX buffer contains
    # this ASCII text. That skips a pause in the middle of the banner.
    contains: str | None = None


@dataclass
class FuzzExecConfig:
    """Per-testcase limits. Unset fields keep ``run.*``.

    ``idle_instructions`` is UART-only. After the guest has drained RX, the
    case stops once TX has been quiet for that many instructions. A guest
    that never drains RX, or never pauses, still runs until the cap or the
    wall-clock timeout.
    """

    max_instructions: int | None = None
    timeout_ms: int | None = None
    idle_instructions: int | None = None


@dataclass
class FuzzConfig:
    mode: str
    buffer: FuzzBufferConfig | None = None
    uart: FuzzUartConfig | None = None
    # Halt PCs that the fuzzer should treat as crashes. A fault is always a
    # crash; these addresses cover a clean BKPT (or other halt) that the
    # program uses as a bug oracle. Compared with the low bit cleared.
    crash_addresses: tuple[int, ...] = ()
    checkpoint: FuzzCheckpointConfig = field(default_factory=FuzzCheckpointConfig)
    exec: FuzzExecConfig = field(default_factory=FuzzExecConfig)
    # An instruction-limit stop is a hang for a buffer or MMIO sink, which
    # is expected to halt. A UART command loop does not halt, so the default
    # there is to treat the cap as a finished execution and keep coverage.
    hang_on_limit: bool = True


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
    if fuzz is not None:
        _check_exec_limits(run, fuzz)
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
    svc_nop = _parse_svc_nop(raw.get("svc_nop", []))
    return RunConfig(
        timeout_ms=timeout_ms,
        max_instructions=max_instructions,
        halt_on_bkpt=halt_on_bkpt,
        halt_addresses=halt_addresses,
        trace_limit=trace_limit,
        collect_coverage=collect_coverage,
        svc_nop=svc_nop,
    )


def _parse_svc_nop(value: Any) -> frozenset[int]:
    if not isinstance(value, list):
        raise ConfigError("run.svc_nop must be a list of SVC immediates")
    immediates: list[int] = []
    for item in value:
        number = parse_int(item, what="run.svc_nop immediate")
        if not 0 <= number <= 255:
            raise ConfigError(f"run.svc_nop immediate {number} must be 0..255")
        immediates.append(number)
    return frozenset(immediates)


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
    if mode not in {"buffer", "mmio", "uart"}:
        raise ConfigError("fuzz.mode must be 'buffer', 'mmio', or 'uart'")
    if mode != "buffer" and "buffer" in raw:
        raise ConfigError(f"fuzz.mode {mode} does not use fuzz.buffer")
    if mode != "uart" and "uart" in raw:
        raise ConfigError(f"fuzz.mode {mode} does not use fuzz.uart")
    buffer = _parse_fuzz_buffer(raw) if mode == "buffer" else None
    uart = _parse_fuzz_uart(raw) if mode == "uart" else None
    addresses = raw.get("crash_addresses", [])
    if not isinstance(addresses, list):
        raise ConfigError("fuzz.crash_addresses must be a list")
    crash_addresses = tuple(parse_u32(item, what="fuzz.crash_addresses") for item in addresses)
    checkpoint = _parse_checkpoint(raw.get("checkpoint"), mode=mode)
    exec_limits = _parse_exec(raw.get("exec"), mode=mode)
    if "hang_on_limit" in raw and raw["hang_on_limit"] is not None:
        hang_on_limit = _bool(raw["hang_on_limit"], "fuzz.hang_on_limit")
    else:
        # A serial command loop runs until the cap. That stop is the end of
        # the case, not a hang, unless the file says otherwise.
        hang_on_limit = mode != "uart"
    return FuzzConfig(
        mode=mode,
        buffer=buffer,
        uart=uart,
        crash_addresses=crash_addresses,
        checkpoint=checkpoint,
        exec=exec_limits,
        hang_on_limit=hang_on_limit,
    )


def _parse_fuzz_buffer(raw: dict[str, Any]) -> FuzzBufferConfig:
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
    return FuzzBufferConfig(address=address, max_size=max_size, length_address=length_address)


def _parse_fuzz_uart(raw: dict[str, Any]) -> FuzzUartConfig:
    if "uart" not in raw:
        raise ConfigError("fuzz.mode uart requires fuzz.uart")
    spec = _mapping(raw["uart"], "fuzz.uart")
    _check_keys(spec, _UART_FUZZ_KEYS, "fuzz.uart")
    name = spec.get("name")
    if name is not None and (not isinstance(name, str) or not name):
        raise ConfigError("fuzz.uart.name must be a peripheral name")
    max_size = parse_int(spec.get("max_size"), what="fuzz.uart.max_size")
    if not 1 <= max_size <= _MAX_FUZZ_BUFFER:
        raise ConfigError("fuzz.uart.max_size must be between 1 and 16 MiB")
    return FuzzUartConfig(max_size=max_size, name=name)


def _parse_checkpoint(value: Any, *, mode: str) -> FuzzCheckpointConfig:
    if value is None:
        return FuzzCheckpointConfig()
    raw = _mapping(value, "fuzz.checkpoint")
    _check_keys(raw, _CHECKPOINT_KEYS, "fuzz.checkpoint")
    checkpoint_mode = raw.get("mode", "boot")
    if checkpoint_mode not in {"boot", "banner"}:
        raise ConfigError("fuzz.checkpoint.mode must be 'boot' or 'banner'")
    if checkpoint_mode == "banner" and mode != "uart":
        raise ConfigError("fuzz.checkpoint mode banner requires fuzz.mode uart")
    idle = None
    if "idle_instructions" in raw and raw["idle_instructions"] is not None:
        idle = parse_int(raw["idle_instructions"], what="fuzz.checkpoint.idle_instructions")
        if idle < 1:
            raise ConfigError("fuzz.checkpoint.idle_instructions must be >= 1")
    if checkpoint_mode == "banner" and idle is None:
        raise ConfigError("fuzz.checkpoint mode banner requires idle_instructions")
    if checkpoint_mode == "boot" and idle is not None:
        raise ConfigError("fuzz.checkpoint mode boot does not use idle_instructions")
    cap = None
    if "max_instructions" in raw and raw["max_instructions"] is not None:
        cap = parse_int(raw["max_instructions"], what="fuzz.checkpoint.max_instructions")
        if cap < 1:
            raise ConfigError("fuzz.checkpoint.max_instructions must be >= 1")
    if checkpoint_mode == "boot" and cap is not None:
        raise ConfigError("fuzz.checkpoint mode boot does not use max_instructions")
    contains = raw.get("contains")
    if contains is not None:
        if checkpoint_mode != "banner":
            raise ConfigError("fuzz.checkpoint.contains requires mode banner")
        if not isinstance(contains, str) or not contains:
            raise ConfigError("fuzz.checkpoint.contains must be a non-empty string")
        try:
            contains.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ConfigError("fuzz.checkpoint.contains must be ASCII") from exc
    return FuzzCheckpointConfig(
        mode=checkpoint_mode,
        idle_instructions=idle,
        max_instructions=cap,
        contains=contains,
    )


def _parse_exec(value: Any, *, mode: str) -> FuzzExecConfig:
    if value is None:
        return FuzzExecConfig()
    raw = _mapping(value, "fuzz.exec")
    _check_keys(raw, _EXEC_KEYS, "fuzz.exec")
    max_instructions = None
    if "max_instructions" in raw and raw["max_instructions"] is not None:
        max_instructions = parse_int(raw["max_instructions"], what="fuzz.exec.max_instructions")
        if max_instructions < 0:
            raise ConfigError("fuzz.exec.max_instructions must be >= 0")
    timeout_ms = None
    if "timeout_ms" in raw and raw["timeout_ms"] is not None:
        timeout_ms = parse_int(raw["timeout_ms"], what="fuzz.exec.timeout_ms")
        if timeout_ms < 0:
            raise ConfigError("fuzz.exec.timeout_ms must be >= 0")
    idle = None
    if "idle_instructions" in raw and raw["idle_instructions"] is not None:
        if mode != "uart":
            raise ConfigError("fuzz.exec.idle_instructions requires fuzz.mode uart")
        idle = parse_int(raw["idle_instructions"], what="fuzz.exec.idle_instructions")
        if idle < 1:
            raise ConfigError("fuzz.exec.idle_instructions must be >= 1")
    return FuzzExecConfig(
        max_instructions=max_instructions,
        timeout_ms=timeout_ms,
        idle_instructions=idle,
    )


def _check_exec_limits(run: RunConfig, fuzz: FuzzConfig) -> None:
    """A testcase still needs a stop, including after ``fuzz.exec`` overrides."""
    timeout_ms = run.timeout_ms if fuzz.exec.timeout_ms is None else fuzz.exec.timeout_ms
    max_instructions = (
        run.max_instructions if fuzz.exec.max_instructions is None else fuzz.exec.max_instructions
    )
    if timeout_ms == 0 and max_instructions == 0:
        raise ConfigError("fuzz.exec leaves the run with no timeout and no instruction limit")
