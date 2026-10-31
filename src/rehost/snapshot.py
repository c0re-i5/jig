# SPDX-License-Identifier: MIT
"""Portable CPU + RAM + peripheral snapshots.

The blob is plain data (registers, region bytes, plugin state) so a later
QEMU or Renode backend can restore it without Unicorn context objects.
Flash and other non-saved regions stay as loaded on the machine; copy the
image separately.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rehost.errors import MachineError

SNAPSHOT_VERSION = 1


def _jsonable_state(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return {"__bytes__": bytes(value).hex()}
    if isinstance(value, dict):
        return {str(key): _jsonable_state(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable_state(item) for item in value]
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) or value is None or isinstance(value, bool):
        return value
    raise MachineError(f"peripheral snapshot value {type(value).__name__} is not JSON-safe")


def _from_jsonable_state(value: Any) -> Any:
    if isinstance(value, dict):
        if set(value) == {"__bytes__"} and isinstance(value["__bytes__"], str):
            try:
                return bytes.fromhex(value["__bytes__"])
            except ValueError as exc:
                raise MachineError("snapshot contains invalid hex bytes") from exc
        return {key: _from_jsonable_state(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_from_jsonable_state(item) for item in value]
    return value


@dataclass
class Snapshot:
    """One restorable machine state. ``memory`` is raw little-endian image bytes."""

    arch: str
    registers: dict[str, int]
    memory: dict[str, bytes]
    memory_base: dict[str, int]
    peripherals: dict[str, dict[str, Any]]
    version: int = SNAPSHOT_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "arch": self.arch,
            "registers": {name: f"{value:#x}" for name, value in self.registers.items()},
            "memory": {
                name: {
                    "base": f"{self.memory_base[name]:#x}",
                    "data_base64": base64.b64encode(blob).decode("ascii"),
                }
                for name, blob in self.memory.items()
            },
            "peripherals": _jsonable_state(self.peripherals),
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True) + "\n"

    def write_json(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Snapshot:
        if not isinstance(data, dict):
            raise MachineError("snapshot root must be an object")
        version = data.get("version")
        if version != SNAPSHOT_VERSION:
            raise MachineError(f"unsupported snapshot version {version!r}")
        arch = data.get("arch")
        if not isinstance(arch, str) or not arch:
            raise MachineError("snapshot is missing arch")
        raw_regs = data.get("registers")
        if not isinstance(raw_regs, dict):
            raise MachineError("snapshot registers must be an object")
        registers: dict[str, int] = {}
        for name, value in raw_regs.items():
            if isinstance(value, str):
                registers[str(name)] = int(value, 0)
            elif isinstance(value, int) and not isinstance(value, bool):
                registers[str(name)] = value
            else:
                raise MachineError(f"snapshot register {name} is not an integer")
        raw_mem = data.get("memory", {})
        if not isinstance(raw_mem, dict):
            raise MachineError("snapshot memory must be an object")
        memory: dict[str, bytes] = {}
        memory_base: dict[str, int] = {}
        for name, spec in raw_mem.items():
            if not isinstance(spec, dict) or "data_base64" not in spec or "base" not in spec:
                raise MachineError(f"snapshot region {name} needs base and data_base64")
            try:
                blob = base64.b64decode(spec["data_base64"], validate=True)
            except (ValueError, TypeError) as exc:
                raise MachineError(f"snapshot region {name} has invalid base64") from exc
            base = spec["base"]
            memory[str(name)] = blob
            memory_base[str(name)] = int(base, 0) if isinstance(base, str) else int(base)
        peripherals = _from_jsonable_state(data.get("peripherals", {}))
        if not isinstance(peripherals, dict):
            raise MachineError("snapshot peripherals must be an object")
        return cls(
            arch=arch,
            registers=registers,
            memory=memory,
            memory_base=memory_base,
            peripherals=peripherals,
            version=version,
        )

    @classmethod
    def read_json(cls, path: str | Path) -> Snapshot:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise MachineError(f"snapshot {path} is not JSON: {exc}") from exc
        return cls.from_dict(data)
