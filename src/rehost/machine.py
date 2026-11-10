# SPDX-License-Identifier: MIT
"""Machine: config, memory map, plugins, and one CPU backend.

This is the object researchers extend. It does not fetch firmware. Call
``load_image`` with bytes you are authorized to analyze, or ``from_fixture``
for the synthetic programs shipped in-repo.
"""

from __future__ import annotations

import copy
import logging
from collections import deque
from pathlib import Path

from rehost.backends import (
    BKPT_VECTOR,
    SVC_VECTOR,
    UNTIL_NEVER,
    CpuBackend,
    MemAccess,
    create_backend,
)
from rehost.config import MachineConfig, load_config
from rehost.errors import BackendError, ConfigError, MachineError
from rehost.memory import PERM_READ, PERM_WRITE, MemoryMap, access_mask, pages_touched
from rehost.nvic import EXC_SYSTICK, REDIRECT, STOP
from rehost.peripherals import create_peripheral
from rehost.peripherals.systick import SysTick
from rehost.result import (
    STATUS_FAULT,
    STATUS_HALTED,
    STATUS_LIMIT,
    STATUS_TIMEOUT,
    RunResult,
    TraceEntry,
)
from rehost.snapshot import SNAPSHOT_VERSION, Snapshot

logger = logging.getLogger(__name__)


class Machine:
    """One rehosted target: a backend, a memory map, and peripheral plugins."""

    def __init__(self, config: MachineConfig, backend: CpuBackend | None = None) -> None:
        self.config = config
        self.backend = backend or create_backend(config.arch)
        regions = []
        for spec in config.memory:
            plugin = None
            if spec.peripheral:
                plugin = create_peripheral(
                    spec.peripheral,
                    name=spec.name,
                    base=spec.base,
                    size=spec.size,
                    config=spec.peripheral_config,
                    read_default=spec.read_default,
                )
            regions.append(spec.to_region(plugin))
        self.memory = MemoryMap(regions)
        self._peripherals = [
            region.peripheral for region in self.memory.regions if region.peripheral is not None
        ]
        self._by_name = {plugin.name: plugin for plugin in self._peripherals}
        self._peripheral_init = copy.deepcopy(
            {plugin.name: plugin.snapshot_state() for plugin in self._peripherals}
        )
        for plugin in self._peripherals:
            if isinstance(plugin, SysTick):
                # Instruction hooks are the clock. VAL reads must not also step.
                plugin.cpu_clock = True
        self._final_perms: dict[int, int] = {}
        self._hook_pages: set[int] = set()
        self._map_pages()
        self._install_hooks()
        self.backend.ensure_system_control()
        self._image_loaded = False
        self._booted = False
        self._protected = False
        self._reason: str | None = None
        self._detail = ""
        self._instructions = 0
        self._trace: deque[TraceEntry] = deque(maxlen=config.run.trace_limit)
        self._trace_total = 0
        self._coverage: set[int] = set()
        self._halt_addresses = set(config.run.halt_addresses)

    @classmethod
    def from_path(cls, path: str | Path, backend: CpuBackend | None = None) -> Machine:
        return cls(load_config(path), backend=backend)

    @classmethod
    def from_fixture(cls, name: str, backend: CpuBackend | None = None) -> Machine:
        """Load a built-in synthetic fixture. No external firmware is read."""
        from rehost.fixtures import build_fixture, fixture_config_path

        machine = cls.from_path(fixture_config_path(name), backend=backend)
        machine.load_image(build_fixture(name))
        return machine

    @property
    def peripherals(self) -> list:
        return list(self._peripherals)

    @property
    def booted(self) -> bool:
        return self._booted

    def peripheral(self, name: str):
        try:
            return self._by_name[name]
        except KeyError as exc:
            known = ", ".join(sorted(self._by_name)) or "(none)"
            raise KeyError(f"no peripheral named {name!r}; have {known}") from exc

    def load_image(self, data: bytes, base: int | None = None) -> None:
        """Copy ``data`` into guest memory. The image is not fetched from anywhere."""
        if not isinstance(data, (bytes, bytearray)) or not data:
            raise MachineError("firmware image is empty")
        blob = bytes(data)
        load_at = self.config.load_base if base is None else base
        if load_at < 0 or load_at + len(blob) > 0x1_0000_0000:
            raise MachineError("firmware image does not fit in the 32-bit address space")
        self.memory.regions_covering(load_at, len(blob))
        if self._protected:
            self._reprotect(writable=True)
        try:
            self.backend.write_memory(load_at, blob)
        except BackendError as exc:
            raise MachineError(f"failed to write firmware at {load_at:#x}: {exc}") from exc
        finally:
            if self._protected:
                self._reprotect(writable=False)
        self._image_loaded = True
        self._booted = False

    def boot(self, *, reset: bool = False) -> None:
        """Set SP and PC from the vector table or from ``boot.entry``.

        A second call is a no-op unless ``reset`` is true. Reset restores
        peripheral state captured at construction and re-reads the boot PC.
        It does not reload the image.
        """
        if not self._image_loaded:
            raise MachineError("load an image before boot")
        if self._booted and not reset:
            return
        if reset:
            for plugin in self._peripherals:
                plugin.restore_state(copy.deepcopy(self._peripheral_init[plugin.name]))
            self.backend.reset_cpu_state()
        boot = self.config.boot
        if boot.mode == "vector":
            sp = self.read_u32(boot.vector_base)
            entry = self.read_u32(boot.vector_base + 4)
        else:
            if boot.sp is None or boot.entry is None:
                raise ConfigError("boot.mode entry requires boot.sp and boot.entry")
            sp = boot.sp
            entry = boot.entry
        self.backend.write_register("sp", sp)
        self.backend.write_register("msp", sp)
        self.backend.write_register("lr", 0xFFFFFFFF)
        # EPSR.T. ``start`` also forces the Thumb bit on the entry address.
        self.backend.write_register("xpsr", 1 << 24)
        self.backend.write_register("pc", entry & ~1)
        if boot.mode == "vector":
            self.backend.set_vector_table(boot.vector_base)
        self._booted = True

    def run(self) -> RunResult:
        """Execute until BKPT, a halt address, a fault, a timeout, or the instruction cap."""
        if not self._image_loaded:
            raise MachineError("load an image before run")
        if not self._booted:
            self.boot()
        self._apply_protection()
        self._reason = None
        self._detail = ""
        self._instructions = 0
        self._trace.clear()
        self._trace_total = 0
        self._coverage.clear()
        self.backend.prepare_run()
        pc = self.backend.read_register("pc")
        timeout_us = self.config.run.timeout_ms * 1000
        timed_out = False
        try:
            timed_out = self.backend.start(
                pc,
                until=UNTIL_NEVER,
                timeout_us=timeout_us,
                count=0,
            )
        except BackendError as exc:
            if self._reason is None:
                self._reason = STATUS_FAULT
                self._detail = str(exc)
        if self._reason is None and self.backend.cpu_fault:
            self._reason = STATUS_FAULT
            self._detail = self.backend.cpu_fault
        if self._reason is None:
            if timed_out:
                self._reason = STATUS_TIMEOUT
                self._detail = f"timeout after {self.config.run.timeout_ms} ms"
            elif (
                self.config.run.max_instructions
                and self._instructions >= self.config.run.max_instructions
            ):
                self._reason = STATUS_LIMIT
                self._detail = f"stopped after {self._instructions} instructions"
            else:
                self._reason = STATUS_HALTED
                self._detail = "reached until address"
        return self._make_result()

    def snapshot(self) -> Snapshot:
        """Capture registers, savable RAM, and peripheral plugin state."""
        memory: dict[str, bytes] = {}
        bases: dict[str, int] = {}
        for region in self.memory.savable():
            memory[region.name] = self.backend.read_memory(region.base, region.size)
            bases[region.name] = region.base
        peripherals = {
            plugin.name: copy.deepcopy(plugin.snapshot_state()) for plugin in self._peripherals
        }
        return Snapshot(
            arch=self.config.arch,
            registers=self.backend.read_registers(),
            memory=memory,
            memory_base=bases,
            peripherals=peripherals,
            cpu=self.backend.snapshot_cpu_state(),
        )

    def restore(self, snap: Snapshot) -> None:
        """Restore a snapshot onto this machine. The loaded image is left in place."""
        if snap.version != SNAPSHOT_VERSION:
            raise MachineError(f"unsupported snapshot version {snap.version}")
        if snap.arch != self.config.arch:
            raise MachineError(f"snapshot arch {snap.arch} does not match machine arch {self.config.arch}")
        expected = {region.name for region in self.memory.savable()}
        if set(snap.memory) != expected:
            raise MachineError(
                "snapshot regions "
                f"{sorted(snap.memory)} do not match savable regions {sorted(expected)}"
            )
        plugin_names = {plugin.name for plugin in self._peripherals}
        if set(snap.peripherals) != plugin_names:
            raise MachineError(
                "snapshot peripherals "
                f"{sorted(snap.peripherals)} do not match {sorted(plugin_names)}"
            )
        for name, blob in snap.memory.items():
            region = self.memory.get(name)
            if len(blob) != region.size:
                raise MachineError(
                    f"snapshot region {name} is {len(blob)} bytes, machine region is {region.size}"
                )
            base = snap.memory_base.get(name)
            if base is not None and base != region.base:
                raise MachineError(
                    f"snapshot region {name} base {base:#x} does not match {region.base:#x}"
                )
            try:
                self.backend.write_memory(region.base, blob)
            except BackendError as exc:
                raise MachineError(f"failed to restore region {name}: {exc}") from exc
        for plugin in self._peripherals:
            plugin.restore_state(copy.deepcopy(snap.peripherals[plugin.name]))
        self.backend.write_registers(snap.registers)
        self.backend.restore_cpu_state(snap.cpu)
        self._booted = True

    def inject_irq(self, irq: int) -> None:
        """Pend external IRQ ``irq``. Enable, priority, and masks still apply."""
        self.backend.inject_irq(irq)

    def read_memory(self, address: int, size: int) -> bytes:
        self.memory.regions_covering(address, size)
        try:
            return self.backend.read_memory(address, size)
        except BackendError as exc:
            raise MachineError(f"cannot read {size} bytes at {address:#x}") from exc

    def write_memory(self, address: int, data: bytes) -> None:
        """Write RAM. Peripheral windows are rejected; use ``write_mmio``."""
        self.ensure_ram(address, len(data))
        try:
            self.backend.write_memory(address, data)
        except BackendError as exc:
            raise MachineError(f"cannot write {len(data)} bytes at {address:#x}") from exc

    def read_u32(self, address: int) -> int:
        return int.from_bytes(self.read_memory(address, 4), "little")

    def write_u32(self, address: int, value: int) -> None:
        self.write_memory(address, (value & 0xFFFFFFFF).to_bytes(4, "little"))

    def ensure_ram(self, address: int, size: int) -> None:
        for region in self.memory.regions_covering(address, size):
            if region.peripheral is not None:
                raise MachineError(
                    f"address {address:#x} hits peripheral region {region.name!r}; "
                    "use write_mmio for plugin state"
                )
            if not region.perms & PERM_WRITE:
                raise MachineError(f"region {region.name!r} is not writable")

    def write_mmio(self, address: int, value: int, size: int) -> None:
        """Perform a plugin write, as a fuzzer MMIO script would."""
        plugin_region = self._plugin_region(address, size)
        if plugin_region is None:
            raise MachineError(f"no peripheral covers {address:#x} size {size}")
        masked = value & access_mask(size)
        plugin_region.peripheral.write(address - plugin_region.base, size, masked)
        try:
            self.backend.write_memory(address, masked.to_bytes(size, "little"))
        except BackendError as exc:
            raise MachineError(f"failed to mirror MMIO write at {address:#x}") from exc

    def read_mmio(self, address: int, size: int) -> int:
        """Perform a plugin read. This has the plugin's side effects."""
        plugin_region = self._plugin_region(address, size)
        if plugin_region is None:
            raise MachineError(f"no peripheral covers {address:#x} size {size}")
        return plugin_region.peripheral.read(address - plugin_region.base, size) & access_mask(size)

    def _map_pages(self) -> None:
        page = self.backend.page_size
        for region in self.memory.regions:
            for start in pages_touched(region.base, region.size, page):
                self._final_perms[start] = self._final_perms.get(start, 0) | region.perms
                if region.peripheral is not None:
                    self._hook_pages.add(start)
        for start, perms in self._final_perms.items():
            # Writable until the image is loaded; ``run`` tightens this.
            self.backend.map_memory(start, page, perms | PERM_WRITE)

    def _install_hooks(self) -> None:
        self.backend.hook_code(self._on_code)
        self.backend.hook_interrupt(self._on_interrupt)
        self.backend.hook_unmapped(self._on_unmapped)
        page = self.backend.page_size
        for start in sorted(self._hook_pages):
            end = start + page - 1
            self.backend.hook_memory_read(self._on_read, start, end)
            self.backend.hook_memory_write(self._on_write, start, end)

    def _apply_protection(self) -> None:
        if self._protected:
            return
        self._reprotect(writable=False)
        self._protected = True

    def _reprotect(self, *, writable: bool) -> None:
        page = self.backend.page_size
        for start, perms in self._final_perms.items():
            # Image load needs a temporary write window on execute-only flash.
            effective = perms | PERM_WRITE if writable else perms
            self.backend.protect_memory(start, page, effective)

    def _on_code(self, address: int, size: int) -> None:
        if address in self._halt_addresses:
            self._reason = STATUS_HALTED
            self._detail = f"halt address {address:#x}"
            self.backend.stop()
            return
        limit = self.config.run.max_instructions
        if limit and self._instructions >= limit:
            self._reason = STATUS_LIMIT
            self._detail = f"stopped after {self._instructions} instructions"
            self.backend.stop()
            return
        self._clock_systick()
        effect = self.backend.service_interrupts(address, size)
        if effect == STOP or self.backend.cpu_fault:
            self._reason = STATUS_FAULT
            self._detail = self.backend.cpu_fault or "cpu fault"
            self.backend.stop()
            return
        if effect == REDIRECT:
            return
        self._instructions += 1
        if self.config.run.collect_coverage:
            self._coverage.add(address)

    def _clock_systick(self) -> None:
        for plugin in self._peripherals:
            if not isinstance(plugin, SysTick):
                continue
            if plugin.consume_cpu_tick():
                self.backend.pend_exception(EXC_SYSTICK)

    def _on_interrupt(self, vector: int) -> None:
        if vector == BKPT_VECTOR and self.config.run.halt_on_bkpt:
            self._reason = STATUS_HALTED
            self._detail = "bkpt"
            self.backend.stop()
            return
        if vector == SVC_VECTOR:
            self.backend.take_svc()
            if self.backend.cpu_fault:
                self._reason = STATUS_FAULT
                self._detail = self.backend.cpu_fault
                self.backend.stop()
            return
        self._reason = STATUS_FAULT
        self._detail = f"exception {vector}"
        self.backend.stop()

    def _on_read(self, address: int, size: int, _value: int) -> None:
        if size not in (1, 2, 4):
            logger.info("unsupported MMIO read size %d at %#x", size, address)
            self.backend.write_memory(address, bytes(size))
            self._record("read", address, size, 0)
            return
        region = self._plugin_region(address, size)
        if region is None:
            return
        result = region.peripheral.read(address - region.base, size) & access_mask(size)
        self._record("read", address, size, result)
        # Unicorn 2 invokes this hook before the load retires, so the bytes
        # written here are the value the instruction observes.
        self.backend.write_memory(address, result.to_bytes(size, "little"))

    def _on_write(self, address: int, size: int, value: int) -> None:
        if size not in (1, 2, 4):
            logger.info("unsupported MMIO write size %d at %#x", size, address)
            self._record("write", address, size, value)
            return
        region = self._plugin_region(address, size)
        if region is None:
            return
        masked = value & access_mask(size)
        region.peripheral.write(address - region.base, size, masked)
        self._record("write", address, size, masked)

    def _on_unmapped(self, access: MemAccess) -> bool:
        if access.kind == "fetch_unmapped":
            self._reason = STATUS_FAULT
            self._detail = f"unmapped fetch at {access.address:#x}"
            return False
        policy = self.config.unmapped
        if policy.action != "log":
            self._reason = STATUS_FAULT
            self._detail = (
                f"unmapped {access.kind} at {access.address:#x} size {access.size}"
            )
            return False
        if policy.log:
            logger.info(
                "unmapped %s at %#x size %d",
                access.kind,
                access.address,
                access.size,
            )
        page = self.backend.page_size
        start = access.address & ~(page - 1)
        if start not in self._final_perms:
            self.backend.map_memory(start, page, PERM_READ | PERM_WRITE)
            word = (policy.read_default & 0xFFFFFFFF).to_bytes(4, "little")
            self.backend.write_memory(start, word * (page // 4))
            self._final_perms[start] = PERM_READ | PERM_WRITE
        self._record(access.kind, access.address, access.size, policy.read_default)
        return True

    def _plugin_region(self, address: int, size: int):
        region = self.memory.region_at(address)
        if region is None or region.peripheral is None:
            return None
        if not region.contains_access(address, size):
            logger.info(
                "MMIO access at %#x size %d is not contained in %s",
                address,
                size,
                region.name,
            )
            return None
        return region

    def _record(self, kind: str, address: int, size: int, value: int) -> None:
        self._trace_total += 1
        masked = value & 0xFFFFFFFF
        if size in (1, 2, 4):
            masked &= access_mask(size)
        self._trace.append(TraceEntry(kind=kind, address=address, size=size, value=masked))

    def _make_result(self) -> RunResult:
        registers = self.backend.read_registers()
        coverage = tuple(sorted(self._coverage)) if self.config.run.collect_coverage else None
        return RunResult(
            status=self._reason or STATUS_FAULT,
            detail=self._detail,
            pc=registers.get("pc", 0),
            sp=registers.get("sp", 0),
            lr=registers.get("lr", 0),
            registers=registers,
            instructions=self._instructions,
            trace=tuple(self._trace),
            trace_total=self._trace_total,
            coverage=coverage,
        )
