# SPDX-License-Identifier: MIT
"""Machine: config, memory map, plugins, and one CPU backend.

This is the object researchers extend. It does not fetch firmware. Call
``load_image`` with bytes you are authorized to analyze (a raw bin, an ELF32,
or Intel HEX), or ``from_fixture`` for the synthetic programs shipped in-repo.
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
from rehost.coverage import MAP_SIZE, edge_location
from rehost.config import MachineConfig, load_config
from rehost.errors import BackendError, ConfigError, MachineError
from rehost.image import LoadSegment, parse_firmware
from rehost.memory import PERM_READ, PERM_WRITE, MemoryMap, access_mask, pages_touched
from rehost.nvic import EXC_SYSTICK, REDIRECT, STOP
from rehost.peripherals import create_peripheral
from rehost.peripherals.bitband import Bitband
from rehost.peripherals.systick import SysTick
from rehost.peripherals.timer import Timer
from rehost.peripherals.uart import Uart
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

# Retired-instruction tail kept for crash bucketing. The edge update matches
# CoverageMap.on_instruction for a 65536-byte map, including when no bitmap
# is attached, so a fuzz run and a later replay hash the same tail.
_RECENT_LIMIT = 8


def _contiguous_spans(pages: dict[int, int], page_size: int) -> list[tuple[int, int, int]]:
    """Merge neighboring pages that share a permission value.

    Returns ``(address, size, perms)`` in address order. ``pages`` maps a
    page start to the permission bits recorded for that page.
    """
    spans: list[tuple[int, int, int]] = []
    for start in sorted(pages):
        perms = pages[start]
        if spans and spans[-1][0] + spans[-1][1] == start and spans[-1][2] == perms:
            base, size, old = spans[-1]
            spans[-1] = (base, size + page_size, old)
        else:
            spans.append((start, page_size, perms))
    return spans


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
            elif isinstance(plugin, Timer):
                plugin.cpu_clock = True
            elif isinstance(plugin, Uart):
                # After the init snapshot, so boot(reset) restores a clear latch
                # and raises again below.
                plugin.bind_rx_irq(self.inject_irq)
            elif isinstance(plugin, Bitband):
                plugin.bind(self._bitband_load_byte, self._bitband_store_byte)
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
        self._coverage_map = None
        # CmpLog, or None. Attached only when a campaign asks for it, and
        # inactive except during that campaign's shadow run.
        self._cmplog = None
        self._rx_feed = None
        # Optional callable(instructions) after each retired instruction.
        # The banner checkpoint uses it. A serial feed is separate.
        self._retire_hook = None
        self._recent_pcs: deque[int] = deque(maxlen=_RECENT_LIMIT)
        self._recent_edges: deque[int] = deque(maxlen=_RECENT_LIMIT)
        self._edge_prev = 0
        self._halt_addresses = set(config.run.halt_addresses)
        self._resets = 0
        self._silent_resets = 0
        # UART tx bytes observed at the previous reset. A later request with
        # no new byte is part of a silent streak.
        self._reset_tx_mark = 0

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
        """Copy ``data`` into guest memory. The image is not fetched from anywhere.

        A raw buffer is one span at ``load.base``, or at ``base`` when that
        argument is passed. A little-endian ARM ELF32 is recognized by its
        magic and each ``PT_LOAD`` segment is written at ``p_paddr``. An
        Intel HEX record stream is written at the addresses in the records.
        ELF and HEX already name their addresses, so ``base`` is rejected
        for those two. A span that is not covered by the memory map raises
        ``MachineError`` and leaves the previous image flag unchanged when
        nothing was written.
        """
        if not isinstance(data, (bytes, bytearray)) or not data:
            raise MachineError("firmware image is empty")
        blob = bytes(data)
        kind, segments = parse_firmware(blob)
        if kind == "raw":
            load_at = self.config.load_base if base is None else base
            if load_at < 0 or load_at + len(blob) > 0x1_0000_0000:
                raise MachineError("firmware image does not fit in the 32-bit address space")
            segments = [LoadSegment(load_at, blob, "raw image")]
        elif base is not None:
            name = "ELF" if kind == "elf" else "Intel HEX"
            raise MachineError(f"{name} images carry their own load addresses; omit base")
        for segment in segments:
            self._require_segment(segment, wrap=kind != "raw")
        if self._protected:
            self._reprotect(writable=True)
        try:
            for segment in segments:
                try:
                    self.backend.write_memory(segment.address, segment.data)
                except BackendError as exc:
                    if kind == "raw":
                        raise MachineError(
                            f"failed to write firmware at {segment.address:#x}: {exc}"
                        ) from exc
                    raise MachineError(
                        f"failed to write {segment.label} at {segment.address:#x}: {exc}"
                    ) from exc
        finally:
            if self._protected:
                self._reprotect(writable=False)
        if kind != "raw":
            placed = ", ".join(
                f"{segment.address:#x}+{len(segment.data):#x}" for segment in segments
            )
            logger.debug("loaded %s: %s", kind, placed)
        self._image_loaded = True
        self._booted = False

    def _require_segment(self, segment: LoadSegment, *, wrap: bool) -> None:
        """Reject a span the memory map does not cover.

        Raw images keep the map's own error text. ELF and HEX name the
        segment as well, so a ``.data`` load address that missed flash is
        obvious.
        """
        try:
            self.memory.regions_covering(segment.address, len(segment.data))
        except MachineError as exc:
            if not wrap:
                raise
            raise MachineError(
                f"{segment.label} at {segment.address:#x} size {len(segment.data):#x} "
                f"falls outside the memory map: {exc}"
            ) from exc

    def boot(self, *, reset: bool = False) -> None:
        """Set SP and PC from the vector table or from ``boot.entry``.

        A second call is a no-op unless ``reset`` is true. Reset restores
        peripheral state captured at construction, clears NVIC and the core
        mode bits, and re-reads the boot PC. It does not reload the image,
        so SRAM keeps whatever the guest left there. ``boot.mode vector``
        uses ``vector_base``. ``boot.mode entry`` uses ``boot.sp`` and
        ``boot.entry``.
        """
        if not self._image_loaded:
            raise MachineError("load an image before boot")
        if self._booted and not reset:
            return
        if reset:
            for plugin in self._peripherals:
                plugin.restore_state(copy.deepcopy(self._peripheral_init[plugin.name]))
            self.backend.reset_cpu_state()
            for plugin in self._peripherals:
                if isinstance(plugin, Uart):
                    plugin.raise_rx_if_needed()
        boot = self.config.boot
        if boot.mode == "vector":
            sp = self.read_u32(boot.vector_base)
            entry = self.read_u32(boot.vector_base + 4)
        else:
            if boot.sp is None or boot.entry is None:
                raise ConfigError("boot.mode entry requires boot.sp and boot.entry")
            sp = boot.sp
            entry = boot.entry
        # Thread mode, privileged, MSP selected, masks clear. Writing CONTROL
        # first makes the following SP write land in MSP when a thread had
        # PSP selected.
        self.backend.write_register("control", 0)
        self.backend.write_register("primask", 0)
        self.backend.write_register("basepri", 0)
        self.backend.write_register("faultmask", 0)
        # write_register clears SP[1:0]. An odd vector word or boot.sp
        # (Atollic ``_estack = ...FFFF``) becomes the word-aligned pointer
        # hardware would have loaded.
        self.backend.write_register("msp", sp)
        self.backend.write_register("sp", sp)
        self.backend.write_register("psp", 0)
        self.backend.write_register("lr", 0xFFFFFFFF)
        # EPSR.T. ``start`` also forces the Thumb bit on the entry address.
        self.backend.write_register("xpsr", 1 << 24)
        self.backend.write_register("pc", entry & ~1)
        if boot.mode == "vector":
            self.backend.set_vector_table(boot.vector_base)
        self._booted = True

    def attach_coverage(self, coverage) -> None:
        """Record AFL-style edges into ``coverage`` on later runs.

        ``coverage`` is a ``CoverageMap``, or None to stop recording. The map
        is not guest state: ``run`` clears it after a snapshot restore and
        before the first instruction, so one execution cannot leak hits into
        the next. ``run.collect_coverage`` still records the PC set when that
        flag is on; the bitmap is separate and only updated when attached.
        """
        self._coverage_map = coverage

    def attach_cmplog(self, cmplog) -> None:
        """Record comparison operands into ``cmplog`` on later runs.

        ``cmplog`` is a ``CmpLog``, or None to detach. Logging stays off
        until ``cmplog.active`` is set, so attaching it does not decode on
        an ordinary execution. The log is not guest state: ``run`` clears
        it at the start of a shadow run, and it is not part of the snapshot.
        """
        self._cmplog = cmplog

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
        self._recent_pcs.clear()
        self._recent_edges.clear()
        self._edge_prev = 0
        self._resets = 0
        self._silent_resets = 0
        self._reset_tx_mark = self._uart_tx_len()
        if self._coverage_map is not None:
            self._coverage_map.begin_run()
        if self._cmplog is not None and self._cmplog.active:
            self._cmplog.begin_run()
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

    def request_stop(self, status: str, detail: str) -> None:
        """Stop at the next instruction boundary with ``status`` and ``detail``.

        A reason that is already set (a fault, a halt address) is kept.
        Used by the banner checkpoint, which is not a guest halt address.
        """
        if self._reason is None:
            self._reason = status
            self._detail = detail
        self.backend.stop()

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
        # A bit-band alias is 32 MiB. Map and hook each contiguous run once
        # instead of once per page.
        self._spans = _contiguous_spans(self._final_perms, page)
        for start, size, perms in self._spans:
            # Writable until the image is loaded; ``run`` tightens this.
            self.backend.map_memory(start, size, perms | PERM_WRITE)

    def _install_hooks(self) -> None:
        self.backend.hook_code(self._on_code)
        self.backend.hook_interrupt(self._on_interrupt)
        self.backend.hook_unmapped(self._on_unmapped)
        self.backend.hook_prot(self._on_prot)
        page = self.backend.page_size
        hooked = {start: 0 for start in self._hook_pages}
        for start, size, _perms in _contiguous_spans(hooked, page):
            end = start + size - 1
            self.backend.hook_memory_read(self._on_read, start, end)
            self.backend.hook_memory_write(self._on_write, start, end)

    def _apply_protection(self) -> None:
        if self._protected:
            return
        self._reprotect(writable=False)
        self._protected = True

    def _reprotect(self, *, writable: bool) -> None:
        for start, size, perms in self._spans:
            # Image load needs a temporary write window on execute-only flash.
            effective = perms | PERM_WRITE if writable else perms
            self.backend.protect_memory(start, size, effective)

    def _bitband_load_byte(self, address: int) -> int:
        """Byte a bit-band alias reads. Plugins win over plain RAM."""
        region = self.memory.region_at(address)
        if region is None:
            return self.config.unmapped.read_default & 0xFF
        peripheral = region.peripheral
        if peripheral is None:
            try:
                return self.backend.read_memory(address, 1)[0]
            except BackendError:
                return 0
        if isinstance(peripheral, Bitband):
            return 0
        return peripheral.read(address - region.base, 1) & 0xFF

    def _bitband_store_byte(self, address: int, value: int) -> None:
        """Read-modify-write one target byte for a bit-band store."""
        value &= 0xFF
        region = self.memory.region_at(address)
        if region is None:
            return
        peripheral = region.peripheral
        if isinstance(peripheral, Bitband):
            return
        if peripheral is not None:
            peripheral.write(address - region.base, 1, value)
        try:
            self.backend.write_memory(address, bytes([value]))
        except BackendError:
            return

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
        if self._consume_reset_request():
            return
        self._clock_peripherals()
        effect = self.backend.service_interrupts(address, size)
        if effect == STOP or self.backend.cpu_fault:
            self._reason = STATUS_FAULT
            self._detail = self.backend.cpu_fault or "cpu fault"
            self.backend.stop()
            return
        if effect == REDIRECT:
            return
        if self._svc_nop(address):
            # Unicorn reports SVC only after it executes. Moving PC first
            # retires the listed immediate as a NOP.
            self.backend.write_register("pc", (address + 2) | 1)
        self._instructions += 1
        self._note_retired(address)
        feed = self._rx_feed
        if feed is not None:
            feed.on_retired(self._instructions)
        hook = self._retire_hook
        if hook is not None:
            hook(self._instructions)
        if self.config.run.collect_coverage:
            self._coverage.add(address)
        coverage_map = self._coverage_map
        if coverage_map is not None:
            coverage_map.on_instruction(address)
        cmplog = self._cmplog
        if cmplog is not None:
            cmplog.on_instruction(self, address, size)

    def _consume_reset_request(self) -> bool:
        """Apply a pending AIRCR reset before this instruction retires.

        Returns True when the instruction should not execute. The request is
        raised from the store that wrote AIRCR, which has already retired.
        """
        request = self.backend.take_reset_request()
        if not request:
            return False
        if self.config.run.halt_on_reset:
            self._reason = STATUS_HALTED
            self._detail = request
            self.backend.stop()
            return True
        tx_len = self._uart_tx_len()
        if tx_len > self._reset_tx_mark:
            self._silent_resets = 0
        self._reset_tx_mark = tx_len
        self._silent_resets += 1
        cap = self.config.run.max_resets
        if cap and self._silent_resets > cap:
            self._reason = STATUS_HALTED
            self._detail = f"stopped after {cap} silent core resets ({request})"
            self.backend.stop()
            return True
        self._resets += 1
        self._apply_core_reset()
        logger.info(
            "core reset via %s; reset %d, continuing at %#010x",
            request,
            self._resets,
            self.backend.read_register("pc") & ~1,
        )
        return True

    def _apply_core_reset(self) -> None:
        """Same path as ``boot(reset=True)``, keeping the UART transcript.

        Peripheral registers, the RX queue, and the NVIC return to the
        construction snapshot. Bytes already accepted into ``tx`` stay: that
        buffer is the host's copy of what left the wire, not the shift
        register. SRAM is not reloaded.
        """
        kept = [
            (plugin, bytes(plugin.tx), plugin.tx_dropped)
            for plugin in self._peripherals
            if isinstance(plugin, Uart)
        ]
        self.boot(reset=True)
        for plugin, tx, dropped in kept:
            plugin.tx = bytearray(tx)
            plugin.tx_dropped = dropped
        # ``boot`` stores an even PC. ``start`` sets the Thumb bit for the
        # initial entry. A redirect from this hook has to set it itself,
        # matching exception entry.
        pc = self.backend.read_register("pc")
        self.backend.write_register("pc", pc | 1)
        xpsr = self.backend.read_register("xpsr")
        self.backend.write_register("xpsr", xpsr | (1 << 24))

    def _uart_tx_len(self) -> int:
        return sum(len(plugin.tx) for plugin in self._peripherals if isinstance(plugin, Uart))

    def _svc_nop(self, address: int) -> bool:
        """True when this halfword is an SVC immediate listed in ``run.svc_nop``."""
        immediates = self.config.run.svc_nop
        if not immediates:
            return False
        try:
            half = int.from_bytes(self.backend.read_memory(address, 2), "little")
        except BackendError:
            return False
        return (half & 0xFF00) == 0xDF00 and (half & 0xFF) in immediates

    def _clock_peripherals(self) -> None:
        """Step SysTick and timers, and latch a UART RX edge, before this instruction.

        They use the NVIC pending bits the backend already delivers. A UART
        with no ``rx_irq``, and a timer that is stopped or still inside its
        period, contribute nothing.
        """
        for plugin in self._peripherals:
            if isinstance(plugin, SysTick):
                if plugin.consume_cpu_tick():
                    self.backend.pend_exception(EXC_SYSTICK)
            elif isinstance(plugin, Timer):
                irq = plugin.consume_cpu_tick()
                if irq is not None:
                    self.inject_irq(irq)
            elif isinstance(plugin, Uart):
                irq = plugin.take_rx_irq_edge()
                if irq is not None:
                    self.inject_irq(irq)

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

    def _on_prot(self, access: MemAccess) -> bool:
        label = {
            "read_prot": "read",
            "write_prot": "write",
            "fetch_prot": "fetch",
        }.get(access.kind, access.kind)
        self._reason = STATUS_FAULT
        self._detail = f"prot {label} at {access.address:#x} size {access.size}"
        self._record(f"prot_{label}", access.address, access.size, access.value)
        return False

    def _note_retired(self, address: int) -> None:
        """Remember one retired instruction for the crash fingerprint.

        ``cur`` and ``prev`` follow ``CoverageMap.on_instruction``. Keeping
        the tail here, and not only in the bitmap, means a run with no
        coverage map still buckets the same way as a fuzz iteration.
        """
        self._recent_pcs.append(address)
        cur = edge_location(address, MAP_SIZE - 1)
        index = cur ^ self._edge_prev
        self._edge_prev = cur >> 1
        self._recent_edges.append(index)

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
            recent_pcs=tuple(self._recent_pcs),
            recent_edges=tuple(self._recent_edges),
            resets=self._resets,
        )
