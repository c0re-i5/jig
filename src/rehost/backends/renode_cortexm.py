# SPDX-License-Identifier: MIT
"""Renode Cortex-M backend.

``renode`` executes Thumb on the Cortex-M4 platform Renode already ships,
``@platforms/cpus/nrf52840.repl``. That file is the CPU, NVIC, flash, and
SRAM; Jig does not invent a second board model. On Renode 1.17 the platform
registers:

* ``sysbus.flash`` at ``0x00000000``, 1 MiB of ``Memory.MappedMemory``
* ``sysbus.ram`` at ``0x20000000`` and an alias at ``0x00800000``, 256 KiB each

The adapter reads those registration points after the platform loads, so a
later Renode that resizes the same two peripherals is picked up. A YAML
region that misses both windows is a ``Memory.MappedMemory`` added with
``LoadPlatformDescriptionFromString`` when the address is free. An address
Renode already decoded (the nRF clock at the fixture UART ``0x40000000``,
the radio at the fixture GPIO ``0x40001000``, the NVIC page that contains
SysTick) stays a host shadow.

Ordinary instructions are one ``cpu Step`` on the monitor socket Renode
opens for ``--disable-gui --plain -P``. ``BKPT`` and ``SVC`` are not
stepped: Renode would vector them through its own NVIC. ``WFI`` and ``WFE``
are not stepped either: ``cpu Step`` sleeps the core, and later steps stop
retiring. Those two advance PC locally. Decoded loads and stores that touch
a shadow page, a plugin hook, an unmapped address, or a permission the map
does not allow are not issued to the board. They call the same hooks
``Machine`` installs for Unicorn, so the UART, GPIO, and SysTick plugins
see the access. The load/store decoder is the one the QEMU adapter already
uses.

``inject_irq`` only records the request. Exception entry stays on the
Unicorn backend. There is no robotframework and no pyrenode dependency.
"""

from __future__ import annotations

import atexit
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time

from rehost.backends.base import CpuBackend, MemAccess
from rehost.backends.qemu_cortexm import decode_thumb, thumb2_memory_base
from rehost.backends.registry import register_backend
from rehost.backends.unicorn_cortexm import BKPT_VECTOR, SVC_VECTOR
from rehost.errors import BackendError
from rehost.memory import PERM_EXEC, PERM_READ, PERM_WRITE
from rehost.nvic import raz_sp

logger = logging.getLogger(__name__)

# Stock platform. ``cpuType`` in that file is cortex-m4.
RENODE_PLATFORM = "@platforms/cpus/nrf52840.repl"
RENODE_CPU = "cortex-m4"
_RENODE_BINARY = "renode"

# Used only when ``GetRegistrationPoints`` cannot be parsed. These are the
# windows in Renode 1.17's nrf52840.repl.
_FALLBACK_RAM = (
    (0x00000000, 0x00100000),
    (0x00800000, 0x00040000),
    (0x20000000, 0x00040000),
)

# Renode parks a lockup here. Stepping a BKPT or SVC into its NVIC also
# leaves the PC at 0 with a nonzero IPSR; those two are not stepped.
_LOCKUP_PC = 0xEFFFFFFE

_SNAPSHOT_REGS = (
    "r0",
    "r1",
    "r2",
    "r3",
    "r4",
    "r5",
    "r6",
    "r7",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "sp",
    "lr",
    "pc",
    "xpsr",
    "msp",
    "psp",
    "control",
    "primask",
    "basepri",
    "faultmask",
)
_STACK_REGS = frozenset({"sp", "msp", "psp"})
# Stepping these sleeps the core: later ``cpu Step`` calls stop retiring.
_WFI = 0xBF30
_WFE = 0xBF20
_READ_CHUNK = 1024

_RANGE = re.compile(r"<\s*(0x[0-9A-Fa-f]+)\s*,\s*(0x[0-9A-Fa-f]+)\s*>")
_HEX_BYTE = re.compile(r"0x([0-9A-Fa-f]+)")
_PROMPT = re.compile(r"\([^)\r\n]+\)\s*$")
_INT = re.compile(r"0x[0-9A-Fa-f]+|\d+")

_LIVE: set[RenodeCortexM] = set()


def _close_live() -> None:
    for backend in list(_LIVE):
        backend.close()


atexit.register(_close_live)


def resolve_renode(binary: str | None = None) -> str:
    """Return the ``renode`` path, or raise naming that binary."""
    if binary is None:
        binary = os.environ.get("JIG_RENODE") or None
    if not binary:
        binary = shutil.which(_RENODE_BINARY)
    if not binary or not os.path.isfile(binary) or not os.access(binary, os.X_OK):
        where = binary or "PATH"
        raise BackendError(
            f"{_RENODE_BINARY} was not found ({where}). "
            f"Install Renode from https://github.com/renode/renode/releases "
            f"and put the {_RENODE_BINARY} binary on PATH, "
            "or set JIG_RENODE to that binary, to use the renode backend."
        )
    return binary


def parse_registration_points(text: str) -> list[tuple[int, int]]:
    """Parse ``GetRegistrationPoints`` output into ``(base, size)`` windows.

    Renode prints inclusive ranges (``<0x20000000, 0x2003FFFF>``).
    """
    windows: list[tuple[int, int]] = []
    for start_text, end_text in _RANGE.findall(text):
        start = int(start_text, 16)
        end = int(end_text, 16)
        if end < start:
            continue
        windows.append((start, end - start + 1))
    return windows


def parse_byte_list(text: str) -> bytes:
    """Parse a monitor ``ReadBytes`` dump (``0x01, 0x20, ...``)."""
    out = bytearray()
    for token in _HEX_BYTE.findall(text):
        value = int(token, 16)
        if value > 0xFF:
            break
        out.append(value)
    return bytes(out)


def _covers(windows: list[tuple[int, int]], address: int) -> bool:
    for base, size in windows:
        if base <= address < base + size:
            return True
    return False


def _reg_name(number: int) -> str:
    if number == 13:
        return "sp"
    if number == 14:
        return "lr"
    if number == 15:
        return "pc"
    if 0 <= number <= 12:
        return f"r{number}"
    raise BackendError(f"register number {number} is not a Cortex-M GPR")


def _sign_extend(value: int, width: int) -> int:
    bits = width * 8
    value &= (1 << bits) - 1
    if value & (1 << (bits - 1)):
        value -= 1 << bits
    return value & 0xFFFFFFFF


def _mask(width: int) -> int:
    return (1 << (8 * width)) - 1


def _hooks_cover(hooks: list[tuple[int, int, object]], address: int, width: int) -> bool:
    last = address + width - 1
    for start, end, _callback in hooks:
        if last < start or address > end:
            continue
        return True
    return False


def _decode_telnet(buf: bytes) -> tuple[str, bytes]:
    """Drop telnet IAC sequences. A trailing incomplete IAC stays unconsumed."""
    out = bytearray()
    index = 0
    while index < len(buf):
        if buf[index] != 255:
            out.append(buf[index])
            index += 1
            continue
        if index + 1 >= len(buf):
            break
        command = buf[index + 1]
        if command == 255:
            out.append(255)
            index += 2
            continue
        if command in (251, 252, 253, 254):
            if index + 2 >= len(buf):
                break
            index += 3
            continue
        if command == 250:
            end = buf.find(bytes([255, 240]), index + 2)
            if end < 0:
                break
            index = end + 2
            continue
        index += 2
    return out.decode("utf-8", "replace"), buf[index:]


def _body(raw: str, line: str) -> str:
    text = _PROMPT.sub("", raw.replace("\r", ""))
    lines = text.split("\n")
    if lines and lines[0].strip() == line:
        lines = lines[1:]
    while lines and not lines[0].strip():
        lines = lines[1:]
    while lines and not lines[-1].strip():
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _is_monitor_error(text: str) -> bool:
    return "There was an error" in text or "Parameters did not match" in text


def _last_int(text: str) -> int:
    matches = _INT.findall(text)
    if not matches:
        shown = " ".join(text.split())
        if len(shown) > 200:
            shown = shown[:200]
        raise BackendError(f"renode returned no integer ({shown!r})")
    return int(matches[-1], 0)


class _Monitor:
    """One Renode monitor socket. Commands are lines; the prompt ends a reply."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._buf = b""
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def read_banner(self) -> str:
        return self._read_prompt(30)

    def cmd(self, line: str, timeout: float = 10) -> str:
        try:
            self._sock.sendall((line + "\n").encode("utf-8"))
        except OSError as exc:
            raise BackendError(f"renode monitor closed: {exc}") from exc
        raw = self._read_prompt(timeout)
        body = _body(raw, line)
        if _is_monitor_error(body):
            shown = " ".join(body.split())
            if len(shown) > 400:
                shown = shown[:400]
            raise BackendError(f"renode rejected {line.split()[0]}: {shown}")
        return body

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            return

    def _read_prompt(self, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        self._sock.settimeout(max(0.2, timeout))
        while time.monotonic() < deadline:
            text, _tail = _decode_telnet(self._buf)
            if _PROMPT.search(text):
                self._buf = b""
                return text
            try:
                chunk = self._sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                raise BackendError("renode monitor closed the connection")
            self._buf += chunk
        raise BackendError(
            "renode monitor timed out waiting for a prompt. "
            "WFI and WFE are not stepped, because cpu Step sleeps the core."
        )


@register_backend("renode")
@register_backend("renode-cortex-m")
class RenodeCortexM(CpuBackend):
    """Cortex-M via Renode's ``nrf52840`` platform and its monitor socket.

    Unicorn stays the default (``arch: cortex-m``). Select this backend with
    ``--backend renode`` or with ``arch: renode`` / ``arch: renode-cortex-m``.
    """

    arch = "renode-cortex-m"
    page_size = 0x1000

    def __init__(self, *, binary: str | None = None) -> None:
        super().__init__()
        self.binary = resolve_renode(binary)
        self.platform = RENODE_PLATFORM
        self._closed = False
        self._proc: subprocess.Popen[bytes] | None = None
        self._log: tempfile._TemporaryFileWrapper[bytes] | None = None
        self._mon: _Monitor | None = None
        self._ram_windows: list[tuple[int, int]] = []
        self._pages: dict[int, int] = {}
        self._ram_pages: set[int] = set()
        self._shadow: dict[int, bytearray] = {}
        self._code_hooks: list = []
        self._intr_hooks: list = []
        self._read_hooks: list[tuple[int, int, object]] = []
        self._write_hooks: list[tuple[int, int, object]] = []
        self._unmapped_hooks: list = []
        self._prot_hooks: list = []
        self._stop = False
        self._pc: int | None = None
        self._launch()

    def close(self) -> None:
        """Stop ``renode``. Safe to call more than once."""
        if self._closed:
            return
        self._closed = True
        self._code_hooks.clear()
        self._intr_hooks.clear()
        self._read_hooks.clear()
        self._write_hooks.clear()
        self._unmapped_hooks.clear()
        self._prot_hooks.clear()
        _LIVE.discard(self)
        mon = self._mon
        self._mon = None
        if mon is not None:
            try:
                mon._sock.sendall(b"quit\n")
            except OSError:
                pass
            mon.close()
        proc = self._proc
        self._proc = None
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except OSError:
                proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    proc.kill()
                proc.wait(timeout=1)
        if self._log is not None:
            self._log.close()
            self._log = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            return

    def map_memory(self, address: int, size: int, perms: int) -> None:
        self._check_pages(address, size)
        self._require_perms(perms)
        pages = list(range(address, address + size, self.page_size))
        for page in pages:
            if page in self._pages:
                raise BackendError(f"mem_map {address:#x} size {size:#x} overlaps an existing mapping")
        outside: list[int] = []
        for page in pages:
            self._pages[page] = perms
            if self._page_is_ram(page):
                self._ram_pages.add(page)
            else:
                outside.append(page)
        for start, nbytes in _runs(outside, self.page_size):
            self._map_outside(start, nbytes)

    def protect_memory(self, address: int, size: int, perms: int) -> None:
        self._check_pages(address, size)
        self._require_perms(perms)
        pages = range(address, address + size, self.page_size)
        missing = [page for page in pages if page not in self._pages]
        if missing:
            raise BackendError(f"mem_protect {address:#x} is not mapped")
        for page in pages:
            self._pages[page] = perms

    def write_memory(self, address: int, data: bytes) -> None:
        data = bytes(data)
        self._copy_memory(address, data, write=True)

    def read_memory(self, address: int, size: int) -> bytes:
        if size < 0:
            raise BackendError(f"mem_read size {size} is negative")
        return self._copy_memory(address, b"\x00" * size, write=False)

    def read_register(self, name: str) -> int:
        if name == "pc" and self._pc is not None:
            return self._pc
        value = self._read_named(name)
        if name == "pc":
            value &= ~1
            self._pc = value
        if name in _STACK_REGS:
            value = raz_sp(value)
        return value & 0xFFFFFFFF

    def write_register(self, name: str, value: int) -> None:
        if not isinstance(value, int) or isinstance(value, bool):
            raise BackendError(f"register {name} value must be an int, not {value!r}")
        stored = value & 0xFFFFFFFF
        if name in _STACK_REGS:
            stored = raz_sp(stored)
        if name == "pc" and stored & 1:
            xpsr = self._read_named("xpsr") | (1 << 24)
            self._write_named("xpsr", xpsr)
            stored &= ~1
        self._write_named(name, stored)
        if name == "pc":
            self._pc = stored & ~1

    def read_registers(self) -> dict[str, int]:
        values: dict[str, int] = {}
        for name in _SNAPSHOT_REGS:
            try:
                values[name] = self.read_register(name)
            except BackendError:
                logger.debug("renode monitor has no readable register %s", name)
        return values

    def write_registers(self, values: dict[str, int]) -> None:
        # CONTROL selects MSP or PSP. Write it before the stack pointers so
        # a later restore does not deposit them in the other bank.
        if "control" in values:
            self.write_register("control", values["control"])
        for name, value in values.items():
            if name == "control":
                continue
            self.write_register(name, value)

    def start(self, pc: int, *, until: int, timeout_us: int, count: int) -> bool:
        if self._closed:
            raise BackendError("renode backend is closed")
        self._stop = False
        self.cpu_fault = None
        self.write_register("pc", pc | 1)
        deadline = time.monotonic() + (timeout_us / 1_000_000) if timeout_us else None
        executed = 0
        stop_at = (until & ~1) if until <= 0xFFFFFFFF else None
        while not self._stop:
            if deadline is not None and time.monotonic() >= deadline:
                return True
            if count and executed >= count:
                return False
            current = self.read_register("pc") & ~1
            if stop_at is not None and current == stop_at:
                return False
            self._one_instruction(current)
            executed += 1
        return False

    def stop(self) -> None:
        self._stop = True

    def hook_code(self, callback) -> None:
        self._code_hooks.append(callback)

    def hook_interrupt(self, callback) -> None:
        self._intr_hooks.append(callback)

    def hook_memory_read(self, callback, start: int, end: int) -> None:
        self._read_hooks.append((start, end, callback))

    def hook_memory_write(self, callback, start: int, end: int) -> None:
        self._write_hooks.append((start, end, callback))

    def hook_unmapped(self, callback) -> None:
        self._unmapped_hooks.append(callback)

    def hook_prot(self, callback) -> None:
        self._prot_hooks.append(callback)

    def prepare_run(self) -> None:
        super().prepare_run()
        self._stop = False

    def set_vector_table(self, address: int) -> None:
        """Write VTOR. Renode's NVIC is not the one Jig delivers interrupts with."""
        self._cmd(f"cpu VecBase {address & 0xFFFFFFFF:#x}")

    def ensure_system_control(self) -> None:
        """Leave the platform NVIC to Renode.

        A SysTick plugin the machine mapped is a shadow page and is
        dispatched through the memory hooks. This backend does not install
        the Unicorn NVIC model on ``0xE000E000``.
        """
        return None

    def _launch(self) -> None:
        _LIVE.add(self)
        port = _free_port()
        self._log = tempfile.TemporaryFile()
        argv = [
            self.binary,
            "--disable-gui",
            "--plain",
            "-P",
            str(port),
        ]
        logger.debug("starting %s", " ".join(argv))
        try:
            self._proc = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=self._log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            sock = _connect(port, self._proc)
            self._mon = _Monitor(sock)
            self._mon.read_banner()
            self._cmd('mach create "jig"')
            self._cmd(f"machine LoadPlatformDescription {RENODE_PLATFORM}", timeout=60)
            self._ram_windows = self._discover_ram()
            logger.debug("renode RAM windows %s", self._ram_windows)
        except Exception as exc:
            detail = self._stderr_tail()
            self.close()
            message = str(exc)
            if detail and detail not in message:
                message = f"{message} renode said: {detail}"
            if isinstance(exc, BackendError):
                raise BackendError(message) from exc
            raise BackendError(f"failed to start {_RENODE_BINARY} ({self.binary}): {message}") from exc

    def _discover_ram(self) -> list[tuple[int, int]]:
        found: list[tuple[int, int]] = []
        for name in ("sysbus.flash", "sysbus.ram"):
            try:
                text = self._cmd(f"sysbus GetRegistrationPoints {name}")
            except BackendError as exc:
                logger.debug("renode registration %s: %s", name, exc)
                continue
            found.extend(parse_registration_points(text))
        if not found:
            found = list(_FALLBACK_RAM)
        if not _covers(found, 0) or not _covers(found, 0x20000000):
            rendered = ", ".join(f"{base:#x}+{size:#x}" for base, size in found)
            raise BackendError(
                f"{RENODE_PLATFORM} does not map flash at 0x0 and SRAM at 0x20000000 "
                f"(windows: {rendered}). This adapter runs the synthetic map on that platform."
            )
        # A read proves the window is memory the CPU can touch. A missing
        # peripheral raises in the monitor.
        self._cmd("sysbus ReadByte 0x0")
        self._cmd("sysbus ReadByte 0x20000000")
        return found

    def _map_outside(self, address: int, size: int) -> None:
        """Add MappedMemory when the address is free; otherwise shadow it."""
        pages = range(address, address + size, self.page_size)
        if not self._address_is_free(address):
            for page in pages:
                self._shadow[page] = bytearray(self.page_size)
            return
        name = f"jigmem{address:08x}"
        desc = f"{name}: Memory.MappedMemory @ sysbus {address:#x} {{ size: {size:#x} }}"
        try:
            self._cmd(f'machine LoadPlatformDescriptionFromString "{desc}"', timeout=30)
            kind = self._cmd(f"sysbus WhatPeripheralIsAt {address:#x}")
            if "MappedMemory" not in kind:
                raise BackendError(f"renode mapped {address:#x} as {kind!r}, not MappedMemory")
        except BackendError as exc:
            logger.debug("renode extra RAM %s size %#x not added: %s", name, size, exc)
            for page in pages:
                self._shadow[page] = bytearray(self.page_size)
            return
        for page in pages:
            self._ram_pages.add(page)

    def _address_is_free(self, address: int) -> bool:
        try:
            text = self._cmd(f"sysbus WhatPeripheralIsAt {address:#x}")
        except BackendError:
            return False
        return text.strip().lower() in ("", "null", "none")

    def _one_instruction(self, pc: int) -> None:
        fetched = self._fetch(pc)
        if fetched is None:
            return
        hw1, hw2, size = fetched
        for callback in list(self._code_hooks):
            callback(pc, size)
            if self._stop:
                return
        if (self.read_register("pc") & ~1) != pc:
            return
        if size == 2 and (hw1 & 0xFF00) == 0xBE00:
            self._fire_intr(BKPT_VECTOR)
            return
        if size == 2 and (hw1 & 0xFF00) == 0xDF00:
            self._fire_intr(SVC_VECTOR)
            if not self._stop:
                self._advance(pc, 2)
            return
        if size == 2 and hw1 in (_WFI, _WFE):
            # ``cpu Step`` of WFI/WFE reports the next PC and then stops
            # retiring further steps. Advance locally so the run continues.
            self._advance(pc, 2)
            return
        decoded = decode_thumb(hw1, hw2, pc, self._read_gpr)
        if decoded is not None and any(self._needs_intercept(op) for op in decoded.ops):
            self._emulate(pc, decoded)
            return
        if decoded is None and size == 4:
            self._refuse_undecoded_memory(pc, hw1, hw2)
            if self._stop:
                return
        landed = self._step()
        if self._stop:
            return
        ipsr = self._read_named("xpsr") & 0x1FF
        if landed == _LOCKUP_PC or ipsr:
            self.cpu_fault = f"renode exception {ipsr} at {pc:#x}"
            self._stop = True

    def _step(self) -> int:
        landed = _last_int(self._cmd("cpu Step")) & ~1
        self._pc = landed
        return landed

    def _fetch(self, pc: int) -> tuple[int, int, int] | None:
        if not self._fetch_allowed(pc):
            return None
        hw1 = int.from_bytes(self.read_memory(pc, 2), "little")
        if hw1 < 0xE800:
            return hw1, 0, 2
        if not self._fetch_allowed(pc + 2):
            return None
        hw2 = int.from_bytes(self.read_memory(pc + 2, 2), "little")
        return hw1, hw2, 4

    def _fetch_allowed(self, address: int) -> bool:
        page = address & ~(self.page_size - 1)
        perms = self._pages.get(page)
        if perms is None:
            if not self._ask(MemAccess("fetch_unmapped", address, 2, 0), self._unmapped_hooks):
                self._stop = True
                return False
            perms = self._pages.get(page)
            if perms is None:
                self._stop = True
                return False
        if not perms & PERM_EXEC:
            if not self._ask(MemAccess("fetch_prot", address, 2, 0), self._prot_hooks):
                self._stop = True
                return False
        if page not in self._ram_pages:
            raise BackendError(
                f"pc {address:#x} is not in {RENODE_PLATFORM} RAM and Renode "
                "did not accept a MappedMemory there; the CPU cannot fetch it"
            )
        return True

    def _refuse_undecoded_memory(self, pc: int, hw1: int, hw2: int) -> None:
        base = thumb2_memory_base(hw1)
        if base is None or base == 15:
            return
        base_val = self._read_gpr(base) & 0xFFFFFFFF
        if not (
            self._needs_intercept_addr(base_val, 4, store=False)
            or self._needs_intercept_addr(base_val, 4, store=True)
        ):
            return
        raise BackendError(
            f"undecoded load/store at {pc:#x} (encoding {hw1:04x} {hw2:04x}); "
            f"base {_reg_name(base)} is {base_val:#x}, which is not {RENODE_PLATFORM} RAM. "
            "Refusing to let renode perform the access."
        )

    def _emulate(self, pc: int, decoded) -> None:
        for op in decoded.ops:
            if not self._guest_access(op):
                return
        self._advance(pc, decoded.size)

    def _guest_access(self, op) -> bool:
        address = op.address & 0xFFFFFFFF
        if not self._span_mapped(address, op.width):
            kind = "write_unmapped" if op.store else "read_unmapped"
            value = op.value if op.store else 0
            if not self._ask(MemAccess(kind, address, op.width, value), self._unmapped_hooks):
                self._stop = True
                return False
            if not self._span_mapped(address, op.width):
                self._stop = True
                return False
        if not self._perms_allow(address, op.width, store=op.store):
            kind = "write_prot" if op.store else "read_prot"
            value = op.value if op.store else 0
            if not self._ask(MemAccess(kind, address, op.width, value), self._prot_hooks):
                self._stop = True
                return False
        if op.store:
            data = (op.value & _mask(op.width)).to_bytes(op.width, "little")
            self.write_memory(address, data)
            self._fire_mem(self._write_hooks, address, op.width, op.value & _mask(op.width))
        else:
            old = int.from_bytes(self.read_memory(address, op.width), "little")
            self._fire_mem(self._read_hooks, address, op.width, old)
            if self._stop:
                return False
            raw = int.from_bytes(self.read_memory(address, op.width), "little")
            value = _sign_extend(raw, op.width) if op.signed else raw
            self.write_register(_reg_name(op.rt), value)
        return not self._stop

    def _needs_intercept(self, op) -> bool:
        return self._needs_intercept_addr(op.address, op.width, store=op.store)

    def _needs_intercept_addr(self, address: int, width: int, *, store: bool) -> bool:
        address &= 0xFFFFFFFF
        if width <= 0 or address + width - 1 > 0xFFFFFFFF:
            return True
        cursor = address
        last = address + width - 1
        while True:
            page = cursor & ~(self.page_size - 1)
            perms = self._pages.get(page)
            if perms is None or page not in self._ram_pages:
                return True
            need = PERM_WRITE if store else PERM_READ
            if not perms & need:
                return True
            page_last = page + self.page_size - 1
            if last <= page_last:
                break
            cursor = page_last + 1
        return _hooks_cover(self._read_hooks, address, width) or _hooks_cover(
            self._write_hooks, address, width
        )

    def _span_mapped(self, address: int, width: int) -> bool:
        if width <= 0 or address + width - 1 > 0xFFFFFFFF:
            return False
        cursor = address
        last = address + width - 1
        while True:
            page = cursor & ~(self.page_size - 1)
            if page not in self._pages:
                return False
            page_last = page + self.page_size - 1
            if last <= page_last:
                return True
            cursor = page_last + 1

    def _perms_allow(self, address: int, width: int, *, store: bool) -> bool:
        need = PERM_WRITE if store else PERM_READ
        cursor = address
        last = address + width - 1
        while True:
            page = cursor & ~(self.page_size - 1)
            perms = self._pages.get(page, 0)
            if not perms & need:
                return False
            page_last = page + self.page_size - 1
            if last <= page_last:
                return True
            cursor = page_last + 1

    def _advance(self, pc: int, size: int) -> None:
        if self._stop:
            return
        if (self.read_register("pc") & ~1) != (pc & ~1):
            return
        self.write_register("pc", (pc + size) | 1)

    def _fire_intr(self, vector: int) -> None:
        for callback in list(self._intr_hooks):
            callback(vector)
            if self._stop:
                return

    def _fire_mem(self, hooks: list[tuple[int, int, object]], address: int, width: int, value: int) -> None:
        for start, end, callback in list(hooks):
            if address + width - 1 < start or address > end:
                continue
            callback(address, width, value)
            if self._stop:
                return

    def _ask(self, event: MemAccess, hooks: list) -> bool:
        if not hooks:
            return False
        for callback in hooks:
            if not callback(event):
                return False
        return True

    def _read_gpr(self, number: int) -> int:
        return self.read_register(_reg_name(number))

    def _read_named(self, name: str) -> int:
        if name in {f"r{index}" for index in range(13)}:
            index = int(name[1:])
            return _last_int(self._cmd(f"cpu GetRegister {index}"))
        if name == "sp":
            return _last_int(self._cmd("cpu SP"))
        if name == "lr":
            return _last_int(self._cmd("cpu LR"))
        if name == "pc":
            return _last_int(self._cmd("cpu PC"))
        if name == "xpsr":
            # CPSR is the monitor name that accepts EPSR.T. Writing
            # XProgramStatusRegister leaves T clear while PC is 0.
            return _last_int(self._cmd("cpu CPSR"))
        if name in ("msp", "psp"):
            return self._read_banked(name)
        if name == "control":
            return _last_int(self._cmd("cpu Control"))
        if name == "primask":
            return _last_int(self._cmd("cpu PRIMASK"))
        if name == "basepri":
            return _last_int(self._cmd("cpu BasePri"))
        if name == "faultmask":
            return _last_int(self._cmd("cpu FAULTMASK"))
        known = ", ".join(_SNAPSHOT_REGS)
        raise BackendError(f"unknown register {name!r}; known: {known}")

    def _write_named(self, name: str, value: int) -> None:
        if name in {f"r{index}" for index in range(13)}:
            index = int(name[1:])
            self._cmd(f"cpu SetRegister {index} {value:#x}")
            return
        if name == "sp":
            self._cmd(f"cpu SP {value:#x}")
            return
        if name == "lr":
            self._cmd(f"cpu LR {value:#x}")
            return
        if name == "pc":
            self._cmd(f"cpu PC {value:#x}")
            return
        if name == "xpsr":
            self._cmd(f"cpu CPSR {value:#x}")
            return
        if name in ("msp", "psp"):
            self._write_banked(name, value)
            return
        if name == "control":
            self._cmd(f"cpu Control {value:#x}")
            return
        if name == "primask":
            self._cmd(f"cpu PRIMASK {value:#x}")
            return
        if name == "basepri":
            self._cmd(f"cpu BasePri {value:#x}")
            return
        if name == "faultmask":
            self._cmd(f"cpu FAULTMASK {value:#x}")
            return
        known = ", ".join(_SNAPSHOT_REGS)
        raise BackendError(f"unknown register {name!r}; known: {known}")

    def _using_psp(self) -> bool:
        text = self._cmd("cpu IsUsingProcessSP").strip().split()
        if not text:
            return False
        token = text[-1].lower()
        if token == "true":
            return True
        if token == "false":
            return False
        raise BackendError(f"renode IsUsingProcessSP returned {text[-1]!r}")

    def _read_banked(self, name: str) -> int:
        # SPSEL clear: SP is MSP and OtherSP is PSP. Renode 1.17 keeps
        # IsUsingProcessSP clear across a CONTROL write, so the two monitor
        # properties are the stored banks until a stepped instruction changes
        # the flag.
        process = self._using_psp()
        if name == "msp":
            prop = "SP" if not process else "OtherSP"
        else:
            prop = "OtherSP" if not process else "SP"
        return _last_int(self._cmd(f"cpu {prop}"))

    def _write_banked(self, name: str, value: int) -> None:
        process = self._using_psp()
        if name == "msp":
            prop = "SP" if not process else "OtherSP"
        else:
            prop = "OtherSP" if not process else "SP"
        self._cmd(f"cpu {prop} {value:#x}")

    def _copy_memory(self, address: int, data: bytes, *, write: bool) -> bytes:
        if not data:
            return b""
        out = bytearray()
        cursor = address
        offset = 0
        while offset < len(data):
            page = cursor & ~(self.page_size - 1)
            if page not in self._pages:
                action = "mem_write" if write else "mem_read"
                raise BackendError(f"{action} {address:#x} size {len(data)} is not mapped")
            page_off = cursor - page
            take = min(len(data) - offset, self.page_size - page_off)
            chunk = data[offset : offset + take]
            if page in self._shadow:
                buffer = self._shadow[page]
                if write:
                    buffer[page_off : page_off + take] = chunk
                else:
                    out += buffer[page_off : page_off + take]
            elif write:
                self._write_ram(cursor, chunk)
            else:
                out += self._read_ram(cursor, take)
            cursor += take
            offset += take
        return bytes(out)

    def _read_ram(self, address: int, size: int) -> bytes:
        out = bytearray()
        cursor = address
        left = size
        while left:
            take = min(left, _READ_CHUNK)
            text = self._cmd(f"sysbus ReadBytes {cursor:#x} {take}", timeout=30)
            chunk = parse_byte_list(text)
            if len(chunk) != take:
                raise BackendError(
                    f"renode read {cursor:#x} returned {len(chunk)} bytes, expected {take}"
                )
            out += chunk
            cursor += take
            left -= take
        return bytes(out)

    def _write_ram(self, address: int, data: bytes) -> None:
        cursor = address
        offset = 0
        while offset < len(data) and cursor & 3:
            self._cmd(f"sysbus WriteByte {cursor:#x} {data[offset]:#x}")
            cursor += 1
            offset += 1
        while offset + 4 <= len(data):
            word = int.from_bytes(data[offset : offset + 4], "little")
            self._cmd(f"sysbus WriteDoubleWord {cursor:#x} {word:#x}")
            cursor += 4
            offset += 4
        while offset < len(data):
            self._cmd(f"sysbus WriteByte {cursor:#x} {data[offset]:#x}")
            cursor += 1
            offset += 1

    def _page_is_ram(self, page: int) -> bool:
        for base, size in self._ram_windows:
            if base <= page and page + self.page_size <= base + size:
                return True
        return False

    def _cmd(self, line: str, timeout: float = 10) -> str:
        mon = self._mon
        if mon is None or self._closed:
            raise BackendError("renode backend is closed")
        if self._proc is not None and self._proc.poll() is not None:
            raise BackendError(f"renode exited ({self._proc.returncode}) during: {line}")
        return mon.cmd(line, timeout)

    def _check_pages(self, address: int, size: int) -> None:
        page = self.page_size
        if address % page or size % page or size <= 0:
            raise BackendError(
                f"mapping address {address:#x} size {size:#x} is not aligned to {page:#x}"
            )

    def _stderr_tail(self) -> str:
        log = self._log
        if log is None:
            return ""
        try:
            log.flush()
            log.seek(0)
            text = log.read().decode("utf-8", errors="replace").strip()
        except Exception:
            return ""
        if len(text) > 500:
            return text[-500:]
        return text

    @staticmethod
    def _require_perms(perms: int) -> None:
        if perms & (PERM_READ | PERM_WRITE | PERM_EXEC) == 0:
            raise BackendError("refusing to map a page with empty permissions")


def _runs(pages: list[int], page_size: int) -> list[tuple[int, int]]:
    """Collapse sorted page addresses into ``(start, size)`` spans."""
    if not pages:
        return []
    ordered = sorted(pages)
    spans: list[tuple[int, int]] = []
    start = ordered[0]
    previous = ordered[0]
    for page in ordered[1:]:
        if page == previous + page_size:
            previous = page
            continue
        spans.append((start, previous + page_size - start))
        start = page
        previous = page
    spans.append((start, previous + page_size - start))
    return spans


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def _connect(port: int, proc: subprocess.Popen[bytes]) -> socket.socket:
    deadline = time.monotonic() + 30
    last = "connection refused"
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise BackendError(
                f"{_RENODE_BINARY} exited ({proc.returncode}) before the monitor accepted a connection"
            )
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=0.2)
            sock.settimeout(30)
            return sock
        except OSError as exc:
            last = str(exc)
            time.sleep(0.05)
    raise BackendError(f"timed out connecting to {_RENODE_BINARY} on port {port}: {last}")
