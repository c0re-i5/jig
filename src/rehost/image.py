# SPDX-License-Identifier: MIT
"""Load a raw bin, an ELF32, or an Intel HEX file into guest addresses.

The caller already has the bytes. Nothing here downloads firmware. Raw images
stay a single copy at ``load.base``. ELF and Intel HEX carry their own
addresses, and each span must fall inside the machine's memory map.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass

from rehost.errors import MachineError

_ELF_MAGIC = b"\x7fELF"
_ELF32_HEADER = 52
_PHDR32 = 32
_PT_LOAD = 1
_ET_EXEC = 2
_ET_DYN = 3
_EM_ARM = 40
_ADDRESS_SPACE = 0x1_0000_0000

# A first line that is one complete Intel HEX record. A raw image whose first
# byte happens to be ``:`` (0x3A) does not match, so it stays a raw bin.
_IHEX_LINE = re.compile(rb":[0-9A-Fa-f]{10,}")


@dataclass(frozen=True)
class LoadSegment:
    """File bytes that belong at one guest address."""

    address: int
    data: bytes
    label: str


@dataclass(frozen=True)
class ProgramHeader:
    """One ELF32 program header.

    ``parse_elf`` keeps only ``PT_LOAD`` entries that have file bytes.
    ``read_elf`` keeps every header, including BSS (``p_filesz`` 0), so a
    map scaffold can see the RAM the image reserved.
    """

    index: int
    p_type: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_flags: int
    p_align: int

    @property
    def load_address(self) -> int:
        """Guest address of the file bytes. Same rule as ``parse_elf``."""
        if self.p_paddr == 0 and self.p_vaddr != 0:
            return self.p_vaddr
        return self.p_paddr


@dataclass(frozen=True)
class ElfFile:
    """The ELF32 fields a map scaffold reads. This does not load the image."""

    e_type: int
    e_machine: int
    e_entry: int
    headers: tuple[ProgramHeader, ...]


def parse_firmware(data: bytes) -> tuple[str, list[LoadSegment]]:
    """Classify ``data`` and return ``("raw", [])`` or the loadable spans.

    ``raw`` means the caller copies the whole buffer to one base address.
    ELF and Intel HEX return one segment per contiguous span. A file that
    starts like one of those formats but is truncated or inconsistent raises
    ``MachineError`` instead of being treated as a raw bin.
    """
    if data.startswith(_ELF_MAGIC):
        return "elf", parse_elf(data)
    if looks_like_ihex(data):
        return "ihex", parse_ihex(data)
    return "raw", []


def looks_like_ihex(data: bytes) -> bool:
    """True when the first record line is Intel HEX, not a binary that starts with ``:``."""
    text = data
    if text.startswith(b"\xef\xbb\xbf"):
        text = text[3:]
    start = 0
    while start < len(text) and text[start] in b" \t\r\n":
        start += 1
    if start >= len(text) or text[start] != ord(":"):
        return False
    line = text[start:].splitlines()[0].strip()
    if _IHEX_LINE.fullmatch(line) is None:
        return False
    return (len(line) - 1) % 2 == 0


def read_elf(data: bytes) -> ElfFile:
    """Parse a little-endian ARM ELF32 header and its program headers.

    The same checks as ``parse_elf``. BSS and non-load headers are kept.
    A segment whose file bytes run past the end of ``data`` is still
    returned; ``parse_elf`` is what rejects that, because a header with
    ``p_filesz`` 0 is a valid BSS entry and has nothing to read.
    """
    if len(data) < _ELF32_HEADER:
        raise MachineError(
            f"ELF image is truncated ({len(data)} bytes; an ELF32 header is {_ELF32_HEADER})"
        )
    elf_class = data[4]
    if elf_class != 1:
        raise MachineError(
            f"ELF class {elf_class} is not ELF32; jig-emu loads 32-bit images"
        )
    if data[5] != 1:
        raise MachineError("ELF is not little-endian; jig-emu loads little-endian ELF32")
    if data[6] != 1:
        raise MachineError(f"ELF identification version {data[6]} is not 1")

    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    e_version = struct.unpack_from("<I", data, 20)[0]
    e_entry = struct.unpack_from("<I", data, 24)[0]
    e_phoff = struct.unpack_from("<I", data, 28)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 42)
    if e_version != 1:
        raise MachineError(f"ELF version {e_version} is not 1")
    if e_type not in (_ET_EXEC, _ET_DYN):
        raise MachineError(
            f"ELF type {e_type} is not a loadable image (expected ET_EXEC or ET_DYN)"
        )
    if e_machine != _EM_ARM:
        raise MachineError(f"ELF machine {e_machine} is not EM_ARM ({_EM_ARM})")
    if e_phnum == 0:
        raise MachineError("ELF has no program headers")
    if e_phentsize < _PHDR32:
        raise MachineError(
            f"ELF program header entry is {e_phentsize} bytes; ELF32 needs at least {_PHDR32}"
        )
    table_end = e_phoff + e_phnum * e_phentsize
    if e_phoff > len(data) or table_end > len(data):
        raise MachineError(
            f"ELF program headers at {e_phoff:#x} ({e_phnum} entries) extend past the end of the file"
        )

    headers: list[ProgramHeader] = []
    for index in range(e_phnum):
        off = e_phoff + index * e_phentsize
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from(
            "<IIIIIIII", data, off
        )
        headers.append(
            ProgramHeader(
                index=index,
                p_type=p_type,
                p_offset=p_offset,
                p_vaddr=p_vaddr,
                p_paddr=p_paddr,
                p_filesz=p_filesz,
                p_memsz=p_memsz,
                p_flags=p_flags,
                p_align=p_align,
            )
        )
    return ElfFile(e_type=e_type, e_machine=e_machine, e_entry=e_entry, headers=tuple(headers))


def parse_elf(data: bytes) -> list[LoadSegment]:
    """PT_LOAD segments of a little-endian ARM ELF32, written at ``p_paddr``.

    ``p_paddr`` is the load memory address (where ``objcopy -O binary`` and
    the reset handler's copy loop expect the bytes). ``p_vaddr`` is where
    the firmware runs after that copy, so a ``.data`` segment whose virtual
    address is SRAM is still stored at its physical address in flash.

    A toolchain that leaves ``p_paddr`` at 0 and puts the only address in
    ``p_vaddr`` is loaded at ``p_vaddr``. Segments with no file bytes (BSS)
    are omitted; guest RAM is already zero.
    """
    elf = read_elf(data)
    segments: list[LoadSegment] = []
    for ph in elf.headers:
        if ph.p_type != _PT_LOAD or ph.p_filesz == 0:
            continue
        if ph.p_offset > len(data) or ph.p_filesz > len(data) - ph.p_offset:
            raise MachineError(
                f"ELF PT_LOAD segment {ph.index} file offset {ph.p_offset:#x} size {ph.p_filesz:#x} "
                "extends past the end of the file"
            )
        address = ph.load_address
        if address + ph.p_filesz > _ADDRESS_SPACE:
            raise MachineError(
                f"ELF PT_LOAD segment {ph.index} at {address:#x} size {ph.p_filesz:#x} "
                "does not fit in the 32-bit address space"
            )
        segments.append(
            LoadSegment(
                address=address,
                data=data[ph.p_offset : ph.p_offset + ph.p_filesz],
                label=(
                    f"ELF PT_LOAD segment {ph.index} "
                    f"(p_paddr {ph.p_paddr:#x}, p_vaddr {ph.p_vaddr:#x})"
                ),
            )
        )
    if not segments:
        raise MachineError("ELF has no PT_LOAD segment with file bytes")
    return segments


def parse_ihex(data: bytes) -> list[LoadSegment]:
    """Decode Intel HEX, including extended linear and segment addresses.

    Data records are placed at ``bias + offset``. A type 04 record sets
    ``bias`` to its word shifted left 16 bits. A type 02 record sets ``bias``
    to its word shifted left 4 bits. The latest of those replaces the bias.
    Type 03 and 05 start-address records are checked and ignored; boot uses
    the vector table or ``boot.entry``. Contiguous bytes become one segment.
    A later record that repeats an address overwrites the earlier byte.
    """
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise MachineError("Intel HEX image is not ASCII") from exc
    if text.startswith("\ufeff"):
        text = text[1:]

    bias = 0
    saw_eof = False
    pieces: list[tuple[int, bytes]] = []
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        if saw_eof:
            raise MachineError(f"Intel HEX line {line_no} continues after the end-of-file record")
        record_type, offset, payload = _parse_ihex_record(line, line_no)
        if record_type == 0x00:
            if not payload:
                continue
            address = bias + offset
            if address + len(payload) > _ADDRESS_SPACE:
                raise MachineError(
                    f"Intel HEX line {line_no} address {address:#x} size {len(payload):#x} "
                    "does not fit in the 32-bit address space"
                )
            pieces.append((address, payload))
        elif record_type == 0x01:
            if payload:
                raise MachineError(f"Intel HEX line {line_no} end-of-file record must be empty")
            saw_eof = True
        elif record_type == 0x02:
            if len(payload) != 2:
                raise MachineError(
                    f"Intel HEX line {line_no} extended segment address must be 2 bytes"
                )
            bias = int.from_bytes(payload, "big") << 4
        elif record_type == 0x04:
            if len(payload) != 2:
                raise MachineError(
                    f"Intel HEX line {line_no} extended linear address must be 2 bytes"
                )
            bias = int.from_bytes(payload, "big") << 16
        elif record_type in (0x03, 0x05):
            if len(payload) != 4:
                raise MachineError(
                    f"Intel HEX line {line_no} start-address record must be 4 bytes"
                )
        else:
            raise MachineError(f"Intel HEX line {line_no} has unsupported record type {record_type:#x}")
    if not saw_eof:
        raise MachineError("Intel HEX image has no end-of-file record")
    segments = _coalesce(pieces)
    if not segments:
        raise MachineError("Intel HEX image has no data records")
    return segments


def _parse_ihex_record(line: str, line_no: int) -> tuple[int, int, bytes]:
    if not line.startswith(":"):
        raise MachineError(f"Intel HEX line {line_no} does not start with ':'")
    hexpart = line[1:]
    if len(hexpart) < 10 or len(hexpart) % 2 != 0:
        raise MachineError(f"Intel HEX line {line_no} is truncated")
    try:
        raw = bytes.fromhex(hexpart)
    except ValueError as exc:
        raise MachineError(f"Intel HEX line {line_no} is not hexadecimal") from exc
    if sum(raw) & 0xFF != 0:
        raise MachineError(f"Intel HEX line {line_no} has a bad checksum")
    count = raw[0]
    offset = (raw[1] << 8) | raw[2]
    record_type = raw[3]
    payload = raw[4:-1]
    if len(payload) != count:
        raise MachineError(
            f"Intel HEX line {line_no} declares {count} data bytes but has {len(payload)}"
        )
    return record_type, offset, payload


def _coalesce(pieces: list[tuple[int, bytes]]) -> list[LoadSegment]:
    """Merge neighboring bytes. A repeated address keeps the later value."""
    memory: dict[int, int] = {}
    for address, payload in pieces:
        for index, byte in enumerate(payload):
            memory[address + index] = byte
    if not memory:
        return []
    ordered = sorted(memory)
    spans: list[tuple[int, bytearray]] = []
    start = ordered[0]
    previous = start
    buffer = bytearray((memory[start],))
    for address in ordered[1:]:
        if address == previous + 1:
            buffer.append(memory[address])
            previous = address
            continue
        spans.append((start, buffer))
        start = previous = address
        buffer = bytearray((memory[address],))
    spans.append((start, buffer))
    return [
        LoadSegment(address=address, data=bytes(buffer), label=f"Intel HEX data at {address:#x}")
        for address, buffer in spans
    ]
