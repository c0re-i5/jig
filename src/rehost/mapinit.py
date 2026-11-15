# SPDX-License-Identifier: MIT
"""Suggest a machine file from an ELF or Intel HEX image.

This does not emulate the image and does not know the chip. It reads the
loadable segments, the vector table at the lowest file-backed address, and
1 KiB-aligned constants in the Cortex-M peripheral window. The YAML is a
starter: flash and SRAM cover what the file actually occupies, SysTick is
the real plugin, and other MMIO is an ``unimplemented`` window per constant
plus ``unmapped.action: log``. A ready bit the image polls will not move
until someone replaces that window.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field

import yaml

from rehost.config import parse_config
from rehost.errors import MachineError
from rehost.image import ElfFile, ProgramHeader, looks_like_ihex, parse_ihex, read_elf

# ELF constants duplicated here so this module does not depend on image.py's
# private names. They match the values in that loader.
_PT_LOAD = 1
_ET_EXEC = 2
_ET_DYN = 3
_EM_ARM = 40

_ELF_MAGIC = b"\x7fELF"
_PF_X = 1
_PF_W = 2
_PF_R = 4
_MIN_REGION = 0x1000
_MAX_WINDOW = 0x200000
# When the initial SP sits inside the loaded RAM instead of at its top,
# the ELF does not say how big SRAM is. 64 KiB is slack, not a datasheet.
_SRAM_SLACK = 0x10000
_MMIO_CAP = 40
# Peripheral bit-band target, plus the AHB2 window some parts use above 1 GiB.
_MMIO_SPANS = ((0x40000000, 0x40100000), (0x50000000, 0x51000000))


@dataclass
class VectorView:
    address: int
    sp: int
    reset: int

    @property
    def reset_target(self) -> int:
        return self.reset & ~1

    @property
    def thumb(self) -> bool:
        return bool(self.reset & 1)


@dataclass
class SuggestedRegion:
    name: str
    base: int
    size: int
    perms: str
    comment: str
    peripheral: str | None = None


@dataclass
class ImageInspection:
    kind: str
    e_type: int | None
    e_machine: int | None
    e_entry: int | None
    segments: tuple[ProgramHeader, ...]
    vector: VectorView | None
    regions: tuple[SuggestedRegion, ...]
    notes: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)


def inspect_image(data: bytes) -> ImageInspection:
    """Classify ``data`` and suggest regions. A raw bin has no addresses."""
    if data.startswith(_ELF_MAGIC):
        return _inspect_elf(data)
    if looks_like_ihex(data):
        return _inspect_ihex(data)
    raise MachineError(
        "map init reads an ELF32 or Intel HEX image. A raw bin has no load "
        "addresses; pass the ELF, or write the memory map yourself."
    )


def format_inspection(info: ImageInspection) -> str:
    """Plain-text report for ``jig-emu inspect``. The YAML is separate."""
    lines: list[str] = []
    if info.kind == "elf":
        lines.append("format: ELF32")
        lines.append(f"type: {_elf_type_name(info.e_type)}")
        lines.append(f"machine: {_machine_name(info.e_machine)}")
        if info.e_entry is not None:
            lines.append(f"e_entry: {info.e_entry:#010x}")
    else:
        lines.append("format: Intel HEX")
        lines.append("type: (no ELF header; spans are the HEX records)")
    lines.append("")
    lines.append("load segments:")
    if not info.segments:
        lines.append("  (none)")
    for segment in info.segments:
        flags = _flag_text(segment.p_flags) if info.kind == "elf" else "n/a"
        lines.append(
            f"  [{segment.index}] p_offset {segment.p_offset:#x} "
            f"p_vaddr {segment.p_vaddr:#010x} p_paddr {segment.p_paddr:#010x} "
            f"filesz {segment.p_filesz:#x} memsz {segment.p_memsz:#x} flags {flags}"
        )
    lines.append("")
    if info.vector is None:
        lines.append("vector table: not found in the first file-backed bytes")
    else:
        thumb = "Thumb" if info.vector.thumb else "low bit clear"
        lines.append(f"vector table at {info.vector.address:#010x}:")
        lines.append(f"  initial SP: {info.vector.sp:#010x}")
        lines.append(
            f"  reset: {info.vector.reset:#010x} ({thumb}, target {info.vector.reset_target:#010x})"
        )
    lines.append("")
    lines.append("suggested regions:")
    for region in info.regions:
        plugin = region.peripheral or "memory"
        lines.append(
            f"  {region.name:<16} {region.base:#010x} size {region.size:#x} "
            f"{region.perms:<3} {plugin}"
        )
        lines.append(f"    {region.comment}")
    if info.notes:
        lines.append("")
        lines.append("notes:")
        for note in info.notes:
            lines.append(f"  - {note}")
    if info.warnings:
        lines.append("")
        lines.append("warnings:")
        for warning in info.warnings:
            lines.append(f"  - {warning}")
    return "\n".join(lines)


def render_machine_yaml(info: ImageInspection, *, name: str) -> str:
    """Starter YAML. Parsed before it is returned, so an overlap fails here."""
    if not info.regions:
        raise MachineError("the image produced no memory regions to write")
    boot = _boot_mapping(info)
    lines: list[str] = [
        "# Generated by jig-emu map init. The image is not copied into this file.",
        "# This is a starter, not a chip model. Flash and SRAM cover the loadable",
        "# image and the vector table's stack pointer. SysTick is the real plugin.",
        "# Each mmio_* window is an aligned constant from the file, logged and",
        "# read as 0. It is not a decoded peripheral. unmapped.action is log, so",
        "# an address with no window still returns 0 and is printed with -v.",
        "#",
        "# TODO: run with -v. A line that says the image spins on a bit needs a",
        "# register_block (follow or read_set), not another unimplemented window.",
        "# If the image reads back a value it stored, drop peripheral: and the",
        "# window becomes sticky RAM. Delete windows the trace never touches.",
        "#",
    ]
    for note in info.notes:
        lines.append(f"# TODO: {note}")
    for warning in info.warnings:
        lines.append(f"# warning: {warning}")
    lines.extend(
        [
            "",
            f"name: {json.dumps(name)}",
            "description: >",
            "  Starter map from jig-emu map init. Flash and SRAM follow the image.",
            "  SysTick is modeled. Other MMIO windows are unimplemented stubs for",
            "  aligned constants in the file, not a vendor peripheral model.",
            "arch: cortex-m",
            "endian: little",
            "",
            "load:",
            f"  base: {_load_base(info):#010x}",
            "",
            "memory:",
        ]
    )
    for region in info.regions:
        lines.append(_format_region(region))
    lines.extend(
        [
            "",
            "boot:",
            "  mode: vector",
            f"  vector_base: {boot['vector_base']:#010x}",
            "",
            "run:",
            "  # The image is not expected to halt. Raise the cap once it boots.",
            "  timeout_ms: 1000",
            "  max_instructions: 1000000",
            "  halt_on_bkpt: true",
            "  trace_limit: 64",
            "",
            "unmapped:",
            "  action: log",
            "  read_default: 0",
            "  log: true",
            "",
        ]
    )
    text = "\n".join(lines)
    parse_config(yaml.safe_load(text))
    return text


def _format_region(region: SuggestedRegion) -> str:
    lines = [f"  # {line}" for line in _wrap(region.comment, 76)]
    lines.append(f"  - name: {region.name}")
    lines.append(f"    base: {region.base:#010x}")
    lines.append(f"    size: {region.size:#x}")
    lines.append(f"    perms: {region.perms}")
    if region.peripheral:
        lines.append(f"    peripheral: {region.peripheral}")
        if region.peripheral == "unimplemented":
            lines.append("    read_default: 0")
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        trial = word if not current else current + " " + word
        if len(trial) > width and current:
            lines.append(current)
            current = word
        else:
            current = trial
    if current:
        lines.append(current)
    return lines or [""]


def machine_name_from_stem(stem: str) -> str:
    """A machine name from a file name. Empty stems become ``image``."""
    cleaned = []
    for char in stem.lower():
        if char.isalnum() or char in "-_":
            cleaned.append(char)
        else:
            cleaned.append("-")
    name = "".join(cleaned).strip("-")
    return name or "image"


def _inspect_elf(data: bytes) -> ImageInspection:
    elf = read_elf(data)
    loads = tuple(header for header in elf.headers if header.p_type == _PT_LOAD)
    vector, vector_blob = _vector_from_elf(elf, data)
    blobs = []
    for header in loads:
        if header.p_filesz == 0:
            continue
        if header.p_offset > len(data) or header.p_filesz > len(data) - header.p_offset:
            raise MachineError(
                f"ELF PT_LOAD segment {header.index} file offset {header.p_offset:#x} "
                f"size {header.p_filesz:#x} extends past the end of the file"
            )
        blobs.append(data[header.p_offset : header.p_offset + header.p_filesz])
    return _assemble(
        kind="elf",
        e_type=elf.e_type,
        e_machine=elf.e_machine,
        e_entry=elf.e_entry,
        segments=loads,
        vector=vector,
        vector_bytes=vector_blob,
        blobs=blobs,
    )


def _inspect_ihex(data: bytes) -> ImageInspection:
    spans = parse_ihex(data)
    segments: list[ProgramHeader] = []
    for index, span in enumerate(spans):
        size = len(span.data)
        segments.append(
            ProgramHeader(
                index=index,
                p_type=_PT_LOAD,
                p_offset=0,
                p_vaddr=span.address,
                p_paddr=span.address,
                p_filesz=size,
                p_memsz=size,
                p_flags=_PF_R | _PF_X,
                p_align=0,
            )
        )
    vector = None
    vector_blob = b""
    if spans and len(spans[0].data) >= 8:
        # parse_ihex returns spans in address order.
        first = min(spans, key=lambda span: span.address)
        if len(first.data) >= 8:
            vector = _vector_at(first.address, first.data[:8])
            vector_blob = first.data[:8]
    return _assemble(
        kind="ihex",
        e_type=None,
        e_machine=None,
        e_entry=None,
        segments=tuple(segments),
        vector=vector,
        vector_bytes=vector_blob,
        blobs=[span.data for span in spans],
    )


def _assemble(
    *,
    kind: str,
    e_type: int | None,
    e_machine: int | None,
    e_entry: int | None,
    segments: tuple[ProgramHeader, ...],
    vector: VectorView | None,
    vector_bytes: bytes,
    blobs: list[bytes],
) -> ImageInspection:
    notes: list[str] = []
    warnings: list[str] = []
    if vector is None:
        warnings.append(
            "No 8-byte vector table was found at the lowest file-backed address. "
            "boot.vector_base is the flash base; check it before running."
        )
    elif not vector.thumb:
        warnings.append(
            f"Reset vector {vector.reset:#x} has the Thumb bit clear. "
            "Cortex-M reset entries are odd."
        )
    if e_entry is not None and vector is not None and (e_entry & ~1) != vector.reset_target:
        notes.append(
            f"ELF e_entry is {e_entry:#x}. Boot uses the reset vector "
            f"{vector.reset:#x}, not e_entry."
        )
    counts, saw_bitband = _scan_constants(blobs)
    regions = _suggest_regions(segments, vector, counts, notes, warnings)
    if saw_bitband:
        notes.append(
            "The file contains a constant in a Cortex-M bit-band alias "
            "(0x22000000 or 0x42000000). Add a bitband region only after the "
            "target window exists; this file does not guess a 32 MiB alias."
        )
    notes.append(
        "run.max_instructions is 1000000 and timeout_ms is 1000. A firmware "
        "loop will hit one of those. Raise the cap once the image boots, and "
        "set timeout_ms to 0 only when the instruction cap remains."
    )
    notes.append(
        "NVIC and SCB stay with the CPU backend at 0xE000E000. SysTick at "
        "0xE000E010 is the one plugin inside that page. Do not map over it."
    )
    if vector_bytes and vector is None:
        warnings.append("Vector bytes were short; the table was not decoded.")
    return ImageInspection(
        kind=kind,
        e_type=e_type,
        e_machine=e_machine,
        e_entry=e_entry,
        segments=segments,
        vector=vector,
        regions=tuple(regions),
        notes=tuple(notes),
        warnings=tuple(warnings),
    )


def _suggest_regions(
    segments: tuple[ProgramHeader, ...],
    vector: VectorView | None,
    counts: Counter[int],
    notes: list[str],
    warnings: list[str],
) -> list[SuggestedRegion]:
    flash_spans: dict[str, list[tuple[int, int]]] = {}
    ram_spans: dict[str, list[tuple[int, int]]] = {}
    for segment in segments:
        file_base = segment.load_address
        file_end = file_base + segment.p_filesz
        runtime_base = segment.p_vaddr
        runtime_end = segment.p_vaddr + max(segment.p_memsz, segment.p_filesz)
        ram = _ram_kind(runtime_base) if segment.p_memsz or segment.p_filesz else None
        if segment.p_filesz and ram is not None and runtime_base != file_base and _ram_kind(file_base) is None:
            # .data image: file bytes stay in flash, the runtime copy is RAM.
            _add_span(flash_spans, _flash_kind(file_base), file_base, file_end)
            _add_span(ram_spans, ram, runtime_base, runtime_end)
        elif ram is not None:
            # BSS, or a span whose runtime address is already SRAM or CCM.
            _add_span(ram_spans, ram, runtime_base, runtime_end)
        elif segment.p_filesz:
            _add_span(flash_spans, _flash_kind(file_base), file_base, file_end)

    sp_top = _exclusive_sp(vector.sp) if vector is not None else None
    if sp_top is not None:
        kind = _ram_kind(sp_top - 1 if sp_top else vector.sp) if vector is not None else None
        if kind is None and vector is not None:
            warnings.append(
                f"Initial SP {vector.sp:#x} is not in a known SRAM window "
                "(0x10000000 CCM, or 0x1FFF0000 / 0x20000000 SRAM)."
            )
        elif kind is not None:
            _add_span(ram_spans, kind, sp_top, sp_top)

    regions: list[SuggestedRegion] = []
    for kind, spans in flash_spans.items():
        regions.extend(
            _windows_from_spans(
                _display_name(kind), kind, spans, "rx", None, sp_top=None, notes=notes
            )
        )
    for kind, spans in ram_spans.items():
        top = sp_top if sp_top is not None and _ram_kind(sp_top - 1) == kind else None
        regions.extend(
            _windows_from_spans(_display_name(kind), kind, spans, "rw", None, sp_top=top, notes=notes)
        )
    taken = [(region.base, region.base + region.size) for region in regions]
    mmio = _mmio_regions(counts, taken, notes)
    regions.extend(mmio)
    if not any(region.peripheral == "systick" for region in regions):
        systick = SuggestedRegion(
            name="systick",
            base=0xE000E010,
            size=0x10,
            perms="rw",
            peripheral="systick",
            comment="Cortex-M SysTick. One step per retired instruction while ENABLE is set.",
        )
        if _overlaps(systick.base, systick.size, taken):
            warnings.append("SysTick at 0xE000E010 overlaps another suggested region and was left out.")
        else:
            regions.append(systick)
    regions.sort(key=lambda region: region.base)
    _rename_duplicates(regions)
    if vector is not None:
        flash_regions = [region for region in regions if region.perms == "rx"]
        if flash_regions and not any(
            region.base <= vector.reset_target < region.base + region.size for region in flash_regions
        ):
            warnings.append(
                f"Reset target {vector.reset_target:#x} is outside the suggested flash window."
            )
        ram_regions = [region for region in regions if region.peripheral is None and "rw" in region.perms]
        sp_aligned = vector.sp & ~3
        if ram_regions and not any(
            region.base <= sp_aligned < region.base + region.size for region in ram_regions
        ):
            warnings.append(
                f"Initial SP {vector.sp:#x} is outside the suggested SRAM window."
            )
    return regions


def _windows_from_spans(
    name: str,
    kind: str,
    spans: list[tuple[int, int]],
    perms: str,
    peripheral: str | None,
    *,
    sp_top: int | None,
    notes: list[str],
) -> list[SuggestedRegion]:
    start = min(span[0] for span in spans)
    end = max(span[1] for span in spans)
    if end < start:
        end = start
    anchor = _anchor(kind, start)
    if anchor <= start and end - anchor <= _MAX_WINDOW:
        base = anchor
    else:
        base = start & ~0x3FF
    observed = end
    slack = False
    if kind in {"sram", "ccm"} and sp_top is not None:
        if sp_top > observed:
            end = sp_top
        elif sp_top <= observed and observed - base < _SRAM_SLACK:
            # The stack pointer is not the top of RAM. The ELF footprint
            # is smaller than a part's SRAM. Add a fixed slack so a heap
            # or a relocated stack has somewhere to go, and say so.
            end = base + _SRAM_SLACK
            slack = True
    need = max(end - base, 1)
    size = _pow2_at_least(need)
    if perms == "rx":
        comment = (
            f"File bytes occupy {start:#x}..{observed:#x}. "
            "Rounded up to a power of two. Shrink or grow it to the part. A store to this window faults."
        )
    elif slack:
        comment = (
            f"ELF RAM footprint ends at {observed:#x}. Initial SP does not sit at the top, "
            f"so this is {_SRAM_SLACK // 1024} KiB of starter space, not the part's SRAM."
        )
    elif kind in {"sram", "ccm"} and sp_top is not None and sp_top >= observed:
        comment = (
            f"Covers the ELF RAM segments and a stack top at {sp_top:#x} "
            "(initial SP, low bits cleared when they were set)."
        )
    else:
        comment = f"Covers file-backed bytes at {start:#x}..{observed:#x}, rounded up."
    if size > need and perms == "rx":
        notes.append(
            f"{name} image uses {need:#x} bytes from {base:#x}; the window is {size:#x}."
        )
    return [
        SuggestedRegion(
            name=name,
            base=base,
            size=size,
            perms=perms,
            peripheral=peripheral,
            comment=comment,
        )
    ]


def _mmio_regions(
    counts: Counter[int],
    taken: list[tuple[int, int]],
    notes: list[str],
) -> list[SuggestedRegion]:
    if not counts:
        base = 0x40000000
        if _overlaps(base, 0x400, taken):
            notes.append(
                "No 1 KiB-aligned peripheral constant was found, and 0x40000000 "
                "overlaps a suggested region, so no MMIO stub was added."
            )
            return []
        notes.append(
            "No 1 KiB-aligned constant in 0x40000000..0x40100000 or "
            "0x50000000..0x51000000. mmio_stub at 0x40000000 is a placeholder, "
            "not an address from the image."
        )
        return [
            SuggestedRegion(
                name="mmio_stub",
                base=base,
                size=0x400,
                perms="rw",
                peripheral="unimplemented",
                comment="Placeholder at the start of the peripheral region. Not from the image.",
            )
        ]
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    chosen = ranked[:_MMIO_CAP]
    if len(ranked) > len(chosen):
        notes.append(
            f"{len(ranked) - len(chosen)} peripheral constants were left out of the "
            f"YAML (cap {_MMIO_CAP}). jig-emu inspect lists the suggestion set."
        )
    regions: list[SuggestedRegion] = []
    for base, count in sorted(chosen, key=lambda item: item[0]):
        if _overlaps(base, 0x400, taken):
            continue
        word = "time" if count == 1 else "times"
        regions.append(
            SuggestedRegion(
                name=f"mmio_{base:08x}",
                base=base,
                size=0x400,
                perms="rw",
                peripheral="unimplemented",
                comment=(
                    f"Aligned constant {base:#x} appears {count} {word} in the image. "
                    "Not decoded. Reads return 0."
                ),
            )
        )
        taken.append((base, base + 0x400))
    return regions


def _vector_from_elf(elf: ElfFile, data: bytes) -> tuple[VectorView | None, bytes]:
    candidates = [
        header
        for header in elf.headers
        if header.p_type == _PT_LOAD and header.p_filesz >= 8
    ]
    if not candidates:
        return None, b""
    header = min(candidates, key=lambda item: item.load_address)
    if header.p_offset > len(data) or header.p_filesz > len(data) - header.p_offset:
        return None, b""
    blob = data[header.p_offset : header.p_offset + 8]
    if len(blob) < 8:
        return None, blob
    return _vector_at(header.load_address, blob), blob


def _vector_at(address: int, blob: bytes) -> VectorView:
    sp = int.from_bytes(blob[:4], "little")
    reset = int.from_bytes(blob[4:8], "little")
    return VectorView(address=address, sp=sp, reset=reset)


def _scan_constants(blobs: list[bytes]) -> tuple[Counter[int], bool]:
    """1 KiB-aligned peripheral bases, plus whether a bit-band alias appears.

    Thumb encodings and ordinary integers also land in ``0x4xxxxxxx``.
    Requiring a 1 KiB-aligned address inside the peripheral bit-band
    target drops most of that. A hit is still only a constant, which is
    why the window is ``unimplemented`` and the comment says so.
    """
    counts: Counter[int] = Counter()
    bitband = False
    for blob in blobs:
        for offset in range(0, len(blob) - 3, 4):
            word = int.from_bytes(blob[offset : offset + 4], "little")
            if 0x22000000 <= word < 0x24000000 or 0x42000000 <= word < 0x44000000:
                bitband = True
            if word & 0x3FF:
                continue
            if any(low <= word < high for low, high in _MMIO_SPANS):
                counts[word] += 1
    return counts, bitband


def _add_span(groups: dict[str, list[tuple[int, int]]], kind: str, start: int, end: int) -> None:
    if end < start:
        return
    groups.setdefault(kind, []).append((start, end))


def _flash_kind(address: int) -> str:
    """Group key. Low flash and an STM32 bank stay separate regions."""
    if address < 0x00200000:
        return "low"
    if 0x08000000 <= address < 0x08200000:
        return "stm32"
    return "rom"


def _display_name(kind: str) -> str:
    if kind in {"low", "stm32"}:
        return "flash"
    return kind


def _ram_kind(address: int) -> str | None:
    if 0x10000000 <= address < 0x10100000:
        return "ccm"
    if 0x1FFF0000 <= address < 0x22000000:
        return "sram"
    return None


def _anchor(kind: str, start: int) -> int:
    """Architectural base for a window, before the size cap rejects a wild snap."""
    if kind == "ccm":
        return 0x10000000 if 0x10000000 <= start < 0x10100000 else start & ~0x3FF
    if kind == "sram":
        if 0x1FFF0000 <= start < 0x20000000:
            return 0x1FFF0000
        if 0x20000000 <= start < 0x20100000:
            return 0x20000000
        return start & ~0x3FF
    if kind == "low":
        return 0x00000000
    if kind == "stm32":
        return 0x08000000
    return start & ~0x3FF


def _exclusive_sp(sp: int) -> int:
    """First address past the initial stack.

    An aligned vector word is already that address (the first push
    decrements first). A word with low bits set, such as Atollic
    ``_estack = 0x2001FFFF``, names the last byte. The byte after it,
    word-aligned, is the top the window has to cover.
    """
    if sp & 3:
        return (sp + 1 + 3) & ~3
    return sp


def _pow2_at_least(need: int) -> int:
    size = 1
    while size < need and size < _MAX_WINDOW:
        size <<= 1
    if size < need:
        return (need + 0xFFF) & ~0xFFF
    if size < _MIN_REGION:
        return _MIN_REGION
    return size


def _overlaps(base: int, size: int, taken: list[tuple[int, int]]) -> bool:
    end = base + size
    return any(base < high and low < end for low, high in taken)


def _rename_duplicates(regions: list[SuggestedRegion]) -> None:
    seen: dict[str, int] = {}
    for region in regions:
        seen[region.name] = seen.get(region.name, 0) + 1
    used: dict[str, int] = {}
    for region in regions:
        if seen[region.name] == 1:
            continue
        used[region.name] = used.get(region.name, 0) + 1
        if used[region.name] == 1:
            continue
        region.name = f"{region.name}_{region.base:08x}"


def _boot_mapping(info: ImageInspection) -> dict:
    if info.vector is not None:
        return {"mode": "vector", "vector_base": info.vector.address}
    flash = next((region for region in info.regions if region.perms == "rx"), None)
    base = flash.base if flash is not None else 0
    return {"mode": "vector", "vector_base": base}


def _load_base(info: ImageInspection) -> int:
    flash = next((region for region in info.regions if region.perms == "rx"), None)
    if flash is not None:
        return flash.base
    return 0


def _elf_type_name(e_type: int | None) -> str:
    if e_type == _ET_EXEC:
        return "ET_EXEC"
    if e_type == _ET_DYN:
        return "ET_DYN"
    return str(e_type)


def _machine_name(e_machine: int | None) -> str:
    if e_machine == _EM_ARM:
        return "EM_ARM"
    return str(e_machine)


def _flag_text(flags: int) -> str:
    parts = []
    if flags & _PF_R:
        parts.append("R")
    if flags & _PF_W:
        parts.append("W")
    if flags & _PF_X:
        parts.append("E")
    return "".join(parts) or "0"

