# SPDX-License-Identifier: MIT
"""Suggest a machine file from an ELF or Intel HEX image.

This does not emulate the image and does not know the chip. It reads the
loadable segments, the vector table at the lowest file-backed address, and
1 KiB-aligned constants in the Cortex-M peripheral window. The YAML is a
starter: flash and SRAM cover what the file actually occupies, SysTick is
the real plugin, and other MMIO is an ``unimplemented`` window per constant
plus ``unmapped.action: log``. A ready bit the image polls will not move
until someone replaces that window.

``aggressive=True`` is the opt-in guess. A constant at a well-known RCC or
MCG address becomes a ``register_block`` whose ready bits follow the enable
bits, and a UART-like constant becomes a ``uart`` stub. Both are marked
TODO. The default leaves those windows unimplemented.

Cortex-M bit-band aliases are emitted whenever the target window is present.
That part is architectural for M3/M4, not a vendor guess. Delete the windows
for an M0 or M0+.
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
    # Extra YAML lines, already indented to sit under the region mapping.
    extra: tuple[str, ...] = ()


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
    aggressive: bool = False


def inspect_image(data: bytes, *, aggressive: bool = False) -> ImageInspection:
    """Classify ``data`` and suggest regions. A raw bin has no addresses.

    ``aggressive`` promotes recognized clock and UART constants. The default
    leaves them unimplemented.
    """
    if data.startswith(_ELF_MAGIC):
        return _inspect_elf(data, aggressive=aggressive)
    if looks_like_ihex(data):
        return _inspect_ihex(data, aggressive=aggressive)
    raise MachineError(
        "map init reads an ELF32 or Intel HEX image. A raw bin has no load "
        "addresses; pass the ELF, or write the memory map yourself."
    )


def format_inspection(info: ImageInspection) -> str:
    """Plain-text report for ``jig-emu inspect``. The YAML is separate."""
    lines: list[str] = []
    if info.aggressive:
        lines.append("aggressive: yes")
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
        "# read as 0, unless --aggressive promoted it. It is not a decoded",
        "# peripheral. unmapped.action is log, so an address with no window still",
        "# returns 0 and is printed with -v.",
        "#",
        "# SP[1:0] are cleared by the CPU model. An odd initial stack word is fine.",
        "# Cortex-M3/M4 bit-band aliases are included when their target is present.",
        "# Delete those windows for an M0 or M0+.",
        "#",
        "# TODO: run with -v. A line that says the image spins on a bit needs a",
        "# register_block (follow or read_set), not another unimplemented window.",
        "# If the image reads back a value it stored, drop peripheral: and the",
        "# window becomes sticky RAM. Delete windows the trace never touches.",
        "# Pass --aggressive to emit guessed RCC/MCG follow rules and UART stubs.",
        "#",
    ]
    if info.aggressive:
        lines.extend(
            [
                "# aggressive: recognized clock and UART constants were promoted.",
                "# The follow rules and UART offsets below are guesses. Read the TODO",
                "# on each promoted region before trusting a boot.",
                "#",
            ]
        )
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
            "  aligned constants in the file, unless --aggressive promoted a",
            "  recognized clock block or UART. Not a vendor peripheral model.",
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
            "  # The CPU model clears SP[1:0] on the vector load and on later",
            "  # writes. An odd _estack becomes the word-aligned pointer below it.",
            f"  vector_base: {boot['vector_base']:#010x}",
            "",
            "run:",
            "  # The instruction cap is the stop. A 1s wall-clock timeout cuts",
            "  # off a real boot before this many instructions finish.",
            "  timeout_ms: 0",
            "  max_instructions: 1000000",
            "  halt_on_bkpt: true",
            "  # SYSRESETREQ and VECTRESET reset the core and continue. true",
            "  # ends the run on the first request. A silent reboot streak stops",
            "  # at run.max_resets (default 8) so it cannot spend this cap.",
            "  halt_on_reset: false",
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
    lines.extend(region.extra)
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


def _inspect_elf(data: bytes, *, aggressive: bool) -> ImageInspection:
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
        aggressive=aggressive,
    )


def _inspect_ihex(data: bytes, *, aggressive: bool) -> ImageInspection:
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
        aggressive=aggressive,
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
    aggressive: bool = False,
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
    regions = _suggest_regions(
        segments, vector, counts, notes, warnings, aggressive=aggressive
    )
    if any(region.peripheral == "bitband" for region in regions):
        notes.append(
            "Cortex-M bit-band alias windows are mapped where SRAM covers "
            "0x20000000 or a peripheral constant was found. Delete them for "
            "an M0 or M0+."
        )
    elif saw_bitband:
        notes.append(
            "The file contains a constant in a Cortex-M bit-band alias "
            "(0x22000000 or 0x42000000), and this map has no SRAM at "
            "0x20000000 and no peripheral constant, so no 32 MiB alias was added."
        )
    if _clock_family(counts) or _uart_hits(_clock_family(counts), counts):
        if aggressive:
            notes.append(
                "Aggressive guesses are on. A recognized clock block is a "
                "register_block and a recognized UART constant is a uart stub. "
                "The follow rules and UART offsets are TODO guesses, not a datasheet."
            )
        else:
            notes.append(
                "A clock or UART constant was recognized and left unimplemented. "
                "jig-emu map init --aggressive emits a register_block and uart "
                "stubs for them."
            )
    notes.append(
        "run.max_instructions is 1000000 and timeout_ms is 0. The instruction "
        "cap stops a firmware loop. A 1 second wall-clock cap cuts off a real "
        "boot before that. Raise the cap once the image is moving."
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
        aggressive=aggressive,
    )


def _suggest_regions(
    segments: tuple[ProgramHeader, ...],
    vector: VectorView | None,
    counts: Counter[int],
    notes: list[str],
    warnings: list[str],
    *,
    aggressive: bool = False,
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
    _add_bitbands(regions, counts, warnings)
    if aggressive:
        _promote_guesses(regions, counts, notes)
    if not any(region.peripheral == "systick" for region in regions):
        systick = SuggestedRegion(
            name="systick",
            base=0xE000E010,
            size=0x10,
            perms="rw",
            peripheral="systick",
            comment="Cortex-M SysTick. One step per retired instruction while ENABLE is set.",
        )
        taken = [(region.base, region.base + region.size) for region in regions]
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


# STM32F2/F4/F7 RCC. F4 GPIOE is also 0x40021000, so that address is an RCC
# only when the F4 RCC and the F4 GPIOA window are absent.
_STM32F4_RCC = 0x40023800
_STM32F1_RCC = 0x40021000
_STM32F4_GPIOA = 0x40020000
_KINETIS_MCG = 0x40064000
_STM32F4_FLASH = 0x40023C00

# Shared by F1 and F4: status at +0, data at +4.
_STM32_SHARED_UART = {
    0x40004400: "USART2",
    0x40004800: "USART3",
    0x40004C00: "UART4",
    0x40005000: "UART5",
}
# F2/F4/F7. Not USART on F1.
_STM32F4_UART = {
    0x40011000: "USART1",
    0x40011400: "USART6",
}
# F1 USART1. On F4 this address is SYSCFG, so it is only used for the F1 guess.
_STM32F1_UART = {
    0x40013800: "USART1",
}
_KINETIS_UART = {
    0x4006A000: "UART0",
    0x4006B000: "UART1",
    0x4006C000: "UART2",
    0x4006D000: "UART3",
}


def _clock_family(counts: Counter[int]) -> str | None:
    """Which guessed clock block, if any, this constant bag looks like.

    The F4 RCC wins over the F1 address when both appear, because F4 GPIOE
    lives at the F1 RCC base. Kinetis MCG is a different address and loses
    only when an STM32 RCC constant is more common.
    """
    ranked: list[tuple[int, str]] = []
    if counts[_STM32F4_RCC]:
        ranked.append((counts[_STM32F4_RCC], "stm32f4"))
    if counts[_KINETIS_MCG]:
        ranked.append((counts[_KINETIS_MCG], "kinetis"))
    f1 = (
        counts[_STM32F1_RCC]
        and not counts[_STM32F4_RCC]
        and not counts[_STM32F4_GPIOA]
    )
    if f1:
        ranked.append((counts[_STM32F1_RCC], "stm32f1"))
    if not ranked:
        return None
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return ranked[0][1]


def _uart_hits(family: str | None, counts: Counter[int]) -> list[tuple[int, str, str]]:
    """``(base, name, layout)`` for UART-like constants that actually appear."""
    if family == "kinetis":
        table = _KINETIS_UART
        layout = "kinetis"
    elif family == "stm32f1":
        table = {**_STM32_SHARED_UART, **_STM32F1_UART}
        layout = "stm32"
    elif family == "stm32f4":
        table = {**_STM32_SHARED_UART, **_STM32F4_UART}
        layout = "stm32"
    else:
        shared = sum(counts[base] for base in _STM32_SHARED_UART)
        kinetis = sum(counts[base] for base in _KINETIS_UART)
        if kinetis and kinetis >= shared:
            table = _KINETIS_UART
            layout = "kinetis"
        else:
            table = _STM32_SHARED_UART
            layout = "stm32"
    found = [
        (base, name, layout)
        for base, name in sorted(table.items())
        if counts[base]
    ]
    return found


def _add_bitbands(
    regions: list[SuggestedRegion],
    counts: Counter[int],
    warnings: list[str],
) -> None:
    """Map the architectural alias windows when their targets exist."""
    wanted: list[tuple[str, int, int, str]] = []
    if _covers_sram_bitband(regions):
        wanted.append(
            (
                "sram_bitband",
                0x22000000,
                0x20000000,
                "Cortex-M SRAM bit-band alias onto 0x20000000. A word store sets or "
                "clears one bit of that target. Only the mapped part of the target "
                "holds data. Delete this window on Cortex-M0 or M0+.",
            )
        )
    if counts:
        wanted.append(
            (
                "peripheral_bitband",
                0x42000000,
                0x40000000,
                "Cortex-M peripheral bit-band alias onto 0x40000000. A store that "
                "sets a clock bit through 0x42xxxxxx lands here. Delete this window "
                "on Cortex-M0 or M0+.",
            )
        )
    taken = [(region.base, region.base + region.size) for region in regions]
    for name, base, target, comment in wanted:
        size = 0x02000000
        if _overlaps(base, size, taken):
            warnings.append(f"{name} at {base:#x} overlaps another region and was left out.")
            continue
        regions.append(
            SuggestedRegion(
                name=name,
                base=base,
                size=size,
                perms="rw",
                peripheral="bitband",
                comment=comment,
                extra=(
                    "    config:",
                    f"      target: {target:#010x}",
                ),
            )
        )
        taken.append((base, base + size))


def _covers_sram_bitband(regions: list[SuggestedRegion]) -> bool:
    lo, hi = 0x20000000, 0x20100000
    for region in regions:
        if region.peripheral is not None or "w" not in region.perms:
            continue
        end = region.base + region.size
        if region.base < hi and lo < end:
            return True
    return False


def _promote_guesses(
    regions: list[SuggestedRegion],
    counts: Counter[int],
    notes: list[str],
) -> None:
    family = _clock_family(counts)
    clock = _clock_region(family) if family else None
    if clock is not None and not _replace_or_append(regions, clock):
        notes.append(
            f"{clock.name} at {clock.base:#x} overlapped another region and was not promoted."
        )
    flash = _flash_region(family)
    if flash is not None and not _replace_or_append(regions, flash):
        notes.append(
            f"{flash.name} at {flash.base:#x} overlapped another region and was not promoted."
        )
    for base, name, layout in _uart_hits(family, counts):
        uart = _uart_region(base, name, layout)
        if not _replace_or_append(regions, uart):
            notes.append(
                f"{name} at {base:#x} overlapped another region and was not promoted."
            )


def _replace_or_append(regions: list[SuggestedRegion], new: SuggestedRegion) -> bool:
    for index, region in enumerate(regions):
        if region.base != new.base:
            continue
        if region.peripheral != "unimplemented":
            return False
        regions[index] = new
        return True
    spans = [(region.base, region.base + region.size) for region in regions]
    if _overlaps(new.base, new.size, spans):
        return False
    regions.append(new)
    return True


def _clock_region(family: str) -> SuggestedRegion | None:
    if family == "stm32f4":
        return SuggestedRegion(
            name="rcc",
            base=_STM32F4_RCC,
            size=0x400,
            perms="rw",
            peripheral="register_block",
            comment=(
                "Guessed STM32F2/F4/F7 RCC because the image contains this address. "
                "TODO: HSIRDY follows HSION, HSERDY follows HSEON, PLLRDY follows PLLON, "
                "PLLI2SRDY follows PLLI2SON, SWS copies SW, LSERDY follows LSEON, and "
                "LSIRDY follows LSION. Enable and reset registers are sticky so a "
                "read-modify-write keeps its bit. Unlisted offsets still read as 0. "
                "This is not a clock tree. Correct it or delete it."
            ),
            extra=_F4_RCC_EXTRA,
        )
    if family == "stm32f1":
        return SuggestedRegion(
            name="rcc",
            base=_STM32F1_RCC,
            size=0x400,
            perms="rw",
            peripheral="register_block",
            comment=(
                "Guessed STM32F1/F3-class RCC. 0x40021000 is present and the F4 GPIOA "
                "window at 0x40020000 is not, so this is not treated as F4 GPIOE. "
                "TODO: ready bits follow the ON bits in CR, and SWS copies SW in CFGR "
                "at offset 0x04. L4 and G4 CR bits differ. Check the reference manual."
            ),
            extra=_F1_RCC_EXTRA,
        )
    if family == "kinetis":
        return SuggestedRegion(
            name="mcg",
            base=_KINETIS_MCG,
            size=0x400,
            perms="rw",
            peripheral="register_block",
            comment=(
                "Guessed Kinetis MCG. TODO: CLKST copies CLKS until PLLS is set, then "
                "reads as the PLL encoding. PLLST and LOCK0 follow PLLS. IREFST follows "
                "IREFS. OSCINIT0 follows EREFS0. That is the FEI to PEE walk this shape "
                "of startup polls. It is not an MCG model. Byte offsets match the K64 "
                "register file; check them."
            ),
            extra=_KINETIS_MCG_EXTRA,
        )
    return None


def _flash_region(family: str | None) -> SuggestedRegion | None:
    """F4 flash latency reads back. The companion of the RCC guess, not a programmer."""
    if family != "stm32f4":
        return None
    return SuggestedRegion(
        name="flash_if",
        base=_STM32F4_FLASH,
        size=0x400,
        perms="rw",
        peripheral="register_block",
        comment=(
            "Guessed STM32F4 flash interface, next to the RCC guess. TODO: ACR "
            "reads back so a latency write is visible. FLASH_SR.BSY stays 0. "
            "This does not program flash. Delete it if the image never touches "
            "0x40023c00."
        ),
        extra=_F4_FLASH_EXTRA,
    )


def _uart_region(base: int, name: str, layout: str) -> SuggestedRegion:
    if layout == "kinetis":
        comment = (
            f"Guessed Kinetis {name}. TODO: S1 is +0x04 (TDRE and TC in "
            "tx_empty_mask, RDRF in rx_ready_mask) and D is +0x07. rx_irq is "
            "omitted. K64 UART0 is IRQ 31, and a handler that reads one byte "
            "needs rx_level: true. Transmit-IRQ keys are not set on this guess. "
            "Other offsets are logged and ignored."
        )
        extra = _KINETIS_UART_EXTRA
    else:
        comment = (
            f"Guessed STM32 {name}. TODO: status is +0 (TXE in tx_empty_mask, "
            "TC in tx_complete_mask, RXNE in rx_ready_mask) and data is +4. "
            "BRR, CR1, CR2, CR3, and GTPR read back. TXEIE and TCIE pend "
            "tx_irq, which defaults to rx_irq, so a firmware helper that pends "
            "the USART line for transmit is not required. rx_irq is omitted "
            "until you set the vector. STM32F4 USART2 is IRQ 38."
        )
        extra = _STM32_UART_EXTRA
    return SuggestedRegion(
        name=name.lower(),
        base=base,
        size=0x400,
        perms="rw",
        peripheral="uart",
        comment=comment,
        extra=extra,
    )


_F4_RCC_EXTRA = (
    "    read_default: 0",
    "    config:",
    "      registers:",
    "        # TODO: guessed STM32F4-class bit positions. Not a clock tree.",
    "        0x00:",
    "          reset: 0x00000083",
    "          writable: true",
    "          follow:",
    "            - {src: 0, dst: 1}        # HSIRDY follows HSION",
    "            - {src: 16, dst: 17}      # HSERDY follows HSEON",
    "            - {src: 24, dst: 25}      # PLLRDY follows PLLON",
    "            - {src: 26, dst: 27}      # PLLI2SRDY follows PLLI2SON",
    "        0x04:",
    "          reset: 0x24003010",
    "          writable: true",
    "        0x08:",
    "          reset: 0",
    "          writable: true",
    "          follow:",
    "            - {src: 0, dst: 2, width: 2}  # SWS copies SW",
    "        0x0C: {reset: 0, writable: true}",
    "        0x10: {reset: 0, writable: true}",
    "        0x14: {reset: 0, writable: true}",
    "        0x18: {reset: 0, writable: true}",
    "        0x20: {reset: 0, writable: true}",
    "        0x24: {reset: 0, writable: true}",
    "        0x30: {reset: 0, writable: true}",
    "        0x34: {reset: 0, writable: true}",
    "        0x38: {reset: 0, writable: true}",
    "        0x40: {reset: 0, writable: true}",
    "        0x44: {reset: 0, writable: true}",
    "        0x50: {reset: 0, writable: true}",
    "        0x54: {reset: 0, writable: true}",
    "        0x58: {reset: 0, writable: true}",
    "        0x60: {reset: 0, writable: true}",
    "        0x64: {reset: 0, writable: true}",
    "        0x70:",
    "          reset: 0",
    "          writable: true",
    "          follow:",
    "            - {src: 0, dst: 1}        # LSERDY follows LSEON",
    "        0x74:",
    "          reset: 0",
    "          writable: true",
    "          follow:",
    "            - {src: 0, dst: 1}        # LSIRDY follows LSION",
    "        0x80: {reset: 0, writable: true}",
    "        0x84: {reset: 0, writable: true}",
)

_F1_RCC_EXTRA = (
    "    read_default: 0",
    "    config:",
    "      registers:",
    "        # TODO: guessed STM32F1/F3-class offsets. L4/G4 CR bits differ.",
    "        0x00:",
    "          reset: 0x00000083",
    "          writable: true",
    "          follow:",
    "            - {src: 0, dst: 1}        # HSIRDY follows HSION",
    "            - {src: 16, dst: 17}      # HSERDY follows HSEON",
    "            - {src: 24, dst: 25}      # PLLRDY follows PLLON",
    "        0x04:",
    "          reset: 0",
    "          writable: true",
    "          follow:",
    "            - {src: 0, dst: 2, width: 2}  # SWS copies SW",
    "        0x08: {reset: 0, writable: true}",
    "        0x0C: {reset: 0, writable: true}",
    "        0x10: {reset: 0, writable: true}",
    "        0x14: {reset: 0, writable: true}",
    "        0x18: {reset: 0, writable: true}",
    "        0x1C: {reset: 0, writable: true}",
    "        0x20:",
    "          reset: 0",
    "          writable: true",
    "          follow:",
    "            - {src: 0, dst: 1}        # LSERDY follows LSEON",
    "        0x24:",
    "          reset: 0",
    "          writable: true",
    "          follow:",
    "            - {src: 0, dst: 1}        # LSIRDY follows LSION",
)

_KINETIS_MCG_EXTRA = (
    "    read_default: 0",
    "    config:",
    "      registers:",
    "        # TODO: guessed K64 MCG byte packing. C1 is the first byte.",
    "        # IREFS is C1 bit 2. CLKS is C1 bits 7:6. EREFS0 is C2 bit 2",
    "        # (bit 10 of this word).",
    "        0x00: {reset: 0, writable: true}",
    "        # C5, C6, S. PLLS is C6 bit 6 (bit 14). S is the third byte:",
    "        # OSCINIT0 bit 17, CLKST bits 19:18, IREFST bit 20, PLLST bit 21,",
    "        # LOCK0 bit 22.",
    "        0x04:",
    "          reset: 0",
    "          writable: true",
    "          follow:",
    "            - {from: 0x00, src: 6, dst: 18, width: 2}   # CLKST copies CLKS",
    "            - {src: 14, dst: 18, width: 2, value: 3}    # PLLS set => CLKST = 3",
    "            - {src: 14, dst: 21}                        # PLLST follows PLLS",
    "            - {src: 14, dst: 22}                        # LOCK0 follows PLLS",
    "            - {from: 0x00, src: 2, dst: 20}             # IREFST follows IREFS",
    "            - {from: 0x00, src: 10, dst: 17}            # OSCINIT0 follows EREFS0",
    "        0x08: {reset: 0, writable: true}",
    "        0x0C: {reset: 0, writable: true}",
)

_F4_FLASH_EXTRA = (
    "    read_default: 0",
    "    config:",
    "      registers:",
    "        # TODO: ACR sticks. SR writes are ignored and BSY (bit 16) reads as 0.",
    "        0x00: {reset: 0, writable: true}",
    "        0x04: {reset: 0, writable: true}",
    "        0x08: {reset: 0, writable: true}",
    "        0x0C:",
    "          reset: 0",
    "          writable: false",
    "          read_mask: 0x00010000",
    "          read_bits: 0",
    "        0x10: {reset: 0, writable: true}",
    "        0x14: {reset: 0, writable: true}",
)

_STM32_UART_EXTRA = (
    "    read_default: 0",
    "    config:",
    "      # TODO: confirm these offsets. rx_irq is intentionally omitted.",
    "      # TX shares that vector once you set rx_irq (or tx_irq). No TX helper.",
    "      data_offset: 0x04",
    "      status_offset: 0x00",
    "      tx_empty_mask: 0x80",
    "      tx_complete_mask: 0x40",
    "      rx_ready_mask: 0x20",
    "      cr1_offset: 0x0C",
    "      txeie_mask: 0x80",
    "      tcie_mask: 0x40",
    "      control_offsets: [0x08, 0x0C, 0x10, 0x14, 0x18]",
)

_KINETIS_UART_EXTRA = (
    "    read_default: 0",
    "    config:",
    "      # TODO: confirm these offsets. rx_irq is intentionally omitted.",
    "      # Set rx_level: true if the handler reads a single byte.",
    "      data_offset: 0x07",
    "      status_offset: 0x04",
    "      tx_empty_mask: 0xC0",
    "      rx_ready_mask: 0x20",
)


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

