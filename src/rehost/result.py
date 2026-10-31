# SPDX-License-Identifier: MIT
"""Run results and the text report printed by the CLI."""

from __future__ import annotations

from dataclasses import dataclass

STATUS_HALTED = "halted"
STATUS_FAULT = "fault"
STATUS_TIMEOUT = "timeout"
STATUS_LIMIT = "instruction_limit"

EXIT_HALTED = 0
EXIT_FAULT = 1
EXIT_TIMEOUT = 2
EXIT_LIMIT = 3
EXIT_USAGE = 4


@dataclass(frozen=True)
class TraceEntry:
    """One MMIO or unmapped access observed during a run."""

    kind: str
    address: int
    size: int
    value: int


@dataclass
class RunResult:
    """How a single ``Machine.run`` ended, plus the trace it kept."""

    status: str
    detail: str
    pc: int
    sp: int
    lr: int
    registers: dict[str, int]
    instructions: int
    trace: tuple[TraceEntry, ...]
    trace_total: int
    coverage: tuple[int, ...] | None = None

    @property
    def faulted(self) -> bool:
        return self.status == STATUS_FAULT

    def exit_code(self) -> int:
        return {
            STATUS_HALTED: EXIT_HALTED,
            STATUS_FAULT: EXIT_FAULT,
            STATUS_TIMEOUT: EXIT_TIMEOUT,
            STATUS_LIMIT: EXIT_LIMIT,
        }.get(self.status, EXIT_USAGE)


def format_report(
    result: RunResult,
    *,
    name: str,
    peripheral_lines: list[str],
    verbose: bool = False,
    dumps: list[str] | None = None,
) -> str:
    """Multi-line status block. Register and trace detail follows ``verbose``."""
    lines = [
        f"name: {name}",
        f"status: {result.status}",
        f"detail: {result.detail or '-'}",
        f"pc: {result.pc:#010x}",
        f"sp: {result.sp:#010x}",
        f"lr: {result.lr:#010x}",
        f"instructions: {result.instructions}",
    ]
    lines.extend(peripheral_lines)
    if dumps:
        lines.extend(dumps)
    if verbose:
        lines.append("registers:")
        for reg in sorted(result.registers):
            lines.append(f"  {reg}: {result.registers[reg]:#010x}")
        if result.coverage is not None:
            shown = ", ".join(f"{pc:#x}" for pc in result.coverage[:32])
            extra = "" if len(result.coverage) <= 32 else f" (+{len(result.coverage) - 32})"
            lines.append(f"coverage: {shown}{extra}")
        lines.append(f"trace: {result.trace_total} access(es), showing {len(result.trace)}")
        for entry in result.trace:
            lines.append(
                f"  {entry.kind} {entry.address:#010x} size {entry.size} value {entry.value:#x}"
            )
    return "\n".join(lines)
