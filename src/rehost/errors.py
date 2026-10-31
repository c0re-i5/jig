# SPDX-License-Identifier: MIT
"""Errors callers can catch. Programming bugs stay as built-in exceptions."""

from __future__ import annotations


class RehostError(Exception):
    """Base class for recoverable rehost failures."""


class ConfigError(RehostError):
    """A machine file, plugin config, or fixture name is invalid."""


class AssembleError(RehostError):
    """The in-repo Thumb assembler could not encode a fixture."""


class MachineError(RehostError):
    """A load, memory access, or snapshot operation cannot be completed."""


class FuzzInputError(RehostError):
    """Fuzzer input does not match the sink configured for this machine."""


class BackendError(RehostError):
    """The CPU backend rejected an operation or stopped with an engine error."""

    def __init__(self, message: str, pc: int | None = None) -> None:
        super().__init__(message)
        self.pc = pc
