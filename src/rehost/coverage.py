# SPDX-License-Identifier: MIT
"""AFL-style edge coverage for one guest execution.

The map is the 64 KiB hit-count bitmap AFL++ uses by default (``MAP_SIZE`` in
``include/config.h``). Each retired instruction updates

    index = cur ^ prev
    prev  = cur >> 1

with ``cur`` a shift-xor of the guest PC, the same shape as AFL QEMU mode's
translation-block hash. Unicorn's code hook is already per instruction, so
each retired instruction is the block. Fall-through after a compare stays
visible, which is what a magic-byte ladder needs.

AFL semantics across ``exec_one``: the bitmap is cleared at the start of
``Machine.run``. It is not part of the guest snapshot, so restoring a boot
checkpoint cannot roll coverage backward or leak the previous case into the
next one. The campaign keeps a separate classified maximum.
"""

from __future__ import annotations

import ctypes
from typing import ByteString

# AFL++ MAP_SIZE_POW2 is 16. The forkserver reports this size and never
# writes past it, so a trailing child-sync word stays untouched.
MAP_SIZE = 1 << 16

# Hit-count classes from AFL's count_class_lookup8. A later execution is
# interesting when any edge moves into a higher class, not only when a byte
# goes from zero to non-zero.
_CLASS = bytearray(256)
for _hit in range(256):
    if _hit == 0:
        _CLASS[_hit] = 0
    elif _hit == 1:
        _CLASS[_hit] = 1
    elif _hit == 2:
        _CLASS[_hit] = 2
    elif _hit == 3:
        _CLASS[_hit] = 4
    elif _hit < 8:
        _CLASS[_hit] = 8
    elif _hit < 16:
        _CLASS[_hit] = 16
    elif _hit < 32:
        _CLASS[_hit] = 32
    elif _hit < 128:
        _CLASS[_hit] = 64
    else:
        _CLASS[_hit] = 128


def edge_location(address: int, mask: int) -> int:
    """Fold a guest PC into a map-sized location id."""
    return ((address >> 1) ^ (address >> 17)) & mask


class CoverageMap:
    """One execution's hit counts, backed by a private buffer or AFL shared memory."""

    def __init__(self, buffer: ByteString | None = None, *, size: int = MAP_SIZE) -> None:
        if buffer is None:
            storage: ByteString = bytearray(size)
        else:
            storage = buffer
        view = memoryview(storage)
        if view.format != "B":
            view = view.cast("B")
        length = len(view)
        if length == 0 or length & (length - 1):
            raise ValueError("coverage map length must be a power of two")
        self._hold = storage
        self.buf = view
        self.mask = length - 1
        self.prev = 0
        self.dirty: list[int] = []

    def begin_run(self) -> None:
        """Zero the bitmap and the previous-location register.

        Byte 0 is then set to 1, matching AFL's runtime: a persistent
        iteration that executed the loop is distinguishable from a map that
        stayed completely untouched. The fuzzer may also have zeroed the map;
        doing it here means a snapshot restore cannot leave the previous
        case's hits in place.
        """
        buf = self.buf
        ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(buf)), 0, len(buf))
        buf[0] = 1
        self.prev = 0
        self.dirty.clear()

    def on_instruction(self, address: int) -> None:
        """Record one retired instruction. Saturated at 255, like AFL."""
        cur = edge_location(address, self.mask)
        index = cur ^ self.prev
        self.prev = cur >> 1
        slot = self.buf[index]
        if slot == 255:
            return
        updated = slot + 1
        self.buf[index] = updated
        if slot == 0 or _CLASS[updated] != _CLASS[slot]:
            self.dirty.append(index)

    def absorb(self, best: bytearray) -> bool:
        """Fold this run's hit classes into ``best``. True when any class grew."""
        if len(best) != len(self.buf):
            raise ValueError("classified map is a different size than the coverage map")
        novel = False
        buf = self.buf
        for index in self.dirty:
            klass = _CLASS[buf[index]]
            if klass > best[index]:
                best[index] = klass
                novel = True
        self.dirty.clear()
        return novel

    def snapshot_bytes(self) -> bytes:
        return bytes(self.buf)
