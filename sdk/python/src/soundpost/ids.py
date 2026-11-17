# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Random hex identifiers for the request hot path, drawn from the operating system's CSPRNG in blocks.

Every span needs a trace identifier, a span identifier and a record identifier; one `os.urandom` system call per identifier was a measurable part of the per-request
CPU. The identifiers are the same bytes `os.urandom` would have returned, only fetched `_BLOCK` identifiers per call and handed out by `deque.popleft`, which is atomic
under the GIL (no lock). A forked child starts with empty pools: it must never hand out identifiers its parent also holds."""
import os
from collections import deque

_BLOCK = 256

class _Pool:
    __slots__ = ('size', 'ids', 'take')

    def __init__(self, size: int):
        self.size = size
        self.ids = deque()
        self.take = self.ids.popleft

    def next(self) -> str:
        try:
            return self.take()
        except IndexError:
            pass
        text = os.urandom(self.size * _BLOCK).hex()
        width = self.size * 2
        first = text[:width]
        self.ids.extend([text[at:at + width] for at in range(width, len(text), width)])
        return first

_POOLS = {16: _Pool(16), 8: _Pool(8)}
hex16 = _POOLS[16].next
hex8 = _POOLS[8].next

def _forget():
    for pool in _POOLS.values():
        pool.ids.clear()

if hasattr(os, 'register_at_fork'):
    os.register_at_fork(after_in_child=_forget)
