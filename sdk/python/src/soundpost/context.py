# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Client-owned trace context; no process-global current client."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import os
import re

_ID = re.compile(r'[0-9a-f]+\Z')

def valid_id(value: object, length: int) -> bool:
    return type(value) is str and len(value) == length and _ID.fullmatch(value) is not None and value != '0' * length

@dataclass(frozen=True, slots=True)
class TraceContext:
    trace_id: str
    span_id: str
    sampled: bool = True
    sample_probability: float = 1.0

    def __post_init__(self):
        if not valid_id(self.trace_id, 32) or not valid_id(self.span_id, 16):
            raise ValueError('invalid trace identity')
        if type(self.sampled) is not bool or type(self.sample_probability) not in (int, float) or not 0 <= self.sample_probability <= 1:
            raise ValueError('invalid sampling decision')

class ContextState:
    def __init__(self):
        self._value = ContextVar('soundpost_trace', default=None)
        self._exporting = ContextVar('soundpost_exporting', default=False)
        self._pid = os.getpid()

    def current(self) -> TraceContext | None:
        # Forked children must not inherit a parent's active request.
        return self._value.get() if os.getpid() == self._pid else None

    @contextmanager
    def bind(self, context: TraceContext | None):
        if context is not None and type(context) is not TraceContext:
            raise TypeError('TraceContext required')
        token = self._value.set(context)
        try:
            yield context
        finally:
            self._value.reset(token)

    @contextmanager
    def exporting(self):
        token = self._exporting.set(True)
        try:
            yield
        finally:
            self._exporting.reset(token)

    def is_exporting(self) -> bool:
        return self._exporting.get()
