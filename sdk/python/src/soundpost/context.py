# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Client-owned trace context; no process-global current client."""
from contextvars import ContextVar
from dataclasses import dataclass
import os
import re

_ID = re.compile(r'[0-9a-f]+\Z')
_ID_MATCH = _ID.fullmatch

def valid_id(value: object, length: int) -> bool:
    return type(value) is str and len(value) == length and _ID_MATCH(value) is not None and value != '0' * length

_set = object.__setattr__

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

    @classmethod
    def trusted(cls, trace_id: str, span_id: str, sampled: bool, sample_probability: float) -> 'TraceContext':
        """Builds a context from values the SDK generated or already validated itself (fresh random identifiers, a parent's validated fields): no re-validation."""
        context = object.__new__(cls)
        _set(context, 'trace_id', trace_id)
        _set(context, 'span_id', span_id)
        _set(context, 'sampled', sampled)
        _set(context, 'sample_probability', sample_probability)
        return context

class _Binding:
    """One use of ContextState.bind: sets the variable on enter, restores the previous value on every exit."""
    __slots__ = ('_variable', '_context', '_token')

    def __init__(self, variable, context):
        self._variable, self._context, self._token = variable, context, None

    def __enter__(self):
        context = self._context
        if context is not None and type(context) is not TraceContext:
            raise TypeError('TraceContext required')
        self._token = self._variable.set(context)
        return context

    def __exit__(self, exception_type, exception, traceback):
        self._variable.reset(self._token)
        return False

class _Exporting:
    __slots__ = ('_variable', '_token')

    def __init__(self, variable):
        self._variable, self._token = variable, None

    def __enter__(self):
        self._token = self._variable.set(True)

    def __exit__(self, exception_type, exception, traceback):
        self._variable.reset(self._token)
        return False

class ContextState:
    def __init__(self):
        self._value = ContextVar('soundpost_trace', default=None)
        self._exporting = ContextVar('soundpost_exporting', default=False)
        self._pid = os.getpid()

    def current(self) -> TraceContext | None:
        # Forked children must not inherit a parent's active request.
        return self._value.get() if os.getpid() == self._pid else None

    def bind(self, context: TraceContext | None) -> _Binding:
        return _Binding(self._value, context)

    def exporting(self) -> _Exporting:
        return _Exporting(self._exporting)

    def is_exporting(self) -> bool:
        return self._exporting.get()
