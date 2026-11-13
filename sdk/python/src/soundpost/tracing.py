# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import asyncio
import secrets
import time
from .context import TraceContext
from .types import SPAN_KINDS

class SpanContextManager:
    """One-use sync/async span scope with token restoration on every exit."""
    def __init__(self, client, operation: str, *, dependency: str | None = None, kind: str = 'internal'):
        if type(operation) is not str or operation not in client._trace_operations:
            raise ValueError('operation must be registered')
        if dependency is not None and (type(dependency) is not str or dependency not in client._trace_dependencies):
            raise ValueError('dependency must be registered')
        if type(kind) is not str or kind not in SPAN_KINDS:
            raise ValueError('invalid span kind')
        self.client = client
        self.operation = operation
        self.dependency = dependency or ''
        self.kind = kind
        self.status = 'ok'
        self._entered = False
        self._exited = False

    def set_status(self, status: str) -> None:
        """Set the outcome recorded when the scope exits: `ok` or `error` (cancellation/incomplete are automatic).

        An exception leaving the scope still wins: it always records `error` (or `cancelled`)."""
        if type(status) is not str or status not in ('ok', 'error'):
            raise ValueError("span status must be 'ok' or 'error'")
        if self._exited:
            raise RuntimeError('span scope already exited')
        self.status = status

    def set_error(self) -> None:
        """Mark this span failed without raising, e.g. a nonzero exit code or an HTTP 5xx handled by the caller."""
        self.set_status('error')

    def _clock(self):
        wall=self.client._read_clock()
        if wall is None:return None
        return {'wall_ns': wall, 'mono_ns': str(time.monotonic_ns()), 'domain': dict(self.client._trace_domain), 'uncertainty_ns': self.client._trace_uncertainty}

    def __enter__(self):
        if self._entered: raise RuntimeError('span scope already entered')
        self._entered = True
        parent = self.client._trace_context.current()
        self.parent_id = parent.span_id if parent else None
        self.context = TraceContext(parent.trace_id if parent else secrets.token_hex(16), secrets.token_hex(8), parent.sampled if parent else True, parent.sample_probability if parent else 1.0)
        self.start = self._clock()
        self._binding = self.client._trace_context.bind(self.context)
        self._binding.__enter__()
        return self

    def __exit__(self, exception_type, exception, traceback):
        self._exited = True
        try:
            if exception_type is not None:
                self.status = 'cancelled' if issubclass(exception_type, asyncio.CancelledError) else 'error'
            end = self._clock()
            if self.start is None or end is None:
                with self.client._lock:self.client._loss("span_clock_unavailable")
                return False
            import struct
            self.client._capture_span({'trace_id': self.context.trace_id, 'span_id': self.context.span_id, 'parent_id': self.parent_id, 'span_kind': self.kind, 'operation': self.operation, 'start': self.start, 'end': end, 'status': self.status, 'dependency_alias': self.dependency, 'links': [], 'sample_probability': struct.pack('>d', self.context.sample_probability).hex(), 'sample_decision': 'keep' if self.context.sampled else 'drop'})
        finally:
            self._binding.__exit__(exception_type, exception, traceback)
        return False

    async def __aenter__(self): return self.__enter__()
    async def __aexit__(self, exception_type, exception, traceback):
        return self.__exit__(exception_type, exception, traceback)
