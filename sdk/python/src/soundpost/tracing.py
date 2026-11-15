# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import asyncio
from os import urandom as _urandom
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

    def _stamp(self):
        """(wall_ns text validated by the client's clock reader, monotonic_ns int), or None when the client clock is unusable."""
        wall=self.client._read_clock()
        if wall is None:return None
        return (wall, time.monotonic_ns())

    def __enter__(self):
        if self._entered: raise RuntimeError('span scope already entered')
        self._entered = True
        parent = self.client._trace_context.current()
        self.parent_id = parent.span_id if parent else None
        # Fresh random identifiers and a validated parent's own fields: nothing for TraceContext's constructor checks to find.
        self.context = TraceContext.trusted(parent.trace_id if parent else _urandom(16).hex(), _urandom(8).hex(), parent.sampled if parent else True, parent.sample_probability if parent else 1.0)
        self.start = self._stamp()
        self._binding = self.client._trace_context.bind(self.context)
        self._binding.__enter__()
        return self

    def __exit__(self, exception_type, exception, traceback):
        self._exited = True
        try:
            if exception_type is not None:
                self.status = 'cancelled' if issubclass(exception_type, asyncio.CancelledError) else 'error'
            end = self._stamp()
            if self.start is None or end is None:
                with self.client._lock:self.client._loss("span_clock_unavailable")
                return False
            self.client._record_span(self, end)
        finally:
            self._binding.__exit__(exception_type, exception, traceback)
        return False

    async def __aenter__(self): return self.__enter__()
    async def __aexit__(self, exception_type, exception, traceback):
        return self.__exit__(exception_type, exception, traceback)
