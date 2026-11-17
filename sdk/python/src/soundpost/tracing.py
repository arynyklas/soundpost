# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import asyncio
from time import time_ns as _time_ns, monotonic_ns as _monotonic_ns
from .context import TraceContext
from .types import SPAN_KINDS
from .ids import hex16 as _hex16, hex8 as _hex8, take16 as _take16, take8 as _take8

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
        client=self.client
        if client._default_clock:return (str(_time_ns()), _monotonic_ns())
        wall=client._read_clock()
        if wall is None:return None
        return (wall, _monotonic_ns())

    def __enter__(self):
        return self._begin(self.client._trace_context.current())

    def _begin(self, parent):
        """Starts the scope as a child of `parent` (a TraceContext or None for a new trace), exactly what `__enter__` does after reading the ambient context.
        The WSGI middleware passes the context it extracted from the request, which would otherwise take a binding of its own just to be read back."""
        if self._entered: raise RuntimeError('span scope already entered')
        self._entered = True
        self.parent_id = parent.span_id if parent else None
        # Fresh random identifiers and a validated parent's own fields: nothing for TraceContext's constructor checks to find.
        if parent: trace_id = parent.trace_id
        else:
            try: trace_id = _take16()
            except IndexError: trace_id = _hex16()
        try: span_id = _take8()
        except IndexError: span_id = _hex8()
        self.context = TraceContext.trusted(trace_id, span_id, parent.sampled if parent else True, parent.sample_probability if parent else 1.0)
        client=self.client
        self.start=(str(_time_ns()),_monotonic_ns()) if client._default_clock else self._stamp()
        # The context variable is set directly (the token is the whole binding): a `_Binding` object and its three calls would only wrap this set and the reset in `__exit__`.
        self._token=client._trace_context._value.set(self.context)
        return self

    def _record(self, exception_type):
        """The outcome of leaving the scope: final status, end stamp and the span record. Touches no context variable."""
        self._exited = True
        if exception_type is not None:
            self.status = 'cancelled' if issubclass(exception_type, asyncio.CancelledError) else 'error'
        end=(str(_time_ns()),_monotonic_ns()) if self.client._default_clock else self._stamp()
        if self.start is None or end is None:
            with self.client._lock:self.client._loss("span_clock_unavailable")
            return
        self.client._record_span(self, end)

    def __exit__(self, exception_type, exception, traceback):
        try:
            self._record(exception_type)
        finally:
            self.client._trace_context._value.reset(self._token)
        return False

    async def __aenter__(self): return self.__enter__()
    async def __aexit__(self, exception_type, exception, traceback):
        return self.__exit__(exception_type, exception, traceback)
