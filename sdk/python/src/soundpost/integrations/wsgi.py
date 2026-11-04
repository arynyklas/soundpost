# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import sys
from ..propagation import extract
from ..tracing import SpanContextManager

def _capture_boundary(client, operation, error):
    if isinstance(error, Exception):
        episode = client.begin_handling_episode()
        try: episode.capture_exception(error, code=operation)
        finally: episode.close()

class WSGIMiddleware:
    def __init__(self, app, client, *, operation: str):
        if type(operation) is not str or operation not in client._trace_operations:
            raise ValueError('operation must be registered')
        self.app, self.client, self.operation = app, client, operation
        self.enabled = True

    def __call__(self, environ, start_response):
        if not self.enabled: return self.app(environ, start_response)
        parent = extract({'traceparent': environ.get('HTTP_TRACEPARENT')})
        binding = self.client._trace_context.bind(parent)
        with binding:
            span = SpanContextManager(self.client, self.operation, kind='server')
            span.__enter__()
            try:
                def start(status, headers, exc_info=None):
                    if status[:3].isdigit() and int(status[:3]) >= 500: span.status = 'error'
                    return start_response(status, headers, exc_info) if exc_info is not None else start_response(status, headers)
                body = self.app(environ, start)
            except BaseException:
                _capture_boundary(self.client, self.operation, sys.exc_info()[1])
                span.__exit__(*sys.exc_info())
                raise
            # Detach until each streaming iteration; never retain request context
            # in the application server between iterator calls.
            span._binding.__exit__(None, None, None)
        return _Response(body, span)

class _Response:
    def __init__(self, body, span):
        self.body, self.span = body, span
        self.iterator = None
        self.closed = False
        self.exhausted = False
        self.body_closed = False

    def __iter__(self): return self

    def __next__(self):
        if self.closed: raise StopIteration
        with self.span.client._trace_context.bind(self.span.context):
            try:
                if self.iterator is None: self.iterator = iter(self.body)
                return next(self.iterator)
            except StopIteration:
                self.exhausted = True
                self.close()
                raise
            except BaseException:
                self._finish(sys.exc_info())
                raise

    def _finish(self, error):
        if self.closed: return
        self.closed = True
        with self.span.client._trace_context.bind(self.span.context):
            if error[1] is not None:
                _capture_boundary(self.span.client, self.span.operation, error[1])
            self.span._binding = self.span.client._trace_context.bind(self.span.context)
            self.span._binding.__enter__()
            self.span.__exit__(*error)

    def close(self):
        if self.body_closed: return
        self.body_closed = True
        if not self.exhausted: self.span.status = 'incomplete'
        try:
            close = getattr(self.body, 'close', None)
            if close is not None: close()
        except BaseException:
            self._finish(sys.exc_info())
            raise
        self._finish((None, None, None))

def install(client, config):
    from . import IntegrationConfig, IntegrationLease
    if type(config) is not IntegrationConfig: raise TypeError('IntegrationConfig required')
    return IntegrationLease(client, WSGIMiddleware(config.target, client, operation=config.operation))
