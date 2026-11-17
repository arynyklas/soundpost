# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import sys
from ..propagation import extract
from ..tracing import SpanContextManager

class ASGIMiddleware:
    """Explicit registered-operation ASGI adapter; never inspects path/body."""
    def __init__(self, app, client, *, operation: str):
        if type(operation) is not str or operation not in client._trace_operations:
            raise ValueError('operation must be registered')
        self.app, self.client, self.operation = app, client, operation
        self.enabled = True

    async def __call__(self, scope, receive, send):
        if not self.enabled: return await self.app(scope, receive, send)
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        headers = {}
        duplicate = False
        for key, value in scope.get('headers', ()):
            if key.lower() == b'traceparent':
                if 'traceparent' in headers: duplicate = True
                try: headers['traceparent'] = value.decode('ascii')
                except UnicodeDecodeError: duplicate = True
        parent = extract(headers) if headers and not duplicate else None
        # The request's own context (None for a request without a valid traceparent, never the ambient one) is the parent: handed to the span directly instead of being bound
        # around a scope that binds its own context straight away and reads the outer one back. The scope ends exactly as `async with` ended it.
        span = SpanContextManager(self.client, self.operation, kind='server')
        span._begin(parent)
        try:
            async def observed_send(message):
                if message['type'] == 'http.response.start' and message['status'] >= 500:
                    span.set_error()
                await send(message)
            try:
                result = await self.app(scope, receive, observed_send)
            except Exception as error:
                episode = self.client.begin_handling_episode()
                try: episode.capture_exception(error, code=self.operation)
                finally: episode.close()
                raise
        except BaseException:
            span.__exit__(*sys.exc_info())
            raise
        span.__exit__(None, None, None)
        return result

def install(client, config):
    from . import IntegrationConfig, IntegrationLease
    if type(config) is not IntegrationConfig: raise TypeError('IntegrationConfig required')
    return IntegrationLease(client, ASGIMiddleware(config.target, client, operation=config.operation))
