# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Explicit task/thread boundaries; no event-loop factory monkeypatch."""
import asyncio
import contextvars

class AsyncioIntegration:
    def __init__(self, client):
        self.client = client
        self.enabled = True

    def create_task(self, coroutine, *, inherit: bool = False, name: str | None = None):
        if not self.enabled: return asyncio.create_task(coroutine, name=name)
        if type(inherit) is not bool: raise TypeError('inherit must be boolean')
        context = contextvars.copy_context()
        if not inherit:
            # Clear this client's context only; preserve unrelated library state.
            def detached():
                with self.client._trace_context.bind(None):
                    return contextvars.copy_context()
            context = context.run(detached)
        return asyncio.create_task(coroutine, name=name, context=context)

    async def to_thread(self, function, /, *args, inherit: bool = False, **kwargs):
        if not self.enabled: return await asyncio.to_thread(function, *args, **kwargs)
        context = self.client._trace_context.current() if inherit else None
        def call():
            with self.client._trace_context.bind(context):
                return function(*args, **kwargs)
        return await asyncio.to_thread(call)

def install(client, config):
    from . import IntegrationConfig, IntegrationLease
    if type(config) is not IntegrationConfig: raise TypeError('IntegrationConfig required')
    return IntegrationLease(client, AsyncioIntegration(client))
