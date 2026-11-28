# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
from ..tracing import SpanContextManager

class PsycopgIntegration:
    """Execute through a supplied psycopg connection; SQL never enters capture."""
    def __init__(self, client, connection, *, operation: str, dependency: str):
        SpanContextManager(client, operation, dependency=dependency, kind='client')
        self.client, self.connection = client, connection
        self.operation, self.dependency = operation, dependency
        self.enabled = True

    def execute(self, query, params=None, **kwargs):
        if not self.enabled: return self.connection.execute(query, params, **kwargs)
        with SpanContextManager(self.client, self.operation, dependency=self.dependency, kind='client'):
            return self.connection.execute(query, params, **kwargs)

class AsyncPsycopgIntegration(PsycopgIntegration):
    async def execute(self, query, params=None, **kwargs):
        if not self.enabled: return await self.connection.execute(query, params, **kwargs)
        async with SpanContextManager(self.client, self.operation, dependency=self.dependency, kind='client'):
            return await self.connection.execute(query, params, **kwargs)

def install(client, config):
    from . import IntegrationConfig, IntegrationLease
    if type(config) is not IntegrationConfig: raise TypeError('IntegrationConfig required')
    adapter = AsyncPsycopgIntegration if config.asynchronous else PsycopgIntegration
    return IntegrationLease(client, adapter(client, config.target, operation=config.operation, dependency=config.dependency))
