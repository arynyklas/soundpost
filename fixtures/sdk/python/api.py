# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import asyncio
from soundpost.integrations.asgi import ASGIMiddleware
from soundpost.integrations.httpx import AsyncHTTPXIntegration
from soundpost.integrations.psycopg import AsyncPsycopgIntegration

class CriticalApplication:
    def __init__(self, client, http, database, dependency_url):
        self.client = client
        self.http = AsyncHTTPXIntegration(client, http, operation='http.call', dependency='dependency', origin='dependency', origin_url=dependency_url)
        self.database = AsyncPsycopgIntegration(client, database, operation='db.execute', dependency='postgres')
        self.dependency_url = dependency_url

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http': raise RuntimeError('HTTP fixture only')
        async def child():
            response = await self.http.request('GET', self.dependency_url + '/PRIVATE_PATH?canary=PRIVATE_QUERY')
            if response.content != b'ok': raise AssertionError('dependency response')
        await asyncio.gather(child(), child())
        cursor = await self.database.execute('SELECT %s::integer', (42,))
        if (await cursor.fetchone())[0] != 42: raise AssertionError('database response')
        import psycopg
        try:
            await self.database.execute('SELECT 1 / 0 /* PRIVATE_SQL */')
        except psycopg.errors.DivisionByZero as error:
            with_episode = self.client.begin_handling_episode()
            try: with_episode.capture_exception(error, code='db.execute')
            finally: with_episode.close()
        async def cancellation():
            async with self.client.span('http.call', dependency='dependency'):
                await asyncio.Event().wait()
        cancelled = asyncio.create_task(cancellation())
        await asyncio.sleep(0)
        cancelled.cancel()
        try: await cancelled
        except asyncio.CancelledError: pass
        await send({'type':'http.response.start', 'status':200, 'headers':[(b'content-length',b'2')]})
        await send({'type':'http.response.body', 'body':b'ok'})

def application(client, http, database, dependency_url):
    return ASGIMiddleware(CriticalApplication(client, http, database, dependency_url), client, operation='request')
