# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import asyncio
import json
import logging
from test_integrations import client
from soundpost.integrations.logging import LoggingLease
from soundpost.integrations.asyncio import AsyncioIntegration

class MessageTrap:
    def __str__(self): raise AssertionError('message rendered')
    def __repr__(self): raise AssertionError('message represented')

def test_logging_ignores_messages_getters_and_arbitrary_fields(client):
    logger = logging.Logger('fixture')
    lease = LoggingLease(client, logger)
    try:
        logger.error(MessageTrap())
        logger.error(MessageTrap(), extra={'soundpost_template':'operation.failed', 'soundpost_fields':{'status':503, 'PRIVATE':MessageTrap()}})
    finally: lease.close()
    records = [json.loads(value) for value in client.buffered_records()]
    assert len(records) == 1
    assert records[0]['payload']['line'] == 'operation failed: 503'
    assert 'PRIVATE' not in json.dumps(records)
    logger.error(MessageTrap())
    assert len(client.buffered_records()) == 1

def test_asyncio_detaches_unrelated_tasks_and_explicit_thread_boundaries(client):
    adapter = AsyncioIntegration(client)
    async def exercise():
        async def current(): return client._trace_context.current()
        async with client.span('request') as span:
            assert await adapter.create_task(current()) is None
            assert await adapter.create_task(current(), inherit=True) == span.context
            assert await adapter.to_thread(client._trace_context.current) is None
            assert await adapter.to_thread(client._trace_context.current, inherit=True) == span.context
        assert client._trace_context.current() is None
    asyncio.run(exercise())

def test_actual_requests_httpx_origin_gate_and_lease_close(client):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    import httpx
    import requests
    from soundpost.integrations.requests import RequestsIntegration
    from soundpost.integrations.httpx import HTTPXIntegration
    from soundpost.integrations import IntegrationConfig
    from soundpost.integrations.httpx import install
    observed=[]
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            observed.append({key.lower():value for key,value in self.headers.items()})
            self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'ok')
        def log_message(self,*args): pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=Thread(target=server.serve_forever,daemon=True);thread.start()
    url=f'http://127.0.0.1:{server.server_port}'
    try:
        with requests.Session() as session:
            session.headers.update({'baggage':'PRIVATE','traceparent':'PRIVATE','tracestate':'PRIVATE'})
            adapter=RequestsIntegration(client,session,operation='http.call',dependency='dependency',origin='dependency',origin_url=url)
            assert adapter.request('GET',url,allow_redirects=False).content==b'ok'
            assert observed[-1]['traceparent'].startswith('00-')
            assert 'baggage' not in observed[-1] and 'tracestate' not in observed[-1]
            forbidden=RequestsIntegration(client,session,operation='http.call',dependency='dependency',origin='forbidden',origin_url=url)
            assert forbidden.request('GET',url,allow_redirects=False).status_code==200
            assert 'traceparent' not in observed[-1]
        with httpx.Client(headers={'baggage':'PRIVATE','traceparent':'PRIVATE','tracestate':'PRIVATE'}) as session:
            adapter=HTTPXIntegration(client,session,operation='http.call',dependency='dependency',origin='dependency',origin_url=url)
            assert adapter.request('GET',url).content==b'ok'
            assert observed[-1]['traceparent'].startswith('00-') and 'baggage' not in observed[-1]
            wrong_target=HTTPXIntegration(client,session,operation='http.call',dependency='dependency',origin='dependency',origin_url='https://example.invalid')
            assert wrong_target.request('GET',url).status_code==200
            assert 'traceparent' not in observed[-1]
            lease=install(client,IntegrationConfig(session,'http.call','dependency','dependency',url))
            lease.close()
            before=len(client.buffered_records())
            assert lease.adapter.request('GET',url).status_code==200
            assert len(client.buffered_records())==before
    finally:
        server.shutdown();server.server_close();thread.join()
    assert 'PRIVATE' not in ''.join(client.buffered_records())
