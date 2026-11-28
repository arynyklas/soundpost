# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import asyncio
import json
import pytest
from soundpost.integrations.asgi import ASGIMiddleware
from soundpost.integrations.wsgi import WSGIMiddleware

@pytest.fixture
def client():
    import base64
    from dataclasses import replace
    from test_policy import config, KEY, b64
    from soundpost import init, SignedPolicy
    original = config(operations=('request', 'http.call', 'db.execute'), dependencies=('dependency', 'postgres'), origins=('dependency',))
    document = json.loads(base64.urlsafe_b64decode(original.policy.payload + '=' * (-len(original.policy.payload) % 4)))
    document.update(traces=True, jobs=False)
    payload = json.dumps(document, sort_keys=True, separators=(',', ':')).encode()
    policy = SignedPolicy(1, 'Ed25519', 'test', b64(payload), b64(KEY.sign(payload)))
    instance = init(replace(original, policy=policy))
    yield instance
    instance.close()

# Removing finally-reset or consuming a streaming iterator eagerly breaks these.
def test_wsgi_preserves_stream_and_close(client):
    state = []
    class Body:
        def __iter__(self):
            state.append('iter')
            yield b'one'
            yield b'two'
        def close(self): state.append('closed')
    def app(environ, start_response):
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return Body()
    middleware = WSGIMiddleware(app, client, operation='request')
    result = middleware({}, lambda status, headers: state.append(status))
    assert 'iter' not in state
    assert list(result) == [b'one', b'two']
    result.close()
    assert state.count('closed') == 1
    assert client._trace_context.current() is None

def test_asgi_protocol_streaming_and_cancellation(client):
    async def exercise():
        sent = []
        async def receive(): return {'type': 'http.request', 'body': b'', 'more_body': False}
        async def send(message): sent.append(message)
        async def app(scope, receive, send):
            await send({'type': 'http.response.start', 'status': 200, 'headers': []})
            await send({'type': 'http.response.body', 'body': b'one', 'more_body': True})
            await asyncio.sleep(0)
            await send({'type': 'http.response.body', 'body': b'two'})
        middleware = ASGIMiddleware(app, client, operation='request')
        await middleware({'type': 'http', 'headers': [], 'path': '/SECRET'}, receive, send)
        assert [m.get('body') for m in sent if m['type'] == 'http.response.body'] == [b'one', b'two']
        assert client._trace_context.current() is None
        async def cancelled(scope, receive, send): raise asyncio.CancelledError()
        with pytest.raises(asyncio.CancelledError):
            await ASGIMiddleware(cancelled, client, operation='request')({'type':'http', 'headers':[]}, receive, send)
        assert client._trace_context.current() is None
    asyncio.run(exercise())
    assert 'SECRET' not in ''.join(client.buffered_records())

def test_nested_spans_and_unsampled_error_independence(client):
    from soundpost.context import TraceContext
    with client._trace_context.bind(TraceContext('a'*32, 'b'*16, False, 0.25)):
        with client.span('request') as outer:
            with client.span('db.execute', dependency='postgres') as inner:
                try: raise ValueError('PRIVATE_EXCEPTION_MESSAGE')
                except ValueError as error:
                    episode = client.begin_handling_episode()
                    try:
                        first = episode.capture_exception(error)
                        assert episode.capture_exception(error) == first
                    finally: episode.close()
            assert client._trace_context.current() == outer.context
        assert inner.parent_id == outer.context.span_id
    records = [json.loads(value) for value in client.buffered_records()]
    errors = [record for record in records if record['kind'] == 'error']
    assert len(errors) == 1
    assert 'PRIVATE_EXCEPTION_MESSAGE' not in json.dumps(records)
    assert client._trace_context.current() is None

def test_exporter_recursion_does_not_capture(client):
    from soundpost.transport import EXPORTING
    token = EXPORTING.set(True)
    try:
        with client.span('request'):
            client.capture_exception(ValueError('PRIVATE'))
    finally: EXPORTING.reset(token)
    assert not client.buffered_records()

def test_real_async_http_pg_critical_path(client):
    import importlib.util
    import os
    import pathlib
    import socket
    import threading
    import time
    import httpx
    import psycopg
    import uvicorn
    root = pathlib.Path(__file__).resolve().parents[3] / 'fixtures' / 'sdk' / 'python'
    def load(name):
        specification = importlib.util.spec_from_file_location('soundpost_fixture_' + name, root / (name + '.py'))
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        return module
    dependency_module, api = load('dependency'), load('api')
    dsn = os.environ['SOUNDPOST_FIXTURE_PG_DSN']
    async def exercise():
        with dependency_module.Dependency() as dependency:
            async with httpx.AsyncClient() as http:
                async with await psycopg.AsyncConnection.connect(dsn, autocommit=True) as database:
                    listener = socket.socket()
                    listener.bind(('127.0.0.1', 0))
                    listener.listen()
                    port = listener.getsockname()[1]
                    server = uvicorn.Server(uvicorn.Config(api.application(client, http, database, dependency.url), lifespan='off', log_level='critical'))
                    serving = asyncio.create_task(server.serve(sockets=[listener]))
                    try:
                        for _ in range(500):
                            if server.started: break
                            await asyncio.sleep(.01)
                        assert server.started, 'ASGI listener did not become ready'
                        response = await http.get(f'http://127.0.0.1:{port}/PRIVATE_REQUEST')
                        assert response.status_code == 200 and response.content == b'ok'
                    finally:
                        server.should_exit = True
                        await asyncio.wait_for(serving, 10)
                        listener.close()
                    assert serving.done()
            assert len(dependency.server.parents) == 2
            assert all(value and value.startswith('00-') for value in dependency.server.parents)
    with asyncio.Runner(loop_factory=asyncio.SelectorEventLoop if os.name == 'nt' else None) as runner:
        runner.run(exercise())
    records = [json.loads(value) for value in client.buffered_records()]
    spans = [record['payload'] for record in records if record['kind'] == 'span']
    assert len(spans) == 6
    root = next(span for span in spans if span['span_kind'] == 'server')
    children = [span for span in spans if span['parent_id'] == root['span_id']]
    assert len(children) == 5
    assert len({span['span_id'] for span in spans}) == 6
    assert all(span['trace_id'] == root['trace_id'] for span in spans)
    assert sum(span['dependency_alias'] == 'postgres' for span in spans) == 2
    assert sum(span['status'] == 'cancelled' for span in spans) == 1
    assert len([record for record in records if record['kind'] == 'error']) == 1
    for span in spans:
        assert span['start']['domain'] == span['end']['domain']
        assert int(span['end']['mono_ns']) >= int(span['start']['mono_ns'])
    assert not any(value in json.dumps(records) for value in ('PRIVATE_', dsn, 'SELECT', 'division by zero'))

def test_one_hundred_overlapping_asgi_requests_are_isolated(client):
    observed=[]
    async def app(scope, receive, send):
        context=client._trace_context.current()
        await asyncio.sleep(0)
        assert client._trace_context.current()==context
        observed.append(context)
        await send({'type':'http.response.start','status':204,'headers':[]})
        await send({'type':'http.response.body','body':b''})
    middleware=ASGIMiddleware(app,client,operation='request')
    async def exercise():
        async def request():
            sent=[]
            async def receive():return {'type':'http.request','body':b''}
            async def send(message):sent.append(message)
            await middleware({'type':'http','headers':[]},receive,send)
            assert sent==[{'type':'http.response.start','status':204,'headers':[]},{'type':'http.response.body','body':b''}]
            assert client._trace_context.current() is None
        await asyncio.gather(*(request() for _ in range(100)))
    asyncio.run(exercise())
    assert len({context.trace_id for context in observed})==100
    assert len({context.span_id for context in observed})==100
    assert len(client.buffered_records())==100

def test_wsgi_early_close_is_incomplete_and_original_exception_survives(client):
    state=[]
    class Body:
        def __iter__(self):
            yield b'first'
            yield b'second'
        def close(self):state.append('closed')
    def app(environ,start):
        start('200 OK',[])
        return Body()
    response=WSGIMiddleware(app,client,operation='request')({},lambda status,headers:None)
    assert next(response)==b'first'
    assert client._trace_context.current() is None
    response.close();response.close()
    assert state==['closed']
    record=json.loads(client.buffered_records()[0])
    assert record['payload']['status']=='incomplete'
    failure=ValueError('PRIVATE')
    def broken(environ,start):raise failure
    with pytest.raises(ValueError) as raised:
        WSGIMiddleware(broken,client,operation='request')({},lambda status,headers:None)
    assert raised.value is failure
    assert client._trace_context.current() is None
    assert len([value for value in client.buffered_records() if json.loads(value)['kind']=='error'])==1
