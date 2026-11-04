# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Actual approved framework applications; imports fail if prerequisites are absent.

These cases reuse owned ASGI/WSGI protocol adapters, never an upstream SDK.
"""
import asyncio
import json
import pytest
from test_integrations import client
from soundpost.integrations.asgi import ASGIMiddleware
from soundpost.integrations.wsgi import WSGIMiddleware


def framework_application(framework, client, seen, entered):
    if framework == 'starlette':
        from starlette.applications import Starlette
        from starlette.responses import PlainTextResponse, StreamingResponse
        from starlette.routing import Route
        async def route(request):
            seen.append(client._trace_context.current())
            return PlainTextResponse('visible-route')
        async def stream(request):
            async def chunks():
                seen.append(client._trace_context.current())
                yield b'one'
                await asyncio.sleep(0)
                seen.append(client._trace_context.current())
                yield b'two'
            return StreamingResponse(chunks())
        async def error(request):
            raise ValueError('PRIVATE_FRAMEWORK_EXCEPTION')
        async def cancelled(request):
            entered.set()
            await asyncio.Event().wait()
        return Starlette(routes=[Route('/registered/{item}',route),Route('/stream',stream),Route('/error',error),Route('/cancel',cancelled)])
    from fastapi import FastAPI
    from fastapi.responses import PlainTextResponse, StreamingResponse
    app=FastAPI()
    @app.get('/registered/{item}')
    async def route(item: str):
        seen.append(client._trace_context.current())
        return PlainTextResponse('visible-route')
    @app.get('/stream')
    async def stream():
        async def chunks():
            seen.append(client._trace_context.current())
            yield b'one'
            await asyncio.sleep(0)
            seen.append(client._trace_context.current())
            yield b'two'
        return StreamingResponse(chunks())
    @app.get('/error')
    async def error():raise ValueError('PRIVATE_FRAMEWORK_EXCEPTION')
    @app.get('/cancel')
    async def cancelled():
        entered.set()
        await asyncio.Event().wait()
    return app


@pytest.mark.parametrize('framework',['starlette','fastapi'])
def test_actual_framework_routes_streaming_errors_and_cancellation(framework,client):
    import httpx
    seen=[]
    async def exercise():
        entered=asyncio.Event()
        app=framework_application(framework,client,seen,entered)
        wrapped=ASGIMiddleware(app,client,operation='request')
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=wrapped),base_url='http://framework.invalid') as http:
            response=await http.get('/registered/PRIVATE_PATH?private=PRIVATE_QUERY')
            assert response.status_code==200 and response.text=='visible-route'
            response=await http.get('/stream')
            assert response.status_code==200 and response.content==b'onetwo'
            with pytest.raises(ValueError):await http.get('/error')
            task=asyncio.create_task(http.get('/cancel'))
            await asyncio.wait_for(entered.wait(),5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):await task
            assert client._trace_context.current() is None
        # Disabled capture must preserve actual framework response semantics.
        inactive=ASGIMiddleware(app,client,operation='request')
        inactive.enabled=False
        count=len(client.buffered_records())
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=inactive),base_url='http://framework.invalid') as http:
            response=await http.get('/registered/PRIVATE_PATH?private=PRIVATE_QUERY')
            assert response.status_code==200 and response.text=='visible-route'
            response=await http.get('/stream')
            assert response.content==b'onetwo'
        assert len(client.buffered_records())==count
    asyncio.run(exercise())
    assert all(context is not None for context in seen[:3])
    assert seen[1]==seen[2]
    assert seen[0].trace_id!=seen[1].trace_id
    records=[json.loads(value) for value in client.buffered_records()]
    spans=[record['payload'] for record in records if record['kind']=='span']
    assert len(spans)==4
    assert [span['status'] for span in spans].count('cancelled')==1
    assert [span['status'] for span in spans].count('error')==1
    assert len([record for record in records if record['kind']=='error'])==1
    assert 'PRIVATE_' not in json.dumps(records)


def test_actual_flask_registered_route_stream_error_and_early_close(client):
    from flask import Flask, Response
    from werkzeug.test import Client as WSGIClient
    seen=[]
    app=Flask('soundpost-fixture')
    app.config.update(TESTING=False,PROPAGATE_EXCEPTIONS=False)
    @app.get('/registered/<item>')
    def route(item):
        seen.append(client._trace_context.current())
        return 'visible-route'
    @app.get('/stream')
    def stream():
        def chunks():
            seen.append(client._trace_context.current())
            yield b'one'
            seen.append(client._trace_context.current())
            yield b'two'
        return Response(chunks())
    @app.get('/error')
    def error():raise ValueError('PRIVATE_FRAMEWORK_EXCEPTION')
    @app.errorhandler(ValueError)
    def handled(error):
        episode=client.begin_handling_episode()
        try:episode.capture_exception(error,code='request')
        finally:episode.close()
        return 'safe-error',500
    wrapped=WSGIMiddleware(app,client,operation='request')
    http=WSGIClient(wrapped)
    response=http.get('/registered/PRIVATE_PATH?private=PRIVATE_QUERY')
    assert response.status_code==200 and response.data==b'visible-route'
    response.close()
    response=http.get('/stream',buffered=False)
    assert b''.join(response.response)==b'onetwo'
    response.close()
    response=http.get('/error')
    assert response.status_code==500 and response.data==b'safe-error'
    response.close()
    response=http.get('/stream',buffered=False)
    assert next(iter(response.response))==b'one'
    response.close()
    assert client._trace_context.current() is None
    count=len(client.buffered_records())
    wrapped.enabled=False
    response=http.get('/registered/PRIVATE_PATH?private=PRIVATE_QUERY')
    assert response.status_code==200 and response.data==b'visible-route'
    response.close()
    assert len(client.buffered_records())==count
    assert all(context is not None for context in seen[:3])
    assert seen[1]==seen[2]
    records=[json.loads(value) for value in client.buffered_records()]
    spans=[record['payload'] for record in records if record['kind']=='span']
    assert len(spans)==4
    assert sum(span['status']=='error' for span in spans)==1
    assert sum(span['status']=='incomplete' for span in spans)==1
    assert len([record for record in records if record['kind']=='error'])==1
    assert 'PRIVATE_' not in json.dumps(records)
