# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import asyncio
import concurrent.futures
import contextvars
import multiprocessing
import pytest
from soundpost.context import ContextState, TraceContext
from soundpost.propagation import extract, inject

TRACE = 'a' * 32
SPAN = '2' * 16

def child_process(queue, explicit=None):
    state=ContextState()
    queue.put(state.current())
    if explicit is not None:
        with state.bind(explicit):queue.put(state.current())
        queue.put(state.current())

def test_context_isolation():
    state = ContextState()
    async def exercise():
        async def request(index):
            context = TraceContext(TRACE, f'{index + 1:016x}')
            with state.bind(context):
                await asyncio.sleep(0)
                assert state.current() == context
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    assert pool.submit(state.current).result() is None
                    assert pool.submit(contextvars.copy_context().run, state.current).result() == context
            assert state.current() is None
        await asyncio.gather(*(request(i) for i in range(100)))
    asyncio.run(exercise())
    assert state.current() is None
    with pytest.raises(RuntimeError):
        with state.bind(TraceContext(TRACE, SPAN)):
            raise RuntimeError('not captured')
    assert state.current() is None
    mp = multiprocessing.get_context('spawn')
    queue = mp.Queue()
    process = mp.Process(target=child_process, args=(queue,))
    process.start()
    assert queue.get(timeout=10) is None
    process.join(10)
    assert process.exitcode == 0
    explicit=TraceContext(TRACE,SPAN)
    process=mp.Process(target=child_process,args=(queue,explicit))
    process.start()
    assert queue.get(timeout=10) is None
    assert queue.get(timeout=10)==explicit
    assert queue.get(timeout=10) is None
    process.join(10)
    assert process.exitcode==0

@pytest.mark.parametrize('value', ['00-' + '0'*32 + '-' + SPAN + '-01', '00-'+TRACE+'-'+'0'*16+'-01', 'ff-'+TRACE+'-'+SPAN+'-01', '00-'+TRACE.upper()+'-'+SPAN+'-01', '00-'+TRACE+'-'+SPAN+'-03', '00-'+TRACE+'-'+SPAN+'-01-extra'])
def test_rejects_invalid_traceparent(value):
    assert extract({'traceparent': value, 'baggage': 'secret=value'}) is None

def test_propagation_never_carries_baggage_or_forbidden_origin():
    context = extract({'traceparent': '00-'+TRACE+'-'+SPAN+'-01', 'baggage': 'secret=value', 'tracestate': 'vendor=secret'})
    assert context == TraceContext(TRACE, SPAN)
    assert inject(context, 'internal', allowed_origins=frozenset({'internal'})) == {'traceparent': '00-'+TRACE+'-'+SPAN+'-01'}
    assert inject(context, 'external', allowed_origins=frozenset({'internal'})) == {}
