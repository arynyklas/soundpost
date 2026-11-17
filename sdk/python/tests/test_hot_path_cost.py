# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Pins for the per-request CPU work of the capture path (lane 4 wave 20): system calls, context-variable traffic, Python call counts and the equality of the cheaper
paths with the reference they replaced. The budget itself is measured by fixtures/sdk/overhead.mjs; these tests keep each saving from silently regressing."""
import hashlib
import json
import os
import re
import sys
import pytest
from soundpost.transport import Outcome
from test_delivery import receipt
from test_span_fast_path import build
from soundpost.types import wall_clock_ns

class Acking:
    def send(self, batch, deadline): return Outcome('receipt', receipt(batch))
    def lookup(self, batch, deadline): return Outcome('not_found')
    def close(self): pass

ENVIRON = {'REQUEST_METHOD': 'GET', 'PATH_INFO': '/', 'wsgi.url_scheme': 'http'}

def wsgi_request(app, environ=None):
    """One WSGI request the way a server drives it: call, join the iterable, close it."""
    sent = []
    result = app(dict(environ or ENVIRON), lambda status, headers, exc_info=None: sent.append(status))
    try: body = b''.join(result)
    finally:
        close = getattr(result, 'close', None)
        if close is not None: close()
    return sent, body

def hello(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return [b'hello']

def test_random_ids_are_fetched_from_the_system_in_blocks(monkeypatch):
    calls = []
    real = os.urandom
    def counting(n):
        calls.append(n)
        return real(n)
    monkeypatch.setattr(os, 'urandom', counting)
    import soundpost.tracing as tracing
    monkeypatch.setattr(tracing, '_urandom', counting, raising=False)
    client = build()
    try:
        for _ in range(1000):
            with client.span('request'): pass
        assert len(client.buffered_records()) == 1000
        # trace id + span id + record id per span; one system call per identifier before, one per 256 identifiers now
        assert len(calls) <= 24, len(calls)
    finally:
        client.close()

def test_pooled_ids_are_well_formed_and_unique():
    from soundpost.ids import hex16, hex8
    wide = [hex16() for _ in range(3000)]
    narrow = [hex8() for _ in range(3000)]
    assert all(len(v) == 32 and re.fullmatch('[0-9a-f]{32}', v) and v != '0' * 32 for v in wide)
    assert all(len(v) == 16 and re.fullmatch('[0-9a-f]{16}', v) and v != '0' * 16 for v in narrow)
    assert len(set(wide)) == 3000 and len(set(narrow)) == 3000

@pytest.mark.skipif(not hasattr(os, 'fork'), reason='fork needed')
def test_a_forked_child_never_hands_out_an_id_its_parent_holds():
    from soundpost.ids import hex16, hex8
    hex16(); hex8()  # both pools are filled in the parent, so the child inherits unused identifiers
    read, write = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(read)
            os.write(write, ' '.join([hex16() for _ in range(40)] + [hex8() for _ in range(40)]).encode())
        finally:
            os._exit(0)
    os.close(write)
    data = b''
    while chunk := os.read(read, 65536): data += chunk
    os.close(read)
    os.waitpid(pid, 0)
    child = set(data.decode().split())
    assert len(child) == 80
    parent = {hex16() for _ in range(40)} | {hex8() for _ in range(40)}
    assert not child & parent

class CountingVariable:
    """A ContextVar stand-in that counts the traffic of one client's trace context."""
    def __init__(self, variable): self.variable, self.sets, self.resets = variable, 0, 0
    def get(self, *default): return self.variable.get(*default)
    def set(self, value):
        self.sets += 1
        return self.variable.set(value)
    def reset(self, token):
        self.resets += 1
        self.variable.reset(token)

def middleware(client, app):
    from soundpost.integrations.wsgi import WSGIMiddleware
    return WSGIMiddleware(app, client, operation='request')

def test_a_plain_wsgi_request_binds_the_trace_context_once():
    client = build(clock=wall_clock_ns)
    try:
        counting = CountingVariable(client._trace_context._value)
        client._trace_context._value = counting
        app = middleware(client, hello)
        for _ in range(5): wsgi_request(app)
        assert len(client.buffered_records()) == 5
        assert (counting.sets, counting.resets) == (5, 5), (counting.sets, counting.resets)
    finally:
        client.close()

@pytest.mark.parametrize('clock', [None, wall_clock_ns])
def test_wsgi_request_context_is_the_requests_own_and_is_restored(clock):
    from soundpost.context import TraceContext
    client = build(clock=clock)
    seen = []
    def probe(environ, start_response):
        seen.append(client._trace_context.current())
        start_response('200 OK', [])
        return [b'x']
    try:
        app = middleware(client, probe)
        ambient = TraceContext('9' * 32, '8' * 16)
        with client._trace_context.bind(ambient):
            wsgi_request(app)  # no traceparent: a new trace, the ambient context is not the parent
            wsgi_request(app, {**ENVIRON, 'HTTP_TRACEPARENT': '00-' + 'a' * 32 + '-' + 'b' * 16 + '-01'})
            assert client._trace_context.current() is ambient
        assert client._trace_context.current() is None
        fresh, inherited = seen
        assert fresh.trace_id != ambient.trace_id and len(fresh.span_id) == 16
        assert inherited.trace_id == 'a' * 32 and inherited.span_id != 'b' * 16
        records = [json.loads(text)['payload'] for text in client.buffered_records()]
        assert [r['parent_id'] for r in records] == [None, 'b' * 16]
        assert [r['trace_id'] for r in records] == [fresh.trace_id, 'a' * 32]
        assert [r['span_id'] for r in records] == [fresh.span_id, inherited.span_id]
        assert all(r['status'] == 'ok' and r['span_kind'] == 'server' for r in records)
    finally:
        client.close()

@pytest.mark.parametrize('clock', [None, wall_clock_ns])
def test_wsgi_outcomes_are_recorded_with_the_same_statuses(clock):
    client = build(clock=clock)
    def failing(environ, start_response):
        start_response('503 Unavailable', [])
        return [b'x']
    def raising(environ, start_response):
        raise ValueError('boom')
    def streaming(environ, start_response):
        start_response('200 OK', [])
        yield b'a'
        yield b'b'
    try:
        wsgi_request(middleware(client, failing))
        with pytest.raises(ValueError): wsgi_request(middleware(client, raising))
        result = middleware(client, streaming)(dict(ENVIRON), lambda status, headers, exc_info=None: None)
        assert next(iter(result)) == b'a'
        result.close()  # closed before exhaustion
        wsgi_request(middleware(client, streaming))
        spans = [json.loads(text) for text in client.buffered_records()]
        assert [s['payload']['status'] for s in spans if s['kind'] == 'span'] == ['error', 'error', 'incomplete', 'ok']
        assert sum(s['kind'] == 'error' for s in spans) == 1
        assert client._trace_context.current() is None
    finally:
        client.close()

def test_wsgi_with_a_custom_clock_still_records_inside_the_request_context():
    client = build(clock=lambda: '1731628800123456789')
    try:
        wsgi_request(middleware(client, hello))
        payload = json.loads(client.buffered_records()[0])['payload']
        assert payload['status'] == 'ok' and payload['start']['wall_ns'] == '1731628800123456789' and client._trace_context.current() is None
    finally:
        client.close()

def python_calls(fn):
    """Number of Python-level function calls `fn` makes."""
    count = [0]
    def profiler(frame, event, arg):
        if event == 'call': count[0] += 1
    sys.setprofile(profiler)
    try: fn()
    finally: sys.setprofile(None)
    return count[0]

def test_the_request_and_flush_paths_stay_within_their_python_call_budgets():
    """Python function calls are the stable proxy for the interpreter work behind the per-request CPU of the delivered-mode WSGI rows (fixtures/sdk/overhead.mjs):
    before wave 20 a plain request made 51 calls and each frozen batch 45; wave 20 brought them to 35 and 28 and wave 21 to 28 and 19.5 (no per-batch priority lambda, receipt
    validation, policy-expiry conversion or persist calls, stamps, clock reading and exporter gate read in place); the bounds leave two calls of headroom over the current values."""
    sent = []
    class Counting(Acking):
        def send(self, batch, deadline):
            sent.append(batch.id)
            return super().send(batch, deadline)
    from soundpost.types import wall_clock_ns as clock
    from test_span_fast_path import build as build_client
    client = build_client(clock=clock)
    client._delivery.transport = Counting()
    try:
        app = middleware(client, hello)
        for _ in range(50): wsgi_request(app)  # warm every cache and import
        client.flush(2.0)
        requests = 300
        per_request = python_calls(lambda: [wsgi_request(app) for _ in range(requests)]) / requests
        sent.clear()
        flush_calls = python_calls(lambda: client.flush(2.0))
        assert len(sent) > 30 and client._delivery.pending == 0
        per_batch = flush_calls / len(sent)
        assert per_request <= 30, per_request
        assert per_batch <= 22, per_batch
    finally:
        client.close()

def test_frozen_loss_record_carries_the_merged_count_not_a_cached_stale_wire_form():
    from soundpost.queue import DeliveryQueue
    from test_delivery import loss_settings, Ledger
    q = DeliveryQueue(loss_settings(), Ledger())
    assert q.record_signal_loss('span', 'policy', 5, '9007199254740993')
    assert q.record_signal_loss('span', 'policy', 7, '9007199254740994')  # merged into the entry already stored
    batch = q.freeze()[0]
    payload = json.loads(batch.body)['records'][0]['payload']
    assert payload['count'] == '12' and payload['end_ns'] == '9007199254740994'

def test_a_mixed_kind_batch_lists_its_kinds_sorted_and_carries_the_earliest_capture_time():
    from soundpost.queue import DeliveryQueue
    from test_delivery import settings, record, Ledger
    q = DeliveryQueue(settings(), Ledger())
    for index, kind in enumerate(('span', 'error', 'span', 'log')):
        assert q._append(record(f'{index + 1:032x}'), kind, 7)
    for entry, wall in zip(q._entries, (50.0, 40.0, 60.0, 45.0)): entry['wall'] = wall
    (batch,) = q.freeze()
    assert batch.count == 4 and batch.kinds == ('error', 'log', 'span') and batch.first_capture == 40.0 and batch.route_slot == 7
    assert batch.hash == hashlib.sha256(batch.body).hexdigest()

# ---- lane 4 wave 21: the delivered-mode warm path (D54). Each pin below failed on the wave-20 source and passes on the cheaper one.

def counted(monkeypatch, owner, name, raising=True):
    """Replaces `owner.name` (an instance method, a class method, a module function or a builtin looked up through a module) by a wrapper that counts its calls."""
    import builtins
    original = getattr(owner, name) if hasattr(owner, name) else getattr(builtins, name)
    def wrapper(*args, **kwargs):
        wrapper.calls += 1
        return original(*args, **kwargs)
    wrapper.calls = 0
    monkeypatch.setattr(owner, name, wrapper, raising=raising)
    return wrapper

def default_clock_client():
    client = build(clock=wall_clock_ns)
    client._delivery.transport = Acking()
    return client

def test_a_span_is_stored_with_its_wire_form_composed_not_cut_out_of_the_finished_text(monkeypatch):
    client = default_clock_client()
    try:
        queue = client._delivery
        cut = counted(monkeypatch, queue, '_wire')
        app = middleware(client, hello)
        for _ in range(20): wsgi_request(app)
        assert cut.calls == 0
        for entry in queue._entries:
            assert entry['wire'] == queue._wire(entry['text'])  # composed form == the cut of the stored text
            assert entry['text'].endswith(f',"policy_revision":"{queue.descriptor.policy_revision}"}}')
        assert len(queue._entries) == 20 and queue._bytes == sum(entry['size'] for entry in queue._entries)
    finally:
        client.close()

def test_a_span_enqueue_scans_for_expiry_only_when_something_can_have_expired(monkeypatch):
    client = default_clock_client()
    try:
        queue = client._delivery
        now = [1000.0]
        queue.now = lambda: now[0]
        scans = counted(monkeypatch, queue, '_expire')
        app = middleware(client, hello)
        for _ in range(10): wsgi_request(app)
        assert scans.calls == 0 and queue._lost == 0
        now[0] += 301  # the first entry is now older than the 300 s limit: the next enqueue must reach the scan and drop it
        wsgi_request(app)
        assert scans.calls == 1 and client.diagnostics().get('queue_expired') == 10 and len(queue._entries) == 1
    finally:
        client.close()

def test_the_span_route_slot_equals_the_slot_of_the_validated_route():
    from soundpost.routing import route_owner
    client = default_clock_client()
    try:
        queue = client._delivery
        for index in range(200):
            trace = hashlib.sha256(str(index).encode()).hexdigest()[:32]
            assert queue.enqueue_span('{"id":"%s","kind":"span","observed_at_ns":"1","payload":{}' % hashlib.sha256(trace.encode()).hexdigest()[:32], trace)
            assert queue._entries[-1]['slot'] == route_owner(queue._span_route, trace.encode())
    finally:
        client.close()

def entries_in_slots(queue, kinds, record):
    """One entry per route slot (slot index = position), appended straight to the queue."""
    for slot, kind in enumerate(kinds): assert queue._append(record(f'{slot + 1:032x}', kind), kind, slot)

def test_a_flush_of_single_record_batches_does_no_per_batch_set_up_work(monkeypatch):
    from soundpost import queue as queue_module
    from soundpost.queue import DeliveryQueue
    from test_delivery import settings, record, Ledger
    ledger = Ledger(); ledger.lost = False
    q = DeliveryQueue(settings(), ledger)
    entries_in_slots(q, ['span'] * 12, record)
    sorts = counted(monkeypatch, queue_module, 'sorted', raising=False)
    sums = counted(monkeypatch, queue_module, 'sum', raising=False)
    persists = counted(monkeypatch, q, 'persist')
    report = q.flush(2.0)
    assert len(report.receipts) == 12 and q.pending == 0 and q._bytes == 0 and q._batches == [] and q._entries == []
    assert sorts.calls <= 2   # the slots of the freeze and nothing per batch (was one sorted(set(...)) per batch)
    assert sums.calls == 0    # the removal of an acknowledged batch subtracts its recorded size (was a sum over every entry left)
    assert persists.calls == 0  # no spool: nothing to persist (was two calls per batch)

def test_the_byte_count_stays_exact_through_removal_of_mixed_batches_and_eviction():
    from soundpost.queue import DeliveryQueue
    from test_delivery import settings, record, Ledger
    ledger = Ledger(); ledger.lost = False
    q = DeliveryQueue(settings(), ledger)
    kinds = ['span', 'error', 'log', 'span', 'span', 'error']
    for index, kind in enumerate(kinds): assert q._append(record(f'{index + 1:032x}', kind), kind, index % 3)  # three slots, several records each
    batches = q.freeze()
    assert len(batches) == 3 and sum(batch.count for batch in batches) == 6
    assert q._bytes == sum(entry['size'] for entry in q._entries) == sum(state['bytes'] for state in q._batches)
    assert q._append(record('f' * 32, 'span'), 'span', 5)  # an entry that is not frozen yet
    q._remove(batches[1], 'queue_expired')
    assert q._bytes == sum(entry['size'] for entry in q._entries) and q._lost == batches[1].count and len(q._entries) == 5
    assert q.flush(2.0).pending == 0 and q._bytes == 0

def test_a_flush_sends_the_highest_priority_batch_first_and_keeps_the_arrival_order_within_a_priority():
    from soundpost.queue import DeliveryQueue
    from test_delivery import settings, record, Ledger
    class Order(Ledger):
        def send(self, batch, deadline):
            self.seen.append((batch.route_slot, batch.kinds))
            return Outcome('receipt', receipt(batch))
    ledger = Order(); ledger.seen = []; ledger.lost = False
    q = DeliveryQueue(settings(), ledger)
    for slot, kind in enumerate(['span', 'log', 'span', 'error', 'log', 'span', 'condition']): assert q._append(record(f'{slot + 1:032x}', kind), kind, slot)
    q.flush(2.0)
    assert [slot for slot, _ in ledger.seen] == [3, 6, 1, 4, 0, 2, 5]

def test_the_default_clock_policy_expiry_check_does_not_revalidate_the_clock_text(monkeypatch):
    from soundpost import queue as queue_module
    client = default_clock_client()
    try:
        validations = counted(monkeypatch, queue_module, 'unix_nano')
        app = middleware(client, hello)
        for _ in range(30): wsgi_request(app)
        assert client._delivery._policy_expired() is False
        assert client.flush(2.0).pending == 0
        assert validations.calls == 0
    finally:
        client.close()
    expired = build(clock=wall_clock_ns, expires='1731628800000000000')
    try:
        assert expired._delivery._policy_expired() is True
    finally:
        expired.close()
    custom = build(clock=lambda: 'not a time')  # a custom clock stays validated, and an unusable reading counts as expired
    try:
        assert custom._delivery._policy_expired() is True
    finally:
        custom.close()

def test_a_receipt_is_validated_once_for_each_value_it_brings(monkeypatch):
    from soundpost import transport
    from soundpost.queue import DeliveryQueue
    from test_delivery import settings, record, Ledger
    q = DeliveryQueue(settings(), Ledger())
    assert q._append(record(), 'error', 3)
    (batch,) = q.freeze()
    ids = counted(monkeypatch, transport, 'canonical_id')
    assert transport.verify_receipt(batch, receipt(batch), False)
    assert ids.calls == 1  # the cursor group; the batch id is the SDK's own and was compared for equality (was validated again: 2)
    for bad in ({'batch_id': 'f' * 32}, {'hash': '0' * 64}, {'cursor': {'group': 'G', 'index': '1'}}, {'cursor': {'group': '9' * 32, 'index': '0'}},
                {'retain_until_ns': '9223372036854775808'}, {'dedup_until_ns': '01'}, {'signal_deadlines': []}):
        assert not transport.verify_receipt(batch, {**receipt(batch), **bad}, False)

def test_unix_nano_int_is_the_integer_of_unix_nano_for_every_text():
    from soundpost.policy import unix_nano, unix_nano_int
    for text in ('0', '-1', '1', '9223372036854775807', '-9223372036854775808', '9223372036854775808', '-9223372036854775809', '01', '-0', '', '1.0', ' 1', '١', 5, None, b'1'):
        try: expected = int(unix_nano(text))
        except ValueError: expected = ValueError
        try: actual = unix_nano_int(text)
        except ValueError: actual = ValueError
        assert actual == expected, text

def test_the_default_clock_span_stamps_and_exporter_gate_are_read_in_place(monkeypatch):
    from soundpost.context import ContextState
    from soundpost.tracing import SpanContextManager
    client = default_clock_client()
    try:
        stamps = counted(monkeypatch, SpanContextManager, '_stamp')
        gates = counted(monkeypatch, ContextState, 'is_exporting')
        reads = counted(monkeypatch, type(client), '_read_clock')
        app = middleware(client, hello)
        for _ in range(10): wsgi_request(app)
        assert stamps.calls == 0 and gates.calls == 0 and reads.calls == 0 and len(client._delivery._entries) == 10
        with client._trace_context.exporting():  # a record captured while the exporter runs is still refused
            wsgi_request(app)
        assert len(client._delivery._entries) == 10 and client.diagnostics()['exporter_recursion'] == 1
    finally:
        client.close()

def test_the_wsgi_stamps_of_a_custom_clock_still_go_through_the_validating_reader(monkeypatch):
    from soundpost.tracing import SpanContextManager
    client = build(clock=lambda: '1731628800123456789')
    try:
        stamps = counted(monkeypatch, SpanContextManager, '_stamp')
        reads = counted(monkeypatch, type(client), '_read_clock')
        wsgi_request(middleware(client, hello))
        assert stamps.calls == 2 and reads.calls == 3  # start, end and the record's own observation, each through the validating reader
    finally:
        client.close()
