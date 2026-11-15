# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""The span record composed by the SDK, the batch bytes derived from stored text and the expiry shortcut equal the validated, re-parsing implementations they replaced."""
import base64
import dataclasses
import hashlib
import json
import struct
import pytest
from soundpost import init, SignedPolicy
from soundpost.context import TraceContext
from soundpost.policy import normalize_record
from soundpost.queue import DeliveryQueue
from soundpost.routing import native_canonical, route_record, route_prefix, route_owner
from soundpost.wire import parse_safe_record
from test_policy import config, KEY, b64
from soundpost.transport import Outcome
from test_delivery import settings, record, Ledger, DESCRIPTOR, receipt

class Acking:
    def send(self, batch, deadline): return Outcome('receipt', receipt(batch))
    def lookup(self, batch, deadline): return Outcome('not_found')
    def close(self): pass

def build(clock=None, expires=None, **document):
    original = config(operations=('request', 'http.call', 'db.execute'), dependencies=('dependency', 'postgres'), origins=('dependency',), transport=Acking(), **({'clock_ns': clock} if clock else {}))
    body = json.loads(base64.urlsafe_b64decode(original.policy.payload + '=' * (-len(original.policy.payload) % 4)))
    body.update(traces=True, jobs=False)
    body.update(document)
    if expires is not None: body['expires_ns'] = expires
    payload = json.dumps(body, sort_keys=True, separators=(',', ':')).encode()
    return init(dataclasses.replace(original, policy=SignedPolicy(1, 'Ed25519', 'test', b64(payload), b64(KEY.sign(payload)))))

def validated_text(client, text):
    """What the validated path (`normalize_record`: normalize_span, then the canonical dump) makes of the same span fields."""
    parsed = json.loads(text)
    out, reason = normalize_record(client._policy, {'kind': 'span', 'id': parsed['id'], 'observed_at_ns': parsed['observed_at_ns'], 'payload': parsed['payload']}, {})
    assert reason is None
    return out

CLOCKS = [lambda: '9007199254740993', lambda: '0', lambda: '-9223372036854775808', lambda: '1731628800123456789']
PARENTS = [None, TraceContext('a' * 32, 'b' * 16), TraceContext('c' * 32, 'd' * 16, False, 1.0), TraceContext('e' * 32, 'f' * 16, True, 0.25), TraceContext('1' * 32, '2' * 16, True, 0.0), TraceContext('3' * 32, '4' * 16, True, 1)]

@pytest.mark.parametrize('clock', CLOCKS)
@pytest.mark.parametrize('parent', PARENTS)
@pytest.mark.parametrize('shape', [('request', None, 'server', 'ok'), ('http.call', 'dependency', 'client', 'error'), ('db.execute', 'postgres', 'client', 'incomplete'), ('request', None, 'internal', 'cancelled'), ('request', 'dependency', 'producer', 'ok'), ('request', None, 'consumer', 'ok')])
def test_composed_span_equals_the_validated_record(clock, parent, shape):
    operation, dependency, kind, status = shape
    client = build(clock=clock)
    try:
        with client._trace_context.bind(parent):
            with client.span(operation, dependency=dependency, kind=kind) as span:
                if status == 'error': span.set_error()
                if status == 'incomplete': span.status = 'incomplete'
                if status == 'cancelled': span.status = 'cancelled'
        kept = client.buffered_records()
        if parent is not None and not parent.sampled:
            assert kept == () and client.diagnostics()['trace_sampled_out'] == 1
            return
        assert len(kept) == 1
        text = kept[0]
        assert text == validated_text(client, text)
        stored = parse_safe_record(text)
        assert stored['payload']['status'] == status and stored['payload']['span_kind'] == kind and stored['payload']['dependency_alias'] == (dependency or '')
        assert stored['payload']['parent_id'] == (parent.span_id if parent else None)
        assert stored['payload']['trace_id'] == (parent.trace_id if parent else stored['payload']['trace_id'])
        assert stored['observed_at_ns'] == clock()
        payload = stored['payload']
        assert payload['start']['wall_ns'] == clock() and payload['end']['wall_ns'] == clock() and int(payload['end']['mono_ns']) >= int(payload['start']['mono_ns'])
        assert payload['start']['domain'] == payload['end']['domain'] == client._trace_domain and payload['start']['uncertainty_ns'] == client._trace_uncertainty
        assert payload['sample_probability'] == struct.pack('>d', parent.sample_probability if parent else 1.0).hex() and payload['sample_decision'] == 'keep' and payload['links'] == []
        assert payload['span_id'] != (parent.span_id if parent else None) and len(payload['span_id']) == 16
        # the batch route is the one route_record computes for the finished record
        assert client._delivery._entries[0]['slot'] == route_record(text, client._delivery.descriptor, client._delivery.producer)
    finally:
        client.close()

def test_route_owner_equals_route_record_for_every_trace_shape():
    descriptor = DESCRIPTOR
    producer = '5' * 32
    prefix = route_prefix(descriptor, 'span')
    slots = set()
    for index in range(300):
        trace = hashlib.sha256(str(index).encode()).hexdigest()[:32]
        text = json.dumps({'kind': 'span', 'id': '8' * 32, 'observed_at_ns': '1', 'policy_revision': '1', 'payload': {'trace_id': trace}})
        slot = route_owner(prefix, trace.encode())
        assert slot == route_record(text, descriptor, producer)
        slots.add(slot)
    assert len(slots) > 32

def test_unusable_span_fields_are_refused_like_the_validated_path():
    client = build()
    try:
        with client.span('request') as span: span.status = 'bogus'
        with client.span('request') as span: span.kind = 'sideways'
        with client.span('request') as span: span.status = ['ok']
        assert client.buffered_records() == () and client.diagnostics()['invalid_span'] == 3
        with client.span('request'): pass
        assert len(client.buffered_records()) == 1
    finally:
        client.close()

def test_span_admission_gates_match_the_validated_path():
    expired = build(clock=lambda: '9223372036854775807')
    disabled = build(traces=False)
    try:
        with expired.span('request'): pass
        assert expired.buffered_records() == () and expired.diagnostics()['policy_expired'] == 1
        with disabled.span('request'): pass
        assert disabled.buffered_records() == () and disabled.diagnostics()['policy_disabled'] == 1
        expired.close(); assert expired.diagnostics().get('closed', 0) == 0
        with expired.span('request'): pass
        assert expired.diagnostics()['closed'] == 1
    finally:
        expired.close(); disabled.close()

def test_trusted_trace_context_equals_the_validated_one_and_stays_frozen():
    made = TraceContext.trusted('a' * 32, 'b' * 16, False, 0.5)
    assert made == TraceContext('a' * 32, 'b' * 16, False, 0.5) and hash(made) == hash(TraceContext('a' * 32, 'b' * 16, False, 0.5))
    with pytest.raises(dataclasses.FrozenInstanceError): made.span_id = 'c' * 16
    with pytest.raises(ValueError): TraceContext('a' * 31, 'b' * 16)

def legacy_batches(queue, entries):
    """The batches the pre-surgery freeze built: re-parse every stored text, drop policy_revision, add the resource, canonical dump; header by canonical dump."""
    result = []
    by_slot = {}
    for entry in entries: by_slot.setdefault(entry['slot'], []).append(entry)
    for slot in sorted(by_slot):
        def header(batch_id):
            return native_canonical(dict(version=1, project=queue.descriptor.project, source=queue.descriptor.source, producer=queue.producer, id=batch_id, policy_revision=queue.descriptor.policy_revision, route_slot=slot, records=[]))
        selected, wire, size = [], [], 0
        groups = []
        for entry in by_slot[slot]:
            parsed = parse_safe_record(entry['text']); parsed.pop('policy_revision'); parsed['resource'] = queue.resource
            encoded = native_canonical(parsed)
            if len(selected) == 512 or len(header('0' * 32)) + size + len(encoded) + len(selected) > 1048576:
                groups.append(wire); selected, wire, size = [], [], 0
            selected.append(entry); wire.append(encoded); size += len(encoded)
        groups.append(wire)
        result.append((slot, [header('0' * 32).replace(b'"records":[]', b'"records":[' + b','.join(w) + b']', 1) for w in groups]))
    return result

def test_batch_bytes_equal_the_reparsing_implementation():
    q = DeliveryQueue(settings(), Ledger())
    trace = 'a' * 32
    for index in range(513):
        text = json.dumps({'kind': 'span', 'id': f'{index + 1:032x}', 'observed_at_ns': '9007199254740993', 'policy_revision': '1',
                           'payload': {'trace_id': trace, 'span_id': f'{index + 1:016x}', 'parent_id': None, 'span_kind': 'server', 'operation': 'request', 'start': {'wall_ns': '1', 'mono_ns': '1', 'uncertainty_ns': '0', 'domain': {'host': '1' * 32, 'boot': '2' * 32, 'runtime': '3' * 32}},
                                        'end': {'wall_ns': '2', 'mono_ns': '2', 'uncertainty_ns': '0', 'domain': {'host': '1' * 32, 'boot': '2' * 32, 'runtime': '3' * 32}}, 'status': 'ok', 'dependency_alias': '', 'links': [], 'sample_probability': '3ff0000000000000', 'sample_decision': 'keep'}}, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        assert q.enqueue(text)
    tricky = ['Ér\u2028ror', 'x,"policy_revision":"9"', 'tail\\', 'quote"\\"']
    for index, name in enumerate(tricky):
        value = json.loads(record(f'{index + 900:032x}'))
        value['payload']['exception_class'] = name
        assert q.enqueue(json.dumps(value, ensure_ascii=False))
    before = [dict(slot=e['slot'], text=e['text']) for e in q._entries]
    batches = q.freeze()
    expected = [body for _slot, bodies in legacy_batches(q, before) for body in bodies]
    # legacy bytes carry a placeholder id: restore each batch's real id before comparing
    actual = [b.body for b in batches]
    assert len(actual) == len(expected)
    for batch, body in zip(batches, expected):
        assert batch.body == body.replace(b'"id":"' + b'0' * 32 + b'"', b'"id":"' + batch.id.encode() + b'"', 1)
        assert batch.hash == hashlib.sha256(batch.body).hexdigest()
    assert max(b.count for b in batches) == 512 and sum(b.count for b in batches) == 513 + len(tricky)
    assert any('\u2028'.encode() not in b.body and b'\\u2028' in b.body for b in batches)

def test_entries_expire_exactly_at_the_age_limit_after_the_scan_shortcut():
    now = [0.0]
    q = DeliveryQueue(settings(), Ledger(), monotonic=lambda: now[0])
    assert q.enqueue(record('1' * 32))
    now[0] = 100.0
    assert q.enqueue(record('2' * 32))
    now[0] = 299.9
    assert q.pending == 2 and q.diagnostics().get('queue_expired', 0) == 0
    now[0] = 300.0
    assert q.pending == 1 and q.diagnostics()['queue_expired'] == 1
    now[0] = 399.9
    assert q.pending == 1
    now[0] = 400.0
    assert q.pending == 0 and q.diagnostics()['queue_expired'] == 2
    assert q.enqueue(record('3' * 32)) and q.pending == 1
