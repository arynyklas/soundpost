# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import base64
import json
from dataclasses import replace
import pytest
from test_policy import config, KEY, b64
from soundpost import init, SignedPolicy
from test_integrations import client

def signed(**changes):
    original=config(operations=('request',))
    payload=json.loads(base64.urlsafe_b64decode(original.policy.payload+'='*(-len(original.policy.payload)%4)))
    payload.update(changes)
    raw=json.dumps(payload,sort_keys=True,separators=(',',':')).encode()
    return replace(original,policy=SignedPolicy(1,'Ed25519','test',b64(raw),b64(KEY.sign(raw))))

def test_old_policy_cannot_authorize_trace_or_jobs_via_errors():
    instance=init(config(operations=('request',)))
    try:
        assert instance.policy_decision.errors
        assert not instance.policy_decision.traces and not instance.policy_decision.jobs and not instance.policy_decision.loss
        with instance.span('request'): instance.capture_exception(ValueError('PRIVATE'))
        records=[json.loads(value) for value in instance.buffered_records()]
        assert [record['kind'] for record in records]==['error']
    finally: instance.close()

@pytest.mark.parametrize('value',[None,0,1,'true',[],{}])
def test_trace_job_bits_are_strict_signed_booleans(value):
    for field in ('traces','jobs','loss'):
        with pytest.raises(ValueError,match='invalid signed policy'):init(signed(**{field:value}))

def test_deployment_denial_intersects_actual_signed_permission():
    instance=init(replace(signed(traces=True,jobs=True,loss=True),deployment_traces=False,deployment_jobs=False,deployment_loss=False))
    try:
        assert not instance.policy_decision.traces and not instance.policy_decision.jobs and not instance.policy_decision.loss
        assert instance.policy_decision.errors
    finally: instance.close()

def test_closed_span_dto_rejects_unknown_attributes_and_bad_clocks(client):
    from soundpost.policy import normalize_span
    with client.span('request'): pass
    record=json.loads(client.buffered_records()[0])['payload']
    with pytest.raises(ValueError):normalize_span({**record,'raw_url':'PRIVATE'})
    with pytest.raises(ValueError):normalize_span({**record,'end':{**record['end'],'mono_ns':'0'}})
    with pytest.raises(ValueError):normalize_span({**record,'sample_probability':'7ff8000000000000'})
    assert normalize_span(record)==record

def test_client_owned_exporter_context_resets_after_failure(client):
    with pytest.raises(RuntimeError):
        with client._trace_context.exporting():
            with client.span('request'): client.capture_exception(ValueError('PRIVATE'))
            raise RuntimeError('PRIVATE')
    assert not client.buffered_records()
    assert not client._trace_context.is_exporting()
    with client.span('request'): pass
    assert len(client.buffered_records())==1

def test_span_normalizer_does_not_compare_or_render_hostile_values(client):
    from soundpost.policy import normalize_span
    class Trap:
        def __eq__(self, other):raise AssertionError('arbitrary equality executed')
        def __str__(self):raise AssertionError('arbitrary rendering executed')
        def __repr__(self):raise AssertionError('arbitrary rendering executed')
    with client.span('request'):pass
    payload=json.loads(client.buffered_records()[0])['payload']
    for field in ('status','span_kind','sample_decision','operation','dependency_alias','sample_probability','trace_id','span_id'):
        with pytest.raises(ValueError):normalize_span({**payload,field:Trap()})

def test_native_sampling_loss_is_frozen_and_receipt_acknowledged():
    from test_delivery import Ledger
    from soundpost.context import TraceContext
    ledger=Ledger();ledger.lost=False
    instance=init(replace(signed(traces=True,loss=True),transport=ledger))
    try:
        with instance._trace_context.bind(TraceContext('a'*32,'b'*16,False,0.25)):
            with instance.span('request'):pass
            with instance.span('request'):instance.capture_exception(ValueError('PRIVATE'))
        report=instance.flush(1)
        assert report.pending==0 and report.receipts
        records=[record for body in ledger.sends for record in json.loads(body)['records']]
        losses=[record['payload'] for record in records if record['kind']=='loss']
        assert len(losses)==1
        loss=losses[0]
        assert loss['signal']=='span' and loss['reason']=='policy' and loss['count']=='2'
        assert loss['source']=='3'*32
        assert len(loss['producer'])==32 and loss['producer']!='0'*32
        assert len(loss['producer_epoch'])==32 and loss['producer_epoch']!='0'*32
        assert int(loss['start_ns'])<=int(loss['end_ns'])
        assert len([record for record in records if record['kind']=='error'])==1
        assert not [record for record in records if record['kind']=='span']
        assert instance.diagnostics()['trace_sampled_out']==2
    finally:instance.close()

def test_local_sampling_diagnostics_cannot_grant_native_loss():
    from test_delivery import Ledger
    from soundpost.context import TraceContext
    ledger=Ledger();ledger.lost=False
    instance=init(replace(signed(traces=True,loss=False),transport=ledger))
    try:
        with instance._trace_context.bind(TraceContext('a'*32,'b'*16,False)):
            with instance.span('request'):pass
        instance.flush(1)
        assert instance.diagnostics()['trace_sampled_out']==1
        assert not ledger.sends
    finally:instance.close()

def test_native_loss_cannot_bypass_expiry_exporter_or_close():
    from test_delivery import Ledger
    from soundpost.context import TraceContext
    for boundary in ('expired','exporter','closed'):
        ledger=Ledger();ledger.lost=False
        settings=replace(signed(traces=True,loss=True),transport=ledger)
        if boundary=='expired':settings=replace(settings,clock_ns=lambda:'9223372036854775807')
        instance=init(settings)
        try:
            if boundary=='closed':instance.close()
            with instance._trace_context.bind(TraceContext('a'*32,'b'*16,False,0.0)):
                if boundary=='exporter':
                    with instance._trace_context.exporting():
                        with instance.span('request'):pass
                else:
                    with instance.span('request'):pass
            assert not instance.buffered_records()
            instance.flush(0)
            assert not ledger.sends
        finally:instance.close()

def test_uncalibrated_clock_cannot_claim_known_cross_domain_wall_order():
    instance=init(signed(traces=True))
    try:
        with instance.span('request'):pass
        span=json.loads(instance.buffered_records()[0])['payload']
        for stamp in (span['start'],span['end']):
            wall,uncertainty=int(stamp['wall_ns']),int(stamp['uncertainty_ns'])
            assert max(-9223372036854775808,wall-uncertainty)==-9223372036854775808
            assert min(9223372036854775807,wall+uncertainty)==9223372036854775807
            assert stamp['wall_ns']=='9007199254740993'
        assert int(span['end']['mono_ns'])>=int(span['start']['mono_ns'])
    finally:instance.close()

def test_explicit_trusted_clock_uncertainty_and_wall_source_are_preserved():
    instance=init(replace(signed(traces=True),clock_ns=lambda:'-17',clock_uncertainty_ns='42'))
    try:
        with instance.span('request'):pass
        record=json.loads(instance.buffered_records()[0])
        assert record['observed_at_ns']=='-17'
        for stamp in (record['payload']['start'],record['payload']['end']):
            assert stamp['wall_ns']=='-17' and stamp['uncertainty_ns']=='42'
    finally:instance.close()

@pytest.mark.parametrize('value',[0,True,None,'-1','01','18446744073709551616','1.0'])
def test_clock_uncertainty_requires_exact_canonical_uint64(value):
    with pytest.raises(ValueError,match='invalid uint64'):init(replace(signed(traces=True),clock_uncertainty_ns=value))

def test_invalid_span_wall_clock_keeps_original_exception_and_resets_context():
    instance=init(replace(signed(traces=True),clock_ns=lambda:'not-a-clock'))
    original=ValueError('PRIVATE')
    try:
        with pytest.raises(ValueError) as raised:
            with instance.span('request'):raise original
        assert raised.value is original
        assert instance._trace_context.current() is None
        assert not instance.buffered_records()
        assert instance.diagnostics()['span_clock_unavailable']==1
    finally:instance.close()
