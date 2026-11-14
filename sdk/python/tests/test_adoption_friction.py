# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Adoption friction regressions: bounded close, span status API, capture_handled, code diagnostics, span kinds, class names."""
import json
import time
import warnings
import pytest
from test_policy import config
from test_delivery import Ledger, settings
from test_integrations import client  # noqa: F401  (traces-enabled client fixture)
from test_transport_retry import ingest, delivery  # noqa: F401
from soundpost import init, FlushReport
from soundpost.transport import Outcome

def kinds(instance):return [json.loads(value) for value in instance.buffered_records()]
def last(instance):return json.loads(instance.buffered_records()[-1])['payload']

# 1. Bounded flush / explicit close -----------------------------------------------------------

class Silent:
    """Transport that never produces a receipt: every send/lookup is ambiguous."""
    def send(self,batch,deadline):return Outcome('ambiguous')
    def lookup(self,batch,deadline):return Outcome('ambiguous')
    def close(self):pass

def test_close_without_delivery_reports_loss_explicitly_instead_of_silently_dropping():
    instance=init(settings(transport=Silent()));instance.capture_exception(ValueError('SECRET'))
    with pytest.warns(RuntimeWarning,match=r'1 undelivered record'):
        report=instance.close(timeout=.3)
    assert type(report) is FlushReport
    assert report.dropped==1 and report.pending==1 and report.receipts==() and report.lost>=1
    assert instance.diagnostics()['closed_pending']==1 and instance.buffered_records()==()
    assert instance.close() is report  # idempotent: the first loss report stays authoritative

def test_close_flushes_buffered_records_with_its_own_bounded_deadline_and_stays_quiet():
    ledger=Ledger();instance=init(settings(transport=ledger));instance.capture_exception(ValueError('SECRET'))
    first=instance.flush(.01)
    assert first.pending==1 and first.receipts==()  # in-flight send lost: ambiguous, nothing acknowledged
    with warnings.catch_warnings():
        warnings.simplefilter('error')
        report=instance.close(timeout=3)
    assert report.dropped==0 and report.pending==0 and len(report.receipts)==1 and ledger.admitted==1
    assert instance.diagnostics().get('closed_pending',0)==0

def test_close_rejects_invalid_timeout_without_closing():
    ledger=Ledger();ledger.lost=False;instance=init(settings(transport=ledger));instance.capture_exception(ValueError('SECRET'))
    for bad in (-1,float('nan'),float('inf'),'2'):
        with pytest.raises(ValueError):instance.close(timeout=bad)
    assert len(instance.buffered_records())==1
    assert instance.close().receipts

def test_close_with_spool_retains_encrypted_work_and_reports_zero_dropped(tmp_path):
    from soundpost.spool import EncryptedSpool
    from test_delivery import DESCRIPTOR
    spool=EncryptedSpool(tmp_path/'spool.bin',bytes(range(32)),DESCRIPTOR,'1')
    instance=init(settings(transport=Silent(),spool=spool));instance.capture_exception(ValueError('SECRET'))
    with warnings.catch_warnings():
        warnings.simplefilter('error')
        report=instance.close(timeout=.2)
    assert report.dropped==0 and report.pending==1

def test_flush_deadline_covers_first_connection_setup_and_response(ingest):
    """A slow first TLS handshake plus a silent peer must not let flush overshoot its own deadline."""
    original=ingest.server.get_request
    def slow_accept():
        time.sleep(.8);return original()
    ingest.server.get_request=slow_accept
    handler=ingest.server.RequestHandlerClass;post=handler.do_POST
    handler.do_POST=lambda self:time.sleep(4)
    try:
        ingest.script=[(200,{})]
        q=delivery(ingest)
        from test_delivery import record
        q.enqueue(record());started=time.monotonic();report=q.flush(1.0);elapsed=time.monotonic()-started
        assert report.pending==1 and report.deadline_exceeded and report.receipts==()
        assert elapsed<1.45,elapsed
    finally:
        handler.do_POST=post
        ingest.server.get_request=original

def test_fresh_process_first_flush_with_slow_first_response_delivers_within_deadline(ingest):
    """A cold first response slower than the connection timeout used to be abandoned; a deadline-sized flush must deliver it."""
    handler=ingest.server.RequestHandlerClass;post=handler.do_POST;first=[True]
    def cold(self):
        if first[0]:first[0]=False;time.sleep(1.0)
        post(self)
    handler.do_POST=cold
    try:
        ingest.script=[(200,{})]
        q=delivery(ingest)
        from test_delivery import record
        q.enqueue(record());report=q.flush(5.0)
        assert report.pending==0 and len(report.receipts)==1 and not report.deadline_exceeded
    finally:handler.do_POST=post

# 2. Span error API ---------------------------------------------------------------------------

def test_span_set_error_and_set_status_are_supported_public_api(client):
    with client.span('request') as span:
        assert span.status=='ok'
        span.set_error()
        assert span.status=='error'
    assert last(client)['status']=='error'
    with client.span('request') as span:
        span.set_error();span.set_status('ok')
    assert last(client)['status']=='ok'
    with client.span('request') as span:span.set_status('error')
    assert last(client)['status']=='error'

def test_span_set_status_is_closed_vocabulary_and_scope_bound(client):
    span=client.span('request')
    span.set_error();assert span.status=='error'  # allowed before entry
    for bad in ('cancelled','incomplete','','ERROR',None,1):
        with pytest.raises(ValueError):span.set_status(bad)
    with span:pass
    assert last(client)['status']=='error'
    with pytest.raises(RuntimeError):span.set_error()  # after exit nothing would be recorded

def test_exception_outcome_overrides_explicit_ok_and_cancel_is_untouched(client):
    with pytest.raises(KeyError):
        with client.span('request') as span:
            span.set_status('ok');raise KeyError('x')
    assert last(client)['status']=='error'

def test_asgi_and_wsgi_adapters_use_the_public_error_setter():
    import inspect
    from soundpost.integrations import asgi,wsgi
    assert 'span.status =' not in inspect.getsource(asgi) and "span.status = 'error'" not in inspect.getsource(wsgi)

# 3. capture_handled --------------------------------------------------------------------------

def test_capture_handled_equals_episode_dance_in_one_call():
    instance=init(config(operations=('db.execute',)))
    event=instance.capture_handled(ValueError('SECRET'),code='db.execute')
    episode=instance.begin_handling_episode()
    try:other=episode.capture_exception(ValueError('SECRET'),code='db.execute')
    finally:episode.close()
    first,second=kinds(instance)
    assert event!=other and first['id']==event and second['id']==other
    assert first['payload']=={**second['payload'],'occurrence_id':event}
    assert first['payload']['handled'] is True and first['payload']['mechanism']=='manual' and first['payload']['code']=='db.execute'
    assert 'SECRET' not in str(instance.buffered_records())

def test_capture_handled_links_current_span_and_is_one_occurrence_per_call(client):
    error=ValueError('SECRET')
    with client.span('request'):
        first=client.capture_handled(error);second=client.capture_handled(error)
    errors=[r for r in kinds(client) if r['kind']=='error']
    assert first!=second and [r['id'] for r in errors]==[first,second]
    assert all('trace_id' in r['payload'] and 'span_id' in r['payload'] for r in errors)

def test_capture_handled_after_close_is_counted_not_raised():
    instance=init(config());instance.close()
    assert type(instance.capture_handled(ValueError('x')))==str and instance.diagnostics()['closed']==1

# 4. Unregistered error codes are observable --------------------------------------------------

def test_unregistered_code_is_counted_and_dropped_never_exported():
    instance=init(config(operations=('db.execute',)))
    instance.capture_exception(ValueError('x'),code='db.execute')
    assert 'unregistered_code' not in instance.diagnostics()
    instance.capture_exception(ValueError('x'),code='free text with SECRET value')
    instance.capture_handled(ValueError('x'),code='not-registered')
    episode=instance.begin_handling_episode()
    try:episode.capture_exception(ValueError('x'),code=12345)
    finally:episode.close()
    instance.capture_exception(ValueError('x'))
    codes=[r['payload']['code'] for r in kinds(instance)]
    assert codes==['db.execute',None,None,None,None]
    assert instance.diagnostics()['unregistered_code']==3
    assert 'SECRET' not in str(instance.diagnostics()) and 'SECRET' not in str(instance.buffered_records())

# 5. span kind --------------------------------------------------------------------------------

@pytest.mark.parametrize('kind',['internal','server','client','producer','consumer'])
def test_client_span_accepts_every_integration_kind(client,kind):
    with client.span('request',kind=kind):pass
    assert last(client)['span_kind']==kind

def test_client_span_defaults_internal_and_rejects_unknown_kind(client):
    with client.span('request'):pass
    assert last(client)['span_kind']=='internal'
    for bad in ('Server','',None,3,'http'):
        with pytest.raises(ValueError):client.span('request',kind=bad)

def test_client_span_kind_is_keyword_only_and_dependency_still_works(client):
    with client.span('http.call',dependency='dependency',kind='client'):pass
    payload=last(client)
    assert payload['span_kind']=='client' and payload['dependency_alias']=='dependency'
    with pytest.raises(TypeError):client.span('request','dependency','client')

# 6. Exception class names --------------------------------------------------------------------

def test_exception_class_with_custom_metaclass_keeps_its_name():
    """asyncpg-style exception hierarchies use a type subclass as metaclass; the class name is still safe to emit."""
    class Meta(type):pass
    class UndefinedTableError(Exception,metaclass=Meta):pass
    instance=init(config());instance.capture_exception(UndefinedTableError('SECRET relation "users" does not exist'))
    payload=last(instance)
    assert payload['exception_class']=='UndefinedTableError' and 'SECRET' not in str(instance.buffered_records())
    assert payload['exception_graph']['reasons']==['project_root_unconfigured']

def test_hostile_metaclass_name_and_attribute_hooks_are_never_invoked():
    class Meta(type):
        @property
        def __name__(cls):raise AssertionError('metaclass __name__ invoked')
        def __getattribute__(cls,name):raise AssertionError('metaclass getattr invoked')
    class Boom(Exception,metaclass=Meta):pass
    instance=init(config());instance.capture_exception(Boom('SECRET'))
    assert last(instance)['exception_class']=='Boom'

@pytest.mark.parametrize('name',['Ошибка','X'*129,'Not Ident','1bad'])
def test_unsafe_class_name_is_replaced_with_a_recorded_reason(name):
    error_type=type(name,(Exception,),{})
    instance=init(config());instance.capture_exception(error_type('SECRET'))
    payload=last(instance)
    assert payload['exception_class']=='UnknownError'
    assert 'foreign_or_custom_error_class' in payload['exception_graph']['reasons']
    assert name not in str(instance.buffered_records())

def test_safe_custom_class_names_carry_no_replacement_reason():
    class AppSpecificError(Exception):pass
    instance=init(config());instance.capture_exception(AppSpecificError('x'))
    payload=last(instance)
    assert payload['exception_class']=='AppSpecificError' and 'foreign_or_custom_error_class' not in payload['exception_graph']['reasons']
