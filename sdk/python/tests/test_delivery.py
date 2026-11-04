# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
"""Delivery regressions: false ACK, mutable retries, lane overlap and plaintext recovery."""
import base64
import json
import hashlib
import threading
from dataclasses import replace
from pathlib import Path
import pytest
from test_policy import config, ORG, PROJECT, SOURCE, BUILD
from soundpost import init, Resource, RoutingDescriptor
from soundpost.queue import DeliveryQueue, retry_delay
from soundpost.routing import route_record, owner_key, native_canonical
from soundpost.transport import Outcome, verify_receipt
from soundpost.spool import EncryptedSpool

RESOURCE=Resource('6'*32,'7'*32,BUILD,'worker-1')
DESCRIPTOR=RoutingDescriptor(1,ORG,PROJECT,SOURCE,1,64,'1')
def settings(**changes):
    values=dict(resource=RESOURCE,descriptor=DESCRIPTOR);values.update(changes);return replace(config(),**values)
def record(identity='8'*32,kind='error'):
    return json.dumps({'kind':kind,'id':identity,'observed_at_ns':'9007199254740993','policy_revision':'1','payload':{'occurrence_id':identity,'exception_class':'Error','code':None,'build_id':BUILD,'handled':True,'fatal':False,'mechanism':'manual','frames':[]}},separators=(',',':'))
def receipt(batch,historical=False):
    return {'version':1,'batch_id':batch.id,'hash':batch.hash,'cursor':{'group':'9'*32,'index':'9007199254740993'},'retain_until_ns':'9007199254740994','signal_deadlines':[{'kind':k,'retain_until_ns':'9007199254740994'} for k in batch.kinds],'dedup_until_ns':'9007199254740995',**({'historical':True} if historical else {})}
class Ledger:
    def __init__(self): self.rows={};self.admitted=0;self.sends=[];self.lookups=0;self.lost=True;self.revoked=False;self.restricted=False
    def send(self,batch,deadline):
        self.sends.append(batch.body)
        if self.revoked:return Outcome('denied')
        if self.restricted:return Outcome('terminal')
        key=(batch.producer,batch.route_slot,batch.id)
        old=self.rows.get(key)
        if old and old['hash']!=batch.hash:return Outcome('terminal')
        if not old:self.rows[key]=receipt(batch);self.admitted+=1
        if self.lost:self.lost=False;return Outcome('ambiguous')
        return Outcome('receipt',self.rows[key])
    def lookup(self,batch,deadline):
        self.lookups+=1
        if self.revoked:return Outcome('denied')
        old=self.rows.get((batch.producer,batch.route_slot,batch.id))
        return Outcome('receipt',{**old,'historical':True}) if old else Outcome('not_found')
    def close(self):pass

def queue(transport,**changes):return DeliveryQueue(settings(),transport,**changes)

def test_lost_commit_uses_historical_lookup_before_expired_policy_and_does_not_reappend():
    ledger=Ledger();q=queue(ledger);q.enqueue(record());first=q.flush(0.01)
    assert first.pending==1 and first.acknowledged_batch_ids==()
    ledger.restricted=True
    result=q.flush(1)
    assert result.pending==0 and result.acknowledged_cursors==('99999999999999999999999999999999:9007199254740993',)
    assert result.receipts[0]['historical'] is True and ledger.admitted==1 and len(ledger.sends)==1 and ledger.lookups==1

def test_invalid_receipt_cannot_drain_and_revoked_source_stops_export():
    ledger=Ledger();ledger.lost=False
    original=ledger.send
    def invalid(batch,deadline):
        outcome=original(batch,deadline);return Outcome('receipt',{**outcome.receipt,'hash':'0'*64})
    ledger.send=invalid;q=queue(ledger);q.enqueue(record())
    assert q.flush(.01).pending==1
    ledger.revoked=True
    assert q.flush(1).pending==1
    calls=len(ledger.sends);q.flush(.01);assert len(ledger.sends)==calls

def test_receipt_requires_cursor_exact_kinds_and_minimum_deadline():
    ledger=Ledger();q=queue(ledger);q.enqueue(record());batch=q.freeze()[0];good=receipt(batch)
    assert verify_receipt(batch,good,False)
    for bad in ({**good,'cursor':{'group':'9'*32,'index':'0'}},{**good,'signal_deadlines':[]},{**good,'retain_until_ns':'9007199254740995'},{**good,'batch_id':'a'*32},{**good,'historical':True}):
        assert not verify_receipt(batch,bad,False)
    assert not verify_receipt(batch,good,True)

def test_bounded_queue_expiry_priority_and_retry_bounds():
    ledger=Ledger();now=[0.0];q=queue(ledger,monotonic=lambda:now[0]);
    for i in range(1024):assert q.enqueue(record(f'{i+1:032x}'))
    assert not q.enqueue(record('a'*32)) and len(q.records())==1024
    now[0]=300;assert q.pending==0 and q.diagnostics()['queue_expired']==1024
    for attempt in range(20):
        assert .25<=retry_delay(attempt,lambda:0)<=30
        assert .25<=retry_delay(attempt,lambda:1)<=30
    q=DeliveryQueue(settings(max_records=2),ledger)
    low=json.loads(record(kind='log'));low['payload']={'severity':'info','template_id':'operation.failed','template_revision':'1','fields':{},'line':'approved','stream_labels':[],'structured_metadata':{},'source_class':'structured'}
    assert q.enqueue(json.dumps(low));assert q.enqueue(record());assert q.enqueue(record('a'*32))
    assert all(json.loads(r)['kind']=='error' for r in q.records()) and q.lost==1

def test_partition_before_ids_split_and_one_inflight_per_lane():
    ledger=Ledger();ledger.lost=False;q=queue(ledger)
    for i in range(513):q.enqueue(record(f'{i+1:032x}'))
    batches=q.freeze();assert sum(b.count for b in batches)==513
    assert all(b.count<=512 and len(b.body)<=1048576 and hashlib.sha256(b.body).hexdigest()==b.hash for b in batches)
    for batch in batches:
        wire=json.loads(batch.body);assert all(route_record(r,DESCRIPTOR,batch.producer)==batch.route_slot for r in wire['records'])
    active=set();overlap=[];gate=threading.Lock();send=ledger.send
    def checked(batch,deadline):
        with gate:
            if batch.route_slot in active:overlap.append(batch.route_slot)
            active.add(batch.route_slot)
        try:return send(batch,deadline)
        finally:
            with gate:active.remove(batch.route_slot)
    ledger.send=checked
    threads=[threading.Thread(target=q.flush,args=(2,)) for _ in range(3)]
    for t in threads:t.start()
    for t in threads:t.join()
    assert not overlap and q.pending==0

def test_encrypted_policy_bound_spool_restart_corruption_and_capacity(tmp_path):
    path=tmp_path/'queue';key=bytes(range(32));ledger=Ledger();spool=EncryptedSpool(path,key,DESCRIPTOR,'1',2097152)
    q=queue(ledger,spool=spool);q.enqueue(record());q.freeze();q.persist();q.release()
    raw=path.read_bytes();assert b'Error' not in raw and b'occurrence_id' not in raw
    recovered=EncryptedSpool(path,key,DESCRIPTOR,'1',2097152);q=queue(ledger,spool=recovered)
    assert q.pending==1;q.release()
    with pytest.raises(ValueError):EncryptedSpool(path,key,replace(DESCRIPTOR,project='a'*32),'1',2097152).load()
    damaged=bytearray(raw);damaged[-1]^=1;path.write_bytes(damaged)
    with pytest.raises(ValueError):EncryptedSpool(path,key,DESCRIPTOR,'1',2097152).load()
    small=EncryptedSpool(tmp_path/'small',key,DESCRIPTOR,'1',64)
    with pytest.raises(OSError):small.save({'canary':'PLAINTEXT_CANARY'*100})
    small.close()

def test_client_real_flush_and_close_release_resources_without_fatal_network_capture():
    ledger=Ledger();ledger.lost=False;c=init(settings(transport=ledger));c.capture_exception(ValueError('SECRET'))
    assert c.flush().pending==0 and ledger.admitted==1
    c.close();assert c.buffered_records()==()

def test_all_owner_golden_vectors_and_exact_histogram():
    vectors=json.loads((Path(__file__).resolve().parents[3]/'fixtures/sdk/delivery/routing-vectors.json').read_text(encoding='utf-8'))
    for v in vectors['vectors']:
        assert owner_key(v['record'],DESCRIPTOR,'a'*32).hex()==v['owner_utf8_hex']
        assert route_record(v['record'],DESCRIPTOR,'a'*32)==v['slot']
        if v['record']['kind']=='metric':assert route_record(v['record'],DESCRIPTOR,'b'*32)==v['slot']
    assert vectors['vectors'][0]['record']['payload']['histogram']['integer']['count']=='9007199254740993'

def test_expired_policy_drops_uncommitted_but_historical_commit_still_acknowledges():
    now=['9007199254740993'];ledger=Ledger();q=DeliveryQueue(settings(clock_ns=lambda:now[0]),ledger)
    q.enqueue(record());q.flush(.01);now[0]='9223372036854775807'
    assert q.flush(1).pending==0 and ledger.admitted==1 and len(ledger.sends)==1
    fresh=DeliveryQueue(settings(clock_ns=lambda:now[0]),ledger);fresh.enqueue(record('a'*32))
    result=fresh.flush();assert result.pending==0 and result.lost==1 and len(ledger.sends)==1

def test_exporter_callbacks_cannot_capture_themselves():
    ledger=Ledger();ledger.lost=False;send=ledger.send
    def instrumented(batch,deadline):client.capture_exception(ValueError('EXPORTER_SECRET'));return send(batch,deadline)
    ledger.send=instrumented;client=init(settings(transport=ledger));client.capture_exception(ValueError('application'))
    assert client.flush().pending==0 and ledger.admitted==1 and client.diagnostics()['exporter_recursion']==1
    client.close()

def test_go_native_canonical_input_goldens():
    vectors=json.loads((Path(__file__).resolve().parents[3]/'fixtures/sdk/delivery/native-vectors.json').read_text(encoding='utf-8'))
    for vector in vectors['vectors']:
        raw=native_canonical(vector['batch'])
        assert raw.decode()==vector['canonical_utf8'] and hashlib.sha256(raw).hexdigest()==vector['sha256']

def test_spool_restart_after_restrictive_policy_recovers_only_original_historical_receipt(tmp_path):
    from test_policy import KEY,b64
    from soundpost import SignedPolicy
    path=tmp_path/'history';key=bytes(range(32));ledger=Ledger();spool=EncryptedSpool(path,key,DESCRIPTOR,'1')
    q=queue(ledger,spool=spool);q.enqueue(record());assert q.flush(.01).pending==1;q.release();ledger.restricted=True
    old=settings();document=json.loads(base64.urlsafe_b64decode(old.policy.payload+'='*(-len(old.policy.payload)%4)));document['revision']='2';payload=native_canonical(document)
    current=replace(old,descriptor=replace(DESCRIPTOR,policy_revision='2'),policy=SignedPolicy(1,'Ed25519','test',b64(payload),b64(KEY.sign(payload))))
    recovered=DeliveryQueue(current,ledger,spool=EncryptedSpool(path,key,current.descriptor,'2'));result=recovered.flush(1)
    assert result.pending==0 and result.receipts[0]['historical'] is True and ledger.admitted==1 and len(ledger.sends)==1
    recovered.close()

def test_all_ten_closed_payloads_reject_nested_unknown_content_before_buffering():
    from soundpost.wire import parse_safe_record
    import copy
    vectors=json.loads((Path(__file__).resolve().parents[3]/'fixtures/sdk/delivery/native-vectors.json').read_text(encoding='utf-8'))
    for item in vectors['vectors']:
        batch=item['batch'];record=batch['records'][0];safe={key:record[key] for key in ('id','kind','observed_at_ns','payload')};safe['policy_revision']=batch['policy_revision']
        assert parse_safe_record(native_canonical(safe).decode())['kind']==record['kind']
        if 'clock' in record['payload']:
            hostile=copy.deepcopy(safe);hostile['payload']['clock']['raw_content']='SECRET_CANARY'
            with pytest.raises(ValueError):parse_safe_record(native_canonical(hostile).decode())

def test_frozen_snapshots_preserve_normalized_records():
    q=queue(Ledger());q.enqueue(record());before=q.records();q.freeze();assert q.records()==before;q.freeze();assert q.records()==before

def test_native_optional_nulls_normalize_like_go_dtos():
    from soundpost.wire import parse_safe_record
    value=json.loads(record());value['payload']['trace_id']=None
    assert 'trace_id' not in parse_safe_record(json.dumps(value))['payload']

def test_approved_native_profile_metadata_is_closed_exact_and_correction_free():
    from soundpost.wire import parse_safe_record
    import copy
    vectors=json.loads((Path(__file__).resolve().parents[3]/'fixtures/sdk/delivery/native-profile-vectors.json').read_text(encoding='utf-8'))
    for item in vectors['vectors']:
        batch=item['batch'];r=batch['records'][0];safe={key:r[key] for key in ('id','kind','observed_at_ns','payload')};safe['policy_revision']=batch['policy_revision']
        assert parse_safe_record(native_canonical(safe).decode())['kind']=='profile_chunk'
        assert native_canonical(batch).decode()==item['canonical_utf8'] and hashlib.sha256(native_canonical(batch)).hexdigest()==item['sha256']
        hostile=copy.deepcopy(safe);hostile['payload']['native_domain']['raw_memory']='SECRET_CANARY'
        with pytest.raises(ValueError):parse_safe_record(native_canonical(hostile).decode())
        missing=copy.deepcopy(safe);missing['payload']['native_capabilities'].pop()
        with pytest.raises(ValueError):parse_safe_record(native_canonical(missing).decode())
        duplicate=copy.deepcopy(safe);duplicate['payload']['native_capabilities'][1]=duplicate['payload']['native_capabilities'][0]
        with pytest.raises(ValueError):parse_safe_record(native_canonical(duplicate).decode())
        if r['payload']['samples']:
            assert r['payload']['samples'][0]['native']['period']=='9007199254740993'
            invalid=copy.deepcopy(safe);invalid['payload']['samples'][0]['native']['unit']='nanoseconds'
            with pytest.raises(ValueError):parse_safe_record(native_canonical(invalid).decode())
        if r['payload']['intervals']:
            invalid=copy.deepcopy(safe);invalid['payload']['intervals'][0]['correction']=True
            with pytest.raises(ValueError):parse_safe_record(native_canonical(invalid).decode())

def test_restart_expires_entire_frozen_batch_at_first_capture(tmp_path):
    import time
    path=tmp_path/'expiry';key=bytes(range(32));ledger=Ledger();spool=EncryptedSpool(path,key,DESCRIPTOR,'1');q=queue(ledger,spool=spool)
    for identity in ('8'*32,'a'*32):
        r=json.loads(record(identity,kind='log'));r['payload']={'severity':'error','template_id':'operation.failed','template_revision':'1','fields':{'status':503},'line':'operation failed: 503','stream_labels':[],'structured_metadata':{},'source_class':'structured'};q.enqueue(json.dumps(r))
    q.freeze();q.persist();stored=spool.load();stored['entries'][0]['wall']=time.time()-301;stored['batches'][0]['first_capture']=stored['entries'][0]['wall'];spool.save(stored);q.release()
    recovered=queue(ledger,spool=EncryptedSpool(path,key,DESCRIPTOR,'1'));report=recovered.flush()
    assert report.pending==0 and not report.acknowledged_batch_ids and recovered.diagnostics()['queue_expired']==2 and ledger.admitted==0
    recovered.close()

def test_resources_are_typed_registered_identity_shapes_not_display_aliases():
    for field in ('service_id','environment_id','build_id'):
        with pytest.raises(ValueError):init(settings(resource=replace(RESOURCE,**{field:'display-alias'})))
    with pytest.raises(ValueError):init(settings(resource=replace(RESOURCE,instance_pseudonym='not-approved-雪')))

def test_metric_start_timestamp_is_exact_optional_signed_metadata():
    from soundpost.wire import parse_safe_record
    import copy
    data=json.loads((Path(__file__).resolve().parents[3]/'fixtures/sdk/delivery/native-vectors.json').read_text(encoding='utf-8'));r=next(v['batch']['records'][0] for v in data['vectors'] if v['batch']['records'][0]['kind']=='metric')
    safe={key:r[key] for key in ('id','kind','observed_at_ns','payload')};safe['policy_revision']='1'
    for start in ('9007199254741993','-9007199254740993','0'):
        value=copy.deepcopy(safe);value['payload']['start_timestamp_ns']=start;decoded=parse_safe_record(native_canonical(value).decode())
        assert decoded['payload']['start_timestamp_ns']==start and decoded['observed_at_ns']=='9007199254740993'
    value=copy.deepcopy(safe);value['payload']['start_timestamp_ns']=None
    assert 'start_timestamp_ns' not in parse_safe_record(native_canonical(value).decode())['payload']
    value['payload']['start_timestamp_ns']={'raw_content':'SECRET_CANARY'};q=queue(Ledger())
    with pytest.raises(ValueError):q.enqueue(native_canonical(value).decode())
    assert q.records()==()

def test_native_frames_require_hashes_artifact_ids_safe_symbols_and_policy_binding():
    from soundpost.wire import parse_safe_record
    import copy
    data=json.loads((Path(__file__).resolve().parents[3]/'fixtures/sdk/delivery/native-profile-vectors.json').read_text(encoding='utf-8'));r=data['vectors'][0]['batch']['records'][0]
    safe={key:copy.deepcopy(r[key]) for key in ('id','kind','observed_at_ns','payload')};safe['policy_revision']='1';safe['payload']['frames'][0]=dict(module_id='1'*64,function='safe._$@:',artifact_id='4'*32,offset='9007199254740993',reason='')
    assert parse_safe_record(native_canonical(safe).decode())['kind']=='profile_chunk'
    for field in ('module_id','function','artifact_id'):
        value=copy.deepcopy(safe);value['payload']['frames'][0][field]='/private/source/CANARY'
        with pytest.raises(ValueError):parse_safe_record(native_canonical(value).decode())
    value=copy.deepcopy(safe);value['payload']['method']='native_offcpu';value['payload']['units']='nanoseconds'
    with pytest.raises(ValueError):parse_safe_record(native_canonical(value).decode())
    value=copy.deepcopy(safe);value['payload']['policy_revision']='2'
    with pytest.raises(ValueError):parse_safe_record(native_canonical(value).decode())

def test_mixed_signal_receipt_preserves_distinct_deadlines_and_their_minimum():
    ledger=Ledger();ledger.lost=False;q=DeliveryQueue(settings(producer='a'*32),ledger);q.enqueue(record('00000000000000000000000000000003'))
    r=json.loads(record(kind='log'));r['payload']={'severity':'error','template_id':'operation.failed','template_revision':'1','fields':{'status':503},'line':'operation failed: 503','stream_labels':[],'structured_metadata':{},'source_class':'structured'};q.enqueue(json.dumps(r));batch=q.freeze()[0];assert batch.count==2
    deadlines=[dict(kind='error',retain_until_ns='9007199254741993'),dict(kind='log',retain_until_ns='9007199254741093')];send=ledger.send
    def mixed(batch,deadline):
        outcome=send(batch,deadline);value={**outcome.receipt,'signal_deadlines':deadlines,'retain_until_ns':'9007199254741093'};ledger.rows[(batch.producer,batch.route_slot,batch.id)]=value;return Outcome('receipt',value)
    ledger.send=mixed;report=q.flush()
    assert report.pending==0 and report.receipts[0]['signal_deadlines']==deadlines and report.receipts[0]['retain_until_ns']=='9007199254741093'
    assert not verify_receipt(batch,{**report.receipts[0],'retain_until_ns':'9007199254741993'},False)

def test_exclusive_backend_spool_lease_rejects_overlap_and_reopens_after_release(tmp_path):
    path=tmp_path/'lease';key=bytes(range(32));first=EncryptedSpool(path,key,DESCRIPTOR,'1');first.save({'count':1});other=EncryptedSpool(path,key,DESCRIPTOR,'1')
    with pytest.raises(OSError):other.load()
    other.close();assert first.load()=={'count':1};first.close();reopened=EncryptedSpool(path,key,DESCRIPTOR,'1');assert reopened.load()=={'count':1};reopened.close()

def test_native_loss_and_throttle_evidence_is_bounded_typed_and_not_duration():
    from soundpost.wire import parse_safe_record
    import copy
    data=json.loads((Path(__file__).resolve().parents[3]/'fixtures/sdk/delivery/native-profile-vectors.json').read_text(encoding='utf-8'))
    for item in data['vectors']:
        r=item['batch']['records'][0];safe={key:r[key] for key in ('id','kind','observed_at_ns','payload')};safe['policy_revision']='1'
        assert parse_safe_record(native_canonical(safe).decode())['payload']['native_loss']==r['payload']['native_loss']
        value=copy.deepcopy(safe);next(v for v in value['payload']['native_loss'] if v['reason'] in ('throttled','unthrottled'))['count']='1'
        with pytest.raises(ValueError):parse_safe_record(native_canonical(value).decode())
        value=copy.deepcopy(safe);value['payload']['native_loss']=[value['payload']['native_loss'][0]]*257
        with pytest.raises(ValueError):parse_safe_record(native_canonical(value).decode())
        value=copy.deepcopy(safe);value['payload']['native_loss'][0]['raw_stack']='SECRET_CANARY'
        with pytest.raises(ValueError):parse_safe_record(native_canonical(value).decode())

def loss_settings(**changes):
    from test_policy import KEY,b64
    from soundpost import SignedPolicy
    c=settings(**changes);doc=json.loads(base64.urlsafe_b64decode(c.policy.payload+'='*(-len(c.policy.payload)%4)));doc['loss']=True;payload=native_canonical(doc)
    return replace(c,policy=SignedPolicy(1,'Ed25519','test',b64(payload),b64(KEY.sign(payload))))

def test_native_sampling_loss_coalesces_exact_counts_and_acks_only_frozen_range():
    ledger=Ledger();q=DeliveryQueue(loss_settings(),ledger)
    assert q.record_signal_loss('span','policy',9007199254740993,'9007199254740993')
    assert q.record_signal_loss('span','policy',1,'9007199254740994')
    first=json.loads(q.records()[0]);assert first['kind']=='loss' and first['payload']['count']=='9007199254740994' and first['payload']['last_ack'] is None
    assert q.flush(.01).pending==1;frozen=ledger.sends[0];assert q.record_signal_loss('span','policy',1,'9007199254740995')
    report=q.flush(1.5);assert report.pending==0 and report.lost==0 and ledger.sends[0]==frozen and ledger.admitted==2
    state=q.signal_loss_counters()[0];assert state['observed_count']=='9007199254740995' and state['acknowledged_count']=='9007199254740995' and state['pending_count']=='0' and state['unexported_count']=='0'
    body=json.loads(frozen);payload=body['records'][0]['payload'];assert payload['source']==SOURCE and payload['producer']==body['producer'] and len(payload['producer_epoch'])==32

def test_native_loss_permission_and_capacity_remain_visible_pending_not_ack():
    denied=queue(Ledger());assert not denied.record_signal_loss('span','policy',1,'9007199254740993') and denied.records()==()
    q=DeliveryQueue(loss_settings(max_bytes=1024,max_records=1),Ledger());assert q.record_signal_loss('span','queue_full',1,'9007199254740993')
    report=q.flush(.01);assert report.pending==1 and not report.acknowledged_batch_ids and q.signal_loss_counters()[0]['acknowledged_count']=='0'

def test_encrypted_loss_restart_preserves_old_identity_and_uses_new_epoch(tmp_path):
    path=tmp_path/'native-loss';key=bytes(range(32));ledger=Ledger();cfg=loss_settings();spool=EncryptedSpool(path,key,DESCRIPTOR,'1');q=DeliveryQueue(cfg,ledger,spool=spool)
    assert q.record_signal_loss('span','policy',1,'9007199254740993') and q.flush(.01).pending==1
    original=ledger.sends[0];q.flush(0);q.release();restarted=DeliveryQueue(cfg,ledger,spool=EncryptedSpool(path,key,DESCRIPTOR,'1'))
    assert restarted.record_signal_loss('span','policy',1,'9007199254740994') and restarted.flush(1.5).pending==0
    counters=restarted.signal_loss_counters()
    assert ledger.admitted==2 and ledger.sends[0]==original and len(counters)==2 and counters[0]['producer_epoch']!=counters[1]['producer_epoch'] and all(c['acknowledged_count']=='1' and c['pending_count']=='0' for c in counters)
    restarted.close()
