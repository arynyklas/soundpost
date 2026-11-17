# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
import base64
import hashlib
import json
from .ids import hex16
from dataclasses import replace
import random
from operator import itemgetter
import secrets
import struct
import threading
import time
from .types import RoutingDescriptor,FlushReport,wall_clock_ns
from .policy import decimal,canonical_id,unix_nano
from .routing import native_canonical,route_record,route_prefix,route_owner,resource_wire,validate_descriptor
from .transport import FrozenBatch,Outcome,verify_receipt,EXPORTING
from .wire import parse_safe_record

_SIZE=itemgetter('size');_KIND=itemgetter('kind');_WALL=itemgetter('wall')
def retry_delay(attempt,random_value=random.random):
    cap=min(30,.25*2**min(attempt,7))
    return max(.25,min(30,cap*(.5+.5*max(0,min(1,random_value())))))
_PRIORITY={'error':2,'condition':2,'capability':2,'loss':2,'job_attempt':2,'log':1}
def _priority(kind):return _PRIORITY.get(kind,0)
_ORDER=itemgetter('order')
class DeliveryQueue:
    def __init__(self,config,transport,*,monotonic=time.monotonic,random_value=random.random,spool=None):
        self.config=config;self.transport=transport;self.now=monotonic;self.random=random_value
        self.policy=json.loads(base64.urlsafe_b64decode(config.policy.payload+'='*(-len(config.policy.payload)%4)))
        self.descriptor=validate_descriptor(config.descriptor or RoutingDescriptor(1,config.org,config.project,config.source,1,64,decimal(self.policy['revision'])))
        if (self.descriptor.org,self.descriptor.project,self.descriptor.source,self.descriptor.policy_revision)!=(config.org,config.project,config.source,self.policy['revision']):raise ValueError('routing identity mismatch')
        self.resource=resource_wire(config.resource,config.build);self.producer=canonical_id(config.producer or secrets.token_hex(16))
        self._resource_tail=',"resource":'+native_canonical(self.resource).decode()+'}';self._span_route=route_prefix(self.descriptor,'span');self._next_expiry=float('inf')
        self._span_route32=self._span_route+struct.pack('>I',32);self._safe_tail=',"policy_revision":"'+self.descriptor.policy_revision+'"}';self._default_clock=config.clock_ns is wall_clock_ns;self._max_records=config.max_records;self._max_bytes=config.max_bytes
        # The canonical batch tail of each route slot (keys sorted, so `records` ends at `route_slot`, then `source`, `version`).
        tail_end=',"source":"'+self.descriptor.source+'","version":1}';self._tails={slot:('],"route_slot":'+str(slot)+tail_end).encode() for slot in range(64)};self._tail_end=tail_end
        try:self._expires=int(unix_nano(self.policy['expires_ns']))
        except Exception:self._expires=float('-inf')  # an unusable expiry reads as expired, as the per-call conversion it replaces did
        self.spool=spool or config.spool;self._entries=[];self._batches=[];self._bytes=0;self._lost=0;self._counts={};self._denied=False;self._closed=False;self._closing=False
        self._loss_epoch=canonical_id(secrets.token_hex(16));self._loss_buckets={};self._last_ack=None;self._materializing_loss=False;self._allow_loss=self.policy.get('loss') is True and getattr(config,'deployment_loss',True) is True
        if self.spool:self.spool.assert_binding(self.descriptor,self.descriptor.policy_revision)
        self._lock=threading.RLock();self._flush_lock=threading.Lock()
        self._recovering=True
        try:
            if self.spool:self._recover(self.spool.load())
        except Exception:
            self.release();raise ValueError('invalid encrypted spool state') from None
        finally:self._recovering=False
    def _policy_expired(self):
        if self._default_clock:return time.time_ns()>=self._expires  # the default clock is always a valid UnixNano, so the checked conversion below would only re-validate it
        try:return int(unix_nano(self.config.clock_ns()))>=self._expires
        except Exception:return True
    def _valid_signal_loss(self,signal,reason):
        return type(signal) is str and signal in ('metric','log','span','error','job_attempt','replay_chunk','profile_chunk','capability','condition') and type(reason) is str and reason in ('queue_full','expired','policy','unsupported','ring_overflow','reorder_gap','transport','shutdown','truncated')
    def record_signal_loss(self,signal,reason,count,at_ns):
        with self._lock:
            if self._closed or self._closing or self._denied or not self._allow_loss or EXPORTING.get():self._counts['native_loss_unavailable']=self._counts.get('native_loss_unavailable',0)+1;return False
            try:
                unix_nano(at_ns)
                if not self._valid_signal_loss(signal,reason) or type(count) is not int or not 0<count<=18446744073709551615 or int(at_ns)>=self._expires:raise ValueError()
            except (ValueError,TypeError):self._counts['invalid_signal_loss']=self._counts.get('invalid_signal_loss',0)+1;return False
            self._expire();self._expire_signal_losses();key=(self._loss_epoch,signal,reason);bucket=self._loss_buckets.get(key)
            if bucket is None:
                while self._bytes+512>self.config.max_bytes:
                    index=next((i for i,e in enumerate(self._entries) if not e['batch'] and _priority(e['kind'])<2),None)
                    if index is None:self._loss('native_loss_unbuffered');return False
                    old=self._entries.pop(index);self._bytes-=old['size'];self._loss('queue_pressure')
                bucket=dict(epoch=self._loss_epoch,signal=signal,reason=reason,revision=self.descriptor.policy_revision,observed=0,acked=0,unbatched=0,start=None,end=None,at=self.now(),wall=time.time());self._loss_buckets[key]=bucket;self._bytes+=512
            if bucket['observed']+count>18446744073709551615:self._loss('native_loss_overflow');return False
            bucket['observed']+=count
            if not bucket['unbatched']:bucket['start']=at_ns;bucket['end']=at_ns;bucket['at']=self.now();bucket['wall']=time.time()
            else:bucket['start']=min((bucket['start'],at_ns),key=int);bucket['end']=max((bucket['end'],at_ns),key=int)
            bucket['unbatched']+=count;self._materialize_signal_losses()
            if self.spool:
                try:self.persist()
                except (OSError,ValueError):self._counts['spool_failed']=self._counts.get('spool_failed',0)+1
            return True
    def _expire_signal_losses(self):
        for bucket in self._loss_buckets.values():
            if bucket['unbatched'] and self.now()-bucket['at']>=300:bucket['unbatched']=0;bucket['start']=None;bucket['end']=None;self._loss('native_loss_expired')
    def _materialize_signal_losses(self):
        if self._materializing_loss or self._closed or self._recovering or self._denied:return
        self._materializing_loss=True
        try:
            for key,bucket in self._loss_buckets.items():
                if not bucket['unbatched']:continue
                if not self._allow_loss or bucket['revision']!=self.descriptor.policy_revision:bucket['unbatched']=0;bucket['start']=None;bucket['end']=None;self._loss('native_loss_policy');continue
                expired=self._policy_expired()
                if expired:continue
                old=next((e for e in self._entries if e.get('loss_key')==key and not e['batch']),None);total=bucket['unbatched']
                if old:
                    record=json.loads(old['text']);payload=record['payload'];total+=old['loss_count'];payload['start_ns']=min((payload['start_ns'],bucket['start']),key=int);payload['end_ns']=max((payload['end_ns'],bucket['end']),key=int);record['observed_at_ns']=payload['end_ns']
                else:
                    payload=dict(source=self.descriptor.source,producer=self.producer,producer_epoch=bucket['epoch'],start_ns=bucket['start'],end_ns=bucket['end'],signal=bucket['signal'],reason=bucket['reason'],count='0',last_ack=None,queue_bytes='0',queue_records='0');record=dict(id=secrets.token_hex(16),kind='loss',observed_at_ns=bucket['end'],policy_revision=bucket['revision'],payload=payload)
                payload['count']=str(total);payload['last_ack']=None if self._last_ack is None else self._last_ack.copy();payload['queue_bytes']=str(self._bytes);payload['queue_records']=str(len(self._entries));encoded=native_canonical(record).decode()
                if old:
                    wire={k:record[k] for k in ('id','kind','observed_at_ns','payload')};wire['resource']=self.resource
                    if len(native_canonical(wire))+512>old['size']:continue
                    old['text']=encoded;old['wire']=None;old['loss_count']=total
                else:
                    if not self.enqueue(encoded):continue
                    entry=self._entries[-1];entry['loss_key']=key;entry['loss_count']=total;entry['at']=bucket['at'];entry['wall']=bucket['wall'];self._next_expiry=min(self._next_expiry,entry['at']+300)
                bucket['unbatched']=0;bucket['start']=None;bucket['end']=None
        finally:self._materializing_loss=False
    def signal_loss_counters(self):
        with self._lock:
            self._expire();self._expire_signal_losses();result=[]
            for key,b in self._loss_buckets.items():
                pending=b['unbatched']+sum(e.get('loss_count',0) for e in self._entries if e.get('loss_key')==key)
                result.append(dict(producer_epoch=b['epoch'],signal=b['signal'],reason=b['reason'],observed_count=str(b['observed']),acknowledged_count=str(b['acked']),pending_count=str(pending),unexported_count=str(b['observed']-b['acked']-pending)))
            return tuple(result)
    def _acknowledge_signal_losses(self,batch,receipt):
        # Called only for a receipt `verify_receipt` accepted, which already checked the cursor's group as an opaque ID and its index as a non-zero uint64.
        cursor=receipt['cursor'];self._last_ack=dict(group=cursor['group'],index=cursor['index'])
        if 'loss' not in batch.kinds:return
        for entry in self._entries:
            if entry['batch']==batch.id and entry.get('loss_key') is not None:
                bucket=self._loss_buckets.get(entry['loss_key']);count=entry['loss_count']
                if bucket is None or bucket['acked']+count>bucket['observed']:raise ValueError('invalid native loss accounting')
                bucket['acked']+=count
    def _restore_signal_losses(self,value):
        self._loss_buckets.clear()
        for b in value['loss_buckets']:
            epoch=canonical_id(b['producer_epoch']);signal=b['signal'];reason=b['reason'];revision=decimal(b['policy_revision']);observed=int(decimal(b['observed_count']));acked=int(decimal(b['acknowledged_count']));unbatched=int(decimal(b['unbatched_count']))
            if not self._valid_signal_loss(signal,reason) or acked>observed or unbatched>observed-acked or type(b['wall']) not in (int,float):raise ValueError('invalid native loss state')
            if observed==acked and not unbatched:continue
            start=None if b['start_ns'] is None else unix_nano(b['start_ns']);end=None if b['end_ns'] is None else unix_nano(b['end_ns'])
            if unbatched and (start is None or end is None or int(end)<int(start)):raise ValueError('invalid native loss interval')
            key=(epoch,signal,reason)
            if key in self._loss_buckets or self._bytes+512>self.config.max_bytes:raise ValueError('native loss capacity exceeded')
            self._loss_buckets[key]=dict(epoch=epoch,signal=signal,reason=reason,revision=revision,observed=observed,acked=acked,unbatched=unbatched,start=start,end=end,wall=b['wall'],at=self.now()-(time.time()-b['wall']));self._bytes+=512
        c=value['last_ack'];self._last_ack=None if c is None else dict(group=canonical_id(c['group']),index=decimal(c['index']))
        if self._last_ack is not None and self._last_ack['index']=='0':raise ValueError('invalid saved ACK cursor')
    def _mark_loss_entry(self,entry,record):
        if record['kind']!='loss':return
        p=record['payload'];key=(canonical_id(p['producer_epoch']),p['signal'],p['reason'])
        if key in self._loss_buckets:entry['loss_key']=key;entry['loss_count']=int(decimal(p['count']))
    def _loss(self,reason,count=1):self._lost+=count;self._counts[reason]=self._counts.get(reason,0)+count
    def _remove(self,batch,reason=None):
        identity=batch.id;batches=self._batches;state=None
        for index,candidate in enumerate(batches):
            if candidate['batch'] is batch:state=candidate;del batches[index];break
        self._entries=[entry for entry in self._entries if entry['batch']!=identity]
        # The frozen batch's own entry bytes were recorded when it was sealed (or recovered), so the total is decremented, not summed over what is left.
        if state is None:self._bytes=sum(map(_SIZE,self._entries))+512*len(self._loss_buckets)
        else:self._bytes-=state['bytes']
        if reason:self._loss(reason,batch.count)
    def _expire(self):
        now=self.now()
        # `_next_expiry` never exceeds the earliest entry's age limit, so while it is in the future nothing can have expired and the scan is skipped.
        if now<self._next_expiry:return
        expired={e['batch'] for e in self._entries if now-e['at']>=300 and e['batch']}
        for state in tuple(self._batches):
            if state['batch'].id in expired:self._remove(state['batch'],'queue_expired')
        retained=[]
        for entry in self._entries:
            if now-entry['at']>=300:self._bytes-=entry['size'];self._loss('queue_expired')
            else:retained.append(entry)
        self._entries=retained;self._next_expiry=min((e['at'] for e in retained),default=float('inf'))+300
    @property
    def pending(self):
        with self._lock:self._expire();self._expire_signal_losses();return len(self._entries) or int(any(b['unbatched'] for b in self._loss_buckets.values()))
    @property
    def lost(self):return self._lost
    def diagnostics(self):
        with self._lock:return self._counts.copy()
    def records(self):
        with self._lock:
            self._expire();batches={s['batch'].id:(s['batch'].policy_revision,json.loads(s['batch'].body)['records']) for s in self._batches};result=[]
            for entry in self._entries:
                if entry['text'] is not None:result.append(entry['text']);continue
                revision,records=batches[entry['batch']];r=records[entry['position']]
                result.append(native_canonical(dict(id=r['id'],kind=r['kind'],observed_at_ns=r['observed_at_ns'],payload=r['payload'],policy_revision=revision)).decode())
            return tuple(result)
    def enqueue(self,text):
        with self._lock:
            if self._closed or self._closing and not self._materializing_loss:self._loss('closed');return False
            self._expire()
            if type(text) is not str:raise ValueError('serialized safe record required')
            record=parse_safe_record(text)
            if not self._recovering and decimal(record['policy_revision'])!=self.descriptor.policy_revision:raise ValueError('policy revision mismatch')
            return self._append(native_canonical(record).decode(),record['kind'],route_record(record,self.descriptor,self.producer))
    def enqueue_span(self,head,trace_id):
        """Enqueues a span record the SDK composed itself in canonical form from identifiers and clock values it generated or validated (tracing.py, Client._admit_span).
        `head` is that record's text up to and including its payload: the queue appends the policy revision for the stored text and the resource for the wire bytes, so
        neither is cut out of a finished text again. Skips the parse and re-validation of `enqueue`; every other step (closed, expiry, size, priority eviction, spool) is the
        shared `_append`. Equality with the validated path is pinned by tests/test_span_fast_path.py."""
        with self._lock:
            if self._closed or self._closing and not self._materializing_loss:self._loss('closed');return False
            now=self.now()
            if now>=self._next_expiry:self._expire()
            owner=trace_id.encode()
            # A trace id is 32 hex digits, so the length frame of the route owner is the constant folded into `_span_route32`.
            slot=int.from_bytes(hashlib.sha256(self._span_route32+owner).digest()[:8],'big')%64 if len(owner)==32 else route_owner(self._span_route,owner)
            return self._append(head+self._safe_tail,'span',slot,(head+self._resource_tail).encode(),now)
    def _wire(self,text):
        """The native wire form of a stored record: the canonical text without its policy_revision (always the last key) and with the resource, as bytes."""
        return (text[:text.rindex(',"policy_revision":')]+self._resource_tail).encode()
    def _append(self,safe,kind,slot,wire=None,now=None):
        if wire is None:wire=self._wire(safe)
        record_bytes=len(wire);size=record_bytes+(1024 if kind=='loss' else 512)
        if record_bytes>(131072 if kind=='replay_chunk' else 262144):
            if not self._materializing_loss:self._loss('record_too_large')
            return False
        while len(self._entries)>=self._max_records or self._bytes+size>self._max_bytes:
            index=next((i for i,e in enumerate(self._entries) if not e['batch'] and _priority(e['kind'])<_priority(kind)),None)
            if index is None:
                if not self._materializing_loss:self._loss('queue_full')
                return False
            old=self._entries.pop(index);self._bytes-=old['size'];self._loss('queue_pressure')
        at=self.now() if now is None else now
        if at+300<self._next_expiry:self._next_expiry=at+300
        self._entries.append({'text':safe,'wire':wire,'size':size,'at':at,'wall':time.time(),'kind':kind,'slot':slot,'batch':None,'position':None});self._bytes+=size
        if self.spool and not self._recovering and not self._materializing_loss:
            try:self.persist()
            except (OSError,ValueError):self._counts['spool_failed']=self._counts.get('spool_failed',0)+1
        return True
    def freeze(self):
        with self._lock:
            self._expire()
            self._expire_signal_losses();self._materialize_signal_losses()
            by_slot={}
            for entry in self._entries:
                if not entry['batch']:by_slot.setdefault(entry['slot'],[]).append(entry)
            if by_slot:
                # The canonical batch header (keys sorted, so `records` sits between `project` and `route_slot`) as text around the batch id and the record array.
                middle=('","policy_revision":"'+self.descriptor.policy_revision+'","producer":"'+self.producer+'","project":"'+self.descriptor.project+'","records":[').encode()
                base=7+32+len(middle);tails=self._tails
                for slot in sorted(by_slot):
                    tail=tails.get(slot) or ('],"route_slot":'+str(slot)+self._tail_end).encode()
                    header_bytes=base+len(tail)
                    group=by_slot[slot]
                    if len(group)==1:  # the common slot of a short flush interval: one record, which always fits a batch (a record is at most 256 KiB)
                        entry=group[0];self._seal(slot,group,[entry['wire'] or self._wire(entry['text'])],middle,tail);continue
                    selected=[];wire=[];record_bytes=0
                    for entry in group:
                        encoded=entry['wire'] or self._wire(entry['text'])
                        if len(selected)==512 or header_bytes+record_bytes+len(encoded)+len(selected)>1048576:
                            self._seal(slot,selected,wire,middle,tail);selected=[];wire=[];record_bytes=0
                        selected.append(entry);wire.append(encoded);record_bytes+=len(encoded)
                    self._seal(slot,selected,wire,middle,tail)
            return tuple(s['batch'] for s in self._batches)
    def _seal(self,slot,selected,wire,middle,tail):
        """Turns the selected entries of one route slot into a frozen batch (a fresh random id, the hash of its exact bytes) and marks them as batched."""
        if not selected:return
        batch_id=hex16();raw=b''.join((b'{"id":"',batch_id.encode(),middle,b','.join(wire),tail))
        if len(selected)==1:
            entry=selected[0];kind=entry['kind'];kinds=(kind,);first=entry['wall'];size=entry['size'];order=-_priority(kind)
            batch=FrozenBatch(batch_id,self.descriptor.source,self.producer,slot,hashlib.sha256(raw).hexdigest(),raw,1,kinds,first,self.descriptor.policy_revision)
            entry['batch']=batch_id;entry['position']=0;entry['text']=None;entry['wire']=None
        else:
            kinds=tuple(sorted(set(map(_KIND,selected))));first=min(map(_WALL,selected));size=sum(map(_SIZE,selected));order=-max(map(_priority,kinds))
            batch=FrozenBatch(batch_id,self.descriptor.source,self.producer,slot,hashlib.sha256(raw).hexdigest(),raw,len(selected),kinds,first,self.descriptor.policy_revision)
            for position,entry in enumerate(selected):entry['batch']=batch_id;entry['position']=position;entry['text']=None;entry['wire']=None
        self._batches.append({'batch':batch,'ambiguous':False,'attempt':0,'next':0,'order':order,'bytes':size})
    def persist(self):
        if not self.spool:return
        with self._lock:
            batches=[]
            for state in self._batches:
                b=state['batch'];batches.append(dict(id=b.id,source=b.source,producer=b.producer,route_slot=b.route_slot,hash=b.hash,body=b.body.decode(),count=b.count,kinds=list(b.kinds),first_capture=b.first_capture,policy_revision=b.policy_revision,ambiguous=state['ambiguous'],attempt=state['attempt']))
            token=EXPORTING.set(True)
            try:self.spool.save(dict(version=2,producer=self.producer,last_ack=self._last_ack,loss_buckets=[dict(producer_epoch=b['epoch'],signal=b['signal'],reason=b['reason'],policy_revision=b['revision'],observed_count=str(b['observed']),acknowledged_count=str(b['acked']),unbatched_count=str(b['unbatched']),start_ns=b['start'],end_ns=b['end'],wall=b['wall']) for b in self._loss_buckets.values()],entries=[dict(text=e['text'],position=e['position'],wall=e['wall'],batch=e['batch']) for e in self._entries],batches=batches))
            finally:EXPORTING.reset(token)
    def _recover(self,value):
        if value is None:return
        if type(value) is not dict or value.get('version')!=2 or type(value.get('entries')) is not list or type(value.get('batches')) is not list or len(value['entries'])>1024:raise ValueError('invalid spool')
        producer=canonical_id(value['producer'])
        if self.config.producer is not None and self.config.producer!=producer:raise ValueError('spool producer mismatch')
        self.producer=producer
        self._restore_signal_losses(value)
        originals={state['id']:(decimal(state['policy_revision']),json.loads(state['body'])['records']) for state in value['batches']}
        expired_batches={stored['batch'] for stored in value['entries'] if stored['batch'] is not None and (time.time()-stored['wall']<0 or time.time()-stored['wall']>=300)}
        for stored in value['entries']:
            age=time.time()-stored['wall']
            if age<0 or age>=300 or stored['batch'] in expired_batches:self._loss('queue_expired');continue
            original=stored['text'];native_size=None
            if stored['batch'] is not None:
                revision,records=originals[canonical_id(stored['batch'])];position=stored['position']
                if type(position) is not int or not 0<=position<len(records):raise ValueError('invalid frozen spool entry')
                r=records[position];original=native_canonical(dict(id=r['id'],kind=r['kind'],observed_at_ns=r['observed_at_ns'],payload=r['payload'],policy_revision=revision)).decode();native_size=len(native_canonical(r))+(1024 if r['kind']=='loss' else 512)
            if stored['batch'] is None and parse_safe_record(original)['policy_revision']!=self.descriptor.policy_revision:self._loss('policy_changed');continue
            if not self.enqueue(original):raise ValueError('spool capacity exceeded')
            entry=self._entries[-1];entry['wall']=stored['wall'];entry['at']=self.now()-age;entry['batch']=stored['batch'];entry['position']=stored['position'];self._next_expiry=min(self._next_expiry,entry['at']+300)
            self._mark_loss_entry(entry,json.loads(original))
            if stored['batch'] is not None:
                self._bytes+=native_size-entry['size'];entry['size']=native_size;entry['text']=None;entry['wire']=None
        if self._bytes>self.config.max_bytes:raise ValueError('spool capacity exceeded')
        for state in value['batches']:
            if not any(e['batch']==state['id'] for e in self._entries):continue
            raw=state['body'].encode();wire=json.loads(raw)
            revision=decimal(state['policy_revision'])
            if hashlib.sha256(raw).hexdigest()!=state['hash'] or wire['id']!=state['id'] or wire['project']!=self.descriptor.project or wire['producer']!=self.producer or wire['source']!=self.descriptor.source or wire['policy_revision']!=revision or wire['route_slot']!=state['route_slot'] or type(state['attempt']) is not int or state['attempt']<0:raise ValueError('invalid frozen spool')
            batch=FrozenBatch(state['id'],state['source'],state['producer'],state['route_slot'],state['hash'],raw,state['count'],tuple(state['kinds']),min(e['wall'] for e in self._entries if e['batch']==state['id']),state['policy_revision'])
            self._batches.append(dict(batch=batch,ambiguous=True,attempt=state['attempt'],next=0,order=-max(map(_priority,batch.kinds)),bytes=sum(e['size'] for e in self._entries if e['batch']==state['id'])))
        if any(e['batch'] and not any(s['batch'].id==e['batch'] for s in self._batches) for e in self._entries):raise ValueError('orphan frozen spool')
        for key,b in self._loss_buckets.items():
            queued=sum(e.get('loss_count',0) for e in self._entries if e.get('loss_key')==key)
            if queued+b['unbatched']+b['acked']>b['observed']:raise ValueError('invalid native loss accounting')
    def _report(self,receipts,exceeded=False):return FlushReport(tuple([r['batch_id'] for r in receipts]),tuple([r['cursor']['group']+':'+r['cursor']['index'] for r in receipts]),self.pending,self.lost,exceeded,tuple(receipts))
    def flush(self,timeout=2.0):
        if type(timeout) not in (int,float) or timeout<0 or timeout!=timeout or timeout==float('inf'):raise ValueError('invalid flush deadline')
        now=self.now;monotonic=time.monotonic;spool=self.spool;deadline=now()+timeout;wire_deadline=monotonic()+timeout;receipts=[]
        if not self._flush_lock.acquire(timeout=max(0,timeout)):return self._report([],True)
        try:
            self.freeze()
            while not self._denied and not self._closed and self.pending and now()<deadline and monotonic()<wire_deadline:
                self.freeze()
                with self._lock:
                    heads=[];slots=set()
                    for state in self._batches:
                        slot=state['batch'].route_slot
                        if slot not in slots:heads.append(state);slots.add(slot)
                    heads.sort(key=_ORDER)  # highest batch priority first (the order was fixed when the batch was sealed or recovered), stable within a priority
                attempted=False;wait=float('inf')
                for state in heads:
                    t=now()
                    if t>=deadline or monotonic()>=wire_deadline:break
                    if state['next']>t:wait=min(wait,state['next']-t);continue
                    if not state['ambiguous']:
                        if self._policy_expired():
                            with self._lock:
                                self._remove(state['batch'],'policy_expired')
                                if spool:self.persist()
                            attempted=True;continue
                    attempted=True;lookup=state['ambiguous'];state['ambiguous']=True
                    if spool:
                        try:self.persist()
                        except (OSError,ValueError):self._counts['spool_failed']=self._counts.get('spool_failed',0)+1;return self._report(receipts,True)
                    token=EXPORTING.set(True)
                    try:out=self.transport.lookup(state['batch'],wire_deadline) if lookup else self.transport.send(state['batch'],wire_deadline)
                    except Exception:out=Outcome('ambiguous')
                    finally:EXPORTING.reset(token)
                    with self._lock:
                        if self._closed:return self._report(receipts,self.pending>0)
                        if out.kind=='receipt' and verify_receipt(state['batch'],out.receipt,lookup):
                            self._acknowledge_signal_losses(state['batch'],out.receipt);receipts.append(out.receipt);self._remove(state['batch'])
                            if spool:self.persist()
                            continue
                        if out.kind=='denied':self._denied=True;self._counts['unauthorized']=self._counts.get('unauthorized',0)+1;break
                        if out.kind=='terminal' and not lookup:self._remove(state['batch'],'terminal_rejected');self.persist();continue
                        if out.kind=='not_found' and lookup:
                            if state['batch'].policy_revision!=self.descriptor.policy_revision:self._remove(state['batch'],'policy_changed');self.persist();continue
                            if self._policy_expired():self._remove(state['batch'],'policy_expired');self.persist();continue
                            state['ambiguous']=False
                        elif out.kind=='retryable' and not lookup:state['ambiguous']=False
                        state['next']=self.now()+max(retry_delay(state['attempt'],self.random),out.retry_after or 0);state['attempt']+=1;self.persist()
                if self._denied or not self.pending:break
                if attempted:continue
                delay=min(wait,deadline-self.now(),wire_deadline-time.monotonic())
                if delay<=0:break
                time.sleep(delay)
            return self._report(receipts,self.pending>0 and (self.now()>=deadline or time.monotonic()>=wire_deadline))
        finally:self._flush_lock.release()
    def release(self):
        """Release only owned transport/disk leases, retaining encrypted pending state."""
        try:self.transport.close()
        finally:
            if self.spool:self.spool.close()
    def close(self,timeout=2.0):
        """Flush within `timeout`, release leases and return a FlushReport whose `dropped` counts records destroyed by this close.

        Without a spool every record still pending after the bounded flush is destroyed and counted as `closed_pending`;
        with a spool the encrypted work is retained for the next process and `dropped` is 0."""
        with self._lock:
            if self._closed:return None
            self._closing=True
        report=None;dropped=0
        try:report=self.flush(timeout)
        finally:
            with self._lock:
                self._closed=True
                try:self.persist()
                finally:
                    self.release()
                    if not self.spool:
                        dropped=len(self._entries)+sum(bool(b['unbatched']) for b in self._loss_buckets.values())
                        self._loss('closed_pending',dropped)
                        for b in self._loss_buckets.values():b['unbatched']=0;b['start']=None;b['end']=None
                        self._entries.clear();self._batches.clear();self._bytes=512*len(self._loss_buckets)
        return replace(report,lost=self._lost,dropped=dropped)
