// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test,expect} from 'bun:test';
import {config,signed,ORG,PROJECT,SOURCE,BUILD} from './fixture.ts';
import {DeliveryQueue,retryDelay} from '../src/queue.ts';
import {routeRecord,ownerKey,nativeCanonical,hashBytes} from '../src/routing.ts';
import {verifyReceipt,HttpsReceiptTransport,retryAfter,strictJSON,type FrozenBatch,type ReceiptTransport,type Outcome} from '../src/transport.ts';
import {EncryptedSpool} from '../src/spool.ts';
import {Client} from '../src/client.ts';
import type {Config,RoutingDescriptor} from '../src/types.ts';
import {mkdtemp,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openEncryptedSpool} from '../../node/src/spool.ts';
import {parseSafeRecord,object,array} from '../src/wire.ts';
const descriptor:RoutingDescriptor={version:1,org:ORG,project:PROJECT,source:SOURCE,routing_version:1,slots:64,policy_revision:'1'};
const settings=():Config=>({...config(),resource:{service_id:'6'.repeat(32),environment_id:'7'.repeat(32),build_id:BUILD,instance_pseudonym:'worker-1',labels:[]},descriptor});
function record(id='8'.repeat(32),kind='error'):string{return JSON.stringify({id,kind,observed_at_ns:'9007199254740993',policy_revision:'1',payload:{occurrence_id:id,exception_class:'Error',code:null,build_id:BUILD,handled:true,fatal:false,mechanism:'manual',frames:[]}});}
function receipt(batch:FrozenBatch,historical=false):Record<string,unknown>{return {version:1,batch_id:batch.id,hash:batch.hash,cursor:{group:'9'.repeat(32),index:'9007199254740993'},retain_until_ns:'9007199254740994',signal_deadlines:batch.kinds.map(kind=>({kind,retain_until_ns:'9007199254740994'})),dedup_until_ns:'9007199254740995',...(historical?{historical:true}:{})};}
class Ledger implements ReceiptTransport {
 rows=new Map<string,Record<string,unknown>>();admitted=0;sends:string[]=[];lookups=0;lost=true;revoked=false;restricted=false;
 async send(batch:FrozenBatch):Promise<Outcome>{this.sends.push(batch.body);if(this.revoked)return {kind:'denied'};if(this.restricted)return {kind:'terminal'};const old=this.rows.get(batch.id);if(old&&old.hash!==batch.hash)return {kind:'terminal'};if(!old){this.rows.set(batch.id,receipt(batch));this.admitted++;}if(this.lost){this.lost=false;return {kind:'ambiguous'};}return {kind:'receipt',receipt:this.rows.get(batch.id)!};}
 async lookup(batch:FrozenBatch):Promise<Outcome>{this.lookups++;if(this.revoked)return {kind:'denied'};const old=this.rows.get(batch.id);return old?{kind:'receipt',receipt:{...old,historical:true}}:{kind:'not_found'};}
 close():void{}
}
test('lost commit uses historical lookup without reappend after restriction/deletion',async()=>{
 const ledger=new Ledger(),q=new DeliveryQueue(settings(),ledger);q.enqueue(record());expect((await q.flush(10)).pending).toBe(1);ledger.restricted=true;
 const report=await q.flush(1000);expect(report.pending).toBe(0);expect(report.receipts[0]?.historical).toBe(true);expect(report.acknowledgedCursors).toEqual(['9'.repeat(32)+':9007199254740993']);expect(ledger.admitted).toBe(1);expect(ledger.sends.length).toBe(1);expect(ledger.lookups).toBe(1);
});
test('invalid durable receipt and revoked source never drain',async()=>{
 const ledger=new Ledger();ledger.lost=false;const send=ledger.send.bind(ledger);ledger.send=async b=>{const out=await send(b);return {...out,receipt:{...out.receipt,hash:'0'.repeat(64)}};};
 const q=new DeliveryQueue(settings(),ledger);q.enqueue(record());expect((await q.flush(10)).pending).toBe(1);ledger.revoked=true;await q.flush(1000);const n=ledger.sends.length;await q.flush(10);expect(ledger.sends.length).toBe(n);expect(q.pending).toBe(1);
});
test('receipt validates exact kinds cursor and minimum not HTTP status',()=>{
 const q=new DeliveryQueue(settings(),new Ledger());q.enqueue(record());const b=q.freeze()[0]!;const good=receipt(b);expect(verifyReceipt(b,good,false)).toBe(true);
 for(const bad of [{...good,cursor:{group:'9'.repeat(32),index:'0'}},{...good,signal_deadlines:[]},{...good,retain_until_ns:'9007199254740995'},{...good,batch_id:'a'.repeat(32)},{...good,historical:true}])expect(verifyReceipt(b,bad,false)).toBe(false);
 expect(verifyReceipt(b,good,true)).toBe(false);
});
test('bounds expiry priority and jitter are actual queue behavior',()=>{
 let now=0;const q=new DeliveryQueue(settings(),new Ledger(),{now:()=>now});for(let i=0;i<1024;i++)expect(q.enqueue(record((i+1).toString(16).padStart(32,'0')))).toBe(true);expect(q.enqueue(record('a'.repeat(32)))).toBe(false);expect(q.pending).toBe(1024);now=300000;expect(q.pending).toBe(0);expect(q.diagnostics().queue_expired).toBe(1024);
 for(let i=0;i<20;i++)for(const rng of [()=>0,()=>1]){expect(retryDelay(i,rng)).toBeGreaterThanOrEqual(250);expect(retryDelay(i,rng)).toBeLessThanOrEqual(30000);}
 const priority=new DeliveryQueue({...settings(),maxRecords:2},new Ledger());const low=JSON.parse(record('b'.repeat(32),'log'));low.payload={severity:'info',template_id:'operation.failed',template_revision:'1',fields:{},line:'approved',stream_labels:[],structured_metadata:{},source_class:'structured'};priority.enqueue(JSON.stringify(low));priority.enqueue(record());expect(priority.enqueue(record('a'.repeat(32)))).toBe(true);expect(priority.records().every(r=>JSON.parse(r).kind==='error')).toBe(true);
});
test('partition precedes identity and concurrent flush cannot overlap lanes',async()=>{
 const ledger=new Ledger();ledger.lost=false;const q=new DeliveryQueue(settings(),ledger);for(let i=0;i<513;i++)q.enqueue(record((i+1).toString(16).padStart(32,'0')));
 const batches=q.freeze();expect(batches.reduce((n,b)=>n+b.count,0)).toBe(513);for(const b of batches){expect(b.count).toBeLessThanOrEqual(512);expect(new TextEncoder().encode(b.body).length).toBeLessThanOrEqual(1048576);for(const r of JSON.parse(b.body).records)expect(routeRecord(r,descriptor,b.producer)).toBe(b.route_slot);}
 const active=new Set<number>();let overlap=false;const send=ledger.send.bind(ledger);ledger.send=async b=>{if(active.has(b.route_slot))overlap=true;active.add(b.route_slot);await Promise.resolve();try{return await send(b);}finally{active.delete(b.route_slot);}};
 await Promise.all([q.flush(),q.flush(),q.flush()]);expect(overlap).toBe(false);expect(q.pending).toBe(0);
});
test('encrypted spool authenticates identity and corruption and never plaintext',async()=>{
 let bytes:Uint8Array|undefined;const backend={read:async()=>bytes,write:async(value:Uint8Array)=>{bytes=value.slice();},close:()=>{}};const key=new Uint8Array(32);const spool=new EncryptedSpool(backend,key,descriptor,'1',2097152);
 await spool.save({canary:'PLAINTEXT_CANARY'});expect(new TextDecoder().decode(bytes)).not.toContain('PLAINTEXT_CANARY');expect(await spool.load()).toEqual({canary:'PLAINTEXT_CANARY'});
 await expect(new EncryptedSpool(backend,key,{...descriptor,project:'a'.repeat(32)},'1',2097152).load()).rejects.toThrow();const damaged=bytes!;damaged[damaged.length-1]=damaged[damaged.length-1]!^1;await expect(spool.load()).rejects.toThrow();
 await expect(new EncryptedSpool(backend,key,descriptor,'1',64).save({large:'x'.repeat(1024)})).rejects.toThrow();
});
test('client flush actually sends and releases only matching receipts',async()=>{
 const ledger=new Ledger();ledger.lost=false;const c=new Client({...settings(),transport:ledger});c.captureException(Error('SECRET'));expect((await c.flush()).pending).toBe(0);expect(ledger.admitted).toBe(1);await c.close();expect(c.bufferedRecords()).toEqual([]);
});
test('cross language owner goldens retain UTF8 and exact integer histogram',async()=>{
 const vectors=await Bun.file(new URL('../../../fixtures/sdk/delivery/routing-vectors.json',import.meta.url)).json();
 for(const v of vectors.vectors){expect(Array.from(ownerKey(v.record,descriptor,'a'.repeat(32)),b=>b.toString(16).padStart(2,'0')).join('')).toBe(v.owner_utf8_hex);expect(routeRecord(v.record,descriptor,'a'.repeat(32))).toBe(v.slot);if(v.record.kind==='metric')expect(routeRecord(v.record,descriptor,'b'.repeat(32))).toBe(v.slot);}
 expect(vectors.vectors[0].record.payload.histogram.integer.count).toBe('9007199254740993');
});
test('policy expiry drops new admission but never blocks original historical lookup',async()=>{
 let now='9007199254740993';const ledger=new Ledger(),q=new DeliveryQueue({...settings(),clockNs:()=>now},ledger);q.enqueue(record());await q.flush(10);now='9223372036854775807';expect((await q.flush(1000)).pending).toBe(0);expect(ledger.sends.length).toBe(1);
 const fresh=new DeliveryQueue({...settings(),clockNs:()=>now},ledger);fresh.enqueue(record('a'.repeat(32)));const report=await fresh.flush();expect(report.pending).toBe(0);expect(report.lost).toBe(1);expect(ledger.sends.length).toBe(1);
});
test('exporter callbacks cannot recursively capture themselves',async()=>{
 const ledger=new Ledger();ledger.lost=false;let client:Client;const send=ledger.send.bind(ledger);ledger.send=async batch=>{client.captureException(Error('EXPORTER_SECRET'));return send(batch);};
 client=new Client({...settings(),transport:ledger});client.captureException(Error('application'));const report=await client.flush();expect(report.pending).toBe(0);expect(ledger.admitted).toBe(1);expect(client.diagnostics().exporter_recursion).toBe(1);await client.close();
});
test('backend encrypted spool persists real frozen bytes across lease restart',async()=>{
 const path=join(await mkdtemp(join(tmpdir(),'soundpost-spool-')),'queue'),key=new Uint8Array(32),ledger=new Ledger();
 const spool=await openEncryptedSpool(path,key,descriptor,'1'),q=new DeliveryQueue(settings(),ledger,{spool});q.enqueue(record());const original=q.freeze()[0]!;await q.flush(0);await spool.close();expect(new TextDecoder().decode(await readFile(path))).not.toContain('occurrence_id');
 const restored=await openEncryptedSpool(path,key,descriptor,'1'),restarted=new DeliveryQueue(settings(),ledger,{spool:restored});ledger.lost=false;const report=await restarted.flush(1500);expect(report.pending).toBe(0);expect(ledger.sends[0]).toBe(original.body);await restarted.close();
});
test('disk write failure leaves visible pending without network admission',async()=>{
 const backend={read:async()=>undefined,write:async()=>{throw Error('disk full');},close(){}},spool=new EncryptedSpool(backend,new Uint8Array(32),descriptor,'1'),ledger=new Ledger(),q=new DeliveryQueue(settings(),ledger,{spool});q.enqueue(record());const report=await q.flush(20);expect(report.pending).toBe(1);expect(ledger.admitted).toBe(0);expect(q.diagnostics().spool_failed).toBeGreaterThan(0);
 await spool.close();
});
test('Go native canonical input goldens retain exact JSON hash',async()=>{
 const vectors=await Bun.file(new URL('../../../fixtures/sdk/delivery/native-vectors.json',import.meta.url)).json();
 for(const v of vectors.vectors){expect(nativeCanonical(v.batch)).toBe(v.canonical_utf8);expect(hashBytes(v.canonical_utf8)).toBe(v.sha256);}
});
test('HTTPS transport omits cookies refuses redirects and uses source-specific headers',async()=>{
 const q=new DeliveryQueue(settings(),new Ledger());q.enqueue(record());const batch=q.freeze()[0]!;const calls:{url:string;options:RequestInit}[]=[];
 for(const sourceClass of ['private','browser'] as const){const transport=new HttpsReceiptTransport({...settings(),sourceClass},async(url,options)=>{calls.push({url,options});return new Response(JSON.stringify(receipt(batch)),{status:200});});expect((await transport.send(batch,performance.now()+1000)).kind).toBe('receipt');await transport.close();}
 for(const call of calls){expect(call.options.credentials).toBe('omit');expect(call.options.redirect).toBe('error');expect(call.options.referrerPolicy).toBe('no-referrer');expect(call.options.method).toBe('POST');expect(call.url).toBe(settings().endpoint);}
 expect(new Headers(calls[0]!.options.headers).get('Authorization')).toBe('Bearer SECRET');expect(new Headers(calls[0]!.options.headers).has('Cookie')).toBe(false);expect(new Headers(calls[1]!.options.headers).get('X-Soundpost-Source')).toBe('SECRET');expect(new Headers(calls[1]!.options.headers).has('Authorization')).toBe(false);
 for(const endpoint of ['http://example.invalid/ingest/v1/batches','https://a:b@example.invalid/ingest/v1/batches','https://example.invalid/ingest/v1/batches?token=secret'])expect(()=>new HttpsReceiptTransport({...settings(),endpoint})).toThrow();
});
test('status handling is terminal denied retryable or ambiguous never status-only ACK',async()=>{
 const q=new DeliveryQueue(settings(),new Ledger());q.enqueue(record());const batch=q.freeze()[0]!;
 for(const [status,want] of [[401,'denied'],[403,'denied'],[409,'terminal'],[422,'terminal'],[429,'retryable'],[503,'retryable'],[302,'terminal']] as const){const transport=new HttpsReceiptTransport(settings(),async()=>new Response('{}',{status,headers:{'Retry-After':'99999'}}));const out=await transport.send(batch,performance.now()+1000);expect(out.kind).toBe(want);if(want==='retryable')expect(out.retryAfterMs).toBe(30000);transport.close();}
 expect(retryAfter('0')).toBe(250);expect(retryAfter('999999')).toBe(30000);expect(retryAfter('not-a-date')).toBeUndefined();expect(()=>strictJSON('{\"hash\":\"a\",\"hash\":\"b\"}')).toThrow();
 const bad=new HttpsReceiptTransport(settings(),async()=>new Response('{\"ok\":true}',{status:200}));const queue=new DeliveryQueue(settings(),bad);queue.enqueue(record());expect((await queue.flush(10)).pending).toBe(1);
});
test('frozen same-slot batches split at 512 and preserve all record order',async()=>{
 const ledger=new Ledger();ledger.lost=false;const q=new DeliveryQueue(settings(),ledger);
 for(let i=0;i<513;i++)q.enqueue(JSON.stringify({id:(i+1).toString(16).padStart(32,'0'),kind:'log',observed_at_ns:'9007199254740993',policy_revision:'1',payload:{severity:'error',template_id:'operation.failed',template_revision:'1',fields:{status:503},line:'operation failed: 503',stream_labels:[],structured_metadata:{},source_class:'structured'}}));
 const batches=q.freeze();expect(batches.map(b=>b.count)).toEqual([512,1]);const report=await q.flush();expect(report.pending).toBe(0);const ids=ledger.sends.flatMap(body=>JSON.parse(body).records.map((r:{id:string})=>r.id));expect(ids).toEqual(Array.from({length:513},(_,i)=>(i+1).toString(16).padStart(32,'0')));
});
test('each concurrent flush owns its own deadline without overlapping a lane',async()=>{
 const ledger=new Ledger();ledger.lost=false;const gate=Promise.withResolvers<void>(),entered=Promise.withResolvers<void>(),send=ledger.send.bind(ledger);ledger.send=async batch=>{entered.resolve();await gate.promise;return send(batch);};
 const q=new DeliveryQueue(settings(),ledger);q.enqueue(record());const first=q.flush(1000);await entered.promise;const start=performance.now();const second=await q.flush(10);expect(performance.now()-start).toBeLessThan(200);expect(second.pending).toBe(1);expect(second.deadlineExceeded).toBe(true);gate.resolve();expect((await first).pending).toBe(0);expect(ledger.sends.length).toBe(1);
});
test('policy-bound spool recovers original historical identity after restrictive policy restart',async()=>{
 const path=join(await mkdtemp(join(tmpdir(),'soundpost-history-')),'queue'),key=new Uint8Array(32),ledger=new Ledger(),old=settings();const spool=await openEncryptedSpool(path,key,descriptor,'1'),q=new DeliveryQueue(old,ledger,{spool});q.enqueue(record());expect((await q.flush(200)).pending).toBe(1);expect(ledger.sends.length).toBe(1);await q.flush(0);await spool.close();ledger.restricted=true;
 const policyDocument=JSON.parse(atob(old.policy.payload.replace(/-/g,'+').replace(/_/g,'/')));policyDocument.revision='2';const current={...old,policy:signed(nativeCanonical(policyDocument)),descriptor:{...descriptor,policy_revision:'2'}};
 const restored=await openEncryptedSpool(path,key,current.descriptor,'2'),restarted=new DeliveryQueue(current,ledger,{spool:restored});const report=await restarted.flush(1000);expect(report.pending).toBe(0);expect(report.receipts[0]?.historical).toBe(true);expect(ledger.admitted).toBe(1);expect(ledger.sends.length).toBe(1);await restarted.close();
});
test('all ten closed native payloads reject unknown nested content before buffering',async()=>{
 const vectors=await Bun.file(new URL('../../../fixtures/sdk/delivery/native-vectors.json',import.meta.url)).json();
 for(const {batch} of vectors.vectors){const r=batch.records[0],safe={id:r.id,kind:r.kind,observed_at_ns:r.observed_at_ns,policy_revision:batch.policy_revision,payload:r.payload};expect(parseSafeRecord(nativeCanonical(safe)).kind).toBe(r.kind);if(r.payload.clock){const hostile=structuredClone(safe);hostile.payload.clock.raw_content='SECRET_CANARY';expect(()=>parseSafeRecord(nativeCanonical(hostile))).toThrow();}}
});
test('frozen snapshots keep normalized record bytes without retaining a second payload copy',()=>{
 const q=new DeliveryQueue(settings(),new Ledger());q.enqueue(record());const before=q.records();q.freeze();expect(q.records()).toEqual(before);q.freeze();expect(q.records()).toEqual(before);
});
test('native optional nulls and empty optional histogram slices normalize like Go DTOs',async()=>{
 const input=JSON.parse(record());input.payload.trace_id=null;expect(parseSafeRecord(JSON.stringify(input)).payload).not.toHaveProperty('trace_id');
 const vectors=await Bun.file(new URL('../../../fixtures/sdk/delivery/native-vectors.json',import.meta.url)).json(),metric=vectors.vectors.find((v:{batch:{records:{kind:string}[]}})=>v.batch.records[0]?.kind==='metric').batch.records[0];metric.payload.histogram.integer.custom_bounds=[];metric.payload.histogram.integer.positive_counts=[];
 const safe={id:metric.id,kind:metric.kind,observed_at_ns:metric.observed_at_ns,policy_revision:'1',payload:metric.payload};const decoded=parseSafeRecord(nativeCanonical(safe));expect(object(object(decoded.payload.histogram).integer)).not.toHaveProperty('custom_bounds');expect(object(object(decoded.payload.histogram).integer)).not.toHaveProperty('positive_counts');
});
test('approved native profile metadata is closed exact and never persists corrections',async()=>{
 const {vectors}=await Bun.file(new URL('../../../fixtures/sdk/delivery/native-profile-vectors.json',import.meta.url)).json();
 for(const {batch,canonical_utf8,sha256} of vectors){const r=batch.records[0],safe={id:r.id,kind:r.kind,observed_at_ns:r.observed_at_ns,policy_revision:batch.policy_revision,payload:r.payload};expect(parseSafeRecord(nativeCanonical(safe)).kind).toBe('profile_chunk');expect(nativeCanonical(batch)).toBe(canonical_utf8);expect(hashBytes(canonical_utf8)).toBe(sha256);
  const unknown=structuredClone(safe);unknown.payload.native_domain.raw_memory='SECRET_CANARY';expect(()=>parseSafeRecord(nativeCanonical(unknown))).toThrow();
  const missing=structuredClone(safe);missing.payload.native_capabilities.pop();expect(()=>parseSafeRecord(nativeCanonical(missing))).toThrow();const duplicate=structuredClone(safe);duplicate.payload.native_capabilities[1]=duplicate.payload.native_capabilities[0];expect(()=>parseSafeRecord(nativeCanonical(duplicate))).toThrow();
  if(r.payload.samples.length){const sample=r.payload.samples[0];expect(sample.native.period).toBe('9007199254740993');const invalid=structuredClone(safe);invalid.payload.samples[0].native.unit='nanoseconds';expect(()=>parseSafeRecord(nativeCanonical(invalid))).toThrow();}
  if(r.payload.intervals.length){const correction=structuredClone(safe);correction.payload.intervals[0].correction=true;expect(()=>parseSafeRecord(nativeCanonical(correction))).toThrow();}
 }
});
test('restart expires a whole frozen lane batch at its earliest capture',async()=>{
 const path=join(await mkdtemp(join(tmpdir(),'soundpost-expiry-')),'queue'),key=new Uint8Array(32),ledger=new Ledger(),spool=await openEncryptedSpool(path,key,descriptor,'1'),q=new DeliveryQueue(settings(),ledger,{spool});
 for(const id of ['8'.repeat(32),'a'.repeat(32)])q.enqueue(JSON.stringify({id,kind:'log',observed_at_ns:'9007199254740993',policy_revision:'1',payload:{severity:'error',template_id:'operation.failed',template_revision:'1',fields:{status:503},line:'operation failed: 503',stream_labels:[],structured_metadata:{},source_class:'structured'}}));
 await q.flush(0);const stored=object(await spool.load()),first=object(array(stored.entries)[0]);first.wall=Date.now()-300001;object(object(array(stored.batches)[0]).batch).firstCapture=first.wall;await spool.save(stored);await spool.close();
 const recovered=new DeliveryQueue(settings(),ledger,{spool:await openEncryptedSpool(path,key,descriptor,'1')});const report=await recovered.flush();expect(report.pending).toBe(0);expect(report.acknowledgedBatchIds).toEqual([]);expect(recovered.diagnostics().queue_expired).toBe(2);expect(ledger.admitted).toBe(0);await recovered.close();
});
test('resource identities never translate human aliases and instance strings match Go bounds',()=>{
 for(const field of ['service_id','environment_id','build_id'])expect(()=>new Client({...settings(),resource:{...settings().resource,[field]:'display-alias'}})).toThrow();
 expect(()=>new Client({...settings(),resource:{...settings().resource,instance_pseudonym:'not-approved-雪'}})).toThrow();
});
test('metric start timestamp is exact optional signed metadata not an observed-time alias',async()=>{
 const vectors=await Bun.file(new URL('../../../fixtures/sdk/delivery/native-vectors.json',import.meta.url)).json(),metric=vectors.vectors.find((v:{batch:{records:{kind:string}[]}})=>v.batch.records[0]?.kind==='metric').batch.records[0];
 for(const start of ['9007199254741993','-9007199254740993','0']){const payload=structuredClone(metric.payload);payload.start_timestamp_ns=start;const safe={id:metric.id,kind:metric.kind,observed_at_ns:metric.observed_at_ns,policy_revision:'1',payload};const decoded=parseSafeRecord(nativeCanonical(safe));expect(decoded.payload.start_timestamp_ns).toBe(start);expect(decoded.observed_at_ns).toBe('9007199254740993');}
 const payload=structuredClone(metric.payload);payload.start_timestamp_ns=null;expect(parseSafeRecord(nativeCanonical({id:metric.id,kind:metric.kind,observed_at_ns:metric.observed_at_ns,policy_revision:'1',payload})).payload).not.toHaveProperty('start_timestamp_ns');
 const q=new DeliveryQueue(settings(),new Ledger());payload.start_timestamp_ns={raw_content:'SECRET_CANARY'};expect(()=>q.enqueue(nativeCanonical({id:metric.id,kind:metric.kind,observed_at_ns:metric.observed_at_ns,policy_revision:'1',payload}))).toThrow();expect(q.records()).toEqual([]);
});
test('native frames retain only module hashes authorized artifact IDs and safe symbols',async()=>{
 const {vectors}=await Bun.file(new URL('../../../fixtures/sdk/delivery/native-profile-vectors.json',import.meta.url)).json(),r=vectors[0].batch.records[0],safe={id:r.id,kind:r.kind,observed_at_ns:r.observed_at_ns,policy_revision:'1',payload:structuredClone(r.payload)};safe.payload.frames[0]={module_id:'1'.repeat(64),function:'safe._$@:',artifact_id:'4'.repeat(32),offset:'9007199254740993',reason:''};expect(parseSafeRecord(nativeCanonical(safe)).kind).toBe('profile_chunk');
 for(const field of ['module_id','function','artifact_id']){const invalid=structuredClone(safe);invalid.payload.frames[0][field]='/private/source/CANARY';expect(()=>parseSafeRecord(nativeCanonical(invalid))).toThrow();}
 const offcpu=structuredClone(safe);offcpu.payload.method='native_offcpu';offcpu.payload.units='nanoseconds';expect(()=>parseSafeRecord(nativeCanonical(offcpu))).toThrow();
 const revision=structuredClone(safe);revision.payload.policy_revision='2';expect(()=>parseSafeRecord(nativeCanonical(revision))).toThrow();
});
test('mixed signal receipt keeps distinct deadlines and verifies their minimum',async()=>{
 const ledger=new Ledger();ledger.lost=false;const q=new DeliveryQueue({...settings(),producer:'a'.repeat(32)},ledger);q.enqueue(record('00000000000000000000000000000003'));
 q.enqueue(JSON.stringify({id:'8'.repeat(32),kind:'log',observed_at_ns:'9007199254740993',policy_revision:'1',payload:{severity:'error',template_id:'operation.failed',template_revision:'1',fields:{status:503},line:'operation failed: 503',stream_labels:[],structured_metadata:{},source_class:'structured'}}));const batch=q.freeze()[0]!;expect(batch.count).toBe(2);
 const deadlines=[{kind:'error',retain_until_ns:'9007199254741993'},{kind:'log',retain_until_ns:'9007199254741093'}],send=ledger.send.bind(ledger);ledger.send=async b=>{const outcome=await send(b);if(!outcome.receipt)return outcome;const mixed={...outcome.receipt,signal_deadlines:deadlines,retain_until_ns:'9007199254741093'};ledger.rows.set(b.id,mixed);return {kind:'receipt',receipt:mixed};};
 const report=await q.flush();expect(report.pending).toBe(0);expect(report.receipts[0]?.signal_deadlines).toEqual(deadlines);expect(report.receipts[0]?.retain_until_ns).toBe('9007199254741093');expect(verifyReceipt(batch,{...report.receipts[0],retain_until_ns:'9007199254741993'},false)).toBe(false);
});
test('exclusive encrypted backend lease cannot be stolen and reopens after release',async()=>{
 const path=join(await mkdtemp(join(tmpdir(),'soundpost-lease-')),'queue'),key=new Uint8Array(32),first=await openEncryptedSpool(path,key,descriptor,'1');await expect(openEncryptedSpool(path,key,descriptor,'1')).rejects.toThrow();await first.save({count:1});await first.close();const second=await openEncryptedSpool(path,key,descriptor,'1');expect(await second.load()).toEqual({count:1});await second.close();
});
test('non-receipt HTTP responses release unread body resources without becoming ACKs',async()=>{
 let cancelled=false;const body=new ReadableStream<Uint8Array>({cancel(){cancelled=true;}}),transport=new HttpsReceiptTransport(settings(),async()=>new Response(body,{status:403})),q=new DeliveryQueue(settings(),new Ledger());q.enqueue(record());const result=await transport.send(q.freeze()[0]!,performance.now()+1000);expect(result.kind).toBe('denied');expect(cancelled).toBe(true);transport.close();
});
test('signed traces and jobs are separate strict permissions with absent deny defaults',()=>{
 const base=settings();expect(new Client(base).policyDecision.traces).toBe(false);expect(new Client(base).policyDecision.jobs).toBe(false);
 const payload=JSON.parse(atob(base.policy.payload.replace(/-/g,'+').replace(/_/g,'/')));payload.errors=false;payload.traces=true;payload.jobs=true;const policy=signed(nativeCanonical(payload)),client=new Client({...base,policy});expect(client.policyDecision.errors).toBe(false);expect(client.policyDecision.traces).toBe(true);expect(client.policyDecision.jobs).toBe(true);
 const narrowed=new Client({...base,policy,deploymentTraces:false,deploymentJobs:false});expect(narrowed.policyDecision.traces).toBe(false);expect(narrowed.policyDecision.jobs).toBe(false);
 for(const flag of ['traces','jobs']){const malformed={...payload,[flag]:'true'};expect(()=>new Client({...base,policy:signed(nativeCanonical(malformed))})).toThrow();}
});
test('native losses and throttle transitions are bounded typed evidence not durations',async()=>{
 const {vectors}=await Bun.file(new URL('../../../fixtures/sdk/delivery/native-profile-vectors.json',import.meta.url)).json();
 for(const {batch} of vectors){const r=batch.records[0],safe={id:r.id,kind:r.kind,observed_at_ns:r.observed_at_ns,policy_revision:'1',payload:r.payload};const parsed=parseSafeRecord(nativeCanonical(safe));expect(parsed.payload.native_loss).toEqual(r.payload.native_loss);
  const invalid=structuredClone(safe),transition=invalid.payload.native_loss.find((v:{reason:string})=>v.reason==='throttled'||v.reason==='unthrottled');transition.count='1';expect(()=>parseSafeRecord(nativeCanonical(invalid))).toThrow();
  const overflow=structuredClone(safe);overflow.payload.native_loss=Array.from({length:257},()=>r.payload.native_loss[0]);expect(()=>parseSafeRecord(nativeCanonical(overflow))).toThrow();
  const raw=structuredClone(safe);raw.payload.native_loss[0].raw_stack='SECRET_CANARY';expect(()=>parseSafeRecord(nativeCanonical(raw))).toThrow();
 }
});
function lossSettings():Config{const c=settings(),doc=JSON.parse(atob(c.policy.payload.replace(/-/g,'+').replace(/_/g,'/')));doc.loss=true;return {...c,policy:signed(nativeCanonical(doc))};}
test('native sampling loss coalesces exact counts and ACKs only its frozen range',async()=>{
 const ledger=new Ledger(),q=new DeliveryQueue(lossSettings(),ledger);expect(q.recordSignalLoss('span','policy',9007199254740993n,'9007199254740993')).toBe(true);expect(q.recordSignalLoss('span','policy',1n,'9007199254740994')).toBe(true);
 const first=JSON.parse(q.records()[0]!);expect(first.kind).toBe('loss');expect(first.payload.count).toBe('9007199254740994');expect(first.payload.last_ack).toBe(null);
 expect((await q.flush(10)).pending).toBe(1);const frozen=ledger.sends[0]!;expect(q.recordSignalLoss('span','policy',1n,'9007199254740995')).toBe(true);const report=await q.flush(1500);expect(report.pending).toBe(0);expect(report.lost).toBe(0);expect(ledger.sends[0]).toBe(frozen);expect(ledger.admitted).toBe(2);
 const state=q.signalLossCounters()[0]!;expect(state.observed_count).toBe('9007199254740995');expect(state.acknowledged_count).toBe('9007199254740995');expect(state.pending_count).toBe('0');expect(state.unexported_count).toBe('0');
 const body=JSON.parse(frozen);expect(body.records[0].payload.source).toBe(SOURCE);expect(body.records[0].payload.producer).toBe(body.producer);expect(body.records[0].payload.producer_epoch).toMatch(/^[0-9a-f]{32}$/);
});
test('native loss permission and bounded pending aggregation never manufacture an ACK',async()=>{
 const denied=new DeliveryQueue(settings(),new Ledger());expect(denied.recordSignalLoss('span','policy',1n,'9007199254740993')).toBe(false);expect(denied.records()).toEqual([]);
 const q=new DeliveryQueue({...lossSettings(),maxBytes:1024,maxRecords:1},new Ledger());expect(q.recordSignalLoss('span','queue_full',1n,'9007199254740993')).toBe(true);const report=await q.flush(10);expect(report.pending).toBe(1);expect(report.acknowledgedBatchIds).toEqual([]);expect(q.signalLossCounters()[0]!.acknowledged_count).toBe('0');
});
test('encrypted restart preserves original loss identity and a distinct new producer epoch',async()=>{
 const path=join(await mkdtemp(join(tmpdir(),'soundpost-native-loss-')),'queue'),key=new Uint8Array(32),ledger=new Ledger(),cfg=lossSettings(),spool=await openEncryptedSpool(path,key,descriptor,'1'),q=new DeliveryQueue(cfg,ledger,{spool});await q.flush(0);expect(q.recordSignalLoss('span','policy',1n,'9007199254740993')).toBe(true);expect((await q.flush(200)).pending).toBe(1);expect(ledger.sends.length).toBe(1);const original=ledger.sends[0]!;await q.flush(0);await spool.close();
 const restored=await openEncryptedSpool(path,key,descriptor,'1'),restarted=new DeliveryQueue(cfg,ledger,{spool:restored});await restarted.flush(0);expect(restarted.recordSignalLoss('span','policy',1n,'9007199254740994')).toBe(true);expect((await restarted.flush(1500)).pending).toBe(0);expect(ledger.admitted).toBe(2);expect(ledger.sends[0]).toBe(original);const counters=restarted.signalLossCounters();expect(counters.length).toBe(2);expect(counters[0]!.producer_epoch).not.toBe(counters[1]!.producer_epoch);expect(counters.every(c=>c.acknowledged_count==='1'&&c.pending_count==='0')).toBe(true);await restarted.close();
});
test('frozen body keeps replacement-pattern characters in record content byte-exact',()=>{
 const tokens=['$&','$$',"$'",'$`','$1','cost $& done $$5'];
 const records=tokens.map((token,index)=>JSON.stringify({id:(index+1).toString(16).padStart(32,'0'),kind:'log',observed_at_ns:'9007199254740993',policy_revision:'1',payload:{severity:'error',template_id:'operation.failed',template_revision:'1',fields:{status:503},line:'operation failed: '+token,stream_labels:[],structured_metadata:{},source_class:'structured'}}));
 const config={...settings(),resource:{...settings().resource,instance_pseudonym:'worker$$1$ x'}},q=new DeliveryQueue(config,new Ledger());for(const text of records)expect(q.enqueue(text)).toBe(true);
 const batches=q.freeze();expect(batches.reduce((n,b)=>n+b.count,0)).toBe(tokens.length);const seen:string[]=[];
 for(const batch of batches){const parsed=JSON.parse(batch.body);expect(parsed.records.length).toBe(batch.count);
  const expected=nativeCanonical({version:1,project:parsed.project,source:parsed.source,producer:parsed.producer,id:parsed.id,policy_revision:parsed.policy_revision,route_slot:parsed.route_slot,records:parsed.records});
  expect(batch.body).toBe(expected);expect(batch.hash).toBe(hashBytes(batch.body));
  for(const r of parsed.records){seen.push(r.payload.line);expect(r.resource.instance_pseudonym).toBe('worker$$1$ x');}}
 expect(seen.sort()).toEqual(tokens.map(t=>'operation failed: '+t).sort());
});
