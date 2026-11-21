// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {Config,FlushReport,RoutingDescriptor,ExportContext} from './types.ts';
import {randomHex,leanSpanPayload,type LiveSpan} from './tracing.ts';
import {decimal,unixNano,canonicalId,utf8Size,compareNano} from './policy.ts';
import {hashBytes,nativeCanonical,resourceWire,routeRecord,routeSlot,validateDescriptor,kinds} from './routing.ts';
import {verifyReceipt,type FrozenBatch,type ReceiptTransport,type Outcome} from './transport.ts';
import type {EncryptedSpool} from './spool.ts';
import {object,array,text,parseSafeRecord,strippedFields,type NativeRecord} from './wire.ts';
export type Entry={text:string;wire:string;wireBytes:number;size:number;at:number;wall:number;kind:string;slot:number;lazy:number;batch?:string;position?:number;lossKey?:string;lossCount?:bigint};
export type BatchState={batch:FrozenBatch;ambiguous:boolean;attempt:number;next:number;rank:number};
type LossBucket={epoch:string;signal:string;reason:string;revision:string;observed:bigint;acked:bigint;unbatched:bigint;start:string|null;end:string|null;at:number;wall:number};
export function retryDelay(attempt:number,random:()=>number=Math.random):number{const cap=Math.min(30000,250*2**Math.min(attempt,7));return Math.max(250,Math.min(30000,cap*(.5+.5*Math.max(0,Math.min(1,random())))));}
const routeEncoder=new TextEncoder();
const id=():string=>randomHex(16);
export const priority=(kind:string):number=>{switch(kind){case 'error':case 'condition':case 'capability':case 'loss':case 'job_attempt':return 2;case 'log':return 1;default:return 0;}};
// The fixed parts of a span record's serialization (id, kind and observed_at_ns before the payload, the resource after it).
export const LEAN_KIND='","kind":"span","observed_at_ns":"',RESOURCE_OPEN=',"resource":';
// A flush works for at most SLICE_MS at a time and then gives the event loop a turn, so a host serving requests is never stalled for the whole flush.
const SLICE_MS=0.5;
const immediate:((callback:()=>void)=>unknown)|undefined=Reflect.get(globalThis,'setImmediate');
const yieldToLoop=():Promise<void>=>new Promise<void>(resolve=>{if(immediate!==undefined)immediate(resolve);else setTimeout(resolve,0);});
export class DeliveryQueue {
 protected held:Entry[]=[];protected batches:BatchState[]=[];protected bytes=0;protected losses=0;protected denied=false;protected closed=false;protected closing=false;
 // Unbatched entries per priority class (undefined = recount on demand), and a lower bound of the oldest entry's `at` (stale-low is safe: it only costs one rescan).
 protected evictable:number[]|undefined;protected oldest=Infinity;
 protected get entries():Entry[]{return this.held;}
 protected set entries(value:Entry[]){this.held=value;this.evictable=undefined;}
 protected readonly now:()=>number;protected readonly wireNow:()=>number;protected readonly sleep:(ms:number)=>Promise<void>;protected readonly random:()=>number;protected readonly descriptor:RoutingDescriptor;protected readonly resource:Record<string,unknown>;protected producer:string;protected readonly policyExpires:string;protected recovering=false;
 protected readonly counts:Record<string,number>=Object.create(null) as Record<string,number>;protected running:Promise<FlushReport>|undefined;protected readonly spool:EncryptedSpool|undefined;protected recovered=false;protected persistChain:Promise<void>=Promise.resolve();
 protected recoveryTask:Promise<void>|undefined;
 protected readonly lossEpoch=canonicalId(id());protected readonly lossBuckets=new Map<string,LossBucket>();protected readonly allowLoss:boolean;protected materializingLoss=false;protected lastAck:{group:string;index:string}|null=null;
 constructor(protected readonly config:Config,protected readonly transport:ReceiptTransport,protected readonly options:{now?:()=>number;wireNow?:()=>number;sleep?:(ms:number)=>Promise<void>;random?:()=>number;spool?:EncryptedSpool;context?:ExportContext}={}){
  const envelope=object(JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(config.policy.payload.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0)))));this.policyExpires=unixNano(envelope.expires_ns);
  const deploymentLoss=object(config).deploymentLoss;this.allowLoss=envelope.loss===true&&(deploymentLoss===undefined||deploymentLoss===true);
  this.descriptor=validateDescriptor(config.descriptor??{version:1,org:config.org,project:config.project,source:config.source,routing_version:1,slots:64,policy_revision:decimal(envelope.revision)});
  if(this.descriptor.org!==config.org||this.descriptor.project!==config.project||this.descriptor.source!==config.source||this.descriptor.policy_revision!==envelope.revision)throw Error('routing identity mismatch');
  this.resource=resourceWire(config.resource,config.build);this.producer=canonicalId(config.producer??id());this.now=options.now??(()=>performance.now());this.wireNow=options.wireNow??(()=>performance.now());this.sleep=options.sleep??(ms=>new Promise<void>(resolve=>{setTimeout(resolve,ms);}));this.random=options.random??Math.random;this.spool=options.spool??config.spool;
 if(this.spool!==undefined&&!this.spoolSupported())throw Error('an encrypted spool needs SpoolingDeliveryQueue');this.spool?.assertBinding(this.descriptor,this.descriptor.policy_revision);this.resourceText=nativeCanonical(this.resource);this.resourceBytes=utf8Size(this.resourceText);
  // routeRecord's input for a span, laid out once: length-prefixed org, project, kind and owner (the 32-character trace ID, written per span at spanRouteAt).
  const org=new TextEncoder().encode(this.descriptor.org),project=new TextEncoder().encode(this.descriptor.project),kind=new TextEncoder().encode("span");
  this.spanRoute=new Uint8Array(16+org.length+project.length+kind.length+32);const view=new DataView(this.spanRoute.buffer);let at=0;
  for(const part of [org,project,kind]){view.setUint32(at,part.length,false);at+=4;this.spanRoute.set(part,at);at+=part.length;}
  view.setUint32(at,32,false);this.spanRouteAt=at+4;this.spanRouteTail=this.spanRoute.subarray(this.spanRouteAt);
 }
 protected readonly resourceText:string;protected readonly resourceBytes:number;protected readonly spanRoute:Uint8Array;protected readonly spanRouteAt:number;protected readonly spanRouteTail:Uint8Array;
 /** True only in SpoolingDeliveryQueue (queue_spool.ts), which carries the persistence and recovery code. */
 protected spoolSupported():boolean{return false;}
 persist():Promise<void>{return Promise.resolve();}
 protected recoverOnce():Promise<void>{return Promise.resolve();}
 /** The queue's two serializations of one parsed record: `safe` (stored and spooled form) and `wire` (batch form with the resource) with the wire's UTF-8 size. The payload is canonicalized once and spliced into both; each object's keys are written in canonical order (id, kind, observed_at_ns, payload, then policy_revision or resource). */
 protected serialize(parsed:NativeRecord):{safe:string;wire:string;bytes:number}{
  const head='{"id":'+JSON.stringify(parsed.id)+',"kind":'+JSON.stringify(parsed.kind)+',"observed_at_ns":'+JSON.stringify(parsed.observed_at_ns)+',"payload":'+nativeCanonical(parsed.payload);
  const wire=head+',"resource":'+this.resourceText+'}';
  return {safe:head+',"policy_revision":'+JSON.stringify(parsed.policy_revision)+'}',wire,bytes:utf8Size(wire)};
 }
 /** The compact-store hooks of queued lean spans (lean_slab.ts), which only the Node/Bun queue (SpoolingDeliveryQueue, through RuntimeClient) implements: it relieves a server's garbage collector, which a browser tab's few spans do not need, and it is its own module so the browser core bundle does not carry it. Without a store, `store` takes no span (-1) and `place` serializes the span at once. */
 protected store(span:LiveSpan):number{return -1;}
 /** Gives back what a dropped, evicted, expired or frozen entry holds in the compact store. */
 protected dropped(entry:Entry):void{}
 /** A lean span serialized at once (this queue has no compact store, or its store was full): the record ID, both texts and the route slot, from the span itself. */
 private serializeSpan(span:LiveSpan):{text:string;wire:string;slot:number;bytes:number}{
  const head='{"id":"'+id()+LEAN_KIND+span.startWall+'","payload":'+leanSpanPayload(span);
  routeEncoder.encodeInto(span.context.traceId,this.spanRouteTail);
  return {text:head+',"policy_revision":"'+this.descriptor.policy_revision+'"}',wire:head+RESOURCE_OPEN+this.resourceText+'}',slot:routeSlot(this.spanRoute),bytes:head.length+RESOURCE_OPEN.length+this.resourceBytes+1};
 }
 /** Builds the batch form of every queued lean span that has none yet, stopping once performance.now() reaches `end`; false when it stopped early. Nothing to do without a compact store. */
 protected materializeWires(end:number):boolean{return true;}
 /** Serializes every lean span still in the compact store completely (safe text and batch form). Nothing to do without one. */
 protected materializeAll():void{}
 protected lossKey(epoch:string,signal:string,reason:string):string{return epoch+":"+signal+":"+reason;}
 protected validSignalLoss(signal:string,reason:string):boolean{return kinds.some(kind=>kind===signal)&&signal!=="loss"&&["queue_full","expired","policy","unsupported","ring_overflow","reorder_gap","transport","shutdown","truncated"].includes(reason);}
 recordSignalLoss(signal:string,reason:string,count:bigint,atNs:string):boolean{
  if(this.closed||this.closing||this.denied||!this.allowLoss||this.options.context?.active()){this.counts.native_loss_unavailable=(this.counts.native_loss_unavailable??0)+1;return false;}
  try{unixNano(atNs);if(typeof signal!=="string"||typeof reason!=="string"||!this.validSignalLoss(signal,reason)||typeof count!=="bigint"||count<=0n||count>18446744073709551615n||BigInt(atNs)>=BigInt(this.policyExpires))throw Error();}catch{this.counts.invalid_signal_loss=(this.counts.invalid_signal_loss??0)+1;return false;}
  if(this.spool&&!this.recovered){void this.recoverOnce().catch(()=>{this.counts.spool_failed=(this.counts.spool_failed??0)+1;});this.loss("native_loss_recovery_pending");return false;}
  this.expire();this.expireSignalLosses();const key=this.lossKey(this.lossEpoch,signal,reason);let bucket=this.lossBuckets.get(key);
  if(!bucket){while(this.bytes+512>(this.config.maxBytes??2097152)){const index=this.entries.findIndex(e=>!e.batch&&priority(e.kind)<2);if(index<0){this.loss("native_loss_unbuffered");return false;}const [old]=this.entries.splice(index,1);this.dropped(old!);this.evictable=undefined;this.bytes-=old!.size;this.loss("queue_pressure");}bucket={epoch:this.lossEpoch,signal,reason,revision:this.descriptor.policy_revision,observed:0n,acked:0n,unbatched:0n,start:null,end:null,at:this.now(),wall:Date.now()};this.lossBuckets.set(key,bucket);this.bytes+=512;}
  if(bucket.observed+count>18446744073709551615n){this.loss("native_loss_overflow");return false;}
  bucket.observed+=count;if(bucket.unbatched===0n){bucket.start=atNs;bucket.end=atNs;bucket.at=this.now();bucket.wall=Date.now();}else{if(BigInt(atNs)<BigInt(bucket.start!))bucket.start=atNs;if(BigInt(atNs)>BigInt(bucket.end!))bucket.end=atNs;}bucket.unbatched+=count;
  this.materializeSignalLosses();if(this.spool)void this.persist().catch(()=>{this.counts.spool_failed=(this.counts.spool_failed??0)+1;});return true;
 }
 protected expireSignalLosses():void{for(const bucket of this.lossBuckets.values())if(bucket.unbatched>0n&&this.now()-bucket.at>=300000){bucket.unbatched=0n;bucket.start=null;bucket.end=null;this.loss("native_loss_expired");}}
 protected materializeSignalLosses():void{
  if(this.materializingLoss||this.closed||this.recovering||this.denied)return;this.materializingLoss=true;
  try{for(const [key,bucket] of this.lossBuckets){if(bucket.unbatched===0n)continue;
   if(!this.allowLoss||bucket.revision!==this.descriptor.policy_revision){bucket.unbatched=0n;bucket.start=null;bucket.end=null;this.loss("native_loss_policy");continue;}
   if(this.policyExpired())continue;
   const old=this.entries.find(e=>e.lossKey===key&&!e.batch);let record:Record<string,unknown>;let payload:Record<string,unknown>;let total=bucket.unbatched;
   if(old){record=object(JSON.parse(old.text));payload=object(record.payload);total+=old.lossCount!;const start=text(payload.start_ns),end=text(payload.end_ns);payload.start_ns=BigInt(start)<BigInt(bucket.start!)?start:bucket.start;payload.end_ns=BigInt(end)>BigInt(bucket.end!)?end:bucket.end;record.observed_at_ns=payload.end_ns;}
   else{payload={source:this.descriptor.source,producer:this.producer,producer_epoch:bucket.epoch,start_ns:bucket.start,end_ns:bucket.end,signal:bucket.signal,reason:bucket.reason,count:"0",last_ack:null,queue_bytes:"0",queue_records:"0"};record={id:id(),kind:"loss",observed_at_ns:bucket.end,policy_revision:bucket.revision,payload};}
   payload.count=total.toString();payload.last_ack=this.lastAck?{...this.lastAck}:null;payload.queue_bytes=String(this.bytes);payload.queue_records=String(this.entries.length);const encoded=nativeCanonical(record);
   if(old){const s=this.serialize(parseSafeRecord(encoded));if(s.bytes+512>old.size)continue;old.text=encoded;old.wire=s.wire;old.wireBytes=s.bytes;old.lossCount=total;}
   else{if(!this.enqueue(encoded))continue;const entry=this.entries[this.entries.length-1]!;entry.lossKey=key;entry.lossCount=total;entry.at=bucket.at;entry.wall=bucket.wall;if(entry.at<this.oldest)this.oldest=entry.at;}
   bucket.unbatched=0n;bucket.start=null;bucket.end=null;
  }}finally{this.materializingLoss=false;}
 }
 signalLossCounters():readonly Readonly<Record<string,string>>[]{this.expire();this.expireSignalLosses();return Object.freeze([...this.lossBuckets].map(([key,b])=>{const pending=this.entries.filter(e=>e.lossKey===key).reduce((n,e)=>n+(e.lossCount??0n),b.unbatched);return Object.freeze({producer_epoch:b.epoch,signal:b.signal,reason:b.reason,observed_count:b.observed.toString(),acknowledged_count:b.acked.toString(),pending_count:pending.toString(),unexported_count:(b.observed-b.acked-pending).toString()});}));}
 protected acknowledgeSignalLosses(batch:FrozenBatch,receipt:Record<string,unknown>):void{const cursor=object(receipt.cursor);this.lastAck={group:canonicalId(cursor.group),index:decimal(cursor.index)};if(this.lossBuckets.size===0)return;for(const entry of this.entries)if(entry.batch===batch.id&&entry.lossKey){const bucket=this.lossBuckets.get(entry.lossKey);if(!bucket||entry.lossCount===undefined||bucket.acked+entry.lossCount>bucket.observed)throw Error("invalid native loss accounting");bucket.acked+=entry.lossCount;}}
 protected loss(reason:string,count=1):void{this.losses+=count;this.counts[reason]=(this.counts[reason]??0)+count;}
 /** True when the signed policy has expired at the queue's wall clock, or when that clock cannot be read (expired is the safe answer). Strings only: canonical UnixNano values compare without BigInt. */
 protected policyExpired():boolean{
  try{const clock=this.config.clockNs,now=clock?clock():(ms=>ms>0?ms+"000000":String(BigInt(ms)*1000000n))(Date.now());return compareNano(unixNano(now),this.policyExpires)>=0;}catch{return true;}
 }
 protected remove(batch:FrozenBatch,reason?:string):void{this.entries=this.entries.filter(e=>{if(e.batch!==batch.id)return true;this.bytes-=e.size;return false;});const index=this.batches.findIndex(s=>s.batch.id===batch.id);if(index>=0)this.batches.splice(index,1);if(reason)this.loss(reason,batch.count);}
 protected expire():void{
  const now=this.now();if(now-this.oldest<300000)return;
  const expired=new Set(this.entries.filter(e=>now-e.at>=300000).map(e=>e.batch).filter((v):v is string=>v!==undefined));for(const b of [...this.batches])if(expired.has(b.batch.id))this.remove(b.batch,'queue_expired');this.entries=this.entries.filter(e=>{if(now-e.at<300000)return true;this.dropped(e);this.bytes-=e.size;this.loss('queue_expired');return false;});
  let oldest=Infinity;for(const e of this.entries)if(e.at<oldest)oldest=e.at;this.oldest=oldest;
 }
 protected unbatchedCounts():number[]{if(!this.evictable){const counts=[0,0,0];for(const e of this.entries)if(!e.batch)counts[priority(e.kind)]!++;this.evictable=counts;}return this.evictable;}
 /** True, counted as queue_full exactly as enqueue would, when the record cap is reached and no unbatched entry of lower priority could make room for a record of this kind: enqueue would drop it. O(1), so callers can skip serializing a record that is certain to be dropped. */
 rejectsWhenFull(kind:string):boolean{
  if(this.closed||this.closing&&!this.recovering&&!this.materializingLoss)return false;this.expire();
  if(this.entries.length<(this.config.maxRecords??1024))return false;
  const counts=this.unbatchedCounts();for(let lower=priority(kind)-1;lower>=0;lower--)if(counts[lower]!>0)return false;
  this.loss("queue_full");return true;
 }
 get pending():number{this.expire();this.expireSignalLosses();return this.entries.length||(this.lossBuckets.size&&[...this.lossBuckets.values()].some(b=>b.unbatched>0n)?1:0);}
 get lost():number{return this.losses;}
 /** Destroys every queued record of `kind` that has not been frozen into a batch. Returns the number destroyed; not a loss (the owner chose to discard). */
 discardUnsent(kind:string):number{const keep=this.entries.filter(e=>e.batch!==undefined||e.kind!==kind);const count=this.entries.length-keep.length;if(count>0){this.bytes-=this.entries.filter(e=>e.batch===undefined&&e.kind===kind).reduce((n,e)=>n+e.size,0);for(const e of this.entries)if(e.batch===undefined&&e.kind===kind)this.dropped(e);this.entries=keep;}return count;}
 diagnostics():Readonly<Record<string,number>>{return Object.freeze({...this.counts});}
 records():readonly string[]{this.expire();this.materializeAll();const batches=new Map(this.batches.map(s=>[s.batch.id,{revision:s.batch.policyRevision,records:array(object(JSON.parse(s.batch.body)).records)}]));return Object.freeze(this.entries.map(e=>{if(e.text)return e.text;const batch=batches.get(e.batch!);if(!batch||e.position===undefined)throw Error('invalid frozen entry');const r=object(batch.records[e.position]);return nativeCanonical({id:r.id,kind:r.kind,observed_at_ns:r.observed_at_ns,policy_revision:batch.revision,payload:r.payload});}));}
 enqueue(text:string):boolean{return this.admitText(text,false);}
 /** `enqueue` for a text the caller just produced with `nativeCanonical` from a record that has exactly the five record fields: that text already is the stored form (keys in canonical order, line separators escaped), so the payload is not serialized a second time and the batch form is the same text with the resource spliced in. A record whose parse removed an empty optional field, or a text that does not end the way the stored form does, takes the full `enqueue` path and gets the same bytes it always did. */
 enqueueNative(text:string):boolean{return this.admitText(text,true);}
 private admitText(text:string,native:boolean):boolean{
  if(this.closed||this.closing&&!this.recovering&&!this.materializingLoss){this.loss("closed");return false;}this.expire();
  if(typeof text!=='string')throw Error('serialized safe record required');const removed=strippedFields(),parsed=parseSafeRecord(text);if(!this.recovering&&parsed.policy_revision!==this.descriptor.policy_revision)throw Error('policy revision mismatch');
  const {safe,wire,bytes:recordBytes}=native&&removed===strippedFields()?this.serializeNative(text,parsed):this.serialize(parsed),slot=routeRecord(parsed,this.descriptor,this.producer);
  return this.place(parsed.kind,safe,wire,recordBytes,slot);
 }
 private serializeNative(text:string,parsed:NativeRecord):{safe:string;wire:string;bytes:number}{
  const tail=',"policy_revision":'+JSON.stringify(parsed.policy_revision)+'}';
  if(!text.endsWith(tail))return this.serialize(parsed);
  const wire=text.slice(0,text.length-tail.length)+',"resource":'+this.resourceText+'}';
  return {safe:text,wire,bytes:utf8Size(wire)};
 }
 /** Enqueues an ended lean span (see LiveSpan) as `enqueue` would its record: serialized now. The Node/Bun queue (SpoolingDeliveryQueue) overrides this to copy the span into its compact store and serialize it when the batch is frozen. The bytes and slot are the same either way (pinned by a differential test). Only the span recorder reaches this. */
 enqueueLeanSpan(span:LiveSpan,policyRevision:string):boolean{
  if(this.closed||this.closing&&!this.recovering&&!this.materializingLoss){this.loss("closed");return false;}this.expire();
  if(!this.recovering&&policyRevision!==this.descriptor.policy_revision)throw Error('policy revision mismatch');
  const made=this.serializeSpan(span);
  return this.place("span",made.text,made.wire,made.bytes,made.slot);
 }
 protected place(kind:string,safe:string,wire:string,recordBytes:number,slot:number,lazy?:LiveSpan):boolean{
  const size=recordBytes+(kind==="loss"?1024:512);
  if(recordBytes>(kind==='replay_chunk'?131072:262144)){if(!this.materializingLoss)this.loss('record_too_large');return false;}
  while(this.entries.length>=(this.config.maxRecords??1024)||this.bytes+size>(this.config.maxBytes??2097152)){
   const counts=this.unbatchedCounts(),wanted=priority(kind);let evictable=false;for(let lower=0;lower<wanted;lower++)if(counts[lower]!>0){evictable=true;break;}
   const index=evictable?this.entries.findIndex(e=>!e.batch&&priority(e.kind)<wanted):-1;if(index<0){if(!this.materializingLoss)this.loss("queue_full");return false;}const [old]=this.entries.splice(index,1);this.dropped(old!);counts[priority(old!.kind)]!--;this.bytes-=old!.size;this.loss("queue_pressure");
  }
  // A lean span is copied into the compact store and the span itself is released; only if the store cannot take it (no free slot, vocabulary table full) is it serialized at once.
  let handle=-1;
  if(lazy!==undefined){handle=this.store(lazy);if(handle<0){const made=this.serializeSpan(lazy);safe=made.text;wire=made.wire;slot=made.slot;if(made.bytes!==recordBytes){recordBytes=made.bytes;this.loss("span_size_mismatch");}}}
  const at=this.now();this.entries.push({text:safe,wire,wireBytes:recordBytes,size:recordBytes+(kind==="loss"?1024:512),at,wall:Date.now(),kind,slot,lazy:handle});if(at<this.oldest)this.oldest=at;if(this.evictable)this.evictable[priority(kind)]!++;this.bytes+=size;if(this.spool&&!this.recovering&&!this.materializingLoss)void this.recoverOnce().then(()=>this.persist()).catch(()=>{this.counts.spool_failed=(this.counts.spool_failed??0)+1;});return true;
 }
 freeze():readonly FrozenBatch[]{this.freezeSome(Infinity);return Object.freeze(this.batches.map(s=>s.batch));}
 /** Freezes the unbatched entries slot by slot, stopping between slots once `budgetMs` of work has passed (the delivery loop yields to the event loop in between, so one flush never stalls the host for long). True when nothing unbatched is left. */
 protected freezeSome(budgetMs:number):boolean{
  const end=performance.now()+budgetMs;
  this.expire();
  this.expireSignalLosses();this.materializeSignalLosses();
  if(!this.materializeWires(end))return false;
  const bySlot=new Map<number,Entry[]>();
  for(const entry of this.entries)if(!entry.batch){const list=bySlot.get(entry.slot);if(list)list.push(entry);else bySlot.set(entry.slot,[entry]);}
  for(let slot=0;slot<64;slot++){
   const pending=bySlot.get(slot);if(!pending)continue;
   let selected:Entry[]=[],wire:string[]=[],recordBytes=0,batchId="";
   // The canonical batch key order is id, policy_revision, producer, project, records, route_slot, source, version; every value is a canonical ID, a decimal or a small integer, so none needs escaping.
   // The batch ID is drawn when the first record of a batch is selected (a slot's last batch no longer draws one it would never use).
   const lead=',"policy_revision":"'+this.descriptor.policy_revision+'","producer":"'+this.producer+'","project":"'+this.descriptor.project+'","records":[',trail='],"route_slot":'+slot+',"source":"'+this.descriptor.source+'","version":1}';
   const headerBytes='{"id":"'.length+32+'"'.length+lead.length+trail.length;
   const finish=():void=>{
    if(!selected.length)return;
    // Records were serialized when queued; the batch body is that text spliced between the fixed header and trailer.
    const body='{"id":"'+batchId+'"'+lead+wire.join(',')+trail;
    let wall=selected[0]!.wall;const kindSet=new Set<string>();for(const e of selected){if(e.wall<wall)wall=e.wall;kindSet.add(e.kind);}
    const batch:FrozenBatch=Object.freeze({id:batchId,source:this.descriptor.source,producer:this.producer,route_slot:slot,hash:hashBytes(body),body,count:selected.length,kinds:Object.freeze([...kindSet].sort()),firstCapture:wall,policyRevision:this.descriptor.policy_revision});
    for(let position=0;position<selected.length;position++){const e=selected[position]!;e.batch=batchId;e.position=position;e.text='';e.wire='';this.dropped(e);}this.evictable=undefined;
    let rank=0;for(const kind of kindSet)rank=Math.max(rank,priority(kind));this.batches.push({batch,ambiguous:false,attempt:0,next:0,rank});selected=[];wire=[];recordBytes=0;batchId="";
   };
   for(const entry of pending){
    if(selected.length===512||headerBytes+recordBytes+entry.wireBytes+selected.length>1048576)finish();
    if(batchId==="")batchId=id();
    selected.push(entry);wire.push(entry.wire);recordBytes+=entry.wireBytes;
   }
   finish();
   if(performance.now()>=end)return false;
  }
  return true;
 }
 flush(timeoutMs=2000):Promise<FlushReport>{
  if(!Number.isFinite(timeoutMs)||timeoutMs<0)throw Error('invalid flush deadline');
  // ES2022 core has no Promise.withResolvers; each waiter still owns its timer.
  if(this.running){const running=this.running;return new Promise<FlushReport>((resolve,reject)=>{const timer=setTimeout(()=>resolve(this.report([],this.pending>0)),timeoutMs);running.then(report=>{clearTimeout(timer);resolve(report);},error=>{clearTimeout(timer);reject(error);});});}
  const job=this.deliver(timeoutMs);this.running=job;void job.finally(()=>{if(this.running===job)this.running=undefined;}).catch(()=>{});return job;
 }
 protected async freezeSliced():Promise<void>{while(!this.freezeSome(SLICE_MS))await yieldToLoop();}
 protected async deliver(timeout:number):Promise<FlushReport>{
  const deadline=this.now()+timeout,wireDeadline=this.wireNow()+timeout,receipts:Record<string,unknown>[]=[];await this.recoverOnce();await this.freezeSliced();try{if(this.spool)await this.persist();}catch{this.counts.spool_failed=(this.counts.spool_failed??0)+1;return this.report(receipts,this.pending>0);}
  while(!this.denied&&!this.closed&&this.pending&&this.now()<deadline&&this.wireNow()<wireDeadline){
   await this.freezeSliced();
   // The oldest batch of every route slot, highest priority first (a slot's batches go out in order).
   const firstOfSlot=new Map<number,BatchState>();for(const s of this.batches)if(!firstOfSlot.has(s.batch.route_slot))firstOfSlot.set(s.batch.route_slot,s);
   const heads=[...firstOfSlot.values()].sort((a,b)=>b.rank-a.rank);
   let attempted=false;let wait=Infinity;let sliceEnd=performance.now()+SLICE_MS;
   for(const state of heads){if(performance.now()>=sliceEnd){await yieldToLoop();sliceEnd=performance.now()+SLICE_MS;}if(this.closed||this.now()>=deadline||this.wireNow()>=wireDeadline)break;if(state.next>this.now()){wait=Math.min(wait,state.next-this.now());continue;}attempted=true;
    if(!state.ambiguous){if(this.policyExpired()){this.remove(state.batch,'policy_expired');if(this.spool)await this.persist();continue;}}
    // Persist possible-send state BEFORE network: a crash must lookup, not blindly reappend.
    const lookup=state.ambiguous;state.ambiguous=true;
    try{if(this.spool)await this.persist();}catch{this.counts.spool_failed=(this.counts.spool_failed??0)+1;return this.report(receipts,true);}
    let out:Outcome;try{const send=()=>lookup?this.transport.lookup(state.batch,wireDeadline):this.transport.send(state.batch,wireDeadline);out=await (this.options.context?this.options.context.run(send):send());}catch{out={kind:'ambiguous'};}
    if(this.closed)return this.report(receipts,this.pending>0);
    if(out.kind==='receipt'&&verifyReceipt(state.batch,out.receipt,lookup)){this.acknowledgeSignalLosses(state.batch,out.receipt);receipts.push(out.receipt);this.remove(state.batch);if(this.spool)await this.persist();continue;}
    if(out.kind==='denied'){this.denied=true;this.counts.unauthorized=(this.counts.unauthorized??0)+1;break;}
    if(out.kind==='terminal'&&!lookup){this.remove(state.batch,'terminal_rejected');if(this.spool)await this.persist();continue;}
    if(out.kind==='not_found'&&lookup){
     if(state.batch.policyRevision!==this.descriptor.policy_revision){this.remove(state.batch,'policy_changed');if(this.spool)await this.persist();continue;}
     const expired=this.policyExpired();
     if(expired){this.remove(state.batch,'policy_expired');if(this.spool)await this.persist();continue;}state.ambiguous=false;
    }else if(out.kind==='retryable'&&!lookup)state.ambiguous=false;
    state.next=this.now()+Math.max(retryDelay(state.attempt++,this.random),out.retryAfterMs??0);if(this.spool)await this.persist();
   }
   if(this.denied||!this.pending)break;
   // Finish ready ordered work; retry waits are bounded by this flush's deadline.
   if(attempted)continue;
   const delay=Math.min(wait,deadline-this.now(),wireDeadline-this.wireNow());if(!(delay>0))break;await this.sleep(delay);
  }
  return this.report(receipts,this.pending>0&&(this.now()>=deadline||this.wireNow()>=wireDeadline));
 }
 protected report(receipts:Record<string,unknown>[],exceeded:boolean):FlushReport{return Object.freeze({acknowledgedBatchIds:Object.freeze(receipts.map(r=>r.batch_id as string)),acknowledgedCursors:Object.freeze(receipts.map(r=>{const c=r.cursor as {group:string;index:string};return c.group+':'+c.index;})),receipts:Object.freeze(receipts),pending:this.pending,lost:this.lost,deadlineExceeded:exceeded});}
 async close():Promise<void>{if(this.closed)return;this.closing=true;try{await this.flush();}finally{this.closed=true;try{await this.transport.close();}finally{try{await this.persist();}finally{try{await this.spool?.close();}finally{this.options.context?.close();if(!this.spool){this.loss('closed_pending',this.entries.length+[...this.lossBuckets.values()].filter(b=>b.unbatched>0n).length);for(const b of this.lossBuckets.values()){b.unbatched=0n;b.start=null;b.end=null;}this.entries=[];this.batches=[];this.bytes=512*this.lossBuckets.size;}}}}}}
}
