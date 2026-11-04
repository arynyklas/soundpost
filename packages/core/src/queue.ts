// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {Config,FlushReport,RoutingDescriptor,ExportContext} from './types.ts';
import {decimal,unixNano,canonicalId} from './policy.ts';
import {hashBytes,nativeCanonical,resourceWire,routeRecord,validateDescriptor,kinds} from './routing.ts';
import {verifyReceipt,type FrozenBatch,type ReceiptTransport,type Outcome} from './transport.ts';
import type {EncryptedSpool} from './spool.ts';
import {object,array,text,parseSafeRecord} from './wire.ts';
type Entry={text:string;size:number;at:number;wall:number;kind:string;slot:number;batch?:string;position?:number;lossKey?:string;lossCount?:bigint};
type BatchState={batch:FrozenBatch;ambiguous:boolean;attempt:number;next:number};
type LossBucket={epoch:string;signal:string;reason:string;revision:string;observed:bigint;acked:bigint;unbatched:bigint;start:string|null;end:string|null;at:number;wall:number};
export function retryDelay(attempt:number,random:()=>number=Math.random):number{const cap=Math.min(30000,250*2**Math.min(attempt,7));return Math.max(250,Math.min(30000,cap*(.5+.5*Math.max(0,Math.min(1,random())))));}
const id=():string=>Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('');
const priority=(kind:string):number=>['error','condition','capability','loss','job_attempt'].includes(kind)?2:kind==='log'?1:0;
export class DeliveryQueue {
 private entries:Entry[]=[];private batches:BatchState[]=[];private bytes=0;private losses=0;private denied=false;private closed=false;private closing=false;
 private readonly now:()=>number;private readonly random:()=>number;private readonly descriptor:RoutingDescriptor;private readonly resource:Record<string,unknown>;private producer:string;private readonly policyExpires:string;private recovering=false;
 private readonly counts:Record<string,number>=Object.create(null) as Record<string,number>;private running:Promise<FlushReport>|undefined;private readonly spool:EncryptedSpool|undefined;private recovered=false;private persistChain:Promise<void>=Promise.resolve();
 private recoveryTask:Promise<void>|undefined;
 private readonly lossEpoch=canonicalId(id());private readonly lossBuckets=new Map<string,LossBucket>();private readonly allowLoss:boolean;private materializingLoss=false;private lastAck:{group:string;index:string}|null=null;
 constructor(private readonly config:Config,private readonly transport:ReceiptTransport,private readonly options:{now?:()=>number;random?:()=>number;spool?:EncryptedSpool;context?:ExportContext}={}){
  const envelope=object(JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(config.policy.payload.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0)))));this.policyExpires=unixNano(envelope.expires_ns);
  const deploymentLoss=object(config).deploymentLoss;this.allowLoss=envelope.loss===true&&(deploymentLoss===undefined||deploymentLoss===true);
  this.descriptor=validateDescriptor(config.descriptor??{version:1,org:config.org,project:config.project,source:config.source,routing_version:1,slots:64,policy_revision:decimal(envelope.revision)});
  if(this.descriptor.org!==config.org||this.descriptor.project!==config.project||this.descriptor.source!==config.source||this.descriptor.policy_revision!==envelope.revision)throw Error('routing identity mismatch');
  this.resource=resourceWire(config.resource,config.build);this.producer=canonicalId(config.producer??id());this.now=options.now??(()=>performance.now());this.random=options.random??Math.random;this.spool=options.spool??config.spool;
  this.spool?.assertBinding(this.descriptor,this.descriptor.policy_revision);
 }
 private lossKey(epoch:string,signal:string,reason:string):string{return epoch+":"+signal+":"+reason;}
 private validSignalLoss(signal:string,reason:string):boolean{return kinds.some(kind=>kind===signal)&&signal!=="loss"&&["queue_full","expired","policy","unsupported","ring_overflow","reorder_gap","transport","shutdown","truncated"].includes(reason);}
 recordSignalLoss(signal:string,reason:string,count:bigint,atNs:string):boolean{
  if(this.closed||this.closing||this.denied||!this.allowLoss||this.options.context?.active()){this.counts.native_loss_unavailable=(this.counts.native_loss_unavailable??0)+1;return false;}
  try{unixNano(atNs);if(typeof signal!=="string"||typeof reason!=="string"||!this.validSignalLoss(signal,reason)||typeof count!=="bigint"||count<=0n||count>18446744073709551615n||BigInt(atNs)>=BigInt(this.policyExpires))throw Error();}catch{this.counts.invalid_signal_loss=(this.counts.invalid_signal_loss??0)+1;return false;}
  if(this.spool&&!this.recovered){void this.recoverOnce().catch(()=>{this.counts.spool_failed=(this.counts.spool_failed??0)+1;});this.loss("native_loss_recovery_pending");return false;}
  this.expire();this.expireSignalLosses();const key=this.lossKey(this.lossEpoch,signal,reason);let bucket=this.lossBuckets.get(key);
  if(!bucket){while(this.bytes+512>(this.config.maxBytes??2097152)){const index=this.entries.findIndex(e=>!e.batch&&priority(e.kind)<2);if(index<0){this.loss("native_loss_unbuffered");return false;}const [old]=this.entries.splice(index,1);this.bytes-=old!.size;this.loss("queue_pressure");}bucket={epoch:this.lossEpoch,signal,reason,revision:this.descriptor.policy_revision,observed:0n,acked:0n,unbatched:0n,start:null,end:null,at:this.now(),wall:Date.now()};this.lossBuckets.set(key,bucket);this.bytes+=512;}
  if(bucket.observed+count>18446744073709551615n){this.loss("native_loss_overflow");return false;}
  bucket.observed+=count;if(bucket.unbatched===0n){bucket.start=atNs;bucket.end=atNs;bucket.at=this.now();bucket.wall=Date.now();}else{if(BigInt(atNs)<BigInt(bucket.start!))bucket.start=atNs;if(BigInt(atNs)>BigInt(bucket.end!))bucket.end=atNs;}bucket.unbatched+=count;
  this.materializeSignalLosses();if(this.spool)void this.persist().catch(()=>{this.counts.spool_failed=(this.counts.spool_failed??0)+1;});return true;
 }
 private expireSignalLosses():void{for(const bucket of this.lossBuckets.values())if(bucket.unbatched>0n&&this.now()-bucket.at>=300000){bucket.unbatched=0n;bucket.start=null;bucket.end=null;this.loss("native_loss_expired");}}
 private materializeSignalLosses():void{
  if(this.materializingLoss||this.closed||this.recovering||this.denied)return;this.materializingLoss=true;
  try{for(const [key,bucket] of this.lossBuckets){if(bucket.unbatched===0n)continue;
   if(!this.allowLoss||bucket.revision!==this.descriptor.policy_revision){bucket.unbatched=0n;bucket.start=null;bucket.end=null;this.loss("native_loss_policy");continue;}
   let expired=true;try{expired=BigInt(unixNano((this.config.clockNs??(()=>String(BigInt(Date.now())*1000000n)))()))>=BigInt(this.policyExpires);}catch{}if(expired)continue;
   const old=this.entries.find(e=>e.lossKey===key&&!e.batch);let record:Record<string,unknown>;let payload:Record<string,unknown>;let total=bucket.unbatched;
   if(old){record=object(JSON.parse(old.text));payload=object(record.payload);total+=old.lossCount!;const start=text(payload.start_ns),end=text(payload.end_ns);payload.start_ns=BigInt(start)<BigInt(bucket.start!)?start:bucket.start;payload.end_ns=BigInt(end)>BigInt(bucket.end!)?end:bucket.end;record.observed_at_ns=payload.end_ns;}
   else{payload={source:this.descriptor.source,producer:this.producer,producer_epoch:bucket.epoch,start_ns:bucket.start,end_ns:bucket.end,signal:bucket.signal,reason:bucket.reason,count:"0",last_ack:null,queue_bytes:"0",queue_records:"0"};record={id:id(),kind:"loss",observed_at_ns:bucket.end,policy_revision:bucket.revision,payload};}
   payload.count=total.toString();payload.last_ack=this.lastAck?{...this.lastAck}:null;payload.queue_bytes=String(this.bytes);payload.queue_records=String(this.entries.length);const encoded=nativeCanonical(record);
   if(old){const r=parseSafeRecord(encoded),size=new TextEncoder().encode(nativeCanonical({id:r.id,kind:r.kind,observed_at_ns:r.observed_at_ns,payload:r.payload,resource:this.resource})).length;if(size+512>old.size)continue;old.text=encoded;old.lossCount=total;}
   else{if(!this.enqueue(encoded))continue;const entry=this.entries[this.entries.length-1]!;entry.lossKey=key;entry.lossCount=total;entry.at=bucket.at;entry.wall=bucket.wall;}
   bucket.unbatched=0n;bucket.start=null;bucket.end=null;
  }}finally{this.materializingLoss=false;}
 }
 signalLossCounters():readonly Readonly<Record<string,string>>[]{this.expire();this.expireSignalLosses();return Object.freeze([...this.lossBuckets].map(([key,b])=>{const pending=this.entries.filter(e=>e.lossKey===key).reduce((n,e)=>n+(e.lossCount??0n),b.unbatched);return Object.freeze({producer_epoch:b.epoch,signal:b.signal,reason:b.reason,observed_count:b.observed.toString(),acknowledged_count:b.acked.toString(),pending_count:pending.toString(),unexported_count:(b.observed-b.acked-pending).toString()});}));}
 private acknowledgeSignalLosses(batch:FrozenBatch,receipt:Record<string,unknown>):void{const cursor=object(receipt.cursor);this.lastAck={group:canonicalId(cursor.group),index:decimal(cursor.index)};for(const entry of this.entries)if(entry.batch===batch.id&&entry.lossKey){const bucket=this.lossBuckets.get(entry.lossKey);if(!bucket||entry.lossCount===undefined||bucket.acked+entry.lossCount>bucket.observed)throw Error("invalid native loss accounting");bucket.acked+=entry.lossCount;}}
 private restoreSignalLosses(value:Record<string,unknown>):void{
  this.lossBuckets.clear();for(const raw of array(value.loss_buckets)){const b=object(raw),epoch=canonicalId(b.producer_epoch),signal=text(b.signal),reason=text(b.reason),revision=decimal(b.policy_revision);if(!this.validSignalLoss(signal,reason))throw Error("invalid native loss state");const observed=BigInt(decimal(b.observed_count)),acked=BigInt(decimal(b.acknowledged_count)),unbatched=BigInt(decimal(b.unbatched_count));if(acked>observed||unbatched>observed-acked||typeof b.wall!=="number"||!Number.isSafeInteger(b.wall))throw Error("invalid native loss state");if(observed===acked&&unbatched===0n)continue;const start=b.start_ns===null?null:unixNano(b.start_ns),end=b.end_ns===null?null:unixNano(b.end_ns);if(unbatched>0n&&(start===null||end===null||BigInt(end)<BigInt(start)))throw Error("invalid native loss interval");const key=this.lossKey(epoch,signal,reason);if(this.lossBuckets.has(key)||this.bytes+512>(this.config.maxBytes??2097152))throw Error("native loss capacity exceeded");this.lossBuckets.set(key,{epoch,signal,reason,revision,observed,acked,unbatched,start,end,wall:b.wall,at:this.now()-(Date.now()-b.wall)});this.bytes+=512;}
  if(value.last_ack===null)this.lastAck=null;else{const c=object(value.last_ack);this.lastAck={group:canonicalId(c.group),index:decimal(c.index)};if(this.lastAck.index==="0")throw Error("invalid saved ACK cursor");}
 }
 private markLossEntry(entry:Entry,record:Record<string,unknown>):void{if(record.kind!=="loss")return;const p=object(record.payload),key=this.lossKey(canonicalId(p.producer_epoch),text(p.signal),text(p.reason));if(this.lossBuckets.has(key)){entry.lossKey=key;entry.lossCount=BigInt(decimal(p.count));}}
 private loss(reason:string,count=1):void{this.losses+=count;this.counts[reason]=(this.counts[reason]??0)+count;}
 private remove(batch:FrozenBatch,reason?:string):void{this.entries=this.entries.filter(e=>{if(e.batch!==batch.id)return true;this.bytes-=e.size;return false;});this.batches=this.batches.filter(s=>s.batch.id!==batch.id);if(reason)this.loss(reason,batch.count);}
 private expire():void{const now=this.now();const expired=new Set(this.entries.filter(e=>now-e.at>=300000).map(e=>e.batch).filter((v):v is string=>v!==undefined));for(const b of [...this.batches])if(expired.has(b.batch.id))this.remove(b.batch,'queue_expired');this.entries=this.entries.filter(e=>{if(now-e.at<300000)return true;this.bytes-=e.size;this.loss('queue_expired');return false;});}
 get pending():number{this.expire();this.expireSignalLosses();return this.entries.length||(this.lossBuckets.size&&[...this.lossBuckets.values()].some(b=>b.unbatched>0n)?1:0);}
 get lost():number{return this.losses;}
 diagnostics():Readonly<Record<string,number>>{return Object.freeze({...this.counts});}
 records():readonly string[]{this.expire();const batches=new Map(this.batches.map(s=>[s.batch.id,{revision:s.batch.policyRevision,records:array(object(JSON.parse(s.batch.body)).records)}]));return Object.freeze(this.entries.map(e=>{if(e.text)return e.text;const batch=batches.get(e.batch!);if(!batch||e.position===undefined)throw Error('invalid frozen entry');const r=object(batch.records[e.position]);return nativeCanonical({id:r.id,kind:r.kind,observed_at_ns:r.observed_at_ns,policy_revision:batch.revision,payload:r.payload});}));}
 enqueue(text:string):boolean{
  if(this.closed||this.closing&&!this.recovering&&!this.materializingLoss){this.loss("closed");return false;}this.expire();
  if(typeof text!=='string')throw Error('serialized safe record required');const parsed=parseSafeRecord(text);if(!this.recovering&&parsed.policy_revision!==this.descriptor.policy_revision)throw Error('policy revision mismatch');
  const safe=nativeCanonical(parsed),slot=routeRecord(parsed,this.descriptor,this.producer),recordBytes=new TextEncoder().encode(nativeCanonical({id:parsed.id,kind:parsed.kind,observed_at_ns:parsed.observed_at_ns,payload:parsed.payload,resource:this.resource})).length,size=recordBytes+(parsed.kind==="loss"?1024:512);
  if(recordBytes>(parsed.kind==='replay_chunk'?131072:262144)){if(!this.materializingLoss)this.loss('record_too_large');return false;}
  while(this.entries.length>=(this.config.maxRecords??1024)||this.bytes+size>(this.config.maxBytes??2097152)){
   const index=this.entries.findIndex(e=>!e.batch&&priority(e.kind)<priority(parsed.kind));if(index<0){if(!this.materializingLoss)this.loss("queue_full");return false;}const [old]=this.entries.splice(index,1);this.bytes-=old!.size;this.loss("queue_pressure");
  }
  this.entries.push({text:safe,size,at:this.now(),wall:Date.now(),kind:parsed.kind,slot});this.bytes+=size;if(this.spool&&!this.recovering&&!this.materializingLoss)void this.recoverOnce().then(()=>this.persist()).catch(()=>{this.counts.spool_failed=(this.counts.spool_failed??0)+1;});return true;
 }
 freeze():readonly FrozenBatch[]{
  this.expire();
  this.expireSignalLosses();this.materializeSignalLosses();
  for(let slot=0;slot<64;slot++){
   const pending=this.entries.filter(e=>e.slot===slot&&!e.batch);if(!pending.length)continue;
   let selected:Entry[]=[],wire:string[]=[],recordBytes=0,batchId=id();
   const header=():string=>nativeCanonical({version:1,project:this.descriptor.project,source:this.descriptor.source,producer:this.producer,id:batchId,policy_revision:this.descriptor.policy_revision,route_slot:slot,records:[]});
   const headerBytes=new TextEncoder().encode(header()).length;
   const finish=():void=>{
    if(!selected.length)return;
    // The fixed schema's own empty records token is replaced by canonical records.
    const body=header().replace('\"records\":[]',()=>'\"records\":['+wire.join(',')+']');
    const batch:FrozenBatch=Object.freeze({id:batchId,source:this.descriptor.source,producer:this.producer,route_slot:slot,hash:hashBytes(body),body,count:selected.length,kinds:Object.freeze([...new Set(selected.map(e=>e.kind))].sort()),firstCapture:Math.min(...selected.map(e=>e.wall)),policyRevision:this.descriptor.policy_revision});
    for(const [position,e] of selected.entries()){e.batch=batchId;e.position=position;e.text='';}
    this.batches.push({batch,ambiguous:false,attempt:0,next:0});selected=[];wire=[];recordBytes=0;batchId=id();
   };
   for(const entry of pending){
    const record=parseSafeRecord(entry.text),encoded=nativeCanonical({id:record.id,kind:record.kind,observed_at_ns:record.observed_at_ns,payload:record.payload,resource:this.resource}),bytes=new TextEncoder().encode(encoded).length;
    if(selected.length===512||headerBytes+recordBytes+bytes+selected.length>1048576)finish();
    selected.push(entry);wire.push(encoded);recordBytes+=bytes;
   }
   finish();
  }
  return Object.freeze(this.batches.map(s=>s.batch));
 }
 private snapshot():unknown{return {version:2,producer:this.producer,last_ack:this.lastAck,loss_buckets:[...this.lossBuckets.values()].map(b=>({producer_epoch:b.epoch,signal:b.signal,reason:b.reason,policy_revision:b.revision,observed_count:b.observed.toString(),acknowledged_count:b.acked.toString(),unbatched_count:b.unbatched.toString(),start_ns:b.start,end_ns:b.end,wall:b.wall})),entries:this.entries.map(e=>({text:e.text||null,position:e.position??null,wall:e.wall,batch:e.batch??null})),batches:this.batches.map(s=>({batch:s.batch,ambiguous:s.ambiguous,attempt:s.attempt}))};}
 async persist():Promise<void>{if(!this.spool)return;await this.recoverOnce();const snapshot=this.snapshot();this.persistChain=this.persistChain.catch(()=>{}).then(()=>{const save=()=>this.spool!.save(snapshot);return this.options.context?this.options.context.run(save):save();});return this.persistChain;}
 private recoverOnce():Promise<void>{return this.recoveryTask??(this.recoveryTask=this.options.context?this.options.context.run(()=>this.recover()):this.recover());}
 private async recover():Promise<void>{
  if(this.recovered)return;if(!this.spool){this.recovered=true;return;}const raw=await this.spool.load();if(raw===undefined){this.recovered=true;return;}const value=object(raw);
  const producer=canonicalId(value.producer);if(value.version!==2||this.config.producer!==undefined&&producer!==this.producer)throw Error('spool identity mismatch');
  const storedEntries=array(value.entries),storedBatches=array(value.batches);if(storedEntries.length>1024)throw Error('invalid spool');
  const originals=new Map(storedBatches.map(item=>{const state=object(item),batch=object(state.batch);return [canonicalId(batch.id),{revision:decimal(batch.policyRevision),records:array(object(JSON.parse(text(batch.body))).records)}] as const;}));
  const expiredBatches=new Set(storedEntries.flatMap(item=>{const stored=object(item);if(typeof stored.wall!=='number'||!Number.isSafeInteger(stored.wall))throw Error('invalid spool');const age=Date.now()-stored.wall;return stored.batch!==null&&(age<0||age>=300000)?[canonicalId(stored.batch)]:[];}));
  const live=this.records();this.entries=[];this.batches=[];this.bytes=0;this.producer=producer;this.recovering=true;
  try{
   this.restoreSignalLosses(value);
   for(const item of storedEntries){
    const stored=object(item);if(typeof stored.wall!=='number'||!Number.isSafeInteger(stored.wall))throw Error('invalid spool');const age=Date.now()-stored.wall;if(age<0||age>=300000||stored.batch!==null&&expiredBatches.has(canonicalId(stored.batch))){this.loss('queue_expired');continue;}
    let original:string;let nativeSize:number|undefined;let position:number|undefined;
    if(stored.batch!==null){const frozen=originals.get(canonicalId(stored.batch));if(!frozen||typeof stored.position!=='number'||!Number.isInteger(stored.position)||stored.position<0||stored.position>=frozen.records.length)throw Error('invalid frozen spool entry');position=stored.position;const record=object(frozen.records[position]);original=nativeCanonical({id:record.id,kind:record.kind,observed_at_ns:record.observed_at_ns,payload:record.payload,policy_revision:frozen.revision});nativeSize=new TextEncoder().encode(nativeCanonical(record)).length+(record.kind==="loss"?1024:512);}
    else original=text(stored.text);
    if(stored.batch===null&&parseSafeRecord(original).policy_revision!==this.descriptor.policy_revision){this.loss('policy_changed');continue;}if(!this.enqueue(original))throw Error('spool capacity exceeded');const entry=this.entries[this.entries.length-1]!;entry.wall=stored.wall;entry.at=this.now()-age;
    this.markLossEntry(entry,object(JSON.parse(original)));
    if(stored.batch!==null){entry.batch=canonicalId(stored.batch);if(position!==undefined)entry.position=position;if(nativeSize!==undefined){this.bytes+=nativeSize-entry.size;entry.size=nativeSize;}entry.text='';}
   }
   if(this.bytes>(this.config.maxBytes??2097152))throw Error('spool capacity exceeded');
   for(const item of storedBatches){const state=object(item),b=object(state.batch),batchId=canonicalId(b.id);const entries=this.entries.filter(e=>e.batch===batchId);if(!entries.length)continue;
    const body=text(b.body),wire=object(JSON.parse(body)),slot=b.route_slot,revision=decimal(b.policyRevision);if(typeof slot!=='number'||!Number.isInteger(slot)||slot<0||slot>=64||wire.id!==batchId||wire.source!==this.descriptor.source||wire.project!==this.descriptor.project||wire.producer!==producer||wire.route_slot!==slot||wire.policy_revision!==revision||hashBytes(body)!==b.hash||b.producer!==producer||b.source!==this.descriptor.source||b.count!==entries.length||typeof state.attempt!=='number'||!Number.isSafeInteger(state.attempt)||state.attempt<0)throw Error('invalid frozen spool');
    const signals=array(b.kinds).map(text),actual=[...new Set(entries.map(e=>e.kind))].sort();if(signals.join(',')!==actual.join(',')||array(wire.records).length!==entries.length||entries.some(e=>e.slot!==slot))throw Error('invalid frozen spool');
    const batch:FrozenBatch=Object.freeze({id:batchId,source:this.descriptor.source,producer,route_slot:slot,hash:text(b.hash),body,count:entries.length,kinds:Object.freeze(signals),firstCapture:Math.min(...entries.map(e=>e.wall)),policyRevision:revision});this.batches.push({batch,ambiguous:true,attempt:state.attempt,next:0});
   }
   if(this.entries.some(e=>e.batch&&!this.batches.some(s=>s.batch.id===e.batch)))throw Error('orphan frozen spool');
   for(const [key,b] of this.lossBuckets){const queued=this.entries.filter(e=>e.lossKey===key).reduce((n,e)=>n+(e.lossCount??0n),0n);if(queued+b.unbatched+b.acked>b.observed)throw Error("invalid native loss accounting");}
   for(const original of live)if(!this.enqueue(original))this.loss('recovery_pressure');this.recovered=true;
  }finally{this.recovering=false;}
 }
 flush(timeoutMs=2000):Promise<FlushReport>{
  if(!Number.isFinite(timeoutMs)||timeoutMs<0)throw Error('invalid flush deadline');
  // ES2022 core has no Promise.withResolvers; each waiter still owns its timer.
  if(this.running){const running=this.running;return new Promise<FlushReport>((resolve,reject)=>{const timer=setTimeout(()=>resolve(this.report([],this.pending>0)),timeoutMs);running.then(report=>{clearTimeout(timer);resolve(report);},error=>{clearTimeout(timer);reject(error);});});}
  const job=this.deliver(timeoutMs);this.running=job;void job.finally(()=>{if(this.running===job)this.running=undefined;}).catch(()=>{});return job;
 }
 private async deliver(timeout:number):Promise<FlushReport>{
  const deadline=this.now()+timeout,wireDeadline=performance.now()+timeout,receipts:Record<string,unknown>[]=[];await this.recoverOnce();this.freeze();try{await this.persist();}catch{this.counts.spool_failed=(this.counts.spool_failed??0)+1;return this.report(receipts,this.pending>0);}
  while(!this.denied&&!this.closed&&this.pending&&this.now()<deadline&&performance.now()<wireDeadline){
   this.freeze();
   const heads=this.batches.filter((s,i,a)=>a.findIndex(b=>b.batch.route_slot===s.batch.route_slot)===i).sort((a,b)=>Math.max(...b.batch.kinds.map(priority))-Math.max(...a.batch.kinds.map(priority)));
   let attempted=false;let wait=Infinity;
   for(const state of heads){if(this.closed||this.now()>=deadline||performance.now()>=wireDeadline)break;if(state.next>this.now()){wait=Math.min(wait,state.next-this.now());continue;}attempted=true;
    if(!state.ambiguous){let expired=true;try{expired=BigInt(unixNano((this.config.clockNs??(()=>String(BigInt(Date.now())*1000000n)))()))>=BigInt(this.policyExpires);}catch{}if(expired){this.remove(state.batch,'policy_expired');await this.persist();continue;}}
    // Persist possible-send state BEFORE network: a crash must lookup, not blindly reappend.
    const lookup=state.ambiguous;state.ambiguous=true;
    try{await this.persist();}catch{this.counts.spool_failed=(this.counts.spool_failed??0)+1;return this.report(receipts,true);}
    let out:Outcome;try{const send=()=>lookup?this.transport.lookup(state.batch,wireDeadline):this.transport.send(state.batch,wireDeadline);out=await (this.options.context?this.options.context.run(send):send());}catch{out={kind:'ambiguous'};}
    if(this.closed)return this.report(receipts,this.pending>0);
    if(out.kind==='receipt'&&verifyReceipt(state.batch,out.receipt,lookup)){this.acknowledgeSignalLosses(state.batch,out.receipt);receipts.push(out.receipt);this.remove(state.batch);await this.persist();continue;}
    if(out.kind==='denied'){this.denied=true;this.counts.unauthorized=(this.counts.unauthorized??0)+1;break;}
    if(out.kind==='terminal'&&!lookup){this.remove(state.batch,'terminal_rejected');await this.persist();continue;}
    if(out.kind==='not_found'&&lookup){
     if(state.batch.policyRevision!==this.descriptor.policy_revision){this.remove(state.batch,'policy_changed');await this.persist();continue;}
     let expired=true;try{expired=BigInt(unixNano((this.config.clockNs??(()=>String(BigInt(Date.now())*1000000n)))()))>=BigInt(this.policyExpires);}catch{}
     if(expired){this.remove(state.batch,'policy_expired');await this.persist();continue;}state.ambiguous=false;
    }else if(out.kind==='retryable'&&!lookup)state.ambiguous=false;
    state.next=this.now()+Math.max(retryDelay(state.attempt++,this.random),out.retryAfterMs??0);await this.persist();
   }
   if(this.denied||!this.pending)break;
   // Finish ready ordered work; retry waits are bounded by this flush's deadline.
   if(attempted)continue;
   const delay=Math.min(wait,deadline-this.now(),wireDeadline-performance.now());if(!(delay>0))break;await new Promise(resolve=>setTimeout(resolve,delay));
  }
  return this.report(receipts,this.pending>0&&(this.now()>=deadline||performance.now()>=wireDeadline));
 }
 private report(receipts:Record<string,unknown>[],exceeded:boolean):FlushReport{return Object.freeze({acknowledgedBatchIds:Object.freeze(receipts.map(r=>r.batch_id as string)),acknowledgedCursors:Object.freeze(receipts.map(r=>{const c=r.cursor as {group:string;index:string};return c.group+':'+c.index;})),receipts:Object.freeze(receipts),pending:this.pending,lost:this.lost,deadlineExceeded:exceeded});}
 async close():Promise<void>{if(this.closed)return;this.closing=true;try{await this.flush();}finally{this.closed=true;try{await this.transport.close();}finally{try{await this.persist();}finally{try{await this.spool?.close();}finally{this.options.context?.close();if(!this.spool){this.loss('closed_pending',this.entries.length+[...this.lossBuckets.values()].filter(b=>b.unbatched>0n).length);for(const b of this.lossBuckets.values()){b.unbatched=0n;b.start=null;b.end=null;}this.entries=[];this.batches=[];this.bytes=512*this.lossBuckets.size;}}}}}}
}
