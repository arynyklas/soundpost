// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {DeliveryQueue,priority,type BatchState,type Entry} from './queue.ts';
import {decimal,unixNano,canonicalId} from './policy.ts';
import {hashBytes,nativeCanonical} from './routing.ts';
import type {FrozenBatch} from './transport.ts';
import {object,array,text,parseSafeRecord} from './wire.ts';
/** The delivery queue plus its encrypted-spool persistence and recovery. It is its own module so a bundle that never has a spool (the browser core entry, which prohibits one) does not carry the recovery code. */
export class SpoolingDeliveryQueue extends DeliveryQueue {
 protected override spoolSupported():boolean{return true;}
 private restoreSignalLosses(value:Record<string,unknown>):void{
  this.lossBuckets.clear();for(const raw of array(value.loss_buckets)){const b=object(raw),epoch=canonicalId(b.producer_epoch),signal=text(b.signal),reason=text(b.reason),revision=decimal(b.policy_revision);if(!this.validSignalLoss(signal,reason))throw Error("invalid native loss state");const observed=BigInt(decimal(b.observed_count)),acked=BigInt(decimal(b.acknowledged_count)),unbatched=BigInt(decimal(b.unbatched_count));if(acked>observed||unbatched>observed-acked||typeof b.wall!=="number"||!Number.isSafeInteger(b.wall))throw Error("invalid native loss state");if(observed===acked&&unbatched===0n)continue;const start=b.start_ns===null?null:unixNano(b.start_ns),end=b.end_ns===null?null:unixNano(b.end_ns);if(unbatched>0n&&(start===null||end===null||BigInt(end)<BigInt(start)))throw Error("invalid native loss interval");const key=this.lossKey(epoch,signal,reason);if(this.lossBuckets.has(key)||this.bytes+512>(this.config.maxBytes??2097152))throw Error("native loss capacity exceeded");this.lossBuckets.set(key,{epoch,signal,reason,revision,observed,acked,unbatched,start,end,wall:b.wall,at:this.now()-(Date.now()-b.wall)});this.bytes+=512;}
  if(value.last_ack===null)this.lastAck=null;else{const c=object(value.last_ack);this.lastAck={group:canonicalId(c.group),index:decimal(c.index)};if(this.lastAck.index==="0")throw Error("invalid saved ACK cursor");}
 }
 private markLossEntry(entry:Entry,record:Record<string,unknown>):void{if(record.kind!=="loss")return;const p=object(record.payload),key=this.lossKey(canonicalId(p.producer_epoch),text(p.signal),text(p.reason));if(this.lossBuckets.has(key)){entry.lossKey=key;entry.lossCount=BigInt(decimal(p.count));}}
 private snapshot():unknown{this.materializeAll();return {version:2,producer:this.producer,last_ack:this.lastAck,loss_buckets:[...this.lossBuckets.values()].map(b=>({producer_epoch:b.epoch,signal:b.signal,reason:b.reason,policy_revision:b.revision,observed_count:b.observed.toString(),acknowledged_count:b.acked.toString(),unbatched_count:b.unbatched.toString(),start_ns:b.start,end_ns:b.end,wall:b.wall})),entries:this.entries.map(e=>({text:e.text||null,position:e.position??null,wall:e.wall,batch:e.batch??null})),batches:this.batches.map(s=>({batch:s.batch,ambiguous:s.ambiguous,attempt:s.attempt}))};}
 override async persist():Promise<void>{if(!this.spool)return;await this.recoverOnce();const snapshot=this.snapshot();this.persistChain=this.persistChain.catch(()=>{}).then(()=>{const save=()=>this.spool!.save(snapshot);return this.options.context?this.options.context.run(save):save();});return this.persistChain;}
 protected override recoverOnce():Promise<void>{return this.recoveryTask??(this.recoveryTask=this.options.context?this.options.context.run(()=>this.recover()):this.recover());}
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
    if(stored.batch!==null){entry.batch=canonicalId(stored.batch);if(position!==undefined)entry.position=position;if(nativeSize!==undefined){this.bytes+=nativeSize-entry.size;entry.size=nativeSize;}entry.text='';entry.wire='';}
   }
   if(this.bytes>(this.config.maxBytes??2097152))throw Error('spool capacity exceeded');
   for(const item of storedBatches){const state=object(item),b=object(state.batch),batchId=canonicalId(b.id);const entries=this.entries.filter(e=>e.batch===batchId);if(!entries.length)continue;
    const body=text(b.body),wire=object(JSON.parse(body)),slot=b.route_slot,revision=decimal(b.policyRevision);if(typeof slot!=='number'||!Number.isInteger(slot)||slot<0||slot>=64||wire.id!==batchId||wire.source!==this.descriptor.source||wire.project!==this.descriptor.project||wire.producer!==producer||wire.route_slot!==slot||wire.policy_revision!==revision||hashBytes(body)!==b.hash||b.producer!==producer||b.source!==this.descriptor.source||b.count!==entries.length||typeof state.attempt!=='number'||!Number.isSafeInteger(state.attempt)||state.attempt<0)throw Error('invalid frozen spool');
    const signals=array(b.kinds).map(text),actual=[...new Set(entries.map(e=>e.kind))].sort();if(signals.join(',')!==actual.join(',')||array(wire.records).length!==entries.length||entries.some(e=>e.slot!==slot))throw Error('invalid frozen spool');
    const batch:FrozenBatch=Object.freeze({id:batchId,source:this.descriptor.source,producer,route_slot:slot,hash:text(b.hash),body,count:entries.length,kinds:Object.freeze(signals),firstCapture:Math.min(...entries.map(e=>e.wall)),policyRevision:revision});this.batches.push({batch,ambiguous:true,attempt:state.attempt,next:0,rank:Math.max(0,...signals.map(priority))});
   }
   if(this.entries.some(e=>e.batch&&!this.batches.some(s=>s.batch.id===e.batch)))throw Error('orphan frozen spool');
   for(const [key,b] of this.lossBuckets){const queued=this.entries.filter(e=>e.lossKey===key).reduce((n,e)=>n+(e.lossCount??0n),0n);if(queued+b.unbatched+b.acked>b.observed)throw Error("invalid native loss accounting");}
   for(const original of live)if(!this.enqueue(original))this.loss('recovery_pressure');this.recovered=true;
  }finally{this.recovering=false;this.evictable=undefined;this.oldest=-Infinity;}
 }
}
