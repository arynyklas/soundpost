// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {Config,EventId,Template,PolicyDecision,CaptureInput,CapabilityInput,ProfileInput,HookMechanism,OwnedHookLease,ExportContext} from "./types.ts";
import {resolve,approveTemplate,normalizeRecord,canonical,canonicalId,unixNano,type SourcePolicy} from "./policy.ts";
import {object} from "./wire.ts";
import {extractException,type ErrorBoundary} from "./errors.ts";
export type {ErrorBoundary} from "./errors.ts";
import {DeliveryQueue} from "./queue.ts";
import {HttpsReceiptTransport} from "./transport.ts";
import type {FlushReport} from "./types.ts";
import {SpanRecorder,createSynchronousMetadataContext,signalAborted} from "./tracing.ts";
import type {MetadataContext,TraceContext,SpanOptions,ActiveSpan} from "./tracing.ts";
import {JobRecorder} from "./jobs.ts";
export {checkedTraceContext,createTraceClock} from "./tracing.ts";
export {createTimerCancellationBoundary} from "./jobs.ts";
type RuntimeErrorBoundary=ErrorBoundary&{readonly timerCancellation?:(error:unknown)=>Promise<boolean>};
export class Client {
 private readonly delivery:DeliveryQueue;
 private readonly counts:Record<string,number>=Object.create(null) as Record<string,number>;
 private readonly policy:SourcePolicy;
 private readonly templates=new Map<string,Template>();
 private readonly clock:()=>string;
 private readonly build:string;private readonly codes:ReadonlySet<string>;private closed=false;
 private readonly hookLeases=new Set<OwnedHookLease>();
 private readonly spans:SpanRecorder;
 private readonly jobs:JobRecorder;
 constructor(config:Config,private readonly errorBoundary?:RuntimeErrorBoundary,private readonly exportContext:ExportContext=(()=>{let depth=0;return {active:()=>depth>0,run<T>(callback:()=>T):T{depth++;try{return callback();}finally{depth--;}},close(){}};})(),private readonly metadataContext:MetadataContext=createSynchronousMetadataContext(config.clockNs)){
  const records=config.maxRecords??1024,bytes=config.maxBytes??2097152;
  if(!Number.isInteger(records)||records<1||records>1024||!Number.isInteger(bytes)||bytes<1||bytes>2097152)throw Error("invalid queue limits");
  for(const identity of [config.org,config.project,config.source,config.build])canonicalId(identity);
  for(const flag of [config.deploymentErrors,config.deploymentLogs,config.deploymentReplay,config.deploymentBodies,config.deploymentTraces,config.deploymentJobs,config.deploymentLoss,config.deploymentProfiles])if(flag!==undefined&&typeof flag!=="boolean")throw Error("deployment permissions must be boolean");
  if(config.integrations?.length)throw Error("integrations not available");
  this.policy=resolve(config);this.clock=config.clockNs??(()=>String(BigInt(Date.now())*1000000n));this.build=config.build;this.codes=new Set(config.operations??[]);
  this.jobs=new JobRecorder(metadataContext,config.jobRegistry,{clock:()=>this.readClock(),emit:(payload,observed)=>{this.admit({kind:"job_attempt",id:this.id(),observed_at_ns:observed,payload});},capture:error=>this.captureException(error),loss:reason=>this.loss(reason),nativeError:error=>this.errorBoundary!==undefined&&this.errorBoundary.isProxy?.(error)!==true&&this.errorBoundary.isNativeError(error),timerCancellation:error=>this.errorBoundary?.timerCancellation?.(error)??Promise.resolve(false)});
  this.delivery=new DeliveryQueue(config,config.transport??new HttpsReceiptTransport(config),{context:this.exportContext});
  this.spans=new SpanRecorder(metadataContext,config.operations??[],config.dependencies??[],config.traceSampleProbability,()=>!this.closed&&this.policy.decision.traces&&!this.exportContext.active(),span=>{this.admit({kind:"span",id:this.id(),observed_at_ns:span.start.wall_ns,span});},reason=>{
   this.loss(reason);if(!this.policy.decision.loss||this.closed||this.exportContext.active())return;const nativeReason=reason==="trace_sampled_out"?"policy":reason==="trace_active_limit"?"queue_full":undefined;if(nativeReason===undefined)return;const at=this.readClock();if(at!==undefined&&BigInt(at)<BigInt(this.policy.expiresNs))this.delivery.recordSignalLoss("span",nativeReason,1n,at);
  });
  for(const template of config.templates??[])this.registerTemplate(template);
 }
 get policyDecision():PolicyDecision{return this.policy.decision;}
 private loss(reason:string):void{this.counts[reason]=(this.counts[reason]??0)+1;}
 private readClock():string|undefined{try{return unixNano(this.clock());}catch{this.loss("invalid_clock");return undefined;}}
 registerTemplate(template:Template):void{
  if(this.closed)throw Error("client closed");const safe=approveTemplate(template),old=this.templates.get(safe.id);
  if(old&&BigInt(old.revision)>=BigInt(safe.revision))throw Error("template revision must increase");this.templates.set(safe.id,safe);
 }
 private admit(input:CaptureInput):boolean{
  if(this.closed){this.loss("closed");return false;}if(this.exportContext.active()){this.loss("exporter_recursion");return false;}const result=normalizeRecord(this.policy,input,this.templates);
  if(!result.record){this.loss(result.reason??"policy_rejected");return false;}
  return this.delivery.enqueue(canonical(result.record));
 }
 private id():string{return Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,"0")).join("");}
 captureException(error:unknown,options?:{code?:string}):EventId{
  return this.captureError(error,options,"manual",false);
 }
 private captureError(error:unknown,options:{code?:string}|undefined,mechanism:HookMechanism|"manual",fatal:boolean):EventId{
  const id=this.id();
  const observed=this.readClock();if(observed===undefined)return id;
  const descriptor=options&&Object.getOwnPropertyDescriptor(options,"code");const value:unknown=descriptor&&"value" in descriptor?descriptor.value:undefined;
  const code=typeof value==="string"&&this.codes.has(value)?value:null;
  const graph=extractException(error,this.policy,this.errorBoundary);
  const context=this.spans.current(),job=this.metadataContext.jobCurrent();
  this.admit({kind:"error",id,observed_at_ns:observed,exception_class:graph.nodes[0]?.exception_class??"UnknownError",code,build_id:this.build,exception_graph:graph,handled:mechanism==="manual",fatal,mechanism,...(context?{trace_id:context.traceId,span_id:context.spanId}:{}),...(job?{run_id:job.runId}:{})});return id;
 }
 beginHandlingEpisode():HandlingEpisode{return new HandlingEpisode(this);}
 captureHook(error:unknown,mechanism:HookMechanism,fatal:boolean):EventId{
  if(!["uncaught_exception","unhandled_rejection","thread_exception","asyncio_exception"].includes(mechanism)||typeof fatal!=="boolean")throw Error("invalid hook mechanism");
  return this.captureError(error,undefined,mechanism,fatal);
 }
 hookCaptureFailed():void{this.loss("hook_capture_failed");}
 /** Enqueues browser-built profile records on the ordinary delivery path (same queue, batching, retry, receipts and loss counters).
  * The capability record goes first and alone is a complete answer for a refusal; chunks follow only after it was accepted, in order,
  * and stop at the first refusal so a profile never has a hole. Never throws: failures are counted in diagnostics() and return false. */
 captureProfile(capability:CapabilityInput,chunks:readonly ProfileInput[]=[]):boolean{
  if(!this.admitProfile(capability)){for(const _chunk of chunks)this.loss("profile_chunk_dropped");return false;}
  for(const [index,chunk] of chunks.entries())if(!this.admitProfile(chunk)){for(let rest=index+1;rest<chunks.length;rest++)this.loss("profile_chunk_dropped");return false;}
  return true;
 }
 private admitProfile(input:CapabilityInput|ProfileInput):boolean{try{return this.admit(input);}catch{this.loss("invalid_profile_record");return false;}}
 /** For adapters whose own profile-to-wire mapping failed before anything reached the queue. */
 profileFailed():void{this.loss("profile_wire_failed");}
 /** Records `count` profile samples the adapter dropped from one run (past its sample/frame/stack bounds or the browser's buffer) as a native loss of the
  * profile_chunk signal with reason "truncated", the way every other signal loss is recorded (durable `loss` record plus the queue's per-signal counters).
  * The diagnostics counter `profile_samples_truncated` always moves; the durable record only when the signed policy allows loss and the client is open.
  * `atNs` is the run's wall end. Never throws; false when no durable record was made. */
 captureProfileLoss(count:bigint,atNs:string):boolean{
  if(typeof count!=="bigint"||count<=0n)return false;
  this.counts.profile_samples_truncated=(this.counts.profile_samples_truncated??0)+Number(count>9007199254740991n?9007199254740991n:count);
  if(!this.policy.decision.loss||this.closed||this.exportContext.active())return false;
  try{if(BigInt(unixNano(atNs))>=BigInt(this.policy.expiresNs))return false;return this.delivery.recordSignalLoss("profile_chunk","truncated",count,atNs);}catch{return false;}
 }
 /** Enqueues one browser-recorded replay chunk on the ordinary delivery path (same queue, closed wire validation, batching, retry, receipts and loss counters). The chunk's own wall clock is its
  * observation time. Never throws: false means the chunk was not queued (policy off, queue full, invalid) and the reason is counted in diagnostics(). */
 captureReplay(chunk:Readonly<Record<string,unknown>>):boolean{
  let observed:string;
  try{observed=unixNano(object(object(chunk).clock).wall_ns);}catch{this.loss("invalid_replay_record");return false;}
  try{return this.admit({kind:"replay_chunk",id:this.id(),observed_at_ns:observed,payload:chunk});}catch{this.loss("invalid_replay_record");return false;}
 }
 /** Destroys the replay chunks that are queued but not yet part of a batch (consent revoked). Batches already frozen or acknowledged are not recalled. Returns how many were destroyed. */
 discardUnsentReplay():number{const count=this.delivery.discardUnsent("replay_chunk");if(count>0)this.counts.replay_chunks_discarded=(this.counts.replay_chunks_discarded??0)+count;return count;}
 ownHookLease(lease:OwnedHookLease):void{if(this.closed)throw Error("client closed");if(this.hookLeases.size>=8)throw Error("hook lease limit");this.hookLeases.add(lease);}
 releaseHookLease(lease:OwnedHookLease):void{this.hookLeases.delete(lease);}
 captureLog(template:string,fields:Readonly<Record<string,unknown>>):EventId|undefined{
  if(typeof template!=="string"){this.loss("unknown_template");return undefined;}
  const id=this.id(),observed=this.readClock();if(observed===undefined)return undefined;
  return this.admit({kind:"log",id,observed_at_ns:observed,template_id:template,fields})?id:undefined;
 }
 /** Internal adapter seams. Context IDs carry causality, never tenant authority. */
 traceContext():TraceContext|undefined{return this.spans.current();}
 withTraceContext<T>(context:TraceContext|null,callback:()=>T):T{if(this.closed)throw Error("client closed");if(context&&this.errorBoundary?.isProxy?.(context))throw Error("invalid_trace_context");return this.spans.run(context,callback);}
 startSpan(operation:string,options?:SpanOptions):ActiveSpan{if(this.closed)throw Error("client closed");return this.spans.start(operation,options);}
 async withSpan<T>(operation:string,callback:()=>Promise<T>,options?:SpanOptions):Promise<T>{
  const span=this.startSpan(operation,options),signal=options?Object.getOwnPropertyDescriptor(options,"signal")?.value:undefined;
  try{const value=await span.run(callback);span.end(signalAborted(signal)?"cancelled":"ok");return value;}catch(error){span.run(()=>this.captureException(error));span.end(signalAborted(signal)?"cancelled":"error");throw error;}
 }
 async withJobAttempt<T>(job:string,runId:string,ordinal:number,callback:()=>Promise<T>):Promise<T>{
  if(this.closed)throw Error("client closed");return this.jobs.run(job,runId,ordinal,callback);
 }
 bufferedRecords():readonly string[]{return this.delivery.records();}
 diagnostics():Readonly<Record<string,number>>{const counts={...this.counts};for(const [key,value] of Object.entries(this.delivery.diagnostics()))counts[key]=(counts[key]??0)+value;return Object.freeze(counts);}
 flush(timeoutMs=2000):Promise<FlushReport>{return this.delivery.flush(timeoutMs);}
 async close():Promise<void>{if(this.closed)return;for(const lease of [...this.hookLeases])lease.close();this.spans.close();this.closed=true;await this.delivery.close();}
}
export function init(config:Config):Client{return new Client(config);}
/** One token means exactly one logical occurrence, not an implicit identity cache.
 * No raw errors, object IDs, messages or stacks are retained across calls. */
export class HandlingEpisode {
 private event:EventId|undefined;private closed=false;
 constructor(private readonly client:Client){}
 belongsTo(client:Client):boolean{return !this.closed&&this.client===client;}
 captureException(error:unknown,options?:{code?:string}):EventId{
  if(this.closed)throw Error("episode closed");
  return this.event??(this.event=this.client.captureException(error,options));
 }
 captureHook(error:unknown,mechanism:HookMechanism,fatal:boolean):EventId{
  if(this.closed)throw Error("episode closed");
  return this.event??(this.event=this.client.captureHook(error,mechanism,fatal));
 }
 close():void{this.closed=true;}
}
/** Per-lease, source-bound weak identity arms. No raw thrown object is retained. */
export class HookEpisodeBindings {
 private pending:{episode:HandlingEpisode;error:WeakRef<object>;mechanism:HookMechanism}[]=[];
 constructor(private readonly client:Client){}
 arm(episode:HandlingEpisode,error:unknown,mechanism:HookMechanism):void{
  if(!episode.belongsTo(this.client))throw Error("invalid handling episode");
  if(!["uncaught_exception","unhandled_rejection","thread_exception","asyncio_exception"].includes(mechanism))throw Error("invalid hook mechanism");
  if(!((typeof error==="object"&&error!==null)||typeof error==="function"))throw Error("weak_error_identity_required");
  this.pending=this.pending.filter(arm=>arm.error.deref()!==undefined&&arm.episode.belongsTo(this.client));
  if(this.pending.some(arm=>arm.mechanism===mechanism&&arm.error.deref()===error))throw Error("ambiguous episode binding");
  if(this.pending.length>=8)throw Error("episode arm limit");
  this.pending.push({episode,error:new WeakRef(error),mechanism});
 }
 take(error:unknown,mechanism:HookMechanism):HandlingEpisode|undefined{
  let match:HandlingEpisode|undefined;
  this.pending=this.pending.filter(arm=>{
   const original=arm.error.deref();
   if(original===undefined||!arm.episode.belongsTo(this.client))return false;
   if(match===undefined&&arm.mechanism===mechanism&&original===error){match=arm.episode;return false;}
   return true;
  });
  return match;
 }
 clear(episode?:HandlingEpisode):void{this.pending=episode?this.pending.filter(arm=>arm.episode!==episode):[];}
}
