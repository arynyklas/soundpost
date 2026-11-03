// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {Config,EventId,Template,PolicyDecision,CaptureInput,HookMechanism,OwnedHookLease} from "./types.ts";
import {resolve,decimal,approveTemplate,normalizeRecord,canonical,utf8Size,type SourcePolicy} from "./policy.ts";
import {extractException,type ErrorBoundary} from "./errors.ts";
export type {ErrorBoundary} from "./errors.ts";
export class Client {
 private readonly queue:{record:string;bytes:number;at:number}[]=[];
 private readonly counts:Record<string,number>=Object.create(null) as Record<string,number>;
 private readonly policy:SourcePolicy;
 private readonly templates=new Map<string,Template>();
 private readonly clock:()=>string;
 private readonly maxRecords:number;private readonly maxBytes:number;private bytes=0;
 private readonly build:string;private readonly codes:ReadonlySet<string>;private closed=false;
 private readonly hookLeases=new Set<OwnedHookLease>();
 constructor(config:Config,private readonly errorBoundary?:ErrorBoundary){
  const records=config.maxRecords??1024,bytes=config.maxBytes??2097152;
  if(!Number.isInteger(records)||records<1||records>1024||!Number.isInteger(bytes)||bytes<1||bytes>2097152)throw Error("invalid queue limits");
  for(const identity of [config.org,config.project,config.source,config.build])if(typeof identity!=="string"||!identity.length||utf8Size(identity)>128)throw Error("invalid identity");
  for(const flag of [config.deploymentErrors,config.deploymentLogs,config.deploymentReplay,config.deploymentBodies])if(flag!==undefined&&typeof flag!=="boolean")throw Error("deployment permissions must be boolean");
  if(config.integrations?.length)throw Error("integrations not available");
  this.policy=resolve(config);this.clock=config.clockNs??(()=>String(BigInt(Date.now())*1000000n));this.maxRecords=records;this.maxBytes=bytes;this.build=config.build;this.codes=new Set(config.operations??[]);
  for(const template of config.templates??[])this.registerTemplate(template);
 }
 get policyDecision():PolicyDecision{return this.policy.decision;}
 private loss(reason:string):void{this.counts[reason]=(this.counts[reason]??0)+1;}
 private expire():void{const now=performance.now();while(this.queue[0]&&now-this.queue[0].at>=300000){const item=this.queue.shift();if(item){this.bytes-=item.bytes;this.loss("queue_expired");}}}
 registerTemplate(template:Template):void{
  if(this.closed)throw Error("client closed");const safe=approveTemplate(template),old=this.templates.get(safe.id);
  if(old&&BigInt(old.revision)>=BigInt(safe.revision))throw Error("template revision must increase");this.templates.set(safe.id,safe);
 }
 private admit(input:CaptureInput):boolean{
  if(this.closed){this.loss("closed");return false;}this.expire();const result=normalizeRecord(this.policy,input,this.templates);
  if(!result.record){this.loss(result.reason??"policy_rejected");return false;}
  const record=canonical(result.record),bytes=new TextEncoder().encode(record).length;
  if(bytes>262144){this.loss("record_too_large");return false;}
  if(this.queue.length>=this.maxRecords||this.bytes+bytes>this.maxBytes){this.loss("queue_full");return false;}
  this.queue.push({record,bytes,at:performance.now()});this.bytes+=bytes;return true;
 }
 private id():string{return Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,"0")).join("");}
 captureException(error:unknown,options?:{code?:string}):EventId{
  return this.captureError(error,options,"manual",false);
 }
 private captureError(error:unknown,options:{code?:string}|undefined,mechanism:HookMechanism|"manual",fatal:boolean):EventId{
  const id=this.id();
  const descriptor=options&&Object.getOwnPropertyDescriptor(options,"code");const value:unknown=descriptor&&"value" in descriptor?descriptor.value:undefined;
  const code=typeof value==="string"&&this.codes.has(value)?value:null;
  const graph=extractException(error,this.policy,this.errorBoundary);
  this.admit({kind:"error",id,observed_at_ns:decimal(this.clock()),exception_class:graph.nodes[0]?.exception_class??"UnknownError",code,build_id:this.build,exception_graph:graph,handled:mechanism==="manual",fatal,mechanism});return id;
 }
 beginHandlingEpisode():HandlingEpisode{return new HandlingEpisode(this);}
 captureHook(error:unknown,mechanism:HookMechanism,fatal:boolean):EventId{
  if(!["uncaught_exception","unhandled_rejection","thread_exception","asyncio_exception"].includes(mechanism)||typeof fatal!=="boolean")throw Error("invalid hook mechanism");
  return this.captureError(error,undefined,mechanism,fatal);
 }
 hookCaptureFailed():void{this.loss("hook_capture_failed");}
 ownHookLease(lease:OwnedHookLease):void{if(this.closed)throw Error("client closed");if(this.hookLeases.size>=8)throw Error("hook lease limit");this.hookLeases.add(lease);}
 releaseHookLease(lease:OwnedHookLease):void{this.hookLeases.delete(lease);}
 captureLog(template:string,fields:Readonly<Record<string,unknown>>):EventId|undefined{
  if(typeof template!=="string"){this.loss("unknown_template");return undefined;}
  const id=this.id();return this.admit({kind:"log",id,observed_at_ns:decimal(this.clock()),template_id:template,fields})?id:undefined;
 }
 bufferedRecords():readonly string[]{this.expire();return Object.freeze(this.queue.map(x=>x.record));}
 diagnostics():Readonly<Record<string,number>>{return Object.freeze({...this.counts});}
 async close():Promise<void>{if(!this.closed){for(const lease of [...this.hookLeases])lease.close();this.counts.closed_pending=(this.counts.closed_pending??0)+this.queue.length;this.queue.length=0;this.bytes=0;this.closed=true;}}
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
