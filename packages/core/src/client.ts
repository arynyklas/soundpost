// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {Config,EventId,Template,PolicyDecision,CaptureInput} from "./types.ts";
import {resolve,decimal,approveTemplate,normalizeRecord,canonical,utf8Size,type SourcePolicy} from "./policy.ts";
export class Client {
 private readonly queue:{record:string;bytes:number;at:number}[]=[];
 private readonly counts:Record<string,number>=Object.create(null) as Record<string,number>;
 private readonly policy:SourcePolicy;
 private readonly templates=new Map<string,Template>();
 private readonly clock:()=>string;
 private readonly maxRecords:number;private readonly maxBytes:number;private bytes=0;
 private readonly build:string;private readonly codes:ReadonlySet<string>;private closed=false;
 constructor(config:Config){
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
 captureException(_error:unknown,options?:{code?:string}):EventId{
  const id=this.id();
  // Do not inspect unknown values/prototypes: accessors, proxies and toJSON are hostile.
  const descriptor=options&&Object.getOwnPropertyDescriptor(options,"code");const value:unknown=descriptor&&"value" in descriptor?descriptor.value:undefined;
  const code=typeof value==="string"&&this.codes.has(value)?value:null;
  this.admit({kind:"error",id,observed_at_ns:decimal(this.clock()),exception_class:"UnknownError",code,build_id:this.build});return id;
 }
 captureLog(template:string,fields:Readonly<Record<string,unknown>>):EventId|undefined{
  if(typeof template!=="string"){this.loss("unknown_template");return undefined;}
  const id=this.id();return this.admit({kind:"log",id,observed_at_ns:decimal(this.clock()),template_id:template,fields})?id:undefined;
 }
 bufferedRecords():readonly string[]{this.expire();return Object.freeze(this.queue.map(x=>x.record));}
 diagnostics():Readonly<Record<string,number>>{return Object.freeze({...this.counts});}
 async close():Promise<void>{if(!this.closed){this.counts.closed_pending=(this.counts.closed_pending??0)+this.queue.length;this.queue.length=0;this.bytes=0;this.closed=true;}}
}
export function init(config:Config):Client{return new Client(config);}
