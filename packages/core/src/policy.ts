// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {ed25519} from "@noble/curves/ed25519";
import type {Config,PolicyDecision,Template,Primitive,CaptureInput,SafeRecord} from "./types.ts";
import {normalizeAttempt} from "./jobs.ts";
export interface SourcePolicy {readonly decision:PolicyDecision;readonly expiresNs:string}
export function utf8Size(value:string):number{
 let bytes=0;
 for(const character of value){
  const point=character.codePointAt(0)!;
  if(point>=0xd800&&point<=0xdfff)throw Error("invalid Unicode text");
  bytes+=point<=0x7f?1:point<=0x7ff?2:point<=0xffff?3:4;
 }
 return bytes;
}
export function canonicalId(value:unknown):string{
 if(typeof value!=="string"||value.length!==32||! /^[0-9a-f]{32}$/.test(value)||value==="0".repeat(32))throw Error("invalid opaque ID");
 return value;
}
export function decimal(value:unknown):string{
 if(typeof value!=="string"||! /^(0|[1-9][0-9]{0,19})$/.test(value))throw Error("invalid uint64");
 const number=BigInt(value);if(number>18446744073709551615n||number.toString()!==value)throw Error("invalid uint64");
 return value;
}
export function unixNano(value:unknown):string{
 if(typeof value!=="string"||! /^(0|-?[1-9][0-9]{0,18})$/.test(value))throw Error("invalid UnixNano");
 const number=BigInt(value);if(number< -9223372036854775808n||number>9223372036854775807n||number.toString()!==value)throw Error("invalid UnixNano");
 return value;
}
function decode(v:string):Uint8Array{
 if(typeof v!=="string"||! /^[A-Za-z0-9_-]+$/.test(v))throw Error("invalid policy encoding");
 const raw=atob(v.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-v.length%4)%4));
 const result=Uint8Array.from(raw,c=>c.charCodeAt(0));
 if(btoa(raw).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_")!==v)throw Error("invalid policy encoding");return result;
}
export function canonical(v:unknown):string{
 if(v===null||typeof v==="boolean")return JSON.stringify(v);
 if(typeof v==="string"){utf8Size(v);return JSON.stringify(v);}
 if(typeof v==="number"&&Number.isSafeInteger(v))return String(v);
 if(Array.isArray(v)){const values:string[]=[];for(let i=0;i<v.length;i++){const d=Object.getOwnPropertyDescriptor(v,String(i));if(!d||!("value" in d))throw Error("noncanonical accessor");values.push(canonical(d.value));}return "["+values.join(",")+"]";}
 if(typeof v==="object"&&v!==null)return "{"+Object.keys(v).sort(utf8Compare).map(k=>{const d=Object.getOwnPropertyDescriptor(v,k);if(!d||!("value" in d))throw Error("noncanonical accessor");return canonical(k)+":"+canonical(d.value);}).join(",")+"}";
 throw Error("noncanonical value");
}
export function utf8Compare(a:string,b:string):number{const x=new TextEncoder().encode(a),y=new TextEncoder().encode(b);for(let i=0;i<Math.min(x.length,y.length);i++)if(x[i]!==y[i])return x[i]!-y[i]!;return x.length-y.length;}
export function resolve(config:Config):SourcePolicy{
 try{
  const e=config.policy;if(e.version!==1||e.algorithm!=="Ed25519")throw Error();
  const bytes=decode(e.payload),sig=decode(e.signature),key=config.trustedKeys[e.key_id];
  if(bytes.length>65536||!key||key.length!==32||!ed25519.verify(sig,bytes,key,{zip215:false}))throw Error();
  const text=new TextDecoder("utf-8",{fatal:true}).decode(bytes);const d:unknown=JSON.parse(text);
  if(canonical(d)!==text||!d||typeof d!=="object"||Array.isArray(d))throw Error();
  const p=d as Record<string,unknown>;
  const names=["version","org","project","source","revision","expires_ns","errors","logs","replay","bodies"].sort();
  if(names.some(k=>!Object.hasOwn(p,k))||Object.keys(p).some(k=>!names.includes(k)&&k!=="traces"&&k!=="jobs"&&k!=="loss")||p.version!==1)throw Error();
  for(const n of ["org","project","source"] as const)if(canonicalId(p[n])!==config[n])throw Error();
  for(const n of ["errors","logs","replay","bodies"])if(typeof p[n]!=="boolean")throw Error();
  for(const n of ["traces","jobs","loss"])if(Object.hasOwn(p,n)&&typeof p[n]!=="boolean")throw Error();
  return Object.freeze({expiresNs:unixNano(p.expires_ns),decision:Object.freeze({approved:true,reason:"approved",revision:decimal(p.revision),errors:p.errors===true&&(config.deploymentErrors??true),logs:p.logs===true&&(config.deploymentLogs??true),replay:p.replay===true&&(config.deploymentReplay??false),bodies:p.bodies===true&&(config.deploymentBodies??false),traces:p.traces===true&&(config.deploymentTraces??true),jobs:p.jobs===true&&(config.deploymentJobs??true),loss:p.loss===true&&(config.deploymentLoss??true)})});
 }catch{throw Error("invalid signed policy");}
}
export function approveTemplate(t:Template):Template{
 if(typeof t.id!=="string"||! /^[a-zA-Z0-9_.-]{1,128}$/.test(t.id)||typeof t.line!=="string"||utf8Size(t.line)>4096)throw Error("invalid template");decimal(t.revision);
 if(typeof t.severity!=="string"||!["trace","debug","info","warn","error","fatal"].includes(t.severity))throw Error("invalid severity");
 const fields:Record<string,readonly Primitive[]>=Object.create(null) as Record<string,readonly Primitive[]>;
 for(const key of Object.keys(t.fields)){
  if(! /^[a-zA-Z_][a-zA-Z0-9_]{0,63}$/.test(key))throw Error("invalid field");
  const desc=Object.getOwnPropertyDescriptor(t.fields,key);if(!desc||!("value" in desc)||!Array.isArray(desc.value)||!desc.value.length)throw Error("invalid field");
  const values:Primitive[]=[];
  for(const value of desc.value){if(!(value===null||typeof value==="boolean"||(typeof value==="string"&&utf8Size(value)<=256)||(typeof value==="number"&&Number.isSafeInteger(value))))throw Error("invalid approved value");values.push(value);}
  fields[key]=Object.freeze(values);
 }
 const stripped=t.line.replace(/\{([^{}]+)\}/g,(_whole,key:string)=>{if(!Object.hasOwn(fields,key))throw Error("invalid placeholder");return "";});
 if(/[{}]/.test(stripped))throw Error("invalid placeholder");
 return Object.freeze({id:t.id,revision:t.revision,line:t.line,fields:Object.freeze(fields),severity:t.severity});
}
export function normalizeRecord(policy:SourcePolicy,input:CaptureInput,templates:ReadonlyMap<string,Template>):{record?:SafeRecord;reason?:string}{
 try{canonicalId(input.id);if(input.kind==="error")canonicalId(input.build_id);}catch{return {reason:"invalid_id"};}
 try{unixNano(input.observed_at_ns);}catch{return {reason:"invalid_clock"};}
 if(BigInt(input.observed_at_ns)>=BigInt(policy.expiresNs))return {reason:"policy_expired"};
 if(!(input.kind==="error"?policy.decision.errors:input.kind==="span"?policy.decision.traces:input.kind==="job_attempt"?policy.decision.jobs:input.kind==="log"?policy.decision.logs:false))return {reason:"policy_disabled"};
 let payload:Record<string,unknown>;
 if(input.kind==="span")payload={trace_id:input.span.trace_id,span_id:input.span.span_id,parent_id:input.span.parent_id,span_kind:input.span.span_kind,operation:input.span.operation,start:input.span.start,end:input.span.end,status:input.span.status,dependency_alias:input.span.dependency_alias,links:input.span.links,sample_probability:input.span.sample_probability,sample_decision:input.span.sample_decision};
 else if(input.kind==="job_attempt"){try{payload={...normalizeAttempt(input.payload)};}catch{return {reason:"invalid_job_attempt"};}}
 else if(input.kind==="error"){
  if(input.trace_id!==undefined){try{canonicalId(input.trace_id);if(typeof input.span_id!=="string"||!/^[0-9a-f]{16}$/.test(input.span_id)||input.span_id==="0".repeat(16))throw Error();}catch{return {reason:"invalid_trace_context"};}}
  if(input.run_id!==undefined){try{canonicalId(input.run_id);}catch{return {reason:"invalid_run_context"};}}
  payload={occurrence_id:input.id,exception_class:input.exception_class,code:input.code,build_id:input.build_id,handled:input.handled,fatal:input.fatal,mechanism:input.mechanism,frames:input.exception_graph.nodes[0]?.frames??[],exception_graph:input.exception_graph,...(input.trace_id!==undefined?{trace_id:input.trace_id,span_id:input.span_id}:{}),...(input.run_id!==undefined?{run_id:input.run_id}:{})};
 }else{
  const template=templates.get(input.template_id);if(!template)return {reason:"unknown_template"};
  if(input.fields===null||typeof input.fields!=="object")return {reason:"invalid_fields"};
  const fields:Record<string,Primitive>=Object.create(null) as Record<string,Primitive>;
  for(const [key,allowed] of Object.entries(template.fields)){
   const desc=Object.getOwnPropertyDescriptor(input.fields,key);if(!desc||!("value" in desc))return {reason:"invalid_field"};
   const value:unknown=desc.value;if(!allowed.some(v=>typeof v===typeof value&&v===value))return {reason:"invalid_field"};fields[key]=value as Primitive;
  }
  const line=template.line.replace(/\{([^{}]+)\}/g,(_whole,key:string)=>{const value=fields[key];return typeof value==="string"?value:JSON.stringify(value);});
  payload={template_id:template.id,template_revision:template.revision,fields:Object.freeze(fields),line,severity:template.severity,stream_labels:[],structured_metadata:{},source_class:"structured"};
 }
 return {record:Object.freeze({kind:input.kind,id:input.id,observed_at_ns:input.observed_at_ns,policy_revision:policy.decision.revision,payload:Object.freeze(payload)})};
}
