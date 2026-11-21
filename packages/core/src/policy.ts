// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {ed25519} from "@noble/curves/ed25519";
import type {Config,PolicyDecision,Template,Primitive,CaptureInput,SafeRecord} from "./types.ts";
import {normalizeAttempt} from "./jobs.ts";
export interface SourcePolicy {readonly decision:PolicyDecision;readonly expiresNs:string}
const asciiOnly=/^[\x00-\x7f]*$/,zeroId="0".repeat(32),idShape=/^[0-9a-f]{32}$/;
export function utf8Size(value:string):number{
 // ASCII is one byte per UTF-16 unit and can hold no surrogate; only other text needs the code point walk.
 if(asciiOnly.test(value))return value.length;
 let bytes=0;
 for(const character of value){
  const point=character.codePointAt(0)!;
  if(point>=0xd800&&point<=0xdfff)throw Error("invalid Unicode text");
  bytes+=point<=0x7f?1:point<=0x7ff?2:point<=0xffff?3:4;
 }
 return bytes;
}
export function canonicalId(value:unknown):string{
 if(typeof value!=="string"||value.length!==32||!idShape.test(value)||value===zeroId)throw Error("invalid opaque ID");
 return value;
}
const unsignedShape=/^(0|[1-9][0-9]{0,19})$/,signedShape=/^(0|-?[1-9][0-9]{0,18})$/;
export function decimal(value:unknown):string{
 if(typeof value!=="string"||!unsignedShape.test(value))throw Error("invalid uint64");
 // The shape has no leading zero, so the range is decided by length and, only at 20 digits, by digit order against 2^64-1.
 if(value.length===20&&value>"18446744073709551615")throw Error("invalid uint64");
 return value;
}
export function unixNano(value:unknown):string{
 if(typeof value!=="string"||!signedShape.test(value))throw Error("invalid UnixNano");
 // Same reasoning against the int64 bounds; equal-length digit strings order like their numbers.
 const negative=value.charCodeAt(0)===45;
 if(value.length-(negative?1:0)===19&&value.slice(negative?1:0)>(negative?"9223372036854775808":"9223372036854775807"))throw Error("invalid UnixNano");
 return value;
}
/** Numeric order of two canonical decimal integers (optional leading minus, no leading zeros), as -1, 0 or 1, without BigInt. */
export function compareNano(a:string,b:string):number{
 const negativeA=a.charCodeAt(0)===45,negativeB=b.charCodeAt(0)===45;
 if(negativeA!==negativeB)return negativeA?-1:1;
 const magnitude=a.length!==b.length?(a.length<b.length?-1:1):a<b?-1:a>b?1:0;
 return negativeA&&magnitude!==0?-magnitude:magnitude;
}
function decode(v:string):Uint8Array{
 if(typeof v!=="string"||! /^[A-Za-z0-9_-]+$/.test(v))throw Error("invalid policy encoding");
 const raw=atob(v.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-v.length%4)%4));
 const result=Uint8Array.from(raw,c=>c.charCodeAt(0));
 if(btoa(raw).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_")!==v)throw Error("invalid policy encoding");return result;
}
const surrogate=/[\ud800-\udfff]/,keyMemo=new Map<string,string>();
/** A key's canonical form, remembered: record shapes repeat, so this skips the surrogate scan and JSON.stringify. Bounded so hostile key sets cannot grow it. */
function canonicalKey(key:string):string{
 let known=keyMemo.get(key);
 if(known===undefined){if(surrogate.test(key))utf8Size(key);known=JSON.stringify(key);if(keyMemo.size<2048)keyMemo.set(key,known);}
 return known;
}
export function canonical(v:unknown):string{
 if(typeof v==="string"){if(surrogate.test(v))utf8Size(v);return JSON.stringify(v);}
 if(v===null||typeof v==="boolean")return JSON.stringify(v);
 if(typeof v==="number"&&Number.isSafeInteger(v))return String(v);
 if(Array.isArray(v)){
  let out="[";
  for(let i=0;i<v.length;i++){const d=Object.getOwnPropertyDescriptor(v,i);if(!d||!("value" in d))throw Error("noncanonical accessor");out+=(i===0?"":",")+canonical(d.value);}
  return out+"]";
 }
 if(typeof v==="object"){
  const keys=Object.keys(v);if(keys.length>1)keys.sort(utf8Compare);
  let out="{";
  for(let i=0;i<keys.length;i++){const key=keys[i]!,d=Object.getOwnPropertyDescriptor(v,key);if(!d||!("value" in d))throw Error("noncanonical accessor");out+=(i===0?"":",")+canonicalKey(key)+":"+canonical(d.value);}
  return out+"}";
 }
 throw Error("noncanonical value");
}
/** Byte-wise UTF-8 order without encoding: code point order, which differs from UTF-16 unit order only where a surrogate meets U+E000..U+FFFF. */
export function utf8Compare(a:string,b:string):number{
 const length=a.length<b.length?a.length:b.length;
 for(let i=0;i<length;i++){
  let x=a.charCodeAt(i),y=b.charCodeAt(i);
  if(x!==y){
   if(x>=0xd800&&y>=0xd800){x=x>=0xe000?x-0x800:x+0x2000;y=y>=0xe000?y-0x800:y+0x2000;}
   return x-y;
  }
 }
 return a.length-b.length;
}
// noble's default 8-bit base-point window builds a ~4 MB table on first use (about 50 ms, and it grows V8's young generation, which lengthens GC pauses for the whole host
// application). A 4-bit window needs a table 8x smaller and ~4x less start-up work; checking a signature costs the same, and the check itself ({zip215:false}) is unchanged.
try{ed25519.Point.BASE.precompute(4);}catch{/* a noble without this tuning point keeps its own default */}
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
  return Object.freeze({expiresNs:unixNano(p.expires_ns),decision:Object.freeze({approved:true,reason:"approved",revision:decimal(p.revision),errors:p.errors===true&&(config.deploymentErrors??true),logs:p.logs===true&&(config.deploymentLogs??true),replay:p.replay===true&&(config.deploymentReplay??false),bodies:p.bodies===true&&(config.deploymentBodies??false),traces:p.traces===true&&(config.deploymentTraces??true),jobs:p.jobs===true&&(config.deploymentJobs??true),loss:p.loss===true&&(config.deploymentLoss??true),profiles:config.deploymentProfiles===true})});
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
/** Why the signed policy refuses a record of `kind` observed at `observedNs` before any serialization (expiry first, then the signal switch), or undefined when it may proceed. */
export function policyRefusal(policy:SourcePolicy,kind:CaptureInput["kind"],observedNs:string):"policy_expired"|"policy_disabled"|undefined{
 if(compareNano(observedNs,policy.expiresNs)>=0)return "policy_expired";
 if(!(kind==="error"?policy.decision.errors:kind==="span"?policy.decision.traces:kind==="job_attempt"?policy.decision.jobs:kind==="log"?policy.decision.logs:kind==="replay_chunk"?policy.decision.replay:kind==="profile_chunk"||kind==="capability"?policy.decision.profiles:false))return "policy_disabled";
 return undefined;
}
export function normalizeRecord(policy:SourcePolicy,input:CaptureInput,templates:ReadonlyMap<string,Template>):{record?:SafeRecord;reason?:string}{
 try{canonicalId(input.id);if(input.kind==="error")canonicalId(input.build_id);}catch{return {reason:"invalid_id"};}
 try{unixNano(input.observed_at_ns);}catch{return {reason:"invalid_clock"};}
 const refusal=policyRefusal(policy,input.kind,input.observed_at_ns);if(refusal!==undefined)return {reason:refusal};
 let payload:Record<string,unknown>;
 if(input.kind==="span")payload={trace_id:input.span.trace_id,span_id:input.span.span_id,parent_id:input.span.parent_id,span_kind:input.span.span_kind,operation:input.span.operation,start:input.span.start,end:input.span.end,status:input.span.status,dependency_alias:input.span.dependency_alias,links:input.span.links,sample_probability:input.span.sample_probability,sample_decision:input.span.sample_decision};
 else if(input.kind==="job_attempt"){try{payload={...normalizeAttempt(input.payload)};}catch{return {reason:"invalid_job_attempt"};}}
 else if(input.kind==="profile_chunk"||input.kind==="capability"||input.kind==="replay_chunk"){payload={...input.payload};}
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
