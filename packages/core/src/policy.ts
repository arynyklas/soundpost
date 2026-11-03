// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {ed25519} from "@noble/curves/ed25519";
import type {Config,PolicyDecision,Template,Primitive,CaptureInput,SafeRecord} from "./types.ts";
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
export function decimal(v:unknown):string{if(typeof v!=="string"||! /^(0|[1-9][0-9]{0,29})$/.test(v))throw Error("invalid decimal");return v;}
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
 if(Array.isArray(v))return "["+v.map(canonical).join(",")+"]";
 if(typeof v==="object"&&v!==null)return "{"+Object.keys(v).sort().map(k=>canonical(k)+":"+canonical((v as Record<string,unknown>)[k])).join(",")+"}";
 throw Error("noncanonical value");
}
export function resolve(config:Config):SourcePolicy{
 try{
  const e=config.policy;if(e.version!==1||e.algorithm!=="Ed25519")throw Error();
  const bytes=decode(e.payload),sig=decode(e.signature),key=config.trustedKeys[e.key_id];
  if(bytes.length>65536||!key||key.length!==32||!ed25519.verify(sig,bytes,key,{zip215:false}))throw Error();
  const text=new TextDecoder("utf-8",{fatal:true}).decode(bytes);const d:unknown=JSON.parse(text);
  if(canonical(d)!==text||!d||typeof d!=="object"||Array.isArray(d))throw Error();
  const p=d as Record<string,unknown>;
  const names=["version","org","project","source","revision","expires_ns","errors","logs","replay","bodies"].sort();
  if(Object.keys(p).sort().join(",")!==names.join(",")||p.version!==1)throw Error();
  for(const n of ["org","project","source"] as const)if(p[n]!==config[n])throw Error();
  for(const n of ["errors","logs","replay","bodies"])if(typeof p[n]!=="boolean")throw Error();
  return Object.freeze({expiresNs:decimal(p.expires_ns),decision:Object.freeze({approved:true,reason:"approved",revision:decimal(p.revision),errors:p.errors===true&&(config.deploymentErrors??true),logs:p.logs===true&&(config.deploymentLogs??true),replay:p.replay===true&&(config.deploymentReplay??false),bodies:p.bodies===true&&(config.deploymentBodies??false)})});
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
 if(BigInt(input.observed_at_ns)>=BigInt(policy.expiresNs))return {reason:"policy_expired"};
 if(!(input.kind==="error"?policy.decision.errors:policy.decision.logs))return {reason:"policy_disabled"};
 let payload:Record<string,unknown>;
 if(input.kind==="error")payload={occurrence_id:input.id,exception_class:input.exception_class,code:input.code,build_id:input.build_id,handled:true,fatal:false,frames:[]};
 else{
  const template=templates.get(input.template_id);if(!template)return {reason:"unknown_template"};
  if(input.fields===null||typeof input.fields!=="object")return {reason:"invalid_fields"};
  const fields:Record<string,Primitive>=Object.create(null) as Record<string,Primitive>;
  for(const [key,allowed] of Object.entries(template.fields)){
   const desc=Object.getOwnPropertyDescriptor(input.fields,key);if(!desc||!("value" in desc))return {reason:"invalid_field"};
   const value:unknown=desc.value;if(!allowed.some(v=>typeof v===typeof value&&v===value))return {reason:"invalid_field"};fields[key]=value as Primitive;
  }
  const line=template.line.replace(/\{([^{}]+)\}/g,(_whole,key:string)=>{const value=fields[key];return typeof value==="string"?value:JSON.stringify(value);});
  payload={template_id:template.id,template_revision:template.revision,fields:Object.freeze(fields),line,severity:template.severity,stream_labels:{},structured_metadata:{},source_class:"structured"};
 }
 return {record:Object.freeze({kind:input.kind,id:input.id,observed_at_ns:input.observed_at_ns,policy_revision:policy.decision.revision,payload:Object.freeze(payload)})};
}
