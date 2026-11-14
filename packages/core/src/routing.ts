// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {sha256} from '@noble/hashes/sha256';
import {canonical,canonicalId,decimal,utf8Compare,utf8Size} from './policy.ts';
import type {RoutingDescriptor,Resource} from './types.ts';
import {object,text} from './wire.ts';
export const kinds=['metric','log','span','error','job_attempt','replay_chunk','profile_chunk','capability','loss','condition'] as const;
const lineSeparators=/[\u2028\u2029]/,encoder=new TextEncoder();
export function nativeCanonical(value:unknown):string{const out=canonical(value);return lineSeparators.test(out)?out.replace(/\u2028/g,'\\u2028').replace(/\u2029/g,'\\u2029'):out;}
type BuiltinCrypto={createHash(name:string):{update(data:string,encoding:'utf8'):{digest(encoding:'hex'):string}}};
interface NodeHost {readonly versions?:{readonly node?:string};getBuiltinModule?(id:string):unknown}
function isBuiltinCrypto(value:unknown):value is BuiltinCrypto{return typeof value==='object'&&value!==null&&'createHash' in value&&typeof value.createHash==='function';}
/** The runtime's native SHA-256 when this is Node or Bun (batch bodies are hundreds of KiB; the pure-JS hash is the slower path there). Same digest either way. */
const nativeCrypto:BuiltinCrypto|undefined=(()=>{
 try{
  const host:NodeHost|undefined=Reflect.get(globalThis,'process');
  const found:unknown=host?.versions?.node!==undefined?host.getBuiltinModule?.('node:crypto'):undefined;
  return isBuiltinCrypto(found)?found:undefined;
 }catch{return undefined;}
})();
export function hashBytes(value:string):string{
 if(nativeCrypto&&value.length>=1024)return nativeCrypto.createHash('sha256').update(value,'utf8').digest('hex');
 return Array.from(sha256(encoder.encode(value)),b=>b.toString(16).padStart(2,'0')).join('');
}
const validated=new WeakSet<RoutingDescriptor>();
export function validateDescriptor(d:RoutingDescriptor):RoutingDescriptor{
 if(d.version!==1||d.routing_version!==1||d.slots!==64)throw Error('invalid routing descriptor');for(const id of [d.org,d.project,d.source])canonicalId(id);decimal(d.policy_revision);const frozen=Object.freeze({...d});validated.add(frozen);return frozen;
}
export function resourceWire(r:Resource|undefined,build:string):Record<string,unknown>{
 if(!r)throw Error('resource required');for(const id of [r.service_id,r.environment_id,r.build_id])canonicalId(id);
 if(r.build_id!==build||typeof r.instance_pseudonym!=='string'||!r.instance_pseudonym.length||r.instance_pseudonym.length>256||/[^a-zA-Z0-9_.:/<>+ $-]/.test(r.instance_pseudonym))throw Error('invalid resource');
 const labels=(r.labels??[]).map(l=>({name:l.name,value:l.value}));validateLabels(labels);
 return {service_id:r.service_id,environment_id:r.environment_id,build_id:r.build_id,instance_pseudonym:r.instance_pseudonym,labels};
}
function validateLabels(value:unknown):asserts value is {name:string;value:string}[]{
 if(!Array.isArray(value))throw Error('labels required');let last:string|undefined;
 for(const item of value){const l=object(item);if(typeof l.name!=='string'||!utf8Size(l.name)||typeof l.value!=='string'||(last!==undefined&&utf8Compare(last,l.name)>=0))throw Error('invalid labels');utf8Size(l.value);last=l.name;}
}
export function ownerKey(record:unknown,descriptor:RoutingDescriptor,producer:string):Uint8Array{
 const r=object(record),kind=text(r.kind),p=object(r.payload);let owner:string;
 switch(kind){
 case 'metric':validateLabels(p.labels);if(typeof p.name!=='string'||!utf8Size(p.name))throw Error('invalid metric name');owner=nativeCanonical({name:p.name,labels:p.labels});break;
 case 'log':validateLabels(p.stream_labels);owner=nativeCanonical(p.stream_labels);break;
 case 'span':owner=canonicalId(p.trace_id);break;
 case 'error':owner=canonicalId(p.occurrence_id);break;
 case 'job_attempt':owner=canonicalId(p.run_id);break;
 case 'replay_chunk':owner=canonicalId(p.replay_id);break;
 case 'profile_chunk':owner=canonicalId(p.profile_id);break;
 case 'condition':owner=canonicalId(p.condition_id);break;
 case 'capability':case 'loss':owner=canonicalId(descriptor.source)+canonicalId(producer)+kind;break;
 default:throw Error('invalid signal');
 }
 return new TextEncoder().encode(owner);
}
export function routeRecord(record:unknown,descriptor:RoutingDescriptor,producer:string):number{
 const r=object(typeof record==='string'?JSON.parse(record):record),d=validated.has(descriptor)?descriptor:validateDescriptor(descriptor);canonicalId(producer);
 const parts=[encoder.encode(d.org),encoder.encode(d.project),encoder.encode(text(r.kind)),ownerKey(r,d,producer)];
 const length=parts.reduce((n,p)=>n+4+p.length,0),input=new Uint8Array(length),view=new DataView(input.buffer);let at=0;
 for(const p of parts){view.setUint32(at,p.length,false);at+=4;input.set(p,at);at+=p.length;}
 const hash=sha256(input);return hash[7]!%64;
}
