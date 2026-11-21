// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {canonicalId,decimal,unixNano} from './policy.ts';
import {nativeCanonical} from './routing.ts';
import type {Config} from './types.ts';
import {object,array,text} from './wire.ts';
export interface FrozenBatch {readonly id:string;readonly source:string;readonly producer:string;readonly route_slot:number;readonly hash:string;readonly body:string;readonly count:number;readonly kinds:readonly string[];readonly firstCapture:number;readonly policyRevision:string}
export interface Outcome {readonly kind:'receipt'|'retryable'|'terminal'|'ambiguous'|'denied'|'not_found'|'invalid'|'unacknowledged';readonly receipt?:Record<string,unknown>;readonly retryAfterMs?:number}
export interface ReceiptTransport {send(batch:FrozenBatch,deadline:number):Promise<Outcome>;lookup(batch:FrozenBatch,deadline:number):Promise<Outcome>;close():void|Promise<void>}
export interface HttpRequestOptions {readonly method:"POST";readonly headers:Readonly<Record<string,string>>;readonly body:string;readonly redirect:"error";readonly credentials:"omit";readonly cache:"no-store";readonly referrerPolicy:"no-referrer";readonly signal:AbortSignal;readonly keepalive:boolean}
export type HttpRequest=(url:string,options:HttpRequestOptions)=>Promise<Response>;
export function strictJSON(text:string):unknown{
 // Validate duplicate keys before JSON.parse discards them. Strings are decoded by JSON itself.
 let p=0;const ws=()=>{while(/\s/.test(text[p]??'')&&p<text.length)p++;};
 const string=():string=>{const start=p++;while(p<text.length){const c=text[p++];if(c==='\\')p++;else if(c==='"')return JSON.parse(text.slice(start,p)) as string;}throw Error('invalid response');};
 const value=(depth:number):void=>{if(depth>64)throw Error('invalid response');ws();const c=text[p];if(c==='"'){string();return;}if(c==='{'||c==='['){p++;ws();const close=c==='{'?'}':']',seen=new Set<string>();if(text[p]===close){p++;return;}for(;;){if(c==='{'){ws();if(text[p]!=='"')throw Error('invalid response');const k=string();if(seen.has(k))throw Error('duplicate response key');seen.add(k);ws();if(text[p++]!==':')throw Error('invalid response');}value(depth+1);ws();if(text[p]===close){p++;return;}if(text[p++]!==',')throw Error('invalid response');}}const m=/^(?:null|true|false|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(p));if(!m)throw Error('invalid response');p+=m[0].length;};
 value(0);ws();if(p!==text.length)throw Error('invalid response');const decoded:unknown=JSON.parse(text);nativeCanonical(decoded);return decoded;
}
export function verifyReceipt(batch:FrozenBatch,value:unknown,historical:boolean):value is Record<string,unknown>{
 try{
  const r=object(value);
  if(r.version!==1||r.batch_id!==batch.id||r.hash!==batch.hash||! /^[0-9a-f]{64}$/.test(text(r.hash))||r.historical!== (historical?true:undefined))return false;
  const cursor=object(r.cursor);canonicalId(r.batch_id);canonicalId(cursor.group);if(decimal(cursor.index)==='0')return false;
  const retain=BigInt(unixNano(r.retain_until_ns));unixNano(r.dedup_until_ns);
  const deadlines=array(r.signal_deadlines);if(deadlines.length!==batch.kinds.length)return false;
  const seen=new Set<string>();let min:bigint|undefined;
  for(const value of deadlines){const d=object(value),kind=text(d.kind);if(!batch.kinds.includes(kind)||seen.has(kind))return false;seen.add(kind);const n=BigInt(unixNano(d.retain_until_ns));min=min===undefined||n<min?n:min;}
  return min!==undefined&&min===retain;
 }catch{return false;}
}
export function retryAfter(value:string|null,now=Date.now()):number|undefined{
 if(value===null)return undefined;let milliseconds:number;if(/^\d+$/.test(value))milliseconds=Number(value)*1000;else milliseconds=Date.parse(value)-now;
 return Number.isFinite(milliseconds)?Math.min(30000,Math.max(250,milliseconds)):undefined;
}
export class HttpsReceiptTransport implements ReceiptTransport {
 private readonly endpoint:URL;private readonly headers:Readonly<Record<string,string>>;private readonly request:HttpRequest;private readonly controllers=new Set<AbortController>();private closed=false;
 constructor(config:Config,request:HttpRequest=globalThis.fetch.bind(globalThis)){
  this.endpoint=new URL(config.endpoint);if(this.endpoint.protocol!=='https:'||this.endpoint.username||this.endpoint.password||this.endpoint.search||this.endpoint.hash||this.endpoint.pathname!=='/ingest/v1/batches')throw Error('HTTPS ingestion endpoint required');
  if(typeof config.credential!=='string'||!config.credential||/[\s\r\n]/.test(config.credential))throw Error('invalid source credential');
  this.headers=Object.freeze({'Content-Type':'application/json',...(config.sourceClass==='browser'?{'X-Soundpost-Source':config.credential}:{Authorization:'Bearer '+config.credential})});this.request=request;
 }
 private async post(path:string,body:string,deadline:number,lookup:boolean,keepalive=false):Promise<Outcome>{
  if(this.closed)return {kind:'denied'};if(deadline<=performance.now())return {kind:'ambiguous'};const controller=new AbortController();this.controllers.add(controller);const timer=setTimeout(()=>controller.abort(),Math.max(1,deadline-performance.now()));
  try{
   const response=await this.request(new URL(path,this.endpoint).href,{method:'POST',headers:this.headers,body,redirect:'error',credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer',signal:controller.signal,keepalive});
   if(response.status!==200){try{await response.body?.cancel();}catch{controller.abort();}}
   if(response.status===401||response.status===403)return {kind:'denied'};
   if(lookup&&response.status===404)return {kind:'not_found'};
   if(response.status===429||response.status===503){const delay=retryAfter(response.headers.get('Retry-After'));return {kind:'retryable',...(delay===undefined?{}:{retryAfterMs:delay})};}
   if(response.status!==200)return {kind:'terminal'};
   if(!response.body)return {kind:keepalive?'unacknowledged':'invalid'};
   const reader=response.body.getReader();const parts:Uint8Array[]=[];let length=0;
   try{for(;;){const item=await reader.read();if(item.done)break;length+=item.value.length;if(length>65536){await reader.cancel();return {kind:'invalid'};}parts.push(item.value);}}finally{reader.releaseLock();}
   const bytes=new Uint8Array(length);let at=0;for(const p of parts){bytes.set(p,at);at+=p.length;}
   const receipt=strictJSON(new TextDecoder('utf-8',{fatal:true}).decode(bytes));return receipt&&typeof receipt==='object'&&!Array.isArray(receipt)?{kind:'receipt',receipt:receipt as Record<string,unknown>}:{kind:'invalid'};
  }catch{return {kind:'ambiguous'};}finally{controller.abort();clearTimeout(timer);this.controllers.delete(controller);}
 }
 send(batch:FrozenBatch,deadline:number):Promise<Outcome>{return this.post('/ingest/v1/batches',batch.body,deadline,false);}
 lookup(batch:FrozenBatch,deadline:number):Promise<Outcome>{return this.post('/ingest/v1/receipts',nativeCanonical({source:batch.source,producer:batch.producer,route_slot:batch.route_slot,batch_id:batch.id,original_hash:batch.hash}),deadline,true);}
 /** A keepalive write is never an ACK without reading and verifying its receipt. */
 pageExit(batch:FrozenBatch,deadline:number):Promise<Outcome>{return this.post('/ingest/v1/batches',batch.body,deadline,false,true);}
 close():void{this.closed=true;for(const c of this.controllers)c.abort();this.controllers.clear();}
}
