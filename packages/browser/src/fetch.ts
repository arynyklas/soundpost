// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {Client} from "@soundpost/core";
import type {TraceContext} from "@soundpost/core/types";
import {propagationHeaders} from "./workers.ts";
export interface FetchIntegrationConfig {readonly operation:string;readonly origins:readonly Readonly<{origin:string;dependency:string}>[];readonly fetch?:typeof globalThis.fetch}
const installed=new WeakMap<Client,FetchLease>();
const requestURL=Object.getOwnPropertyDescriptor(Request.prototype,"url")!.get!;
const requestHeaders=Object.getOwnPropertyDescriptor(Request.prototype,"headers")!.get!;
const urlHref=Object.getOwnPropertyDescriptor(URL.prototype,"href")!.get!;
const aborted=Object.getOwnPropertyDescriptor(AbortSignal.prototype,"aborted")!.get!;
const nodeBaseURI=typeof Node==="function"?Object.getOwnPropertyDescriptor(Node.prototype,"baseURI")?.get:undefined;
function originOf(input:unknown):string|undefined {
 try{if(typeof input==="string")return new URL(input).origin;if(!input||typeof input!=="object")return undefined;try{return new URL(Reflect.apply(requestURL,input,[]) as string).origin;}catch{const href=Reflect.apply(urlHref,input,[]) as string;if(Object.getPrototypeOf(input)!==URL.prototype||Object.hasOwn(input,"toString")||Object.hasOwn(input,Symbol.toPrimitive))return undefined;return new URL(href).origin;}}catch{return undefined;}
}
export class FetchLease {
 private closed=false;private readonly origins=new Map<string,string>();private readonly original:typeof globalThis.fetch;private readonly operation:string;
 constructor(private readonly client:Client,config:FetchIntegrationConfig){
  this.operation=config.operation;if(installed.has(client))throw Error("fetch_already_installed");if(!/^[a-zA-Z0-9_.-]{1,128}$/.test(this.operation)||config.origins.length>64)throw Error("invalid_fetch_config");
  for(const item of config.origins){const url=new URL(item.origin);if(url.origin!==item.origin||!["http:","https:"].includes(url.protocol)||url.username||url.password||!/^[a-zA-Z0-9_.-]{1,128}$/.test(item.dependency)||this.origins.has(item.origin))throw Error("invalid_fetch_origin");this.origins.set(item.origin,item.dependency);}
  this.original=config.fetch??globalThis.fetch.bind(globalThis);client.ownHookLease(this);installed.set(client,this);
 }
 /** The returned Response is the original object. Fetch spans end at response headers;
  * body streaming and cancellation remain entirely owned by the application. */
 fetch(input:Parameters<typeof globalThis.fetch>[0],init?:RequestInit,parent?:TraceContext):Promise<Response>{
  if(this.closed)throw Error("fetch_lease_closed");
  // Accessor-bearing init is delegated untouched. Instrumentation never evaluates it.
  if(typeof input==="string"){try{new URL(input);}catch{const base=typeof document==="object"&&nodeBaseURI?Reflect.apply(nodeBaseURI,document,[]) as string:typeof location==="object"?location.href:undefined;if(base!==undefined){try{input=new URL(input,base).href;}catch{return this.original(input,init);}}}}
  if(init){const prototype=Object.getPrototypeOf(init);if(prototype!==null&&prototype!==Object.prototype)return this.original(input,init);}
  const descriptors=init?Object.getOwnPropertyDescriptors(init):{};
  if(init&&Reflect.ownKeys(descriptors).some(key=>!("value" in descriptors[key as string]!)))return this.original(input,init);
  const dependency=this.origins.get(originOf(input)??"");
  const span=dependency?this.client.startSpan(this.operation,{kind:"client",dependency,parent:parent??null}):undefined;
  const options:RequestInit={};for(const key of Reflect.ownKeys(descriptors)){const descriptor=descriptors[key as string]!;Object.defineProperty(options,key,{value:descriptor.value,enumerable:descriptor.enumerable===true,configurable:true,writable:true});}
  let headers:Headers;
  try{const originalHeaders=descriptors.headers?.value??(()=>{try{return Reflect.apply(requestHeaders,input,[]);}catch{return undefined;}})();headers=new Headers(originalHeaders as HeadersInit|undefined);}catch(error){span?.end("error");return Promise.reject(error);}
  headers.delete("baggage");headers.delete("traceparent");headers.delete("tracestate");headers.delete("x-soundpost-context");
  if(span){const propagation=propagationHeaders(span.context);headers.set("traceparent",propagation.traceparent);headers.set("x-soundpost-context",propagation.companion);}
  Object.defineProperty(options,"headers",{value:headers,enumerable:true,configurable:true,writable:true});
  let pending:Promise<Response>;
  try{pending=span?span.run(()=>this.original(input,options)):this.original(input,options);}catch(error){span?.end("error");throw error;}
  return pending.then(response=>{span?.end(response.status>=400?"error":"ok");return response;},error=>{let cancelled=false;try{cancelled=Reflect.apply(aborted,descriptors.signal?.value,[])===true;}catch{}span?.run(()=>this.client.captureException(error));span?.end(cancelled?"cancelled":"error");throw error;});
 }
 close():void{if(this.closed)return;this.closed=true;this.origins.clear();installed.delete(this.client);this.client.releaseHookLease(this);}
}
export function installFetch(client:Client,config:FetchIntegrationConfig):FetchLease{return new FetchLease(client,config);}
