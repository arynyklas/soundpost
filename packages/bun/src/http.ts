// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {request as httpRequest,ClientRequest,type IncomingMessage,type ServerResponse,type RequestOptions,type RequestListener,type OutgoingHttpHeaders} from "node:http";
import {request as httpsRequest} from "node:https";
import {errorMonitor} from "node:events";
import type {Client} from "@soundpost/core";
import {parsePropagation,propagationHeaders} from "./workers.ts";
export interface HttpIntegrationConfig {readonly operation:string;readonly origins?:readonly Readonly<{origin:string;dependency:string}>[]}
const installed=new WeakMap<Client,HttpLease>();
const propagationNames:Readonly<Record<string,true>>={baggage:true,traceparent:true,tracestate:true,"x-soundpost-context":true};
const nativeRequestAbort=Object.getOwnPropertyDescriptor(ClientRequest.prototype,"aborted")?.get;
const nativeSignalAbort=Object.getOwnPropertyDescriptor(AbortSignal.prototype,"aborted")!.get!;
export class HttpLease {
 private closed=false;private readonly pending=new Set<()=>void>();private readonly origins=new Map<string,string>();private readonly operation:string;
 constructor(private readonly client:Client,config:HttpIntegrationConfig){this.operation=config.operation;if(installed.has(client))throw Error("http_already_installed");if(!/^[a-zA-Z0-9_.-]{1,128}$/.test(this.operation)||(config.origins?.length??0)>64)throw Error("invalid_http_config");for(const item of config.origins??[]){const url=new URL(item.origin);if(url.origin!==item.origin||!["http:","https:"].includes(url.protocol)||!/^[a-zA-Z0-9_.-]{1,128}$/.test(item.dependency)||this.origins.has(item.origin))throw Error("invalid_http_origin");this.origins.set(item.origin,item.dependency);}client.ownHookLease(this);installed.set(client,this);}
 listener(handler:RequestListener):RequestListener {
  const lease=this;
  return function(this:unknown,request:IncomingMessage,response:ServerResponse):void{
   if(lease.closed){Reflect.apply(handler,this,[request,response]);return;}
   const parent=parsePropagation(request.headers.traceparent,request.headers["x-soundpost-context"]),span=lease.client.startSpan(lease.operation,{kind:"server",parent:parent??null});
   let ended=false;
   const cleanup=():void=>{response.removeListener("finish",finish);response.removeListener("close",close);request.removeListener("aborted",cancel);lease.pending.delete(incomplete);};
   const end=(status:"ok"|"error"|"cancelled"|"incomplete"):void=>{if(ended)return;ended=true;cleanup();span.end(status);};
   const finish=():void=>end(response.statusCode>=400?"error":"ok"),close=():void=>end(response.writableFinished?(response.statusCode>=400?"error":"ok"):"cancelled"),cancel=():void=>end("cancelled"),incomplete=():void=>end("incomplete");
   if(lease.pending.size>=1024){span.end("incomplete");Reflect.apply(handler,this,[request,response]);return;}
   lease.pending.add(incomplete);response.once("finish",finish);response.once("close",close);request.once("aborted",cancel);
   try{span.run(()=>Reflect.apply(handler,this,[request,response]));}catch(error){span.run(()=>lease.client.captureException(error));end("error");throw error;}
   // Do not attach promise rejection/error listeners: native HTTP ignores the return
   // value, and observing it here would change the application's fatal behavior.
  };
 }
 request(input:string|URL,options:RequestOptions={},callback?:(response:IncomingMessage)=>void):ClientRequest {
  if(this.closed)throw Error("http_lease_closed");const url=new URL(input),original=url.protocol==="https:"?httpsRequest:httpRequest,dependency=this.origins.get(url.origin);
  const span=dependency?this.client.startSpan(this.operation,{kind:"client",dependency}):undefined,configured=options.headers;let headers:RequestOptions["headers"]=configured;
  if(!span){/* Unregistered origin: application headers (Headers, array, object) reach the delegate untouched. */}
  else if(Array.isArray(configured)){const raw:string[]=[];for(let index=0;index<configured.length;index+=2){const name=configured[index]!;if(!Object.hasOwn(propagationNames,name.toLowerCase()))raw.push(name,configured[index+1]!);}const propagation=propagationHeaders(span.context);raw.push("traceparent",propagation.traceparent,"x-soundpost-context",propagation.companion);headers=raw;}
  else{const safe:OutgoingHttpHeaders={};if((configured as unknown) instanceof Headers){(configured as unknown as Headers).forEach((value,name)=>{if(name!=="set-cookie")safe[name]=value;});const cookies=(configured as unknown as Headers).getSetCookie();if(cookies.length)safe["set-cookie"]=cookies;}else Object.assign(safe,configured);for(const name of Object.keys(safe))if(Object.hasOwn(propagationNames,name.toLowerCase()))delete safe[name];const propagation=propagationHeaders(span.context);safe.traceparent=propagation.traceparent;safe["x-soundpost-context"]=propagation.companion;headers=safe;}
  let request:ClientRequest;try{request=span?span.run(()=>original(url,{...options,headers},callback)):original(url,{...options,headers},callback);}catch(error){span?.end("error");throw error;}
  // Bun emits request close at response headers, before its IncomingMessage ends.
  // Error monitors observe both streams without adding consuming error listeners.
  if(span){
   let response:IncomingMessage|undefined,ended=false,abortSeen=false;
   const signal=Object.getOwnPropertyDescriptor(options,"signal")?.value;
   const isCancelled=():boolean=>{
    if(abortSeen)return true;
    const own=Object.getOwnPropertyDescriptor(request,"aborted");
    if(own&&"value" in own&&own.value===true)return true;
    try{if(nativeRequestAbort&&Reflect.apply(nativeRequestAbort,request,[])===true)return true;}catch{}
    try{return Reflect.apply(nativeSignalAbort,signal,[])===true;}catch{return false;}
   };
   const end=(status:"ok"|"error"|"cancelled"|"incomplete"):void=>{
    if(ended)return;ended=true;
    request.removeListener("response",onResponse);request.removeListener("close",onRequestClose);request.removeListener("abort",onAbort);request.removeListener(errorMonitor,onError);
    response?.removeListener("end",onEnd);response?.removeListener("close",onResponseClose);response?.removeListener("aborted",onResponseAborted);response?.removeListener(errorMonitor,onError);
    this.pending.delete(incomplete);span.end(status);
   };
   const onEnd=():void=>end((response?.statusCode??0)>=400?"error":"ok");
   const onResponseClose=():void=>end(isCancelled()?"cancelled":"error");
   const onResponseAborted=():void=>end(isCancelled()?"cancelled":"error");
   const onRequestClose=():void=>{if(response===undefined)end(isCancelled()?"cancelled":"incomplete");};
   const onAbort=():void=>{abortSeen=true;end("cancelled");};
   const onError=(error:unknown):void=>{span.run(()=>this.client.captureException(error));end(isCancelled()?"cancelled":"error");};
   const incomplete=():void=>end("incomplete");
   const onResponse=(value:IncomingMessage):void=>{
    // Count application listeners before their once callbacks run; this observer
    // must not change Bun's native no-response-consumer auto-discard behavior.
    const applicationObservesResponse=request.listenerCount("response")>0;
    response=value;value.once("end",onEnd);value.once("close",onResponseClose);value.once("aborted",onResponseAborted);value.on(errorMonitor,onError);
    if(!applicationObservesResponse)value.resume();
   };
   if(this.pending.size>=1024)span.end("incomplete");
   else{this.pending.add(incomplete);request.prependOnceListener("response",onResponse);request.once("close",onRequestClose);request.once("abort",onAbort);request.on(errorMonitor,onError);}
  }
  return request;
 }
 close():void{if(this.closed)return;this.closed=true;for(const end of [...this.pending])end();installed.delete(this.client);this.client.releaseHookLease(this);}
}
export function installHttp(client:Client,config:HttpIntegrationConfig):HttpLease{return new HttpLease(client,config);}
