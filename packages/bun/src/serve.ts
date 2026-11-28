// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {Client} from "@soundpost/core";
import type {ActiveSpan,SpanStatus} from "@soundpost/core/types";
import {parsePropagation} from "./workers.ts";
export interface ServeIntegrationConfig {readonly operation:string}
export type ServeHandler=(request:Request,server:Bun.Server<any>)=>Response|void|Promise<Response|void>;
// D31: Bun reports a body it already holds in memory (string, ArrayBuffer/typed array, Blob, FormData, URLSearchParams, Bun.file) in its Response summary as "Response (N bytes)" or "Response (N.NN KB|MB|GB)" (one or two decimals); a stream, an already-used or touched body and Response.error() report "(0 KB)". Reading `.body` would create a stream and defeat Bun's native buffered send, so the summary is the probe; anything not recognised is treated as streaming and wrapped.
// No cheaper probe is exact in Bun 1.3.14 (lane 4 wave 21, evidence l4w21-evidence/bun): `bun:jsc` estimateShallowMemoryUsageOf is fixed at construction (stale once a body is touched or used) and blind to Blob/FormData/URLSearchParams/file bodies; Response.clone() reports the live state but turns a touched body back into a buffered one, so it changes the answer it is asked for; inspecting a clone costs the same as inspecting the Response.
export const bufferedSummary=/^Response \((?:\d+ bytes|\d+\.\d+ (?:KB|MB|GB|TB))\)/;
// One options object for every probe: Bun.inspect reads it and keeps nothing, so a fresh literal per request is garbage for nothing.
const summaryOptions=Object.freeze({depth:0,colors:false});
const installed=new WeakMap<Client,ServeLease>();
export class ServeLease {
 private closed=false;private readonly pending=new Set<()=>void>();private readonly operation:string;
 constructor(private readonly client:Client,config:ServeIntegrationConfig){this.operation=config.operation;if(installed.has(client))throw Error("serve_already_installed");if(!/^[a-zA-Z0-9_.-]{1,128}$/.test(this.operation))throw Error("invalid_serve_operation");client.ownHookLease(this);installed.set(client,this);}
 /** A span that outlives the handler's return (an async handler, a streaming body) is held: counted as in flight (a closing lease ends it `incomplete`) and ended `cancelled` when the request aborts. A span that ends when the handler returns is never held: nothing can abort it in between, so it needs no abort listener, no closures and no pending entry. */
 private hold(request:Request,span:ActiveSpan):(status:SpanStatus)=>void{
  let ended=false;
  const end=(status:SpanStatus):void=>{if(ended)return;ended=true;request.signal.removeEventListener("abort",cancel);this.pending.delete(incomplete);span.end(status);},cancel=():void=>end("cancelled"),incomplete=():void=>end("incomplete");
  this.pending.add(incomplete);request.signal.addEventListener("abort",cancel,{once:true});if(request.signal.aborted)cancel();
  return end;
 }
 private finish(span:ActiveSpan,held:((status:SpanStatus)=>void)|undefined,status:SpanStatus):void{if(held!==undefined)held(status);else span.end(this.closed?"incomplete":status);}
 private respond(request:Request,span:ActiveSpan,held:((status:SpanStatus)=>void)|undefined,value:Response|void):Response|void{
  if(!value){this.finish(span,held,"incomplete");return value;}
  const status=value.status>=400?"error":"ok";
  if(request.method==="HEAD"||bufferedSummary.test(Bun.inspect(value,summaryOptions))){this.finish(span,held,status);return value;}
  if(!value.body){this.finish(span,held,status);return value;}
  if(value.status===0||value.body.locked){this.finish(span,held,"incomplete");return value;}
  const end=held??this.hold(request,span),reader=value.body.getReader(),client=this.client;
  // One pull at a time; no body bytes enter telemetry, no eager body materialization.
  const stream=new ReadableStream<Uint8Array>({async pull(controller){try{const next=await span.run(()=>reader.read());if(next.done){reader.releaseLock();end(status);controller.close();}else controller.enqueue(next.value);}catch(error){span.run(()=>client.captureException(error));end("error");try{reader.releaseLock();}catch{}controller.error(error);}},async cancel(reason){end("cancelled");try{await reader.cancel(reason);}finally{reader.releaseLock();}}},{highWaterMark:0});
  return new Response(stream,{status:value.status,statusText:value.statusText,headers:value.headers});
 }
 handler(handler:ServeHandler):ServeHandler {
  return (request,server)=>{
   if(this.closed)return handler(request,server);
   const headers=request.headers,traceparent=headers.get("traceparent"),parent=traceparent===null?undefined:parsePropagation(traceparent,headers.get("x-soundpost-context")),span=this.client.startAdapterSpan(this.operation,"server",undefined,parent??null);
   if(this.pending.size>=1024){span.end("incomplete");return handler(request,server);}
   // Aborted before the handler ran: the status is decided now, and the handler still runs.
   if(request.signal.aborted)span.end("cancelled");
   let value:Response|void|Promise<Response|void>;try{value=span.run(()=>handler(request,server));}catch(error){span.run(()=>this.client.captureException(error));span.end("error");throw error;}
   if(value instanceof Promise){const held=this.hold(request,span);return value.then(response=>this.respond(request,span,held,response),error=>{span.run(()=>this.client.captureException(error));held(request.signal.aborted?"cancelled":"error");throw error;});}
   return this.respond(request,span,undefined,value);
  };
 }
 close():void{if(this.closed)return;this.closed=true;for(const end of [...this.pending])end();installed.delete(this.client);this.client.releaseHookLease(this);}
}
export function installServe(client:Client,config:ServeIntegrationConfig):ServeLease{return new ServeLease(client,config);}
