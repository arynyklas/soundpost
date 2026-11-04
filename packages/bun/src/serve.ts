// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {Client} from "@soundpost/core";
import {parsePropagation} from "./workers.ts";
export interface ServeIntegrationConfig {readonly operation:string}
export type ServeHandler=(request:Request,server:Bun.Server<any>)=>Response|void|Promise<Response|void>;
const installed=new WeakMap<Client,ServeLease>();
export class ServeLease {
 private closed=false;private readonly pending=new Set<()=>void>();private readonly operation:string;
 constructor(private readonly client:Client,config:ServeIntegrationConfig){this.operation=config.operation;if(installed.has(client))throw Error("serve_already_installed");if(!/^[a-zA-Z0-9_.-]{1,128}$/.test(this.operation))throw Error("invalid_serve_operation");client.ownHookLease(this);installed.set(client,this);}
 handler(handler:ServeHandler):ServeHandler {
  return (request,server)=>{
   if(this.closed)return handler(request,server);
   const parent=parsePropagation(request.headers.get("traceparent"),request.headers.get("x-soundpost-context")),span=this.client.startSpan(this.operation,{kind:"server",parent:parent??null});let ended=false;
   const end=(status:"ok"|"error"|"cancelled"|"incomplete"):void=>{if(ended)return;ended=true;request.signal.removeEventListener("abort",cancel);this.pending.delete(incomplete);span.end(status);},cancel=():void=>end("cancelled"),incomplete=():void=>end("incomplete");
   if(this.pending.size>=1024){span.end("incomplete");return handler(request,server);}
   this.pending.add(incomplete);request.signal.addEventListener("abort",cancel,{once:true});if(request.signal.aborted)cancel();
   const response=(value:Response|void):Response|void=>{
    if(!value){end("incomplete");return value;}
    const status=value.status>=400?"error":"ok";
    if(!value.body||request.method==="HEAD"){end(status);return value;}
    if(value.status===0||value.body.locked){end("incomplete");return value;}
    const reader=value.body.getReader(),client=this.client;
    // One pull at a time; no body bytes enter telemetry, no eager body materialization.
    const stream=new ReadableStream<Uint8Array>({async pull(controller){try{const next=await span.run(()=>reader.read());if(next.done){reader.releaseLock();end(status);controller.close();}else controller.enqueue(next.value);}catch(error){span.run(()=>client.captureException(error));end("error");try{reader.releaseLock();}catch{}controller.error(error);}},async cancel(reason){end("cancelled");try{await reader.cancel(reason);}finally{reader.releaseLock();}}},{highWaterMark:0});
    return new Response(stream,{status:value.status,statusText:value.statusText,headers:value.headers});
   };
   let value:Response|void|Promise<Response|void>;try{value=span.run(()=>handler(request,server));}catch(error){span.run(()=>this.client.captureException(error));end("error");throw error;}
   if(value instanceof Promise)return value.then(response,error=>{span.run(()=>this.client.captureException(error));end(request.signal.aborted?"cancelled":"error");throw error;});
   return response(value);
  };
 }
 close():void{if(this.closed)return;this.closed=true;for(const end of [...this.pending])end();installed.delete(this.client);this.client.releaseHookLease(this);}
}
export function installServe(client:Client,config:ServeIntegrationConfig):ServeLease{return new ServeLease(client,config);}
