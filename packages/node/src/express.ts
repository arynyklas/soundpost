// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {IncomingMessage,ServerResponse} from "node:http";
import type {Client} from "@soundpost/core";
import {requestPropagation} from "./workers.ts";
export type ExpressHandler=(request:IncomingMessage,response:ServerResponse,next:(error?:unknown)=>void)=>unknown;
const installed=new WeakMap<Client,ExpressLease>();
export class ExpressLease {
 private closed=false;private readonly pending=new Set<()=>void>();
 constructor(private readonly client:Client){if(installed.has(client))throw Error("express_already_installed");client.ownHookLease(this);installed.set(client,this);}
 /** Register a finite operation alias, never req.url/req.route or arbitrary attributes. */
 handler(operation:string,handler:ExpressHandler):ExpressHandler {
  if(!/^[a-zA-Z0-9_.-]{1,128}$/.test(operation))throw Error("invalid_express_operation");
  const lease=this;
  return function(this:unknown,request,response,next):unknown {
   if(lease.closed)return Reflect.apply(handler,this,[request,response,next]);
   const existing=lease.client.traceContext(),parent=existing??requestPropagation(request),span=lease.client.startSpan(operation,{kind:"server",parent:parent??null});let ended=false;
   const end=(status:"ok"|"error"|"cancelled"|"incomplete"):void=>{if(ended)return;ended=true;response.removeListener("finish",finish);response.removeListener("close",close);lease.pending.delete(incomplete);span.end(status);},finish=():void=>end(response.statusCode>=400?"error":"ok"),close=():void=>end(response.writableFinished?(response.statusCode>=400?"error":"ok"):"cancelled"),incomplete=():void=>end("incomplete");
   if(lease.pending.size>=1024){span.end("incomplete");return Reflect.apply(handler,this,[request,response,next]);}
   lease.pending.add(incomplete);response.once("finish",finish);response.once("close",close);
   const forward=(error?:unknown):void=>{if(error){span.run(()=>lease.client.captureException(error));end("error");}next(error);};
   let value:unknown;try{value=span.run(()=>Reflect.apply(handler,this,[request,response,forward]));}catch(error){span.run(()=>lease.client.captureException(error));end("error");throw error;}
   if(value instanceof Promise)return value.catch(error=>{span.run(()=>lease.client.captureException(error));end("error");throw error;});
   return value;
  };
 }
 close():void{if(this.closed)return;this.closed=true;for(const end of [...this.pending])end();installed.delete(this.client);this.client.releaseHookLease(this);}
}
export function installExpress(client:Client):ExpressLease{return new ExpressLease(client);}
