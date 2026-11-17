// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Server capture cost, wave 23 (Bun): every property read on a Bun Request returns a native wrapper object (FetchHeaders, AbortSignal) that the collector then owns, and the D31 probe
// formats the Response through Bun.inspect. The behaviour is fixed (D31: the span of a buffered Response ends when it is returned; a pre-aborted request ends cancelled; the handler
// still runs); this pins that each wrapper is read once per request and that the probe's options object is one shared constant.
import {test,expect} from "bun:test";
import type {Client} from "@soundpost/core";
import {init} from "../src/index.ts";
import {installServe} from "../src/serve.ts";
import {config,signed} from "../../core/test/fixture.ts";
import {canonical} from "../../core/src/policy.ts";
function settings(){const base=config();return {...base,operations:["request"],dependencies:[],policy:signed(canonical({version:1,org:base.org,project:base.project,source:base.source,revision:"1",expires_ns:"9223372036854775807",errors:true,logs:true,replay:false,bodies:false,traces:true,jobs:false}))};}
const statuses=(client:Client)=>client.bufferedRecords().map(text=>JSON.parse(text)).filter(record=>record.kind==="span").map(record=>record.payload.status as string);
/** A request that counts how often each wrapper property is read. */
function reads(aborted=false){
 const controller=new AbortController();if(aborted)controller.abort();
 const counts={headers:0,signal:0},headers=new Headers({traceparent:"00-"+"a".repeat(32)+"-"+"b".repeat(16)+"-01"});
 const request={method:"GET",get headers(){counts.headers++;return headers;},get signal(){counts.signal++;return controller.signal;}} as unknown as Request;
 return {request,counts,controller};
}
const server=undefined as never;

test("a synchronous handler's request reads headers once and the abort signal once", async()=>{
 const client=init(settings()),lease=installServe(client,{operation:"request"});
 try{
  for(const make of [()=>new Response("hello"),()=>Response.json({a:1}),()=>undefined]){
   const {request,counts}=reads();
   lease.handler(()=>make() as Response)(request,server);
   expect(counts).toEqual({headers:1,signal:1});
  }
 }finally{lease.close();await client.close();}
});

test("an async handler and a streaming body read each wrapper a fixed small number of times, never per chunk", async()=>{
 const client=init(settings()),lease=installServe(client,{operation:"request"});
 try{
  const {request,counts}=reads();
  const stream=new ReadableStream<Uint8Array>({pull(controller){controller.enqueue(new TextEncoder().encode("x"));},cancel(){}},{highWaterMark:0});
  const response=await lease.handler(async()=>new Response(stream))(request,server) as Response;
  const reader=response.body!.getReader();for(let i=0;i<5;i++)await reader.read();await reader.cancel();
  expect(counts.headers).toBe(1);
  expect(counts.signal).toBeLessThanOrEqual(4);   // pre-abort check, listener add, listener remove, final status
 }finally{lease.close();await client.close();}
});

test("a request aborted before the handler ran still ends cancelled and the handler still runs", async()=>{
 const client=init(settings()),lease=installServe(client,{operation:"request"}),before=statuses(client).length;
 try{
  const {request,counts}=reads(true);let ran=false;
  const value=new Response("late");
  expect(lease.handler(()=>{ran=true;return value;})(request,server)).toBe(value);
  expect(ran).toBe(true);expect(statuses(client).slice(before)).toEqual(["cancelled"]);expect(counts.signal).toBe(1);
 }finally{lease.close();await client.close();}
});

test("the D31 probe passes Bun.inspect one shared options object", async()=>{
 const client=init(settings()),lease=installServe(client,{operation:"request"}),inspect=Bun.inspect,options:unknown[]=[];
 Bun.inspect=((value:unknown,option?:object)=>{options.push(option);return Reflect.apply(inspect,Bun,[value,option]);}) as typeof Bun.inspect;
 try{
  for(let i=0;i<3;i++){const {request}=reads();lease.handler(()=>new Response("hello"))(request,server);}
 }finally{Bun.inspect=inspect;lease.close();await client.close();}
 expect(options.length).toBe(3);expect(options[0]).toEqual({depth:0,colors:false});expect(options[1]).toBe(options[0]);expect(options[2]).toBe(options[0]);
});
