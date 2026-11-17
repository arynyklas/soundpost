// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Pins the lifetime of a server span in installServe (lane 4 wave 21): a span that ends when the handler returns holds no abort listener and no in-flight entry (cost work: the
// per-request add/removeEventListener and three closures were the second-largest Bun cost after the D31 probe), while a span that outlives the return (async handler, streaming body)
// is still ended `cancelled` by an abort, `incomplete` by a closing lease, and its listener is gone when it ends.
import {test,expect} from "bun:test";
import type {Client} from "@soundpost/core";
import {init} from "../src/index.ts";
import {installServe} from "../src/serve.ts";
import {config,signed} from "../../core/test/fixture.ts";
import {canonical} from "../../core/src/policy.ts";
function settings(){const base=config();return {...base,operations:["request"],dependencies:[],policy:signed(canonical({version:1,org:base.org,project:base.project,source:base.source,revision:"1",expires_ns:"9223372036854775807",errors:true,logs:true,replay:false,bodies:false,traces:true,jobs:false}))};}
const statuses=(client:Client)=>client.bufferedRecords().map(text=>JSON.parse(text)).filter(record=>record.kind==="span").map(record=>record.payload.status as string);
/** A request whose abort signal counts listener traffic. */
function counted(aborted=false){
 const controller=new AbortController(),signal=controller.signal,calls={added:0,removed:0};
 const add=signal.addEventListener.bind(signal),remove=signal.removeEventListener.bind(signal);
 signal.addEventListener=((...args:Parameters<typeof add>)=>{if(args[0]==="abort")calls.added++;return add(...args);}) as typeof add;
 signal.removeEventListener=((...args:Parameters<typeof remove>)=>{if(args[0]==="abort")calls.removed++;return remove(...args);}) as typeof remove;
 if(aborted)controller.abort();
 return {request:{method:"GET",headers:new Headers(),signal} as unknown as Request,controller,calls};
}
const server=undefined as never;
const encoder=new TextEncoder();

test("a handler that returns synchronously holds no abort listener, whatever it returns",async()=>{
 const client=init(settings());
 try{
  for(const [name,make] of [["buffered",()=>new Response("hello")],["JSON",()=>Response.json({a:1})],["nothing",()=>undefined],["empty body",()=>new Response(null,{status:204})],["500",()=>new Response("x",{status:500})]] as const){
   const lease=installServe(client,{operation:"request"}),before=statuses(client).length;
   try{
    const {request,calls}=counted(),value=make();
    const returned=lease.handler(()=>value as Response)(request,server);
    expect(returned,name).toBe(value);
    expect(calls,name).toEqual({added:0,removed:0});
    expect(statuses(client).slice(before),name).toEqual([value===undefined?"incomplete":(value as Response).status>=400?"error":"ok"]);
   }finally{lease.close();}
  }
  const lease=installServe(client,{operation:"request"}),before=statuses(client).length;
  try{
   const {request,calls}=counted(),failure=new Error("CANARY_SYNC_THROW");
   expect(()=>lease.handler(()=>{throw failure;})(request,server)).toThrow(failure);
   expect(calls).toEqual({added:0,removed:0});
   expect(statuses(client).slice(before)).toEqual(["error"]);
  }finally{lease.close();}
 }finally{await client.close();}
});

test("an async handler holds exactly one abort listener until it settles, and an abort while it is pending ends the span cancelled",async()=>{
 const client=init(settings());
 try{
  let lease=installServe(client,{operation:"request"}),before=statuses(client).length;
  try{
   const {request,calls}=counted(),gate=Promise.withResolvers<Response>();
   const returned=lease.handler(()=>gate.promise)(request,server) as Promise<Response>;
   expect(calls).toEqual({added:1,removed:0});
   gate.resolve(new Response("late"));
   await returned;
   expect(calls).toEqual({added:1,removed:1});
   expect(statuses(client).slice(before)).toEqual(["ok"]);
  }finally{lease.close();}
  lease=installServe(client,{operation:"request"});before=statuses(client).length;
  try{
   const {request,controller,calls}=counted(),gate=Promise.withResolvers<Response>();
   const returned=lease.handler(()=>gate.promise)(request,server) as Promise<Response>;
   controller.abort();
   expect(statuses(client).slice(before)).toEqual(["cancelled"]);
   expect(calls.removed).toBe(1);
   gate.resolve(new Response("too late"));
   await returned;
   expect(statuses(client).slice(before)).toEqual(["cancelled"]);
  }finally{lease.close();}
  lease=installServe(client,{operation:"request"});before=statuses(client).length;
  try{
   const {request,calls}=counted(),failure=new Error("CANARY_ASYNC_REJECT");
   await expect((lease.handler(async()=>{throw failure;})(request,server) as Promise<Response>)).rejects.toBe(failure);
   expect(calls).toEqual({added:1,removed:1});
   expect(statuses(client).slice(before)).toEqual(["error"]);
  }finally{lease.close();}
 }finally{await client.close();}
});

test("a request aborted before the handler ran ends cancelled, the handler still runs and its response is unchanged",async()=>{
 const client=init(settings());
 try{
  for(const asynchronous of [false,true]){
   const lease=installServe(client,{operation:"request"}),before=statuses(client).length;
   try{
    const {request}=counted(true),original=new Response("body");let ran=false;
    const returned=lease.handler(()=>{ran=true;return asynchronous?Promise.resolve(original):original;})(request,server);
    const result=asynchronous?await returned:returned;
    expect(ran).toBe(true);expect(result).toBe(original);
    expect(statuses(client).slice(before)).toEqual(["cancelled"]);
   }finally{lease.close();}
  }
 }finally{await client.close();}
});

test("a streaming body keeps its span open with one abort listener, and any ending removes the listener",async()=>{
 const client=init(settings());
 try{
  const make=()=>new Response(new ReadableStream({pull(controller){controller.enqueue(encoder.encode("chunk"));controller.close();}},{highWaterMark:0}));
  let lease=installServe(client,{operation:"request"}),before=statuses(client).length;
  try{
   const {request,calls}=counted(),original=make();
   const result=lease.handler(()=>original)(request,server) as Response;
   expect(result).not.toBe(original);
   expect(calls).toEqual({added:1,removed:0});expect(statuses(client).slice(before)).toEqual([]);
   expect(await result.text()).toBe("chunk");
   expect(calls).toEqual({added:1,removed:1});expect(statuses(client).slice(before)).toEqual(["ok"]);
  }finally{lease.close();}
  lease=installServe(client,{operation:"request"});before=statuses(client).length;
  try{
   const {request,controller,calls}=counted(),endless=new Response(new ReadableStream({pull(c){c.enqueue(encoder.encode("chunk"));}},{highWaterMark:0}));
   const result=lease.handler(()=>endless)(request,server) as Response,reader=result.body!.getReader();
   await reader.read();expect(statuses(client).slice(before)).toEqual([]);
   controller.abort();
   expect(statuses(client).slice(before)).toEqual(["cancelled"]);expect(calls).toEqual({added:1,removed:1});
   await reader.cancel();expect(statuses(client).slice(before)).toEqual(["cancelled"]);
  }finally{lease.close();}
 }finally{await client.close();}
});

test("closing the lease ends in-flight spans incomplete, and a lease closed during a synchronous handler ends that span incomplete too",async()=>{
 const client=init(settings());
 try{
  let lease=installServe(client,{operation:"request"}),before=statuses(client).length;
  const {request,calls}=counted(),gate=Promise.withResolvers<Response>();
  const returned=lease.handler(()=>gate.promise)(request,server) as Promise<Response>;
  lease.close();
  expect(statuses(client).slice(before)).toEqual(["incomplete"]);expect(calls).toEqual({added:1,removed:1});
  gate.resolve(new Response("after close"));await returned;
  expect(statuses(client).slice(before)).toEqual(["incomplete"]);
  lease=installServe(client,{operation:"request"});before=statuses(client).length;
  const second=counted();
  const value=lease.handler(()=>{lease.close();return new Response("closed inside");})(second.request,server) as Response;
  expect(await value.text()).toBe("closed inside");
  expect(statuses(client).slice(before)).toEqual(["incomplete"]);
 }finally{await client.close();}
});

test("real Bun.serve: a client that disconnects while an async handler waits ends the span cancelled, a sync buffered answer ends ok",async()=>{
 const client=init(settings()),lease=installServe(client,{operation:"request"}),before=statuses(client).length,waiting=Promise.withResolvers<void>(),release=Promise.withResolvers<void>(),disconnected=Promise.withResolvers<void>();
 const app=Bun.serve({hostname:"127.0.0.1",port:0,fetch:lease.handler(async request=>{
  if(new URL(request.url).pathname==="/wait"){request.signal.addEventListener("abort",()=>disconnected.resolve(),{once:true});waiting.resolve();await release.promise;return new Response("late");}
  return new Response("now");
 })});
 try{
  expect(await (await fetch(new URL("/now",app.url))).text()).toBe("now");
  expect(statuses(client).slice(before)).toEqual(["ok"]);
  const controller=new AbortController(),pending=fetch(new URL("/wait",app.url),{signal:controller.signal}).catch(error=>error);
  await waiting.promise;controller.abort();await pending;
  // The server observes the disconnect through the request's own signal (the fixture's listener runs before the SDK's); one turn of the event loop lets the SDK's listener finish.
  await disconnected.promise;const turn=Promise.withResolvers<void>();setImmediate(turn.resolve);await turn.promise;
  expect(statuses(client).slice(before)).toEqual(["ok","cancelled"]);
 }finally{release.resolve();lease.close();await app.stop(true);await client.close();}
},30000);
