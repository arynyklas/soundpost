// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Server capture cost, wave 22: what a captured request leaves for the garbage collector. Profiles of the D54 warm window (Node 22 and Bun 1.3, lane 4 wave 22) put the largest
// request-attributable costs in collector work, not in the SDK's own JavaScript: a span that stays queued for the 100 ms until the next flush survives young-generation collections
// (V8 then grows its new space, which doubles the scavenge pause and with it the p95; JSC marks every retained object in each cycle), weak collections cost an ephemeron
// fixpoint per cycle, and the export built several copies of every record. These tests pin the behaviours that removed that pressure; none of them changes a byte on the wire
// (span-fast-path.test.ts and capture-cost.test.ts keep pinning the bytes).
import {test,expect} from "bun:test";
import crypto from "node:crypto";
import type {SignedPolicy} from "../src/types.ts";
import {readStackFrames} from "../src/frames.ts";
import {LeanSlab} from "../src/lean_slab.ts";
import {leanSpanPayload,type LiveSpan} from "../src/tracing.ts";
import {Client,checkedTraceContext} from "../src/client.ts";
import type {FrozenBatch,Outcome,ReceiptTransport} from "../src/transport.ts";
import {config,signed} from "./fixture.ts";

const sealed=():SignedPolicy=>{const base=config(),doc:Record<string,unknown>={version:1,org:base.org,project:base.project,source:base.source,revision:"1",expires_ns:"9223372036854775807",errors:true,logs:true,replay:false,bodies:false,traces:true};return signed(JSON.stringify(doc,Object.keys(doc).sort()));};
const receipt=(batch:FrozenBatch)=>({version:1,batch_id:batch.id,hash:batch.hash,cursor:{group:"9".repeat(32),index:"9007199254740993"},retain_until_ns:"9007199254740994",signal_deadlines:batch.kinds.map(kind=>({kind,retain_until_ns:"9007199254740994"})),dedup_until_ns:"9007199254740995"});
class Acking implements ReceiptTransport {
 readonly batches:FrozenBatch[]=[];
 async send(batch:FrozenBatch):Promise<Outcome>{this.batches.push(batch);return {kind:"receipt",receipt:receipt(batch)};}
 async lookup():Promise<Outcome>{return {kind:"not_found"};}
 close():void{}
}
const make=(extra:Record<string,unknown>={})=>{const transport=new Acking();return {client:new Client({...config(),operations:["op","other"],dependencies:["db"],policy:sealed(),transport,...extra}),transport};};
const collect=():void=>{for(let i=0;i<4;i++)Bun.gc(true);};

test("ending root spans adds nothing to a weak collection (a WeakSet entry per span is an ephemeron every collection cycle must resolve)",()=>{
 const {client}=make();
 client.startAdapterSpan("op","server",undefined,null).end("ok");   // first use builds the module's lazily created state
 const adds=WeakSet.prototype.add,sets=WeakMap.prototype.set;let added=0;
 WeakSet.prototype.add=function(this:WeakSet<object>,value:object){added++;return Reflect.apply(adds,this,[value]) as WeakSet<object>;};
 WeakMap.prototype.set=function(this:WeakMap<object,unknown>,key:object,value:unknown){added++;return Reflect.apply(sets,this,[key,value]) as WeakMap<object,unknown>;};
 try{
  for(let i=0;i<50;i++){const span=client.startAdapterSpan("op","server",undefined,null);span.run(()=>{client.startAdapterSpan("other","client","db",undefined).end("ok");});span.end("ok");}
  for(let i=0;i<50;i++)client.startSpan("op").end("ok");
 }finally{WeakSet.prototype.add=adds;WeakMap.prototype.set=sets;}
 expect(added).toBe(0);
});

test("a context is trusted only when this module built it: same fields, same prototype, a copy or a spoofed brand are all validated again",()=>{
 const {client}=make();
 const built=client.startAdapterSpan("op","server",undefined,null);const ctx=built.context;built.end("ok");
 expect(checkedTraceContext(ctx)).toBe(ctx);
 const fields={traceId:ctx.traceId,spanId:ctx.spanId,sampled:ctx.sampled,probability:ctx.probability,clockDomain:{...ctx.clockDomain}};
 const copy=checkedTraceContext({...fields});expect(copy).not.toBe(ctx);expect(copy).toEqual(ctx);
 const bad={...fields,probability:"not-a-probability"};
 expect(()=>checkedTraceContext(bad)).toThrow("invalid_trace_probability");
 const forged=Object.assign(Object.create(Object.getPrototypeOf(ctx)),bad);
 expect(()=>checkedTraceContext(forged)).toThrow();
 const spoof=Object.assign({},bad);expect(()=>checkedTraceContext(spoof)).toThrow("invalid_trace_probability");
 expect(()=>checkedTraceContext(Object.freeze(Object.assign(Object.create(null),bad)))).toThrow("invalid_trace_probability");
 expect(Object.isFrozen(ctx)).toBe(true);
 expect(Object.keys(ctx).sort()).toEqual(["clockDomain","probability","sampled","spanId","traceId"]);
 expect(Reflect.ownKeys(ctx).length).toBe(5);
 expect(JSON.parse(JSON.stringify(ctx))).toEqual({traceId:ctx.traceId,spanId:ctx.spanId,sampled:true,probability:ctx.probability,clockDomain:{...ctx.clockDomain}});
});

test("a span that waits in the queue for the next flush does not keep the span, its context or their strings alive",async()=>{
 const {client}=make();
 const refs=(()=>{const span=client.startAdapterSpan("op","server",undefined,null);span.run(()=>{});span.end("ok");return {span:new WeakRef(span),context:new WeakRef(span.context),domain:new WeakRef(span.context.clockDomain)};})();
 // Still queued (not flushed). bufferedRecords() serializes what is queued, so it must come after the collection; a WeakRef keeps its target until the end of the current job, hence the macrotask turn.
 await new Promise<void>(resolve=>setImmediate(resolve));collect();
 expect(refs.span.deref()).toBeUndefined();
 expect(refs.context.deref()).toBeUndefined();
 expect(client.bufferedRecords().length).toBe(1);
 // The record is still complete and valid: it is serialized from what the queue kept.
 const [record]=client.bufferedRecords();const parsed=JSON.parse(record!);
 expect(parsed.kind).toBe("span");expect(parsed.payload.operation).toBe("op");expect(parsed.payload.status).toBe("ok");
 expect(parsed.payload.trace_id).toMatch(/^[0-9a-f]{32}$/);expect(parsed.payload.span_id).toMatch(/^[0-9a-f]{16}$/);
});

test("a flush routes every span without allocating a digest buffer for it (one ArrayBuffer per span is young-generation work in V8 and a native allocation in JSC)",async()=>{
 const original=crypto.hash;let buffers=0,calls=0;
 (crypto as unknown as {hash:unknown}).hash=(algorithm:string,data:unknown,encoding:string)=>{calls++;if(encoding==="buffer")buffers++;return (original as unknown as (...a:unknown[])=>unknown)(algorithm,data,encoding);};
 try{
  const {client,transport}=make();
  for(let i=0;i<40;i++)client.startAdapterSpan("op","server",undefined,null).end("ok");
  const report=await client.flush(2000);
  expect(report.pending).toBe(0);expect(transport.batches.reduce((n,b)=>n+b.count,0)).toBe(40);
  expect(calls).toBeGreaterThan(0);   // the native hash is in use (otherwise this test would prove nothing)
  expect(buffers).toBe(0);
 }finally{(crypto as unknown as {hash:unknown}).hash=original;}
});

test("a stack seen again is not parsed again, and the memory of it keeps no message or stack text",()=>{
 const root=new URL("../../..",import.meta.url).pathname.replace(/^\/([A-Za-z]:)/,"$1"),naming={root};
 const raise=():Error=>{try{throw new Error("same message at one site");}catch(error){return error as Error;}};
 const [first,second,other]=[0,1,2].map(index=>index<2?raise():(()=>{try{throw new Error("a different message");}catch(error){return error as Error;}})());
 const a=readStackFrames(first!,{},naming,128),b=readStackFrames(second!,{},naming,128),c=readStackFrames(other!,{},naming,128);
 expect(a.frames.length).toBeGreaterThan(0);
 expect(b.frames).toEqual(a.frames);
 expect(b.frames).toBe(a.frames);   // the second read is the first read's result: the stack text was recognised, not parsed
 expect(c.frames).not.toBe(a.frames);expect(c.frames.length).toBeGreaterThan(0);
 // another naming (a different client), another frame budget or another header is a different question and gets its own answer
 expect(readStackFrames(second!,{},{root,ids:new Map()},128).frames).not.toBe(a.frames);
 expect(readStackFrames(second!,{},naming,1).frames.length).toBe(1);
 expect(Object.isFrozen(a.frames)).toBe(true);expect(Object.isFrozen(a.frames[0])).toBe(true);
});

test("the compact store writes the exact payload of the span it copied, with parents, dependencies and statuses, and recycles slots",()=>{
 const {client}=make({maxRecords:1024});
 const roots=[client.startAdapterSpan("op","server",undefined,null),client.startAdapterSpan("other","client","db",null)];
 const child=roots[0]!.run(()=>client.startAdapterSpan("other","client","db",undefined));
 const all=[...roots,child] as unknown as LiveSpan[];
 ["ok","error","cancelled"].forEach((status,index)=>all[index]!.end(status as never));
 expect(child.context.traceId).toBe(roots[0]!.context.traceId);
 const slab=new LeanSlab(2);const slots=[slab.put(all[0]!),slab.put(all[2]!)];
 expect(slots.every(slot=>slot>=0)).toBe(true);expect(slab.used).toBe(2);
 expect(slab.put(all[1]!)).toBe(-1);   // full: the caller serializes the span at once
 expect(slab.payload(slots[0]!)).toBe(leanSpanPayload(all[0]!));
 expect(slab.payload(slots[1]!)).toBe(leanSpanPayload(all[2]!));
 expect(JSON.parse(slab.payload(slots[1]!)).parent_id).toBe(roots[0]!.context.spanId);
 expect(slab.startWall(slots[0]!)).toBe(all[0]!.startWall);
 const route=new Uint8Array(32);slab.writeTraceId(slots[0]!,route);expect(new TextDecoder().decode(route)).toBe(all[0]!.context.traceId);
 slab.release(slots[0]!);const reused=slab.put(all[1]!);expect(reused).toBe(slots[0]!);expect(slab.payload(reused)).toBe(leanSpanPayload(all[1]!));
});
