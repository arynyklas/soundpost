// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Server capture cost, wave 27: a root span draws its trace and span IDs from the entropy pool with one hex encoding (not one per ID), and the queue encodes the three IDs of a queued span
// back to text with one native call (not one per ID). Every call is a native transition and a fresh string; the IDs, the record bytes and their order are unchanged (the equality pins
// of export-pass.test.ts and span-fast-path.test.ts keep covering them).
import {test,expect} from "bun:test";
import type {SignedPolicy} from "../src/types.ts";
import {Client} from "../src/client.ts";
import {leanSpanPayload,randomHex,type LiveSpan} from "../src/tracing.ts";
import type {FrozenBatch,Outcome,ReceiptTransport} from "../src/transport.ts";
import {config,signed} from "./fixture.ts";

const sealed=():SignedPolicy=>{const base=config(),doc:Record<string,unknown>={version:1,org:base.org,project:base.project,source:base.source,revision:"1",expires_ns:"9223372036854775807",errors:true,logs:true,replay:false,bodies:false,traces:true,jobs:false};return signed(JSON.stringify(doc,Object.keys(doc).sort()));};
const receipt=(batch:FrozenBatch)=>({version:1,batch_id:batch.id,hash:batch.hash,cursor:{group:"9".repeat(32),index:"9007199254740993"},retain_until_ns:"9007199254740994",signal_deadlines:batch.kinds.map(kind=>({kind,retain_until_ns:"9007199254740994"})),dedup_until_ns:"9007199254740995"});
class Acking implements ReceiptTransport {
 readonly batches:FrozenBatch[]=[];
 async send(batch:FrozenBatch):Promise<Outcome>{this.batches.push(batch);return {kind:"receipt",receipt:receipt(batch)};}
 async lookup():Promise<Outcome>{return {kind:"not_found"};}
 close():void{}
}
const make=()=>{const transport=new Acking();return {client:new Client({...config(),operations:["op"],dependencies:[],policy:sealed(),transport}),transport};};

/** Calls of Buffer.prototype.toString with the "hex" encoding while `body` runs. */
async function hexCalls(body:()=>Promise<void>|void):Promise<number>{
 const original=Buffer.prototype.toString;let calls=0;
 Buffer.prototype.toString=function(this:Buffer,...args:unknown[]){if(args[0]==="hex")calls++;return Reflect.apply(original,this,args) as string;} as typeof original;
 try{await body();}finally{Buffer.prototype.toString=original;}
 return calls;
}

test("a queued root span costs three hex encodings from its start to its serialization, and a batch one for its ID",async()=>{
 const {client,transport}=make();
 for(let i=0;i<20;i++)client.startAdapterSpan("op","server",undefined,null).end("ok");   // warm-up: first use builds the module's lazily created state
 await client.flush(2000);
 const spans=60,sent=transport.batches.length;
 const calls=await hexCalls(async()=>{
  for(let i=0;i<spans;i++)client.startAdapterSpan("op","server",undefined,null).end("ok");
  const report=await client.flush(2000);
  expect(report.pending).toBe(0);
 });
 const batches=transport.batches.slice(sent);
 expect(batches.reduce((n,batch)=>n+batch.count,0)).toBe(spans);
 expect(new Set(batches.map(batch=>batch.id)).size).toBe(batches.length);
 // Per span: the entropy of its two IDs (one draw), its record ID, its three IDs read back from the queue's store (one call): 3 (was 5). Per batch: its ID, drawn when the batch starts (was two draws).
 expect(calls).toBeLessThanOrEqual(spans*3+batches.length);
});

test("the trace and span IDs of a root span are distinct lowercase hex cut from one draw, and a child keeps its parent's trace",()=>{
 const {client}=make();
 const seen=new Set<string>();
 for(let i=0;i<200;i++){
  const root=client.startAdapterSpan("op","server",undefined,null);
  const {traceId,spanId}=root.context;
  expect(traceId).toMatch(/^[0-9a-f]{32}$/);expect(spanId).toMatch(/^[0-9a-f]{16}$/);
  expect(traceId).not.toBe("0".repeat(32));expect(spanId).not.toBe("0".repeat(16));
  expect(seen.has(traceId)||seen.has(spanId)).toBe(false);seen.add(traceId);seen.add(spanId);
  const child=root.run(()=>client.startAdapterSpan("op","client",undefined,undefined));
  expect(child.context.traceId).toBe(traceId);expect(child.context.spanId).toMatch(/^[0-9a-f]{16}$/);expect(child.context.spanId).not.toBe(spanId);
  seen.add(child.context.spanId);child.end("ok");root.end("ok");
 }
 expect(randomHex(8)).toMatch(/^[0-9a-f]{16}$/);
});

test("a queued span's payload still carries its IDs: root, child and a span whose parent came from a header",async()=>{
 const {client}=make();
 const expected:string[]=[];
 const recorder=Reflect.get(client,"spans") as {emitLean(span:LiveSpan):void};
 const original=recorder.emitLean;
 recorder.emitLean=function(this:unknown,span:LiveSpan){expected.push(leanSpanPayload(span));return Reflect.apply(original,this,[span]);};
 const ids:{trace:string;span:string;parent:string|null}[]=[];
 try{
  const root=client.startAdapterSpan("op","server",undefined,null);
  const child=root.run(()=>client.startAdapterSpan("op","client",undefined,undefined));
  const foreign={traceId:"c".repeat(32),spanId:"d".repeat(16),sampled:true,probability:"3ff0000000000000",clockDomain:root.context.clockDomain};
  const adopted=client.startAdapterSpan("op","server",undefined,foreign);
  for(const span of [child,adopted,root])span.end("ok");
  ids.push({trace:root.context.traceId,span:root.context.spanId,parent:null},{trace:root.context.traceId,span:child.context.spanId,parent:root.context.spanId},{trace:"c".repeat(32),span:adopted.context.spanId,parent:"d".repeat(16)});
 }finally{recorder.emitLean=original;}
 const records=client.bufferedRecords().map(text=>JSON.parse(text).payload as {trace_id:string;span_id:string;parent_id:string|null});
 expect(records.length).toBe(3);expect(expected.length).toBe(3);
 const byId=new Map(records.map(payload=>[payload.span_id,payload]));
 for(const id of ids){const payload=byId.get(id.span)!;expect(payload.trace_id).toBe(id.trace);expect(payload.parent_id).toBe(id.parent);}
 expect(new Set(records.map(payload=>JSON.stringify(payload)))).toEqual(new Set(expected.map(text=>JSON.stringify(JSON.parse(text)))));
});
