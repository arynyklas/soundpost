// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// The compact store of queued lean spans (lean_slab.ts) belongs to the Node/Bun queue only. The core Client's queue, which the browser core bundle carries, has none and
// serializes a span when it is queued, so the bundle does not carry the store (browser/test/entries.test.ts pins the size). Both give the same spans on the wire.
import {test,expect} from "bun:test";
import type {SignedPolicy} from "../src/types.ts";
import {Client} from "../src/client.ts";
import {RuntimeClient} from "../src/runtime_client.ts";
import {leanSpanPayload,type LiveSpan} from "../src/tracing.ts";
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
interface Queue {entries:{lazy:number;text:string;wire:string}[];leanSlab?:()=>unknown}
interface SpanPayload {span_id:string}
interface BatchBody {records:{kind:string;payload:SpanPayload}[]}
const SPANS=40;

/** Starts and ends SPANS spans, returning the payload each had as a LiveSpan, then flushes and returns the span payloads the batches carried (both sorted by span ID). */
async function run(Make:typeof Client){
 const transport=new Acking(),client=new Make({...config(),operations:["op"],dependencies:[],policy:sealed(),transport});
 const expected:SpanPayload[]=[],recorder=Reflect.get(client,"spans") as {emitLean:(span:LiveSpan)=>void},original=recorder.emitLean;
 recorder.emitLean=(span:LiveSpan)=>{expected.push(JSON.parse(leanSpanPayload(span)));original.call(recorder,span);};
 try{for(let i=0;i<SPANS;i++)client.startAdapterSpan("op","server",undefined,null).end(i%5===0?"cancelled":"ok");}finally{recorder.emitLean=original;}
 const queue=Reflect.get(client,"delivery") as Queue,entries=queue.entries.map(entry=>({lazy:entry.lazy,text:entry.text,wire:entry.wire})),slab=queue.leanSlab?.();
 const report=await client.flush(5000);
 const delivered:SpanPayload[]=transport.batches.flatMap(batch=>{const body:BatchBody=JSON.parse(batch.body);return body.records.filter(record=>record.kind==="span").map(record=>record.payload);});
 await client.close();
 const order=(a:SpanPayload,b:SpanPayload):number=>a.span_id.localeCompare(b.span_id);
 return {entries,slab,report,delivered:delivered.sort(order),expected:expected.sort(order)};
}

test("the core Client's queue has no compact store: a span is serialized when it is queued, and is delivered unchanged",async()=>{
 const {entries,slab,report,delivered,expected}=await run(Client);
 expect(slab).toBeUndefined();
 expect(entries.length).toBe(SPANS);
 expect(entries.every(entry=>entry.lazy===-1&&entry.text!==""&&entry.wire!=="")).toBe(true);
 expect(report.pending).toBe(0);
 expect(delivered).toEqual(expected);
});

test("the Node/Bun RuntimeClient's queue keeps queued spans in the compact store until they are batched, and delivers the same spans",async()=>{
 const {entries,slab,report,delivered,expected}=await run(RuntimeClient);
 expect(slab).toBeDefined();
 expect(entries.length).toBe(SPANS);
 expect(entries.every(entry=>entry.lazy>=0&&entry.text===""&&entry.wire==="")).toBe(true);
 expect(report.pending).toBe(0);
 expect(delivered).toEqual(expected);
});
