// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Server capture cost, wave 25: what the export costs per queued span and per acknowledged batch. About half a batch is exported per request (one batch per route slot of every
// 100 ms flush), so work done per batch over the whole queue is work done per request. These pins keep the per-batch part constant (no scan of the queue's entries to settle loss
// accounting when there is none, one rebuild of the entry list and none of the batch list when a batch is removed) and the per-span string work low (the payload is composed
// from per-vocabulary fragments, see the last test). Nothing here changes a byte on the wire.
import {test,expect} from "bun:test";
import {heapStats} from "bun:jsc";
import type {SignedPolicy} from "../src/types.ts";
import type {Client} from "../src/client.ts";
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
const make=()=>{const transport=new Acking();return {client:new RuntimeClient({...config(),operations:["op"],dependencies:[],policy:sealed(),transport}),transport};};
/** The queue's protected state, which these tests read and drive directly. */
interface Internals {entries:unknown[];batches:{batch:FrozenBatch}[];bytes:number;freeze():readonly FrozenBatch[];acknowledgeSignalLosses(batch:FrozenBatch,receipt:Record<string,unknown>):void;remove(batch:FrozenBatch,reason?:string):void}
const queueOf=(client:Client):Internals=>Reflect.get(client,"delivery") as Internals;
const spans=(client:Client,count:number):void=>{for(let i=0;i<count;i++)client.startAdapterSpan("op","server",undefined,null).end("ok");};

test("a flush rebuilds the entry list once per acknowledged batch, and no batch is found by a list rebuild",async()=>{
 const {client,transport}=make();
 spans(client,300);
 const filter=Array.prototype.filter;let filters=0;
 Array.prototype.filter=function(this:unknown[],...args:Parameters<typeof filter>){filters++;return Reflect.apply(filter,this,args);} as typeof filter;
 let report;
 try{report=await client.flush(5000);}finally{Array.prototype.filter=filter;}
 expect(report.pending).toBe(0);
 expect(transport.batches.length).toBeGreaterThan(20);
 // one filter per removed batch (the entry list) and a constant number elsewhere; it was two per batch (entries and batches)
 expect(filters).toBeLessThanOrEqual(transport.batches.length+6);
 await client.close();
});

test("acknowledging a batch settles loss accounting without scanning the queue when no loss is being counted",async()=>{
 const {client}=make();
 const queue=queueOf(client);
 spans(client,30);
 const [first]=queue.freeze();
 expect(first).toBeDefined();
 let reads=0;
 const descriptor=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Object.getPrototypeOf(queue)),"entries")??Object.getOwnPropertyDescriptor(Object.getPrototypeOf(queue),"entries");
 expect(descriptor?.get).toBeDefined();
 Object.defineProperty(queue,"entries",{configurable:true,get(){reads++;return descriptor!.get!.call(this);},set(value){descriptor!.set!.call(this,value);}});
 try{queue.acknowledgeSignalLosses(first!,receipt(first!));}finally{Reflect.deleteProperty(queue,"entries");}
 expect(reads).toBe(0);
 await client.close();
});

test("removing a batch drops exactly its entries and its batch state, keeps the byte count exact, and counts the reason",async()=>{
 const {client}=make();
 spans(client,40);
 const queue=queueOf(client),batches=queue.freeze();
 expect(batches.length).toBeGreaterThan(3);
 const before=queue.entries.length,bytes=queue.bytes,victim=batches[2]!;
 queue.remove(victim,"queue_expired");
 expect(queue.entries.length).toBe(before-victim.count);
 expect(queue.batches.some(state=>state.batch.id===victim.id)).toBe(false);
 expect(queue.batches.length).toBe(batches.length-1);
 expect(queue.bytes).toBeLessThan(bytes);
 expect(client.diagnostics().queue_expired).toBe(victim.count);
 queue.remove(victim); // removing it again changes nothing
 expect(queue.batches.length).toBe(batches.length-1);
 await client.close();
});

/** heapStats() counts string cells, live or not yet collected: the allocation of a step is its delta over a loop too short to collect. */
const stringCells=():number=>heapStats().objectTypeCounts.string??0;
interface Cells {entries:{lazy:number;wire:string}[];leanSlab():{payload(slot:number):string};materializeWire(entry:{lazy:number;wire:string}):void}

test("a queued span's payload and wire form are composed from per-vocabulary fragments (few string cells per span) and equal the span's own payload",async()=>{
 const {client}=make();
 const queue=Reflect.get(client,"delivery") as Cells;
 // the spans' own payload, for the byte comparison, captured while they are still LiveSpans
 const expected:string[]=[];
 const recorder=Reflect.get(client,"spans") as {emitLean:(span:LiveSpan)=>void};
 const original=recorder.emitLean;
 recorder.emitLean=(span:LiveSpan)=>{expected.push(leanSpanPayload(span));original.call(recorder,span);};
 try{for(let i=0;i<300;i++)client.startAdapterSpan("op","server",undefined,null).end(i%7===0?"cancelled":"ok");}finally{recorder.emitLean=original;}
 const slab=queue.leanSlab(),lazy=queue.entries.filter(entry=>entry.lazy>=0);
 expect(lazy.length).toBe(expected.length);
 const before=stringCells();
 const payloads=lazy.map(entry=>slab.payload(entry.lazy));
 const perPayload=(stringCells()-before)/payloads.length;
 expect(payloads).toEqual(expected);
 // 33 cells per payload when every constant was joined again for every span, 24 with the fragments
 expect(perPayload).toBeLessThanOrEqual(28);
 const beforeWire=stringCells();
 for(const entry of lazy)queue.materializeWire(entry);
 const perWire=(stringCells()-beforeWire)/lazy.length;
 // 43 cells per span (payload, record head with its ID and wall text, wire form) before: the wall text is built once, not twice
 expect(perWire).toBeLessThanOrEqual(37);
 await client.close();
});
