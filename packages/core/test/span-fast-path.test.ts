// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// The span recorder writes a span's canonical payload itself and the queue takes it without re-parsing (the per-request capture-cost work).
// These tests pin that this direct path writes exactly the bytes, route slot, size and refusals of the generic validated path, and that
// anything it cannot vouch for (custom clocks, contexts) still goes through full validation.
import {test,expect} from "bun:test";
import {sha256} from "@noble/hashes/sha256";
import type {SignedPolicy} from "../src/types.ts";
import {Client,checkedTraceContext} from "../src/client.ts";
import {createTraceClock,leanSpanLength,leanSpanPayload,type LiveSpan,type MetadataContext,type TraceContext,type TraceClock} from "../src/tracing.ts";
import {EncryptedSpool} from "../src/spool.ts";
import {nativeCanonical,resourceWire,routeRecord,routeSlot,validateDescriptor} from "../src/routing.ts";
import {parseSafeRecord,object,array} from "../src/wire.ts";
import type {FrozenBatch,Outcome,ReceiptTransport} from "../src/transport.ts";
import {config,signed} from "./fixture.ts";

const sealed=():SignedPolicy=>{const base=config(),doc:Record<string,unknown>={version:1,org:base.org,project:base.project,source:base.source,revision:"1",expires_ns:"9223372036854775807",errors:true,logs:true,replay:false,bodies:false,traces:true};return signed(JSON.stringify(doc,Object.keys(doc).sort()));};
const receipt=(batch:FrozenBatch)=>({version:1,batch_id:batch.id,hash:batch.hash,cursor:{group:"9".repeat(32),index:"9007199254740993"},retain_until_ns:"9007199254740994",signal_deadlines:batch.kinds.map(kind=>({kind,retain_until_ns:"9007199254740994"})),dedup_until_ns:"9007199254740995"});
class Recorder implements ReceiptTransport {
 readonly batches:FrozenBatch[]=[];ack=true;
 async send(batch:FrozenBatch):Promise<Outcome>{this.batches.push(batch);return this.ack?{kind:"receipt",receipt:receipt(batch)}:{kind:"retryable"};}
 async lookup():Promise<Outcome>{return {kind:"not_found"};}
 close():void{}
}
/** A metadata context over one deterministic clock. `generic` hands out unfrozen copies of every reading, which the recorder cannot vouch for, so those spans take the validated path. */
function context(options:{generic?:boolean;current?:()=>TraceContext|undefined;wall?:()=>string;mono?:()=>bigint}={}):MetadataContext{
 let current:TraceContext|undefined,tick=1000000000000000n;
 const clock=createTraceClock(options.mono??(()=>(tick+=7n)),options.wall??(()=>"1700000000123000000"));
 const read=options.generic?Object.assign(():TraceClock=>({...clock()}),{domain:clock.domain}):clock;
 return {clockDomain:clock.domain,current:options.current??(()=>current),run<T>(next:TraceContext|undefined,callback:()=>T):T{const prior=current;current=next;try{return callback();}finally{current=prior;}},jobCurrent:()=>undefined,runJob:<T>(_job:unknown,callback:()=>T):T=>callback(),clock:read,close(){}};
}
function client(ctx:MetadataContext,extra:Record<string,unknown>={}){
 const transport=new Recorder();
 return {client:new Client({...config(),operations:["op","other"],dependencies:["db"],policy:sealed(),transport,...extra},undefined,undefined,ctx),transport};
}
const mask=(text:string):string=>text.replace(/"mono_ns":"\d+"/g,'"mono_ns":"#"').replace(/"(id|trace_id|span_id|parent_id|boot|host|runtime)":"[0-9a-f]+"/g,'"$1":"#"');
type Scenario=(c:Client)=>void;
const scenarios:Record<string,Scenario>={
 "root span":c=>{c.startSpan("op").end("ok");},
 "error status":c=>{c.startSpan("other").end("error");},
 "cancelled":c=>{c.startSpan("op").end("cancelled");},
 "client span with dependency":c=>{c.startSpan("op",{kind:"client",dependency:"db"}).end("ok");},
 "server span":c=>{c.startSpan("op",{kind:"server",parent:null}).end("ok");},
 "child of an active span":c=>{const parent=c.startSpan("op");parent.run(()=>c.startSpan("other",{kind:"client",dependency:"db"}).end("ok"));parent.end("ok");},
 "child of a remote parent":c=>{const remote=checkedTraceContext({traceId:"a".repeat(32),spanId:"b".repeat(16),sampled:true,probability:"3ff0000000000000",clockDomain:{...c.traceContext()?.clockDomain??{host:"c".repeat(32),boot:"d".repeat(32),runtime:"e".repeat(32)}}});c.startSpan("op",{parent:remote}).end("ok");},
};

test("direct span encoding writes the bytes the validated path writes",()=>{
 for(const [name,run] of Object.entries(scenarios)){
  const fast=client(context()).client,slow=client(context({generic:true})).client;
  run(fast);run(slow);
  const a=fast.bufferedRecords(),b=slow.bufferedRecords();
  expect(a.length,name).toBeGreaterThan(0);expect(a.length,name).toBe(b.length);
  expect(a.map(mask),name).toEqual(b.map(mask));
  for(const text of a)expect(nativeCanonical(parseSafeRecord(text)),name).toBe(text);
 }
});

test("a span ended with an unreadable end clock is written as incomplete exactly like the validated path",()=>{
 const make=(generic:boolean)=>{let reads=0;const base=context({generic,mono:()=>{reads++;if(reads===2)throw Error("clock fault");return BigInt(1000000000000000+reads);}});return client(base).client;};
 const fast=make(false),slow=make(true);
 fast.startSpan("op").end("ok");slow.startSpan("op").end("ok");
 const a=fast.bufferedRecords(),b=slow.bufferedRecords();
 expect(a.length).toBe(1);expect(JSON.parse(a[0]!).payload.end).toBeNull();expect(JSON.parse(a[0]!).payload.status).toBe("incomplete");
 expect(a.map(mask)).toEqual(b.map(mask));expect(fast.diagnostics().invalid_clock).toBe(1);
});

test("every direct span is routed, framed and hashed as the generic route would",async()=>{
 const {client:c,transport}=client(context());
 for(let i=0;i<300;i++)scenarios[Object.keys(scenarios)[i%Object.keys(scenarios).length]!]!(c);
 const queued=c.bufferedRecords().length,report=await c.flush(5000);
 expect(report.pending).toBe(0);expect(transport.batches.length).toBeGreaterThan(8);
 const base=config(),descriptor=validateDescriptor({version:1,org:base.org,project:base.project,source:base.source,routing_version:1,slots:64,policy_revision:"1"});
 let records=0;
 for(const batch of transport.batches){
  const body=object(JSON.parse(batch.body));
  expect(nativeCanonical(body),"batch body is canonical").toBe(batch.body);
  expect(body.route_slot).toBe(batch.route_slot);expect(body.id).toBe(batch.id);expect(body.producer).toBe(batch.producer);
  expect(batch.hash).toBe(Array.from(sha256(new TextEncoder().encode(batch.body)),byte=>byte.toString(16).padStart(2,"0")).join(""));
  for(const item of array(body.records)){records++;expect(routeRecord(object(item),descriptor,batch.producer),"route slot of "+JSON.stringify(item).slice(0,80)).toBe(batch.route_slot);}
  expect(array(body.records).length).toBe(batch.count);
 }
 expect(records).toBe(queued);expect(queued).toBeGreaterThan(300);
});

test("direct and validated spans take the same queue space, byte for byte",()=>{
 const base=config(),resource=nativeCanonical(resourceWire(base.resource,base.build));
 const probe=client(context()).client;probe.startSpan("op").end("ok");
 const safe=probe.bufferedRecords()[0]!,wire=safe.slice(0,safe.lastIndexOf(',"policy_revision"'))+',"resource":'+resource+"}",size=new TextEncoder().encode(wire).length+512;
 for(const [limit,expected] of [[3*size,3],[3*size-1,2],[3*size+size-1,3]] as const){
  for(const generic of [false,true]){
   const {client:c}=client(context({generic}),{maxBytes:limit});
   for(let i=0;i<6;i++)c.startSpan("op").end("ok");
   expect(c.bufferedRecords().length,`limit ${limit} generic ${generic}`).toBe(expected);expect(c.diagnostics().queue_full,`limit ${limit} generic ${generic}`).toBe(6-expected);
  }
 }
});

test("spans built on readings or contexts the recorder did not make are fully validated, never spliced",()=>{
 const hostile=context({wall:()=>'1700000000123000000"},"smuggled":{"x":"'});
 // The wall clock shape is checked when the reading is made, so a hostile wall clock cannot even produce a reading.
 const {client:c}=client(hostile);c.startSpan("op").end("ok");
 expect(c.bufferedRecords()).toEqual([]);expect(c.diagnostics().invalid_clock).toBeGreaterThan(0);
 const liar=context({generic:true}),read=liar.clock;
 const forged:MetadataContext={...liar,clock:Object.assign(():TraceClock=>({...read(),wall_ns:'1700000000123000000"},"smuggled":{"x":"'}),{domain:liar.clockDomain})};
 const {client:d}=client(forged);d.startSpan("op").end("ok");
 expect(d.bufferedRecords()).toEqual([]);expect(d.diagnostics().invalid_clock).toBeGreaterThan(0);
});

test("a parent context nobody validated cannot reach the encoder",()=>{
 const domain=createTraceClock(()=>1n).domain;
 const lie:TraceContext={traceId:'a"b'.padEnd(32,"c"),spanId:"b".repeat(16),sampled:true,probability:"3ff0000000000000",clockDomain:domain};
 const {client:c}=client(context({current:()=>lie}));
 const span=c.startSpan("op");
 expect(()=>span.end("ok")).toThrow();
 expect(c.bufferedRecords()).toEqual([]);
});

test("the adapter entry point applies the same checks as startSpan",()=>{
 const {client:c}=client(context());
 for(const [adapter,generic] of [[()=>c.startAdapterSpan("missing","server",undefined,null),()=>c.startSpan("missing",{kind:"server",parent:null})],[()=>c.startAdapterSpan("op","client","nope",undefined),()=>c.startSpan("op",{kind:"client",dependency:"nope"})],[()=>c.startAdapterSpan("op","bogus" as never,undefined,null),()=>c.startSpan("op",{kind:"bogus" as never,parent:null})]] as const){
  let a:unknown,b:unknown;try{adapter();}catch(error){a=(error as Error).message;}try{generic();}catch(error){b=(error as Error).message;}
  expect(a).toBeDefined();expect(a).toBe(b);
 }
 const own=c.startAdapterSpan("op","server",undefined,null);expect(own.context.sampled).toBe(true);own.end("ok");
 const bad={traceId:"x",spanId:"y",sampled:true,probability:"3ff0000000000000",clockDomain:{}} as never;
 expect(()=>c.startAdapterSpan("op","server",undefined,bad)).toThrow();expect(()=>c.startSpan("op",{parent:bad})).toThrow();
 c.close();expect(()=>c.startAdapterSpan("op","server",undefined,null)).toThrow("client closed");
});

test("a context the recorder built is trusted by identity; a lookalike is validated",()=>{
 const {client:c}=client(context());
 const span=c.startSpan("op"),built=span.context;
 expect(checkedTraceContext(built)).toBe(built);
 const copy=checkedTraceContext({...built,clockDomain:{...built.clockDomain}});
 expect(copy).not.toBe(built);expect(copy).toEqual(built);
 expect(()=>checkedTraceContext({...built,traceId:"not an id"})).toThrow("invalid opaque ID");
 expect(()=>checkedTraceContext({...built,spanId:"0".repeat(16)})).toThrow("invalid_trace_context");
 expect(()=>checkedTraceContext(Object.freeze({...built,clockDomain:{host:"x",boot:"y",runtime:"z"}}))).toThrow();
 span.end("ok");
});

test("trace clocks keep the monotonic reading canonical: bounds, type and decimal shape",()=>{
 const wall=()=>"1700000000123000000";
 expect(createTraceClock(()=>0n,wall)().mono_ns).toBe("0");
 expect(createTraceClock(()=>18446744073709551615n,wall)().mono_ns).toBe("18446744073709551615");
 expect(createTraceClock((()=>5) as never,wall)().mono_ns).toBe("5");
 for(const bad of [-1n,18446744073709551616n,1.5,-0.5,"x",NaN])expect(()=>createTraceClock((()=>bad) as never,wall)(),String(bad)).toThrow("invalid uint64");
});

test("the route slot is byte 7 of the SHA-256 of the routing input, native or portable",()=>{
 const random=(n:number)=>Uint8Array.from({length:n},(_,i)=>(i*131+n*17)&255);
 for(const n of [1,55,56,63,64,65,116,500])expect(routeSlot(random(n)),String(n)).toBe(sha256(random(n))[7]!%64);
});

test("a lean span's serialized length is computed exactly, for every clock width, parent, end and status",()=>{
 const widths=[0n,1n,9n,10n,99n,100n,999999999999999n,1000000000000000n,9999999999999999n,10000000000000000n,99999999999999999n,100000000000000000n,999999999999999999n,1000000000000000000n,9999999999999999999n,10000000000000000000n,18446744073709551615n];
 const walls=["0","1","1700000000123000000","-5","9223372036854775807"];
 let checked=0;
 for(const first of widths)for(const second of widths){
  const readings=[first,second];let at=0;
  const {client:c}=client(context({mono:()=>readings[at++%2]!,wall:()=>walls[(at+checked)%walls.length]!}));
  for(const [kind,dependency,status] of [["internal",undefined,"ok"],["client","db","error"],["server",undefined,"cancelled"],["producer",undefined,"incomplete"]] as const){
   at=0;const span=c.startAdapterSpan("op",kind,dependency,null) as unknown as LiveSpan;
   at=1;span.end(status);
   if(span.endWall===null)continue;
   expect(leanSpanLength(span),String([first,second,kind,status])).toBe(leanSpanPayload(span).length);
   expect(JSON.parse(leanSpanPayload(span)).start.mono_ns).toBe(String(first));checked++;
  }
 }
 expect(checked).toBeGreaterThan(100);expect(checked).toBeLessThan(widths.length*widths.length*4);
 const {client:p}=client(context());
 const parent=p.startSpan("op");
 parent.run(()=>{const child=p.startSpan("other",{kind:"client",dependency:"db"}) as unknown as LiveSpan;child.end("ok");expect(child.parentId).not.toBeNull();expect(leanSpanLength(child)).toBe(leanSpanPayload(child).length);});
 parent.end("ok");
 const first=p.bufferedRecords();for(const text of first)expect(nativeCanonical(parseSafeRecord(text))).toBe(text);
});

test("queued spans are serialized when the batch is frozen, read or persisted, and the size accounted at queue time was the real size",async()=>{
 const {client:c,transport}=client(context());
 for(let i=0;i<40;i++)c.startSpan("op").end("ok");
 const texts=c.bufferedRecords();expect(texts.length).toBe(40);
 expect(new Set(texts.map(text=>JSON.parse(text).id)).size).toBe(40);
 expect(c.diagnostics().span_size_mismatch).toBeUndefined();
 await c.flush(2000);expect(transport.batches.reduce((n,batch)=>n+batch.count,0)).toBe(40);
 expect(c.diagnostics().span_size_mismatch).toBeUndefined();
 const sealedQueue=client(context(),{maxBytes:4096}).client;for(let i=0;i<10;i++)sealedQueue.startSpan("op").end("ok");
 expect(sealedQueue.diagnostics().queue_full).toBeGreaterThan(0);expect(sealedQueue.bufferedRecords().length+(sealedQueue.diagnostics().queue_full??0)).toBe(10);
});

test("lean spans survive a spool round trip byte for byte",async()=>{
 let bytes:Uint8Array|undefined;const backend={read:async()=>bytes,write:async(value:Uint8Array)=>{bytes=value.slice();},close:()=>{}};
 const base=config(),descriptor=validateDescriptor({version:1,org:base.org,project:base.project,source:base.source,routing_version:1,slots:64,policy_revision:"1"});
 const make=()=>{const transport=new Recorder();transport.ack=false;return client(context(),{producer:"7".repeat(32),transport,spool:new EncryptedSpool(backend,new Uint8Array(32),descriptor,"1")}).client;};
 const first=make();for(let i=0;i<5;i++)first.startSpan("op").end("ok");
 const before=first.bufferedRecords();await first.flush(50);expect(bytes).toBeDefined();
 const second=make();await second.flush(50);
 expect(second.bufferedRecords().map(text=>JSON.parse(text).id).sort()).toEqual(before.map(text=>JSON.parse(text).id).sort());
});

test("a large flush gives the event loop turns while it works instead of stalling the host",async()=>{
 const {client:c,transport}=client(context());
 for(let i=0;i<1000;i++)c.startSpan("op").end("ok");
 let ticks=0,stop=false;const spin=():void=>{ticks++;if(!stop)setImmediate(spin);};spin();
 const report=await c.flush(10000);stop=true;
 expect(report.pending).toBe(0);expect(transport.batches.reduce((n,batch)=>n+batch.count,0)).toBe(1000);
 expect(ticks,"event loop turns during the flush").toBeGreaterThan(2);
});
