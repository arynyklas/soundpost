// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Pins the behavior that the per-request capture cost work must not change: canonical bytes, numeric bounds, queue admission and
// eviction order, drop accounting, the policy-before-queue ordering, and the identity/hash primitives that were made cheaper.
import {test,expect} from "bun:test";
import {sha256} from "@noble/hashes/sha256";
import type {SignedPolicy} from "../src/types.ts";
import {init,type Client} from "../src/client.ts";
import {canonical,compareNano,decimal,unixNano,utf8Compare,utf8Size} from "../src/policy.ts";
import {hashBytes,nativeCanonical} from "../src/routing.ts";
import {randomHex} from "../src/tracing.ts";
import {DeliveryQueue} from "../src/queue.ts";
import {parseSafeRecord,object,array} from "../src/wire.ts";
import type {FrozenBatch,Outcome,ReceiptTransport} from "../src/transport.ts";
import {config,signed,BUILD} from "./fixture.ts";

const bytewise=(a:string,b:string):number=>{const x=new TextEncoder().encode(a),y=new TextEncoder().encode(b);for(let i=0;i<Math.min(x.length,y.length);i++)if(x[i]!==y[i])return x[i]!-y[i]!;return x.length-y.length;};
const sign=(n:number):number=>n<0?-1:n>0?1:0;

test("utf8Compare orders exactly like the UTF-8 bytes, including astral against U+E000..U+FFFF",()=>{
 const corpus=["","a","b","ab","abc","B","_","\u007f","\u0080","\u07ff","\u0800","\ud7ff","\ue000","\uf8ff","\uffff","\u{10000}","\u{1f600}","\u{10ffff}","a\u{10000}","a\uffff","\u{1f600}a","\u{1f600}\uffff","\uffff\u{1f600}","é","e\u0301","日本","日本語"];
 for(const a of corpus)for(const b of corpus)expect(sign(utf8Compare(a,b)),JSON.stringify([a,b])).toBe(sign(bytewise(a,b)));
 expect(canonical({"\u{1f600}":1,"\uffff":2,"a":3})).toBe('{"a":3,"\uffff":2,"\u{1f600}":1}');
});

test("canonical text is unchanged by the faster string, key and array paths",()=>{
 expect(canonical({b:[1,{d:null,c:true},"x"],a:"é\u2028\"\\\n",z:-0})).toBe('{"a":"é\u2028\\"\\\\\\n","b":[1,{"c":true,"d":null},"x"],"z":0}');
 expect(nativeCanonical({a:"x\u2028y\u2029z"})).toBe('{"a":"x\\u2028y\\u2029z"}');
 expect(nativeCanonical({a:"plain"})).toBe('{"a":"plain"}');
 for(const hostile of ["\ud800","a\udc00b","\udc00\ud800"])expect(()=>canonical(hostile)).toThrow();
 expect(()=>canonical({["\ud800"]:1})).toThrow();
 expect(()=>canonical({get a(){return 1;}})).toThrow("noncanonical accessor");
 expect(()=>canonical([1,,3])).toThrow();
 const accessorArray:unknown[]=[1];Object.defineProperty(accessorArray,1,{get:()=>2,enumerable:true});expect(()=>canonical(accessorArray)).toThrow("noncanonical accessor");
 for(const bad of [undefined,1.5,NaN,Infinity,9007199254740993,10n,()=>1,Symbol("x")])expect(()=>canonical(bad as never)).toThrow("noncanonical value");
 expect(utf8Size("abc")).toBe(3);expect(utf8Size("é日\u{1f600}")).toBe(2+3+4);expect(()=>utf8Size("\ud800")).toThrow();
});

test("decimal and UnixNano keep exact uint64 and int64 bounds without BigInt",()=>{
 for(const ok of ["0","1","999999999999999","18446744073709551615","1844674407370955161"])expect(decimal(ok)).toBe(ok);
 for(const bad of ["","-1","01","18446744073709551616","99999999999999999999","100000000000000000000","1.0","1e3"," 1",1 as never])expect(()=>decimal(bad)).toThrow("invalid uint64");
 for(const ok of ["0","1","-1","9223372036854775807","-9223372036854775808","123456789012345","-12345678901234"])expect(unixNano(ok)).toBe(ok);
 for(const bad of ["","-0","00","01","9223372036854775808","-9223372036854775809","99999999999999999999","-","+1","1.5"," 1",1 as never])expect(()=>unixNano(bad)).toThrow("invalid UnixNano");
 const samples=["0","1","9","10","99","100","123","-1","-9","-10","-100","9223372036854775807","-9223372036854775808","1700000000123456789","1700000000123456788","-1700000000123456789"];
 for(const a of samples)for(const b of samples)expect(compareNano(a,b),a+" "+b).toBe(BigInt(a)<BigInt(b)?-1:BigInt(a)>BigInt(b)?1:0);
});

test("random identifiers stay well formed, unique and independent across pool refills",()=>{
 const seen=new Set<string>();
 for(let i=0;i<6000;i++){const id=randomHex(16);expect(id).toMatch(/^[0-9a-f]{32}$/);expect(seen.has(id)).toBe(false);seen.add(id);const span=randomHex(8);expect(span).toMatch(/^[0-9a-f]{16}$/);expect(seen.has(span)).toBe(false);seen.add(span);}
 expect(randomHex(1)).toMatch(/^[0-9a-f]{2}$/);
 for(const bad of [0,-1,1.5,4097,Number.NaN])expect(()=>randomHex(bad)).toThrow();
});

test("batch hashing is the same SHA-256 on the native and the portable path",()=>{
 const portable=(value:string):string=>Array.from(sha256(new TextEncoder().encode(value)),b=>b.toString(16).padStart(2,"0")).join("");
 for(const size of [0,1,100,1023,1024,1025,4096,70000]){const ascii="x".repeat(size),mixed="é日\u{1f600}a".repeat(Math.ceil(size/4)).slice(0,size);expect(hashBytes(ascii)).toBe(portable(ascii));expect(hashBytes(mixed)).toBe(portable(mixed));}
});

// ----- queue admission, drop accounting and wire bytes
const sealed=(expires="9223372036854775807",extra:Record<string,unknown>={}):SignedPolicy=>{const base=config(),doc:Record<string,unknown>={version:1,org:base.org,project:base.project,source:base.source,revision:"1",expires_ns:expires,errors:true,logs:true,replay:false,bodies:false,traces:true,...extra};return signed(JSON.stringify(doc,Object.keys(doc).sort()));};
const receipt=(batch:FrozenBatch)=>({version:1,batch_id:batch.id,hash:batch.hash,cursor:{group:"9".repeat(32),index:"9007199254740993"},retain_until_ns:"9007199254740994",signal_deadlines:batch.kinds.map(kind=>({kind,retain_until_ns:"9007199254740994"})),dedup_until_ns:"9007199254740995"});
class Gate implements ReceiptTransport {
 ack=false;
 async send(batch:FrozenBatch):Promise<Outcome>{return this.ack?{kind:"receipt",receipt:receipt(batch)}:{kind:"retryable"};}
 async lookup():Promise<Outcome>{return {kind:"not_found"};}
 close():void{}
}
function traced(maxRecords:number,options:{expires?:string;clock?:()=>string;gate?:Gate}={}){
 const gate=options.gate??new Gate(),base=config();
 const client=init({...base,operations:["op"],policy:sealed(options.expires),maxRecords,transport:gate,...(options.clock?{clockNs:options.clock}:{})});
 return {client,gate};
}
const span=(client:Client):void=>{client.startSpan("op").end("ok");};
const kindsOf=(client:Client):string[]=>client.bufferedRecords().map(text=>parseSafeRecord(text).kind);

test("a full queue drops spans as queue_full, counted once each, and keeps what it holds",()=>{
 const {client}=traced(3);
 for(let i=0;i<3;i++)span(client);
 const held=client.bufferedRecords();expect(held.length).toBe(3);expect(client.diagnostics().queue_full).toBeUndefined();
 for(let i=0;i<5;i++)span(client);
 expect(client.diagnostics().queue_full).toBe(5);expect(client.bufferedRecords()).toEqual(held);
 expect(client.diagnostics().queue_pressure).toBeUndefined();
});

test("a higher priority record still evicts a span from a full queue; an equal one cannot",()=>{
 const {client}=traced(3);
 for(let i=0;i<3;i++)span(client);
 client.captureException(new Error("first"));
 expect(kindsOf(client).sort()).toEqual(["error","span","span"]);expect(client.diagnostics().queue_pressure).toBe(1);
 client.captureException(new Error("second"));client.captureException(new Error("third"));
 expect(kindsOf(client)).toEqual(["error","error","error"]);expect(client.diagnostics().queue_pressure).toBe(3);
 client.captureException(new Error("fourth"));
 expect(kindsOf(client)).toEqual(["error","error","error"]);expect(client.diagnostics().queue_full).toBe(1);
 span(client);expect(client.diagnostics().queue_full).toBe(2);
});

test("the signed policy and the clock are judged before queue space",()=>{
 let now="9007199254740993";
 const {client}=traced(2,{expires:"9007199254740999",clock:()=>now});
 span(client);span(client);expect(client.bufferedRecords().length).toBe(2);
 now="9007199254741000";
 span(client);span(client);
 expect(client.diagnostics().policy_expired).toBe(2);expect(client.diagnostics().queue_full).toBeUndefined();
 now="9007199254740993";
 span(client);expect(client.diagnostics().queue_full).toBe(1);
 const off=init({...config(),operations:["op"],policy:sealed(undefined,{traces:false}),maxRecords:1,transport:new Gate()});
 span(off);span(off);expect(off.bufferedRecords().length).toBe(0);expect(off.diagnostics().queue_full).toBeUndefined();
});

test("space returns to spans once delivered batches are acknowledged, and frozen entries are never evicted",async()=>{
 const {client,gate}=traced(3);
 for(let i=0;i<3;i++)span(client);
 await client.flush(20);
 expect(client.bufferedRecords().length).toBe(3);
 span(client);client.captureException(new Error("cannot evict a frozen batch"));
 expect(client.diagnostics().queue_full).toBe(2);expect(client.bufferedRecords().length).toBe(3);expect(client.diagnostics().queue_pressure).toBeUndefined();
 gate.ack=true;
 const report=await client.flush(3000);
 expect(report.pending).toBe(0);expect(report.acknowledgedBatchIds.length).toBeGreaterThan(0);
 for(let i=0;i<3;i++)span(client);
 expect(client.bufferedRecords().length).toBe(3);expect(client.diagnostics().queue_full).toBe(2);
});

test("entries expire on schedule even after earlier entries left the queue",()=>{
 let at=0;
 const q=new DeliveryQueue({...config(),maxRecords:8},new Gate(),{now:()=>at});
 const record=(id:string)=>JSON.stringify({id,kind:"error",observed_at_ns:"9007199254740993",policy_revision:"1",payload:{occurrence_id:id,exception_class:"Error",code:null,build_id:BUILD,handled:true,fatal:false,mechanism:"manual",frames:[]}});
 q.enqueue(record("1".repeat(32)));at=100000;q.enqueue(record("2".repeat(32)));at=250000;q.enqueue(record("3".repeat(32)));
 at=299999;expect(q.records().length).toBe(3);
 at=300000;expect(q.records().length).toBe(2);
 at=400000;expect(q.records().length).toBe(1);expect(q.diagnostics().queue_expired).toBe(2);
 at=549999;expect(q.records().length).toBe(1);
 at=550000;expect(q.records().length).toBe(0);expect(q.diagnostics().queue_expired).toBe(3);
});

test("queued and framed bytes equal the independent canonical serialization, line separators included",async()=>{
 const sent:string[]=[];
 const transport:ReceiptTransport={async send(batch){sent.push(batch.body);return {kind:"receipt",receipt:receipt(batch)};},async lookup(){return {kind:"not_found"};},close(){}};
 const base=config(),q=new DeliveryQueue({...base,resource:{service_id:"6".repeat(32),environment_id:"7".repeat(32),build_id:BUILD,instance_pseudonym:"worker-1",labels:[{name:"a",value:"b\u2028c"}]}},transport);
 const make=(n:number,exception:string)=>JSON.stringify({payload:{frames:[],mechanism:"manual",fatal:false,handled:true,build_id:BUILD,code:null,exception_class:exception,occurrence_id:String(n).repeat(32)},policy_revision:"1",observed_at_ns:"9007199254740993",kind:"error",id:String(n).repeat(32)});
 const texts=[make(1,"Plain"),make(2,"Line\u2028Sep\u2029Para"),make(3,"é日\u{1f600}")];
 for(const text of texts)q.enqueue(text);
 expect(q.records()).toEqual(texts.map(text=>nativeCanonical(parseSafeRecord(text))));
 await q.flush(1000);
 expect(sent.length).toBeGreaterThan(0);
 const wire=sent.flatMap(body=>array(object(JSON.parse(body)).records));
 expect(wire.length).toBe(3);
 const resource=object(wire[0]).resource;
 for(const text of texts){
  const parsed=parseSafeRecord(text);
  const expected=nativeCanonical({id:parsed.id,kind:parsed.kind,observed_at_ns:parsed.observed_at_ns,payload:parsed.payload,resource});
  expect(sent.some(body=>body.includes(expected)),expected).toBe(true);
 }
 expect(sent.join("")).not.toContain("\u2028");expect(sent.join("")).not.toContain("\u2029");
});

test("the verified signed policy cannot be changed after construction",()=>{
 const base=config(),policy={...sealed()};
 const client=init({...base,operations:["op"],policy,transport:new Gate()});
 const before=client.policyDecision;
 policy.payload=sealed(undefined,{traces:false}).payload;
 span(client);expect(client.bufferedRecords().length).toBe(1);expect(client.policyDecision).toBe(before);expect(Object.isFrozen(client.policyDecision)).toBe(true);
 expect(()=>init({...base,operations:["op"],policy,transport:new Gate()})).toThrow("invalid signed policy");
});
