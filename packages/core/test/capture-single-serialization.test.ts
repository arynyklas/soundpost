// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Server capture cost, wave 23: a captured error is serialized once. The client's own canonical text of the record is the queue's stored form and the batch form is that text with
// the resource spliced in, so the payload is not canonicalized a second time. This pins the byte equality with the old two-pass form (line separators and stripped empty optional
// fields included) and the number of string renders one capture costs.
import {test,expect} from "bun:test";
import {init} from "../src/client.ts";
import {nativeCanonical} from "../src/routing.ts";
import {DeliveryQueue} from "../src/queue.ts";
import {parseSafeRecord,object,array} from "../src/wire.ts";
import type {Outcome,ReceiptTransport} from "../src/transport.ts";
import {config,signed,BUILD} from "./fixture.ts";

const receipt=(batch:{id:string;hash:string;kinds:readonly string[]})=>({version:1,batch_id:batch.id,hash:batch.hash,cursor:{group:"9".repeat(32),index:"9007199254740993"},retain_until_ns:"9007199254740994",signal_deadlines:batch.kinds.map(kind=>({kind,retain_until_ns:"9007199254740994"})),dedup_until_ns:"9007199254740995"});
const keys={version:0,org:0,project:0,source:0,revision:0,expires_ns:0,errors:0,logs:0,replay:0,bodies:0,traces:0,jobs:0};
const policy=()=>{const base=config();return signed(JSON.stringify({version:1,org:base.org,project:base.project,source:base.source,revision:"1",expires_ns:"9223372036854775807",errors:true,logs:true,replay:false,bodies:false,traces:true,jobs:false},Object.keys(keys).sort()));};
const sink=(sent:string[]):ReceiptTransport=>({async send(batch):Promise<Outcome>{sent.push(batch.body);return {kind:"receipt",receipt:receipt(batch)};},async lookup(){return {kind:"not_found"};},close(){}});
const record=(n:number,exception:string,extra:Record<string,unknown>={})=>({id:String(n).repeat(32),kind:"error",observed_at_ns:"9007199254740993",policy_revision:"1",payload:{occurrence_id:String(n).repeat(32),exception_class:exception,code:null,build_id:BUILD,handled:true,fatal:false,mechanism:"manual",frames:[],...extra}});

test("a trusted canonical text queues the same stored and framed bytes as the two-pass form, line separators and stripped optional fields included",async()=>{
 const sentOld:string[]=[],sentNew:string[]=[];
 const resource={service_id:"6".repeat(32),environment_id:"7".repeat(32),build_id:BUILD,instance_pseudonym:"worker-1",labels:[{name:"a",value:"b\u2028c"}]};
 const old=new DeliveryQueue({...config(),resource},sink(sentOld)),fresh=new DeliveryQueue({...config(),resource},sink(sentNew));
 const records=[record(1,"Plain"),record(2,"Line\u2028Sep\u2029Para"),record(3,"é日\u{1f600}"),record(4,"Optional",{trace_id:null,release_id:null,exception_graph:{nodes:[{id:0,exception_class:"Optional",frames:[],context_suppressed:false}],edges:[],reasons:[]}}),record(5,"Frames",{frames:[{module_id:"m",function:"f",artifact_id:"a",line:3,column:null,in_app:true,async:false}]})];
 for(const value of records){
  old.enqueue(JSON.stringify(value));
  fresh.enqueueNative(nativeCanonical(value));
 }
 expect(fresh.records()).toEqual(old.records());
 expect(fresh.records()[3]).not.toContain("trace_id");   // the stripped optional null is not in the stored text
 expect(parseSafeRecord(fresh.records()[0]!).payload.exception_class).toBe("Plain");
 await old.flush(1000);await fresh.flush(1000);
 const wire=(sent:string[])=>sent.flatMap(body=>array(object(JSON.parse(body)).records)).map(value=>nativeCanonical(value));
 expect(wire(sentNew)).toEqual(wire(sentOld));expect(wire(sentNew).length).toBe(5);
 expect(sentNew.join("")).not.toContain("\u2028");
});

test("an invalid or mismatched trusted text is refused like the text path",()=>{
 const q=new DeliveryQueue(config(),sink([]));
 expect(()=>q.enqueueNative('{"id":"1"}')).toThrow();
 expect(()=>q.enqueueNative(nativeCanonical({...record(1,"X"),policy_revision:"2"}))).toThrow("policy revision mismatch");
 expect(q.records().length).toBe(0);
});

test("one captured error reads every property of the record once (the client's canonical text is the only serialization)",()=>{
 const client=init({...config(),operations:["request"],policy:policy(),transport:sink([])});
 const cause=new RangeError("inner"),error=new TypeError("outer",{cause});
 client.captureException(error);   // first use: caches, compiles
 // canonical() reads each own property and array element once through a descriptor, so descriptor reads count serialization passes.
 const read=Object.getOwnPropertyDescriptor;let calls=0;
 Object.getOwnPropertyDescriptor=((...args:Parameters<typeof read>)=>{calls++;return Reflect.apply(read,Object,args);}) as typeof read;
 try{client.captureException(error);}finally{Object.getOwnPropertyDescriptor=read;}
 let properties=0;
 const walk=(value:unknown):void=>{if(Array.isArray(value)){properties+=value.length;value.forEach(walk);}else if(value&&typeof value==="object"){for(const [,member] of Object.entries(value)){properties++;walk(member);}}};
 walk(JSON.parse(client.bufferedRecords().at(-1)!));
 // one pass over the record plus a few reads around it; the two-pass form read the payload again (41 reads for 23 properties)
 expect(properties).toBeGreaterThan(15);
 expect(calls).toBeLessThanOrEqual(properties+6);
});
