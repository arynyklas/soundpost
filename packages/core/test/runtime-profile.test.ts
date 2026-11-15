// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// 03.09-W4: a finished Node/Bun runtime_engine_samples report is admitted by the core client as one capability record plus, only for a
// supported run, linked profile chunks, through the REAL queue (closed wire validation, batching, receipts). The transport is a recording
// ledger that issues genuine receipts; what the real server stores for these records is the Go model test and the journeys smoke.
import {test,expect} from "bun:test";
import {init} from "../src/client.ts";
import {runtimeProfileWire,type RuntimeProfileReport} from "../src/profile_wire.ts";
import {parseSafeRecord} from "../src/wire.ts";
import type {FrozenBatch,Outcome,ReceiptTransport} from "../src/transport.ts";
import {config} from "./fixture.ts";

class Ledger implements ReceiptTransport {
 readonly bodies:string[]=[];
 async send(batch:FrozenBatch):Promise<Outcome>{
  this.bodies.push(batch.body);
  return {kind:"receipt",receipt:{version:1,batch_id:batch.id,hash:batch.hash,cursor:{group:"9".repeat(32),index:String(this.bodies.length)},retain_until_ns:"9007199254740994",dedup_until_ns:"9007199254740995",signal_deadlines:batch.kinds.map(kind=>({kind,retain_until_ns:"9007199254740994"}))}};
 }
 async lookup():Promise<Outcome>{return {kind:"not_found"};}
 close():void{}
}
type Wire={id:string;kind:string;observed_at_ns:string;payload:Record<string,any>};
const sent=(ledger:Ledger):Wire[]=>ledger.bodies.flatMap(body=>(JSON.parse(body) as {records:Wire[]}).records);
const WALL="1700000000000000000";
const domain={host:"a".repeat(32),boot:"b".repeat(32),runtime:"c".repeat(32)};
function report(over:Partial<RuntimeProfileReport>={},status="supported",reason="ok"):RuntimeProfileReport{
 return {units:"samples",
  capability:{id:"d".repeat(32),runtime:"node",version:"v22.23.4",build:"12.4.254.21-node.33",os:"linux",arch:"x64",signal:"profile_chunk",method:"runtime_engine_samples",status,reason,coverage:{frames:"partial",threads:"partial",workers:"none",tasks:"none"},clock_domain:domain,expires_ns:"1700003600000000000"},
  clock:{domain,uncertainty_ns:"18446744073709551615",wall_start_ns:WALL,wall_end_ns:"1700000005000000000"},
  frames:[{module_id:"src/work.js",function:"busyWork",artifact_id:"src/work.js",offset:"0",reason:""},{module_id:"external",function:"",artifact_id:"",offset:"0",reason:"not_captured"}],
  stacks:[{frames:[0,1]},{frames:[1]}],
  samples:[{at_us:"0",stack:0,count:"1",thread:"0"},{at_us:"1000",stack:0,count:"1",thread:"0"},{at_us:"2100",stack:1,count:"1",thread:"0"}],
  truncated:false,losses:[],...over};
}
const mk=(enable=true)=>{const ledger=new Ledger();return {ledger,client:init({...config(),transport:ledger,...(enable?{deploymentProfiles:true}:{})})};};

test("a supported run is one capability record and one linked runtime_cpu chunk, valid under the closed wire, acknowledged by a real flush",async()=>{
 const {ledger,client}=mk();
 expect(client.captureRuntimeProfile(report())).toBe(true);
 const flush=await client.flush(2000);expect(flush.pending).toBe(0);expect(flush.lost).toBe(0);expect(flush.acknowledgedCursors.length).toBeGreaterThan(0);
 const records=sent(ledger);expect(records.map(r=>r.kind).sort()).toEqual(["capability","profile_chunk"]);
 const capability=records.find(r=>r.kind==="capability")!,chunk=records.find(r=>r.kind==="profile_chunk")!;
 // The SDK's own method names the engine samples; the chunk uses the server's closed vocabulary (documented mapping), never an OS CPU unit.
 expect(capability.payload.method).toBe("runtime_engine_samples");expect(capability.payload.signal).toBe("profile_chunk");expect(capability.payload.status).toBe("supported");
 expect(chunk.payload.capability_id).toBe(capability.id);expect(chunk.payload.method).toBe("runtime_cpu");expect(chunk.payload.units).toBe("samples");
 expect(chunk.payload.clock.domain).toEqual(capability.payload.clock_domain);expect(chunk.payload.clock.mono_ns).toBe("0");
 expect(chunk.payload.samples.map((s:Record<string,string>)=>s.at_ns)).toEqual(["0","1000000","2100000"]);
 expect(chunk.payload.process_id).not.toBe(chunk.payload.profile_id);
 for(const frame of chunk.payload.frames)expect(Object.keys(frame).sort()).toEqual(["artifact_id","function","module_id","offset","reason"]);
 for(const r of records)expect(()=>parseSafeRecord(JSON.stringify({id:r.id,kind:r.kind,observed_at_ns:r.observed_at_ns,payload:r.payload,policy_revision:"1"}))).not.toThrow();
 expect(client.diagnostics()).toEqual({});
 await client.close();
});

test("a refused or failed run is the capability truth record alone: never a chunk, never samples",async()=>{
 for(const [status,reason] of [["denied","profiler_owned"],["unsupported","inspector_unavailable"],["error","inspector_error"]] as const){
  const {ledger,client}=mk();
  expect(client.captureRuntimeProfile(report({frames:[],stacks:[],samples:[]},status,reason))).toBe(true);await client.flush(2000);
  const records=sent(ledger);expect(records.map(r=>r.kind)).toEqual(["capability"]);expect(records[0]!.payload.status).toBe(status);expect(records[0]!.payload.reason).toBe(reason);
  await client.close();
 }
 // Even a report that still carries samples never sends them when the capability is not supported.
 const {ledger,client}=mk();client.captureRuntimeProfile(report({},"error","inspector_error"));await client.flush(2000);
 expect(sent(ledger).map(r=>r.kind)).toEqual(["capability"]);await client.close();
});

test("a large profile is split by the record byte budget: one profile_id, every sample once, loss on the first chunk only, every record under the queue's record cap",async()=>{
 const samples=Array.from({length:9000},(_,i)=>({at_us:String(i*10),stack:i%2,count:"1",thread:"0"}));
 const wire=runtimeProfileWire(report({samples,truncated:true,losses:[{reason:"truncated",count:"7"},{reason:"sample_gap",count:"5"}]}),{process:"e".repeat(32),id:(()=>{let n=0;return ()=>(++n).toString(16).padStart(32,"0");})()});
 expect(wire.chunks.length).toBeGreaterThan(1);
 const counts=wire.chunks.map(c=>(c.payload.samples as unknown[]).length);
 expect(counts.reduce((a,b)=>a+b,0)).toBe(9000);expect(Math.max(...counts)).toBeLessThanOrEqual(8192);
 expect(new Set(wire.chunks.map(c=>c.payload.profile_id)).size).toBe(1);
 expect(wire.chunks.map(c=>c.payload.loss)).toEqual(["12",...wire.chunks.slice(1).map(()=>"0")]);expect(wire.chunks.map(c=>c.payload.truncated)).toEqual([true,...wire.chunks.slice(1).map(()=>false)]);
 for(const chunk of wire.chunks){expect(JSON.stringify(chunk).length).toBeLessThan(262_144);expect(chunk.payload.capability_id).toBe(wire.capability.id);}
 // Through the real queue: the capability goes first and every chunk is accepted.
 const {ledger,client}=mk();expect(client.captureRuntimeProfile(report({samples}))).toBe(true);await client.flush(2000);
 expect(sent(ledger).filter(r=>r.kind==="profile_chunk").length).toBe(wire.chunks.length);await client.close();
});

test("samples the profiler dropped are a recorded truncated loss; without the deployment flag nothing is queued and the refusal is counted",async()=>{
 const {client}=mk();client.captureRuntimeProfile(report({truncated:true,losses:[{reason:"truncated",count:"4"}]}));
 expect(client.diagnostics().profile_samples_truncated).toBe(4);await client.close();
 const {ledger,client:off}=mk(false);expect(off.captureRuntimeProfile(report())).toBe(false);await off.flush(2000);
 expect(sent(ledger)).toEqual([]);expect(Object.keys(off.diagnostics()).length).toBeGreaterThan(0);await off.close();
});

test("a report the wire mapping cannot read is counted as profile_wire_failed and never throws",async()=>{
 const {client}=mk();
 expect(client.captureRuntimeProfile({...report(),stacks:[],samples:[{at_us:"0",stack:3,count:"1",thread:"0"}]})).toBe(false);
 expect(client.diagnostics().profile_wire_failed).toBe(1);await client.close();
});
