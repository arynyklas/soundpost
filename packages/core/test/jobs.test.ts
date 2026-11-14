// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test,expect} from "bun:test";
import {Client} from "../src/client.ts";
import {normalizeAttempt,createTimerCancellationBoundary} from "../src/jobs.ts";
import {JOB,RUN,jobSettings} from "./jobs-fixture.ts";
import {config} from "./fixture.ts";
import {types} from "node:util";
function records(client:Client,kind="job_attempt"){return client.bufferedRecords().map(value=>JSON.parse(value)).filter(value=>value.kind===kind);}
test("job success preserves exact callback result and emits stable native attempt identity",async()=>{
 const client=new Client(jobSettings()),result={private:"CANARY_BODY"};let calls=0;
 try{
  expect(await client.withJobAttempt("fixture.task",RUN,Number.MAX_SAFE_INTEGER,async()=>{calls++;return result;})).toBe(result);expect(calls).toBe(1);
  const events=records(client),[started,terminal]=events.map(value=>value.payload);
  expect(events).toHaveLength(2);expect(events.map(value=>value.payload.state)).toEqual(["started","succeeded"]);
  expect(started.job_id).toBe(JOB);expect(started.run_id).toBe(RUN);expect(started.ordinal).toBe("9007199254740991");expect(started.attempt_id).toBe(terminal.attempt_id);expect(started.attempt_id).not.toBe("0".repeat(32));expect(started.producer_epoch).toBe(terminal.producer_epoch);expect(started.producer_epoch).not.toBe("0".repeat(32));expect([started.sequence,terminal.sequence]).toEqual(["1","2"]);
  expect(started.schedule_occurrence).toBe("manual."+RUN);expect(started.observed_ns).toBe("9007199254740993");expect(started.terminal_ns).toBeNull();expect(terminal.terminal_ns).toBe("9007199254740993");
  const bytes=client.bufferedRecords().join("");expect(bytes).not.toContain("fixture.task");expect(bytes).not.toContain("CANARY");expect(terminal.health).toBeUndefined();
 }finally{await client.close();}
});
test("job failure and cancellation retain thrown identity without reading thrown getters",async()=>{
 const client=new Client(jobSettings());let gets=0;const thrown=Object.defineProperties({}, {message:{get(){gets++;throw Error("CANARY_GETTER");}},name:{get(){gets++;throw Error("CANARY_GETTER");}}});
 try{
  await expect(client.withJobAttempt("fixture.task",RUN,1,async()=>{throw thrown;})).rejects.toBe(thrown);
  const failed=records(client).at(-1).payload,error=records(client,"error")[0];expect(failed.state).toBe("failed");expect(failed.cause_error).toBe(error.id);expect(error.payload.run_id).toBe(RUN);expect(gets).toBe(0);
  const aborted=new DOMException("CANARY_ABORT","AbortError");await expect(client.withJobAttempt("fixture.task",RUN,2,async()=>{throw aborted;})).rejects.toBe(aborted);
  expect(records(client).at(-1).payload.state).toBe("cancelled");expect(records(client).at(-1).payload.cause_error).toBeUndefined();
  client.captureException(Error("outside"));expect(records(client,"error").at(-1).payload.run_id).toBeUndefined();expect(client.bufferedRecords().join("")).not.toContain("CANARY");
 }finally{await client.close();}
});
test("invalid public arguments never enter the callback",async()=>{
 const client=new Client(jobSettings());let calls=0;
 try{
  for(const ordinal of [0,-1,1.5,NaN,Infinity,Number.MAX_SAFE_INTEGER+1,true,"1"]){await expect(client.withJobAttempt("fixture.task",RUN,ordinal as number,async()=>{calls++;})).rejects.toThrow();}
  for(const [job,run] of [["unknown",RUN],["fixture.task","0".repeat(32)],["fixture.task","B".repeat(32)]])await expect(client.withJobAttempt(job!,run!,1,async()=>{calls++;})).rejects.toThrow();
  expect(calls).toBe(0);expect(client.bufferedRecords()).toHaveLength(0);
 }finally{await client.close();}
});
test("registry is finite immutable and never invokes accessor values",async()=>{
 let gets=0;const accessors=Object.defineProperty({},"task",{enumerable:true,get(){gets++;throw Error("CANARY");}});
 for(const registry of [{task:"0".repeat(32)},{"private/path":JOB},accessors,Object.fromEntries(Array.from({length:1025},(_,i)=>["task"+i,JOB]))])expect(()=>new Client(jobSettings({jobRegistry:registry}))).toThrow();expect(gets).toBe(0);
 const registry={"fixture.task":JOB},client=new Client(jobSettings({jobRegistry:registry}));try{registry["fixture.task"]="c".repeat(32);await client.withJobAttempt("fixture.task",RUN,1,async()=>1);expect(records(client)[0].payload.job_id).toBe(JOB);}finally{await client.close();}
});
test("job signed/deployment denial and invalid clocks do not replace callback results",async()=>{
 for(const changes of [{deploymentJobs:false},{clockNs:()=>"invalid"},{maxRecords:1}]){
  const client=new Client(jobSettings(changes));const original=Error("CANARY");try{await expect(client.withJobAttempt("fixture.task",RUN,1,async()=>{throw original;})).rejects.toBe(original);if(changes.deploymentJobs===false)expect(records(client)).toHaveLength(0);expect(client.bufferedRecords().join("")).not.toContain("CANARY");}finally{await client.close();}
 }
});
test("closed native job validator rejects state/time/zero-ID and unsafe schedule mutations",async()=>{
 const client=new Client(jobSettings());try{await client.withJobAttempt("fixture.task",RUN,1,async()=>1);const payload=records(client)[0].payload;expect(normalizeAttempt(payload)).toEqual(payload);
  for(const changes of [{arguments:"CANARY"},{producer_epoch:"0".repeat(32)},{ordinal:"0"},{schedule_occurrence:"unsafe/path"},{schedule_occurrence:"manual.valid\n"},{schedule_occurrence:"a".repeat(257)},{terminal_ns:"1"},{state:"succeeded"},{state:"failed",terminal_ns:"1"}])expect(()=>normalizeAttempt({...payload,...changes})).toThrow();
 }finally{await client.close();}
});
test("old signed policies cannot authorize jobs through the errors bit",async()=>{
 const client=new Client(jobSettings({policy:config().policy}));
 try{const original=Error("CANARY");await expect(client.withJobAttempt("fixture.task",RUN,1,async()=>{throw original;})).rejects.toBe(original);expect(records(client)).toHaveLength(0);expect(records(client,"error")).toHaveLength(1);}finally{await client.close();}
});
test("retry IDs are distinct and terminal clock regression remains unknown rather than invented",async()=>{
 const client=new Client(jobSettings());
 try{await client.withJobAttempt("fixture.task",RUN,1,async()=>1);await client.withJobAttempt("fixture.task",RUN,2,async()=>2);const events=records(client).map(value=>value.payload);expect(events[0].attempt_id).not.toBe(events[2].attempt_id);expect(events[0].producer_epoch).toBe(events[2].producer_epoch);expect(events.map(value=>value.ordinal)).toEqual(["1","1","2","2"]);}finally{await client.close();}
 const clocks=["9007199254740993","9007199254740992"],regressed=new Client(jobSettings({clockNs:()=>clocks.shift()!}));
 try{expect(await regressed.withJobAttempt("fixture.task",RUN,1,async()=>7)).toBe(7);expect(records(regressed).map(value=>value.payload.state)).toEqual(["started"]);expect(regressed.diagnostics().job_clock_unavailable).toBe(1);}finally{await regressed.close();}
});
test("runtime cancellation calibration rejects generic or unavailable brands",async()=>{
 const trusted=(error:unknown)=>!types.isProxy(error)&&types.isNativeError(error);
 const generic=createTimerCancellationBoundary(()=>Promise.reject(Error()),()=>Promise.reject(TypeError()),trusted);
 expect(await generic(Error())).toBe(false);expect(await generic(TypeError())).toBe(false);
 const pending=Promise.withResolvers<void>(),unavailable=createTimerCancellationBoundary(()=>pending.promise,()=>Promise.reject(TypeError()),trusted);
 expect(await unavailable(Error())).toBe(false);pending.resolve();
});
test("terminal observation precedes asynchronous runtime classification",async()=>{
 let at="9007199254740993";const original=Error("CANARY"),client=new Client(jobSettings({clockNs:()=>at}),{isNativeError:types.isNativeError,isProxy:types.isProxy,timerCancellation:async()=>{await Promise.resolve();at="9007199254741993";return false;}});
 try{await expect(client.withJobAttempt("fixture.task",RUN,1,async()=>{throw original;})).rejects.toBe(original);expect(records(client).at(-1).payload.terminal_ns).toBe("9007199254740993");}finally{await client.close();}
});
test("failure ordinal 1 then success ordinal 2 retains both attempts and the failed terminal bytes never change",async()=>{
 const client=new Client(jobSettings()),original=Error("CANARY_TASK_FAILURE");
 try{
  await expect(client.withJobAttempt("fixture.task",RUN,1,async()=>{throw original;})).rejects.toBe(original);
  const failedBytes=client.bufferedRecords().filter(value=>JSON.parse(value).payload.state==="failed");expect(failedBytes).toHaveLength(1);
  expect(await client.withJobAttempt("fixture.task",RUN,2,async()=>"recovered")).toBe("recovered");
  const events=records(client).map(value=>value.payload);expect(events.map(value=>[value.ordinal,value.state])).toEqual([["1","started"],["1","failed"],["2","started"],["2","succeeded"]]);
  expect(new Set(events.map(value=>value.run_id))).toEqual(new Set([RUN]));expect(events[0].attempt_id).toBe(events[1].attempt_id);expect(events[1].attempt_id).not.toBe(events[2].attempt_id);expect(events.map(value=>value.sequence)).toEqual(["1","2","3","4"]);
  expect(client.bufferedRecords().filter(value=>JSON.parse(value).payload.state==="failed")).toEqual(failedBytes);
  expect(events[1].cause_error).toBeDefined();expect(events[3].cause_error).toBeUndefined();expect(client.bufferedRecords().join("")).not.toContain("CANARY");
 }finally{await client.close();}
});
test("an attempt inside an active span records the trace as a link and never creates or adopts a child span",async()=>{
 const client=new Client(jobSettings({operations:["worker"]}));let seen:unknown;
 try{
  await client.withSpan("worker",async()=>{await client.withJobAttempt("fixture.task",RUN,1,async()=>{seen=client.bufferedRecords().length;});});
  const spans=records(client,"span"),attempts=records(client).map(value=>value.payload);
  expect(spans).toHaveLength(1);expect(spans[0].payload.parent_span_id??null).toBeNull();
  expect(attempts.every(value=>value.cause_trace===spans[0].payload.trace_id)).toBe(true);
  expect(records(client,"span").some(value=>value.payload.operation==="fixture.task")).toBe(false);void seen;
 }finally{await client.close();}
});
