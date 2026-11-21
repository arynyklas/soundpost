// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Server capture cost, wave 23: every enabled AsyncLocalStorage store is visited by the runtime for each async resource the process creates, so a client holds ONE store for
// its trace scope, its job scope and its exporter-recursion scope. This pins that (the number of distinct stores used) and that the three scopes stay independent.
import {test,expect} from "bun:test";
import {AsyncLocalStorage} from "node:async_hooks";
import {init} from "../src/index.ts";
import {createMetadataContext} from "../src/context.ts";
import {jobSettings} from "../../core/test/jobs-fixture.ts";
const receipt=(batch:{id:string;hash:string;kinds:string[]})=>({version:1,batch_id:batch.id,hash:batch.hash,cursor:{group:"9".repeat(32),index:"1"},retain_until_ns:"9007199254740994",signal_deadlines:batch.kinds.map(kind=>({kind,retain_until_ns:"9007199254740994"})),dedup_until_ns:"9007199254740995"});
test("a client uses one AsyncLocalStorage store for trace, job and exporter scopes",async()=>{
 const used=new Set<unknown>(),run=AsyncLocalStorage.prototype.run,get=AsyncLocalStorage.prototype.getStore;
 AsyncLocalStorage.prototype.run=function(this:unknown,...args:Parameters<typeof run>){used.add(this);return Reflect.apply(run,this,args);} as typeof run;
 AsyncLocalStorage.prototype.getStore=function(this:unknown){used.add(this);return Reflect.apply(get,this,[]);} as typeof get;
 const transport={async send(batch:{id:string;hash:string;kinds:string[]}){return {kind:"receipt",receipt:receipt(batch)};},async lookup(){return {kind:"not_found"};},close(){}};
 const client=init(jobSettings({operations:["request"],transport:transport as never}));
 try{
  await client.withSpan("request",async()=>{await client.withJobAttempt("fixture.task","d".repeat(32),1,async()=>{await Promise.resolve();client.captureException(new Error("CANARY"));});});
  await client.flush();
 }finally{AsyncLocalStorage.prototype.run=run;AsyncLocalStorage.prototype.getStore=get;await client.close();}
 expect(used.size).toBe(1);
});
test("trace, job and exporter scopes are independent in one store: each run keeps the others and restores on exit", async()=>{
 const client=init(jobSettings({operations:["request"]}));
 try{
  expect(client.traceContext()).toBeUndefined();
  await client.withSpan("request",async()=>{
   const outer=client.traceContext();expect(outer).toBeDefined();
   await client.withJobAttempt("fixture.task","d".repeat(32),1,async()=>{await Promise.resolve();expect(client.traceContext()).toBe(outer);});
   expect(client.traceContext()).toBe(outer);
  });
  expect(client.traceContext()).toBeUndefined();
 }finally{await client.close();}
 const scopes=createMetadataContext(),trace={traceId:"1".repeat(32),spanId:"2".repeat(16),sampled:true,probability:"ffffffffffffffff"} as never,job={jobId:"a".repeat(32),runId:"b".repeat(32),attemptId:"c".repeat(32)} as never;
 expect(scopes.current()).toBeUndefined();expect(scopes.jobCurrent()).toBeUndefined();
 scopes.run(trace,()=>{expect(scopes.current()).toBe(trace);expect(scopes.jobCurrent()).toBeUndefined();scopes.runJob(job,()=>{expect(scopes.current()).toBe(trace);expect(scopes.jobCurrent()).toBe(job);scopes.run(undefined,()=>{expect(scopes.current()).toBeUndefined();expect(scopes.jobCurrent()).toBe(job);});});expect(scopes.jobCurrent()).toBeUndefined();});
 expect(scopes.current()).toBeUndefined();
 scopes.close();
});
