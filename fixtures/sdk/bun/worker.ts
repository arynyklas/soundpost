// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {writeSync} from "node:fs";
import {init} from "../../../packages/bun/src/index.ts";
import {withWorkerContext} from "../../../packages/bun/src/workers.ts";
import {loadConfig,safeRecords} from "../node/support.mjs";
type Phase="module.loaded"|"message"|"config.before"|"config.loaded"|"client.before"|"client.ready"|"parent.before"|"parent.after"|"unrelated.before"|"unrelated.after"|"records.before"|"flush.before"|"flush.after"|"reply.before"|"reply.after"|"failed"|"cleanup.client.before"|"cleanup.client.after"|"cleanup.process.exit";
/** Only fixed codes reach synchronous stderr; worker messages/configuration never do. */
function phase(step:Phase):void{try{writeSync(2,"SOUNDPOST_FIXTURE_PHASE worker."+step+"\n");}catch{/* Diagnostic I/O must not alter the worker contract. */}}
phase("module.loaded");
if(Bun.isMainThread)throw Error("worker_process_required");
const scope=globalThis as unknown as {onmessage:(event:MessageEvent)=>void;postMessage:(value:unknown)=>void};
scope.onmessage=async(event:MessageEvent):Promise<void>=>{
 phase("message");phase("config.before");const config=loadConfig("SOUNDPOST_FIXTURE_WORKER_CONFIG");phase("config.loaded");
 phase("client.before");const client=init(config),start=String(BigInt(Date.now())*1000000n);phase("client.ready");
 try{
  phase("parent.before");
  await withWorkerContext(client,event.data,()=>client.withSpan("worker",async()=>{await Promise.resolve();if(client.traceContext()!.traceId!==event.data.trace_id)throw Error("worker_parent_missing");}));phase("parent.after");
  if(client.traceContext()!==undefined)throw Error("worker_context_leaked");phase("unrelated.before");
  await client.withSpan("worker.unrelated",async()=>{if(client.traceContext()!.traceId===event.data.trace_id)throw Error("worker_unrelated_inherited");});phase("unrelated.after");
  phase("records.before");const records=safeRecords(client);
  phase("flush.before");const report=await client.flush(10000);phase("flush.after");
  phase("reply.before");scope.postMessage({worker_verified:true,records,report,start_ns:start,end_ns:String(BigInt(Date.now())*1000000n)});phase("reply.after");
 }catch{phase("failed");scope.postMessage({worker_verified:false});}
 finally{phase("cleanup.client.before");await client.close();phase("cleanup.client.after");phase("cleanup.process.exit");process.exit(0);}
};
