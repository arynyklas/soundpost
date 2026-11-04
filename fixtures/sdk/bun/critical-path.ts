// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {createRequire} from "node:module";
import {writeSync} from "node:fs";
import {init} from "../../../packages/bun/src/index.ts";
import {installServe} from "../../../packages/bun/src/serve.ts";
import {installFetch} from "../../../packages/bun/src/fetch.ts";
import {installPg} from "../../../packages/bun/src/pg.ts";
import {serializeWorkerContext} from "../../../packages/bun/src/workers.ts";
import {loadConfig,safeRecords,verifyReceipts,workerEnvironment} from "../node/support.mjs";
type Phase=
 |"module.loaded"|"start"|"config.before"|"config.loaded"|"client.before"|"client.ready"|"dependencies.before"|"dependencies.ready"
 |"serve.before"|"serve.ready"|"http.before"|"http.headers"|"http.body.verified"|"server.request"|"dependency.before"|"dependency.headers"|"dependency.bodies"
 |"pg.query.before"|"pg.query.after"|"pg.error.before"|"pg.error.after"|"fetch.cancel.before"|"fetch.cancel.after"|"server.stream.start"|"server.stream.close"
 |"worker.span.before"|"worker.construct.before"|"worker.construct.after"|"worker.post.before"|"worker.post.after"|"worker.message"|"worker.readback.before"|"worker.readback.after"|"worker.close.observed"|"worker.close.before"|"worker.close.after"|"worker.terminate.before"|"worker.terminate.after"
 |"records.before"|"records.verified"|"flush.before"|"flush.after"|"readback.before"|"readback.after"|"cleanup.server.before"|"cleanup.server.after"|"cleanup.pg.before"|"cleanup.pg.after"|"cleanup.client.before"|"cleanup.client.after"|"failed";
/** Fixed phase codes only: never inspect or stringify fixture inputs or failures. */
function phase(step:Phase):void{try{writeSync(2,"SOUNDPOST_FIXTURE_PHASE main."+step+"\n");}catch{/* Diagnostic I/O must not replace acceptance behavior. */}}
phase("module.loaded");
async function main():Promise<void>{
 phase("start");
 if(Bun.version!=="1.3.14")throw Error("pinned_bun_required");
 phase("config.before");const config=loadConfig();phase("config.loaded");
 phase("client.before");const client=init(config);phase("client.ready");
 const dsn=process.env.SOUNDPOST_FIXTURE_DATABASE_URL,dependency=process.env.SOUNDPOST_FIXTURE_DEPENDENCY_URL;
 if(!dsn||!dependency||new URL(dependency).protocol!=="https:")throw Error("real_dependencies_required");
 phase("dependencies.before");
 const require=createRequire(import.meta.url),{Pool}=require("pg") as {Pool:new(options:unknown)=>any},pool=new Pool({connectionString:dsn}),outbound=installFetch(client,{operation:"http.call",origins:[{origin:new URL(dependency).origin,dependency:"dependency"}]}),pg=installPg(client,{operation:"db.execute",dependency:"postgres"}),serve=installServe(client,{operation:"request"}),start=String(BigInt(Date.now())*1000000n);
 phase("dependencies.ready");phase("serve.before");
 const server=Bun.serve({hostname:"127.0.0.1",port:0,fetch:serve.handler(async()=>{
  phase("server.request");phase("dependency.before");
  const replies=await Promise.all([outbound.fetch(dependency),outbound.fetch(dependency)]);phase("dependency.headers");
  for(const reply of replies){if(!reply.ok)throw Error("real_dependency_failed");await reply.arrayBuffer();}phase("dependency.bodies");
  phase("pg.query.before");const result=await pg.query<{answer:number}>(pool,"SELECT $1::integer AS answer /* CANARY_SQL */",[42]);phase("pg.query.after");
  if(result.rows[0]?.answer!==42)throw Error("database_result_changed");
  phase("pg.error.before");
  try{await pg.query(pool,"SELECT 1/0 /* CANARY_SQL_ERROR */");throw Error("database_error_missing");}catch(error){if(!error||typeof error!=="object"||!("code" in error)||error.code!=="22012")throw error;}phase("pg.error.after");
  phase("fetch.cancel.before");const cancel=new AbortController();cancel.abort();
  try{await outbound.fetch(dependency,{signal:cancel.signal});throw Error("cancel_missing");}catch{if(!cancel.signal.aborted)throw Error("cancel_not_preserved");}phase("fetch.cancel.after");
  return new Response(new ReadableStream({start(controller){phase("server.stream.start");controller.enqueue(new TextEncoder().encode("critical-"));queueMicrotask(()=>{controller.enqueue(new TextEncoder().encode("ok"));controller.close();phase("server.stream.close");});}}),{status:201});
 }),error(){return new Response("application-error",{status:503});}});
 phase("serve.ready");
 try{
  phase("http.before");const response=await fetch(server.url);phase("http.headers");
  if(response.status!==201||await response.text()!=="critical-ok")throw Error("application_behavior_changed");phase("http.body.verified");
  phase("worker.span.before");
  await client.withSpan("worker",async()=>{
   phase("worker.construct.before");const worker=new Worker(new URL("./worker.ts",import.meta.url).href,{env:workerEnvironment()});phase("worker.construct.after");
   const gate=Promise.withResolvers<MessageEvent>(),closed=Promise.withResolvers<number>();let workerClosed=false,replySeen=false;
   worker.onmessage=event=>{replySeen=true;gate.resolve(event);};worker.onerror=gate.reject;
   worker.addEventListener("close",event=>{workerClosed=true;phase("worker.close.observed");closed.resolve(event.code);if(!replySeen)gate.reject(Error("worker_closed_before_reply"));},{once:true});
   phase("worker.post.before");worker.postMessage(serializeWorkerContext(client.traceContext()!));phase("worker.post.after");
   try{const reply=await gate.promise;phase("worker.message");if(reply.data.worker_verified!==true)throw Error("worker_fixture_failed");
    phase("worker.readback.before");await verifyReceipts(reply.data.report,loadConfig("SOUNDPOST_FIXTURE_WORKER_CONFIG"),reply.data.records,reply.data.start_ns,reply.data.end_ns);phase("worker.readback.after");
    phase("worker.close.before");const exit=await closed.promise;phase("worker.close.after");if(exit!==0)throw Error("worker_exit_not_zero");
   }finally{if(!workerClosed){phase("worker.terminate.before");worker.terminate();phase("worker.terminate.after");await closed.promise;}}
  });
  phase("records.before");const expected=safeRecords(client),spans=expected.filter((record:any)=>record.kind==="span").map((record:any)=>record.payload);
  if(!spans.some((span:any)=>span.span_kind==="server")||!spans.some((span:any)=>span.dependency_alias==="postgres")||!spans.some((span:any)=>span.status==="cancelled"))throw Error("critical_path_missing");phase("records.verified");
  phase("flush.before");const endNs=String(BigInt(Date.now())*1000000n),report=await client.flush(10000);phase("flush.after");
  phase("readback.before");const result=await verifyReceipts(report,config,expected,start,endNs);phase("readback.after");
  console.log(JSON.stringify({fixture:"bun_real_critical_path",runtime:Bun.version,...result,admitted_records_verified:true,tls_verified:true,internal_dependency:"unobserved"}));
 }finally{
  phase("cleanup.server.before");server.stop(true);serve.close();pg.close();outbound.close();phase("cleanup.server.after");
  phase("cleanup.pg.before");await pool.end();phase("cleanup.pg.after");
  phase("cleanup.client.before");await client.close();phase("cleanup.client.after");
 }
}
try{await main();}catch{phase("failed");process.stderr.write("critical_path_fixture_failed\n");process.exitCode=1;}
