// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Compile this entrypoint with Bun --target=node, then execute that artifact in Node22 AND Node24.
import process from "node:process";
import {createRequire} from "node:module";
import {createServer} from "node:http";
import {once} from "node:events";
import {Worker,isMainThread,workerData,parentPort} from "node:worker_threads";
import {init} from "../../../packages/node/src/index.ts";
import {installExpress} from "../../../packages/node/src/express.ts";
import {installFetch} from "../../../packages/node/src/fetch.ts";
import {installPg} from "../../../packages/node/src/pg.ts";
import {installHttp} from "../../../packages/node/src/http.ts";
import {serializeWorkerContext,withWorkerContext} from "../../../packages/node/src/workers.ts";
import {loadConfig,safeRecords,verify,verifyReceipts,workerEnvironment} from "./support.mjs";
const require=createRequire(import.meta.url);
async function worker() {
 const config=loadConfig("SOUNDPOST_FIXTURE_WORKER_CONFIG"),client=init(config),start=String(BigInt(Date.now())*1000000n);
 try{await withWorkerContext(client,workerData,()=>client.withSpan("worker",async()=>{await Promise.resolve();if(client.traceContext().traceId!==workerData.trace_id)throw Error("worker_parent_missing");}));if(client.traceContext()!==undefined)throw Error("worker_context_leaked");await client.withSpan("worker.unrelated",async()=>{if(client.traceContext().traceId===workerData.trace_id)throw Error("unrelated_worker_trace_inherited");});const records=safeRecords(client),report=await client.flush(10000);parentPort.postMessage({worker_verified:true,records,report,start_ns:start,end_ns:String(BigInt(Date.now())*1000000n)});}finally{await client.close();}
}
async function main() {
 if(!/^v(?:22|24)\./.test(process.version))throw Error("node22_or24_required");const config=loadConfig(),client=init(config),dsn=process.env.SOUNDPOST_FIXTURE_DATABASE_URL,dependency=process.env.SOUNDPOST_FIXTURE_DEPENDENCY_URL;if(!dsn||!dependency||new URL(dependency).protocol!=="https:")throw Error("private_real_dependencies_required");const express=require("express"),{Pool}=require("pg"),pool=new Pool({connectionString:dsn}),routes=installExpress(client),outbound=installFetch(client,{operation:"http.call",origins:[{origin:new URL(dependency).origin,dependency:"dependency"}]}),database=installPg(client,{operation:"db.execute",dependency:"postgres"}),app=express(),start=String(BigInt(Date.now())*1000000n);
 const http=installHttp(client,{operation:"http.call",origins:[{origin:new URL(dependency).origin,dependency:"dependency"}]});
 const httpCall=()=>{const gate=Promise.withResolvers();let status=0,complete=false;const request=http.request(dependency,{},response=>{status=response.statusCode;response.once("end",()=>{complete=true;});response.once("error",gate.reject);response.resume();});request.once("error",gate.reject);request.once("close",()=>{if(!complete||status<200||status>=300)gate.reject(Error("real_dependency_failed"));else gate.resolve();});request.end();return gate.promise;};
 app.use((req,res,next)=>{const origin=process.env.SOUNDPOST_FIXTURE_BROWSER_ORIGIN;if(origin&&req.headers.origin===origin){res.setHeader("access-control-allow-origin",origin);res.setHeader("access-control-allow-headers","traceparent,x-soundpost-context,content-type,x-canary");res.setHeader("access-control-allow-methods","GET,OPTIONS");}if(req.method==="OPTIONS"){res.status(204).end();return;}next();});
 app.get("/critical",routes.handler("request",async(_request,response)=>{await Promise.all([outbound.fetch(dependency).then(async reply=>{if(!reply.ok)throw Error("real_dependency_failed");await reply.arrayBuffer();}),httpCall()]);const rows=await database.query(pool,"SELECT $1::integer AS answer /* CANARY_SQL */",[42]);if(rows.rows[0].answer!==42)throw Error("database_result_changed");try{await database.query(pool,"SELECT 1/0 /* CANARY_SQL_ERROR */");throw Error("database_error_missing");}catch(error){if(error.code!=="22012")throw error;}const controller=new AbortController();controller.abort();try{await outbound.fetch(dependency,{signal:controller.signal});throw Error("cancel_missing");}catch(error){if(!controller.signal.aborted)throw error;}response.status(201);response.write("critical-");response.end("ok");}));
 app.use((_error,_request,response,_next)=>response.status(503).end("application-error"));const server=createServer(app);server.listen(Number(process.env.SOUNDPOST_FIXTURE_NODE_PORT??0),"127.0.0.1");await once(server,"listening");const address=server.address(),origin=`http://127.0.0.1:${address.port}`;
 try{
  if(process.argv.includes("--serve")){console.log(JSON.stringify({fixture:"node_browser_backend_ready",origin,runtime:process.version}));await once(process,"SIGTERM");}
  else{const reply=await fetch(origin+"/critical?CANARY_URL");if(reply.status!==201||await reply.text()!=="critical-ok")throw Error("application_behavior_changed");await client.withSpan("worker",async()=>{const child=new Worker(new URL(import.meta.url),{workerData:serializeWorkerContext(client.traceContext()),env:workerEnvironment()});const exited=once(child,"exit"),[result]=await once(child,"message");const [exit]=await exited;if(exit!==0||result.worker_verified!==true)throw Error("worker_fixture_failed");await verifyReceipts(result.report,loadConfig("SOUNDPOST_FIXTURE_WORKER_CONFIG"),result.records,result.start_ns,result.end_ns);});}
  const expected=safeRecords(client),result=await verify(client,config,expected,start,String(BigInt(Date.now())*1000000n));const spans=expected.filter(record=>record.kind==="span").map(record=>record.payload);if(!spans.some(span=>span.span_kind==="server")||!spans.some(span=>span.dependency_alias==="postgres")||!spans.some(span=>span.status==="cancelled"))throw Error("critical_path_missing");console.log(JSON.stringify({fixture:"node_real_critical_path",runtime:process.version,...result,admitted_records_verified:true,tls_verified:true,internal_dependency:"unobserved"}));
 }finally{server.closeAllConnections();server.close();routes.close();http.close();outbound.close();database.close();await pool.end();await client.close();}
}
try{if(isMainThread)await main();else await worker();}catch{process.stderr.write("critical_path_fixture_failed\n");process.exitCode=1;}
