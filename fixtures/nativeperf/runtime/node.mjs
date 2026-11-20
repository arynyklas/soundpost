// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Task 04.09 Node runtime column. Run by fixtures/nativeperf/acceptance as: node node.mjs <seconds> [phases]
// Protocol: prints "ready <pid>", waits for "go" on stdin, runs a JS CPU loop, real loopback HTTP waits and (when
// SOUNDPOST_FIXTURE_DB_ADDR names a PostgreSQL server) real database waits, one `select pg_sleep(0.2)` after the other over
// the PostgreSQL wire protocol (pgwait.mjs), while the C09 supplement (packages/node/src/profile.ts, method
// runtime_engine_samples) profiles it, then prints ONE JSON line. The supplement's samples are V8 ENGINE samples: this
// runtime's separate comparison column, never native engine output and never OS CPU time. The native capture of this
// process is taken by the acceptance runner. phases is a comma list of cpu, http, db (default cpu,http: the runner takes the
// database wait in a capture of its own, so that neither capture holds more than the other's budget).
// The SDK module is compiled once with the pinned Bun (--target=node), exactly as fixtures/sdk/profiles/node.mjs does.
import {spawnSync} from "node:child_process";
import {existsSync,mkdtempSync,rmSync} from "node:fs";
import http from "node:http";
import {tmpdir} from "node:os";
import {dirname,join,resolve} from "node:path";
import {createInterface} from "node:readline";
import {fileURLToPath,pathToFileURL} from "node:url";
import {DB_DELAY_S,connectPg,databaseWait} from "./pgwait.mjs";

const here=fileURLToPath(import.meta.url),root=resolve(dirname(here),"../../..");
const seconds=Number(process.argv[2]);
const phases=new Set((process.argv[3]??"cpu,http").split(",").map((p)=>p.trim()).filter(Boolean));
const DB_REQUESTS=12;
const dbAddr=process.env.SOUNDPOST_FIXTURE_DB_ADDR??"";

function jsCpuLoop(milliseconds){
 const end=performance.now()+milliseconds;let x=0;
 while(performance.now()<end){for(let i=0;i<20000;i++)x+=Math.sqrt(i)*Math.sin(i);}
 return x;
}
function httpWait(server,port){
 return new Promise((resolveRequest,rejectRequest)=>{
  const started=performance.now();
  http.get({host:"127.0.0.1",port,agent:false},(response)=>{
   response.resume();
   response.on("end",()=>resolveRequest(performance.now()-started));
  }).on("error",rejectRequest);
 });
}
// the text of a failure without the address of the database
function scrub(error){return String(error?.message??error).replaceAll(dbAddr||"\u0000","<db>").replace(/\d+\.\d+\.\d+\.\d+(:\d+)?/g,"<ip>");}

const bunCandidates=[process.env.SOUNDPOST_BUN,"/opt/bun/bin/bun",join(root,".tools/bun-1.3.14/package/bin/bun")].filter(Boolean);
const bun=bunCandidates.find(existsSync);
if(!bun){console.error("the pinned Bun is required to compile the SDK module");process.exit(2);}
const out=mkdtempSync(join(tmpdir(),"soundpost-nativeperf-node-"));
const modulePath=join(out,"profile.mjs");
const built=spawnSync(bun,["build",join(root,"packages/node/src/profile.ts"),"--target=node","--format=esm","--outfile",modulePath],{cwd:root,encoding:"utf8"});
if(built.status!==0){console.error("bundle failed: "+built.stderr.slice(0,300));rmSync(out,{recursive:true,force:true});process.exit(2);}
const {startProfile}=await import(pathToFileURL(modulePath).href);
rmSync(out,{recursive:true,force:true});

// Everything that creates threads (server, inspector session, a warm-up request) or sockets (the database connection and
// its first statement) happens BEFORE the ready line: the native helper treats a thread creation or exit inside a live
// capture as a coverage change.
const server=http.createServer((request,response)=>{setTimeout(()=>{response.end("ok");},50);});
await new Promise((r)=>server.listen(0,"127.0.0.1",r));
const port=server.address().port;
const handle=await startProfile({durationMs:60000,intervalUs:1000,isolate:"main",projectRoot:root});
await httpWait(server,port);
let db=null;
let dbResult={status:"not_run",reason:phases.has("db")?"SOUNDPOST_FIXTURE_DB_ADDR is not set":"phase not requested"};
if(phases.has("db")&&dbAddr){
 try{db=await connectPg(dbAddr,{user:process.env.SOUNDPOST_FIXTURE_DB_USER||"postgres",database:process.env.SOUNDPOST_FIXTURE_DB_NAME||"postgres",password:process.env.SOUNDPOST_FIXTURE_DB_PASSWORD||""});}
 catch(error){dbResult={status:"error",reason:"database_unreachable: "+scrub(error)};}
}
console.log(`ready ${process.pid}`);
await new Promise((resolveGo)=>{const rl=createInterface({input:process.stdin});rl.once("line",(line)=>{rl.close();resolveGo(line);});});
let cpuSeconds=0;
if(phases.has("cpu")){
 const t0=performance.now();
 jsCpuLoop(seconds*600);
 cpuSeconds=(performance.now()-t0)/1000;
}
let waitAnnounced=false;
function announceWait(){ // CLOCK_MONOTONIC (uv_hrtime): the clock of the native scheduler events
 if(waitAnnounced)return;
 waitAnnounced=true;
 console.log(`wait_begin ${process.hrtime.bigint()}`); // the harness releases the loop thread's CPU-phase intervals at the source from here on
}
const sum=(a)=>a.reduce((x,y)=>x+y,0);
let httpResult={status:"not_run",reason:"phase not requested"};
if(phases.has("http")){
 const waits=[];
 const requests=Math.max(4,Math.floor(seconds*0.4/0.06));
 announceWait();
 const waitStartNs=process.hrtime.bigint();
 for(let i=0;i<requests;i++)waits.push(await httpWait(server,port));
 const waitEndNs=process.hrtime.bigint();
 httpResult={kind:"loopback HTTP (node:http server and client)",requests:waits.length,wait_seconds_total:sum(waits)/1000,wait_seconds_min:Math.min(...waits)/1000,server_delay_s:0.05,window_ns:[Number(waitStartNs),Number(waitEndNs)]};
}
if(db){
 try{
  announceWait();
  const windowStartNs=process.hrtime.bigint();
  const r=await databaseWait(db,DB_REQUESTS,()=>performance.now());
  const windowEndNs=process.hrtime.bigint();
  dbResult={kind:"PostgreSQL v3 simple query (pg_sleep) over node:net",server_version:db.params.server_version??"",requests:r.waitsMs.length,wait_seconds_total:sum(r.waitsMs)/1000,wait_seconds_min:Math.min(...r.waitsMs)/1000,server_delay_s:DB_DELAY_S,server_reported_s_total:sum(r.reportedS),window_ns:[Number(windowStartNs),Number(windowEndNs)]};
 }catch(error){dbResult={status:"error",reason:"database_failed: "+scrub(error)};}
}
// The supplement's helper thread exits when it stops, and the native helper ends a capture when a thread of its target
// exits. So the report waits: this line tells the runner the measured phase is over, the runner closes the native
// capture (its final proof needs a live, unchanged target) and then answers "exit".
console.log("done");
await new Promise((resolveExit)=>{const rl=createInterface({input:process.stdin});rl.once("line",(line)=>{rl.close();resolveExit(line);});});
if(db)db.close();
const report=await handle.stop();
server.close();
const leaves={};
for(const sample of report.samples){
 const frames=report.stacks[sample.stack].frames;
 const f=frames.length?report.frames[frames[0]]:null;
 const name=(f&&f.function)||"<external>";
 leaves[name]=(leaves[name]??0)+1;
}
console.log(JSON.stringify({
 runtime:"node",version:process.version,v8:process.versions.v8,arch:process.arch,executable:process.execPath,
 engine:{supplement:"packages/node/src/profile.ts startProfile (C09)",method:report.method,units:report.units,time_delta_unit:report.time_delta_unit,
  status:report.capability.status,reason:report.capability.reason,started:report.capability.status==="supported",sample_count:report.sample_count,
  leaf_samples:Object.fromEntries(Object.entries(leaves).sort((a,b)=>b[1]-a[1]).slice(0,8)),coverage:report.coverage,interval:report.interval,losses:report.losses,
  native_extension_work:"not_run: no native addon workload in this fixture"},
 cpu:{loop_seconds:cpuSeconds,function:"jsCpuLoop"},
 wait:{loop_tid:process.pid,http:httpResult,database:dbResult},
}));
process.exit(report.capability.status==="supported"&&report.sample_count>0?0:1);
