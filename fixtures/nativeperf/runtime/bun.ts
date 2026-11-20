// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Task 04.09 Bun runtime column. Run by fixtures/nativeperf/acceptance as: bun bun.ts <seconds> [phases]
// Protocol: prints "ready <pid>", waits for "go" on stdin, runs a JS CPU loop, real loopback HTTP waits (Bun.serve +
// fetch) and (when SOUNDPOST_FIXTURE_DB_ADDR names a PostgreSQL server) real database waits, one `select pg_sleep(0.2)`
// after the other over the PostgreSQL wire protocol on Bun.connect (pgwait.ts), while the C09 supplement
// (packages/bun/src/profile.ts, method runtime_engine_samples) profiles it, then prints ONE JSON line. These are
// JavaScriptCore ENGINE samples: Bun's own separate comparison column. A Node result never qualifies Bun, and these
// samples are never native engine output or OS CPU time. The native capture of this process is taken by the acceptance
// runner. phases is a comma list of cpu, http, db (default cpu,http: the runner takes the database wait in a capture of its
// own, so that neither capture holds more than the other's budget, and the whole run ends before JavaScriptCore's idle helper
// threads time out, which the native helper reports as a coverage change).
import {createInterface} from "node:readline";
import {resolve} from "node:path";
import {startProfile} from "../../../packages/bun/src/profile.ts";
import {dlopen,FFIType,ptr} from "bun:ffi";
import {DB_DELAY_S,connectPg,databaseWait,type PgClient} from "./pgwait.ts";

// Bun's process.hrtime.bigint() counts from the start of the process, not from CLOCK_MONOTONIC (the clock of the native
// scheduler events), so the wait window is read from libc's clock_gettime(CLOCK_MONOTONIC) itself. Opened before the
// ready line like everything else that may create a thread.
const libc=dlopen("libc.so.6",{clock_gettime:{args:[FFIType.i32,FFIType.ptr],returns:FFIType.i32}});
const timespec=new BigInt64Array(2);
function monotonicNs():bigint{libc.symbols.clock_gettime(1,ptr(timespec));return timespec[0]*1000000000n+timespec[1];}

const root=resolve(import.meta.dir,"../../..");
const seconds=Number(process.argv[2]);
const phases=new Set((process.argv[3]??"cpu,http").split(",").map((p)=>p.trim()).filter(Boolean));
const DB_REQUESTS=12;
const dbAddr=process.env.SOUNDPOST_FIXTURE_DB_ADDR??"";

function jsCpuLoop(milliseconds:number):number{
 const end=performance.now()+milliseconds;let x=0;
 while(performance.now()<end){for(let i=0;i<20000;i++)x+=Math.sqrt(i)*Math.sin(i);}
 return x;
}
// the text of a failure without the address of the database
function scrub(error:unknown):string{return String((error as Error)?.message??error).replaceAll(dbAddr||"\u0000","<db>").replace(/\d+\.\d+\.\d+\.\d+(:\d+)?/g,"<ip>");}

// Everything that creates threads (server, profiler, a warm-up fetch that starts Bun's HTTP client thread) or sockets (the
// database connection and its first statement) happens BEFORE the ready line: the native helper treats a thread creation
// or exit inside a live capture as a coverage change.
const server=Bun.serve({port:0,hostname:"127.0.0.1",async fetch(){await new Promise((r)=>setTimeout(r,50));return new Response("ok");}});
const handle=await startProfile({durationMs:60000,intervalUs:1000,isolate:"main",projectRoot:root});
await (await fetch(`http://127.0.0.1:${server.port}/`)).text();
let db:PgClient|null=null;
let dbResult:Record<string,unknown>={status:"not_run",reason:phases.has("db")?"SOUNDPOST_FIXTURE_DB_ADDR is not set":"phase not requested"};
if(phases.has("db")&&dbAddr){
 try{db=await connectPg(dbAddr,{user:process.env.SOUNDPOST_FIXTURE_DB_USER||"postgres",database:process.env.SOUNDPOST_FIXTURE_DB_NAME||"postgres",password:process.env.SOUNDPOST_FIXTURE_DB_PASSWORD||""});}
 catch(error){dbResult={status:"error",reason:"database_unreachable: "+scrub(error)};}
}
console.log(`ready ${process.pid}`);
await new Promise<string>((resolveGo)=>{const rl=createInterface({input:process.stdin});rl.once("line",(line)=>{rl.close();resolveGo(line);});});
let cpuSeconds=0;
if(phases.has("cpu")){
 const t0=performance.now();
 jsCpuLoop(seconds*600);
 cpuSeconds=(performance.now()-t0)/1000;
}
let waitAnnounced=false;
function announceWait():void{ // CLOCK_MONOTONIC: the clock of the native scheduler events
 if(waitAnnounced)return;
 waitAnnounced=true;
 console.log(`wait_begin ${monotonicNs()}`); // the harness releases the loop thread's CPU-phase intervals at the source from here on
}
const sum=(a:number[])=>a.reduce((x,y)=>x+y,0);
let httpResult:Record<string,unknown>={status:"not_run",reason:"phase not requested"};
if(phases.has("http")){
 const waits:number[]=[];
 const requests=Math.max(4,Math.floor(seconds*0.4/0.06));
 announceWait();
 const waitStartNs=monotonicNs();
 for(let i=0;i<requests;i++){
  const started=performance.now();
  const response=await fetch(`http://127.0.0.1:${server.port}/`);
  await response.text();
  waits.push(performance.now()-started);
 }
 const waitEndNs=monotonicNs();
 httpResult={kind:"loopback HTTP (Bun.serve and fetch)",requests:waits.length,wait_seconds_total:sum(waits)/1000,wait_seconds_min:Math.min(...waits)/1000,server_delay_s:0.05,window_ns:[Number(waitStartNs),Number(waitEndNs)]};
}
if(db){
 try{
  announceWait();
  const windowStartNs=monotonicNs();
  const r=await databaseWait(db,DB_REQUESTS,()=>performance.now());
  const windowEndNs=monotonicNs();
  dbResult={kind:"PostgreSQL v3 simple query (pg_sleep) over Bun.connect",server_version:db.params.server_version??"",requests:r.waitsMs.length,wait_seconds_total:sum(r.waitsMs)/1000,wait_seconds_min:Math.min(...r.waitsMs)/1000,server_delay_s:DB_DELAY_S,server_reported_s_total:sum(r.reportedS),window_ns:[Number(windowStartNs),Number(windowEndNs)]};
 }catch(error){dbResult={status:"error",reason:"database_failed: "+scrub(error)};}
}
// The supplement may start or stop helper threads when it stops, and the native helper ends a capture when a thread of
// its target comes or goes. So the report waits: this line tells the runner the measured phase is over, the runner
// closes the native capture (its final proof needs a live, unchanged target) and then answers "exit".
console.log("done");
await new Promise<string>((resolveExit)=>{const rl=createInterface({input:process.stdin});rl.once("line",(line)=>{rl.close();resolveExit(line);});});
db?.close();
const report=await handle.stop();
server.stop(true);
const leaves:Record<string,number>={};
for(const sample of report.samples){
 const frames=report.stacks[sample.stack].frames;
 const f=frames.length?report.frames[frames[0]]:null;
 const name=(f&&f.function)||"<external>";
 leaves[name]=(leaves[name]??0)+1;
}
console.log(JSON.stringify({
 runtime:"bun",version:Bun.version,revision:Bun.revision,arch:process.arch,executable:process.execPath,
 engine:{supplement:"packages/bun/src/profile.ts startProfile (C09)",method:report.method,units:report.units,time_delta_unit:report.time_delta_unit,
  status:report.capability.status,reason:report.capability.reason,started:report.capability.status==="supported",sample_count:report.sample_count,
  leaf_samples:Object.fromEntries(Object.entries(leaves).sort((a,b)=>b[1]-a[1]).slice(0,8)),coverage:report.coverage,interval:report.interval,losses:report.losses,
  native_extension_work:"not_run: no native addon workload in this fixture"},
 cpu:{loop_seconds:cpuSeconds,function:"jsCpuLoop"},
 wait:{loop_tid:process.pid,http:httpResult,database:dbResult},
}));
process.exit(report.capability.status==="supported"&&report.sample_count>0?0:1);
