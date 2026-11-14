// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Task 04.09 Bun runtime column. Run by fixtures/nativeperf/acceptance as: bun bun.ts <seconds>
// Protocol: prints "ready <pid>", waits for "go" on stdin, runs a JS CPU loop and real loopback HTTP waits (Bun.serve +
// fetch) while the C09 supplement (packages/bun/src/profile.ts, method runtime_engine_samples) profiles it, then prints
// ONE JSON line. These are JavaScriptCore ENGINE samples: Bun's own separate comparison column. A Node result never
// qualifies Bun, and these samples are never native engine output or OS CPU time. The native capture of this process is
// taken by the acceptance runner.
import {createInterface} from "node:readline";
import {resolve} from "node:path";
import {startProfile} from "../../../packages/bun/src/profile.ts";

const root=resolve(import.meta.dir,"../../..");
const seconds=Number(process.argv[2]);

function jsCpuLoop(milliseconds:number):number{
 const end=performance.now()+milliseconds;let x=0;
 while(performance.now()<end){for(let i=0;i<20000;i++)x+=Math.sqrt(i)*Math.sin(i);}
 return x;
}

// Everything that creates threads (server, profiler, a warm-up fetch that starts Bun's HTTP client thread) happens BEFORE
// the ready line: the native helper treats a thread creation or exit inside a live capture as a coverage change.
const server=Bun.serve({port:0,hostname:"127.0.0.1",async fetch(){await new Promise((r)=>setTimeout(r,50));return new Response("ok");}});
const handle=await startProfile({durationMs:60000,intervalUs:1000,isolate:"main",projectRoot:root});
await (await fetch(`http://127.0.0.1:${server.port}/`)).text();
console.log(`ready ${process.pid}`);
await new Promise<string>((resolveGo)=>{const rl=createInterface({input:process.stdin});rl.once("line",(line)=>{rl.close();resolveGo(line);});});
const t0=performance.now();
jsCpuLoop(seconds*600);
const cpuSeconds=(performance.now()-t0)/1000;
const waits:number[]=[];
const requests=Math.max(4,Math.floor(seconds*0.4/0.06));
for(let i=0;i<requests;i++){
 const started=performance.now();
 const response=await fetch(`http://127.0.0.1:${server.port}/`);
 await response.text();
 waits.push(performance.now()-started);
}
const report=await handle.stop();
server.stop(true);
const leaves:Record<string,number>={};
for(const sample of report.samples){
 const frames=report.stacks[sample.stack].frames;
 const f=frames.length?report.frames[frames[0]]:null;
 const name=(f&&f.function)||"<external>";
 leaves[name]=(leaves[name]??0)+1;
}
const sum=(a:number[])=>a.reduce((x,y)=>x+y,0);
console.log(JSON.stringify({
 runtime:"bun",version:Bun.version,revision:Bun.revision,arch:process.arch,executable:process.execPath,
 engine:{supplement:"packages/bun/src/profile.ts startProfile (C09)",method:report.method,units:report.units,time_delta_unit:report.time_delta_unit,
  status:report.capability.status,reason:report.capability.reason,started:report.capability.status==="supported",sample_count:report.sample_count,
  leaf_samples:Object.fromEntries(Object.entries(leaves).sort((a,b)=>b[1]-a[1]).slice(0,8)),coverage:report.coverage,interval:report.interval,losses:report.losses,
  native_extension_work:"not_run: no native addon workload in this fixture"},
 cpu:{loop_seconds:cpuSeconds,function:"jsCpuLoop"},
 wait:{kind:"loopback HTTP (Bun.serve and fetch)",requests:waits.length,wait_seconds_total:sum(waits)/1000,wait_seconds_min:Math.min(...waits)/1000,server_delay_s:0.05,
  database_wait:"not_run: no database engine in this fixture"},
}));
process.exit(report.capability.status==="supported"&&report.sample_count>0?0:1);
