// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Task 04.09 Node runtime column. Run by fixtures/nativeperf/acceptance as: node node.mjs <seconds>
// Protocol: prints "ready <pid>", waits for "go" on stdin, runs a JS CPU loop and real loopback HTTP waits while the
// C09 supplement (packages/node/src/profile.ts, method runtime_engine_samples) profiles it, then prints ONE JSON
// line. The supplement's samples are V8 ENGINE samples: this runtime's separate comparison column, never native
// engine output and never OS CPU time. The native capture of this process is taken by the acceptance runner.
// The SDK module is compiled once with the pinned Bun (--target=node), exactly as fixtures/sdk/profiles/node.mjs does.
import {spawnSync} from "node:child_process";
import {existsSync,mkdtempSync,rmSync} from "node:fs";
import http from "node:http";
import {tmpdir} from "node:os";
import {dirname,join,resolve} from "node:path";
import {createInterface} from "node:readline";
import {fileURLToPath,pathToFileURL} from "node:url";

const here=fileURLToPath(import.meta.url),root=resolve(dirname(here),"../../..");
const seconds=Number(process.argv[2]);

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

const bunCandidates=[process.env.SOUNDPOST_BUN,"/opt/bun/bin/bun",join(root,".tools/bun-1.3.14/package/bin/bun")].filter(Boolean);
const bun=bunCandidates.find(existsSync);
if(!bun){console.error("the pinned Bun is required to compile the SDK module");process.exit(2);}
const out=mkdtempSync(join(tmpdir(),"soundpost-nativeperf-node-"));
const modulePath=join(out,"profile.mjs");
const built=spawnSync(bun,["build",join(root,"packages/node/src/profile.ts"),"--target=node","--format=esm","--outfile",modulePath],{cwd:root,encoding:"utf8"});
if(built.status!==0){console.error("bundle failed: "+built.stderr.slice(0,300));rmSync(out,{recursive:true,force:true});process.exit(2);}
const {startProfile}=await import(pathToFileURL(modulePath).href);
rmSync(out,{recursive:true,force:true});

// Everything that creates threads (server, inspector session, a warm-up request) happens BEFORE the ready line: the
// native helper treats a thread creation or exit inside a live capture as a coverage change.
const server=http.createServer((request,response)=>{setTimeout(()=>{response.end("ok");},50);});
await new Promise((r)=>server.listen(0,"127.0.0.1",r));
const port=server.address().port;
const handle=await startProfile({durationMs:60000,intervalUs:1000,isolate:"main",projectRoot:root});
await httpWait(server,port);
console.log(`ready ${process.pid}`);
await new Promise((resolveGo)=>{const rl=createInterface({input:process.stdin});rl.once("line",(line)=>{rl.close();resolveGo(line);});});
const t0=performance.now();
jsCpuLoop(seconds*600);
const cpuSeconds=(performance.now()-t0)/1000;
const waits=[];
const requests=Math.max(4,Math.floor(seconds*0.4/0.06));
for(let i=0;i<requests;i++)waits.push(await httpWait(server,port));
const report=await handle.stop();
server.close();
const leaves={};
for(const sample of report.samples){
 const frames=report.stacks[sample.stack].frames;
 const f=frames.length?report.frames[frames[0]]:null;
 const name=(f&&f.function)||"<external>";
 leaves[name]=(leaves[name]??0)+1;
}
const sum=(a)=>a.reduce((x,y)=>x+y,0);
console.log(JSON.stringify({
 runtime:"node",version:process.version,v8:process.versions.v8,arch:process.arch,executable:process.execPath,
 engine:{supplement:"packages/node/src/profile.ts startProfile (C09)",method:report.method,units:report.units,time_delta_unit:report.time_delta_unit,
  status:report.capability.status,reason:report.capability.reason,started:report.capability.status==="supported",sample_count:report.sample_count,
  leaf_samples:Object.fromEntries(Object.entries(leaves).sort((a,b)=>b[1]-a[1]).slice(0,8)),coverage:report.coverage,interval:report.interval,losses:report.losses,
  native_extension_work:"not_run: no native addon workload in this fixture"},
 cpu:{loop_seconds:cpuSeconds,function:"jsCpuLoop"},
 wait:{kind:"loopback HTTP (node:http server and client)",requests:waits.length,wait_seconds_total:sum(waits)/1000,wait_seconds_min:Math.min(...waits)/1000,server_delay_s:0.05,
  database_wait:"not_run: no database engine in this fixture"},
}));
process.exit(report.capability.status==="supported"&&report.sample_count>0?0:1);
