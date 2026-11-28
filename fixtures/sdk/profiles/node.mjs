// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Real Node process row for packages/node/src/profile.ts. Run: node fixtures/sdk/profiles/node.mjs (Node 22/24).
// The SDK module is compiled once with the pinned Bun (`--target=node`), never executed through TypeScript stripping.
// Prints ONE JSON evidence line; exits 0 only if every assertion held.
import {spawnSync} from "node:child_process";
import {existsSync,mkdtempSync,openSync,readSync,closeSync,rmSync} from "node:fs";
import inspector from "node:inspector";
import {tmpdir} from "node:os";
import {dirname,join,resolve} from "node:path";
import {fileURLToPath,pathToFileURL} from "node:url";
import {Worker,isMainThread,workerData,parentPort,threadId} from "node:worker_threads";

const here=fileURLToPath(import.meta.url),root=resolve(dirname(here),"../../..");
const relativeSelf="fixtures/sdk/profiles/node.mjs";

/** Deterministic workload: named JS busy loop plus genuinely blocking file reads and a blocking wait. */
function busyLoop(milliseconds){
 const end=performance.now()+milliseconds;let x=0;
 while(performance.now()<end){for(let i=0;i<20000;i++)x+=Math.sqrt(i)*Math.sin(i);}
 return x;
}
function blockingIo(milliseconds){
 const end=performance.now()+milliseconds,buffer=Buffer.alloc(65536),wait=new Int32Array(new SharedArrayBuffer(4));let total=0;
 while(performance.now()<end){
  const fd=openSync(here,"r");try{total+=readSync(fd,buffer,0,buffer.length,0);}finally{closeSync(fd);}
  Atomics.wait(wait,0,0,5);
 }
 return total;
}

if(!isMainThread){
 // Worker isolate row: this thread profiles only its own isolate and must say so.
 const {startProfile}=await import(workerData.module);
 const handle=await startProfile({durationMs:5000,intervalUs:1000,isolate:"worker",projectRoot:workerData.root});
 busyLoop(150);blockingIo(60);
 const report=await handle.stop();
 parentPort.postMessage({status:report.capability.status,reason:report.capability.reason,isolate:report.scope.isolate,thread_id:report.scope.thread_id,sample_count:report.sample_count,thread_ok:report.samples.length>0&&report.samples.every(s=>s.thread===String(threadId)),coverage:report.coverage});
}else{
 const failures=[],checks=[];
 const check=(name,condition)=>{checks.push({name,ok:Boolean(condition)});if(!condition)failures.push(name);};
 const bunCandidates=[process.env.SOUNDPOST_BUN,join(root,".tools/bun-1.3.14/package/bin/bun.exe"),join(root,".tools/bun-1.3.14/package/bin/bun"),"/opt/bun/bin/bun"].filter(Boolean);
 const bun=bunCandidates.find(existsSync);
 if(!bun){console.error("qualification requires SOUNDPOST_BUN or the pinned Bun 1.3.14 to compile the SDK module");process.exit(2);}
 const out=mkdtempSync(join(tmpdir(),"soundpost-profile-node-"));
 const modulePath=join(out,"profile.mjs");
 const exit=(code)=>{rmSync(out,{recursive:true,force:true});process.exit(code);};
 const built=spawnSync(bun,["build",join(root,"packages/node/src/profile.ts"),"--target=node","--format=esm","--outfile",modulePath],{cwd:root,encoding:"utf8"});
 if(built.status!==0){console.error("bundle failed: "+built.stderr.slice(0,400));exit(2);}
 // Observe every inspector call the SDK actually makes in this real runtime.
 const posted=[],listeners=[];
 const originalPost=inspector.Session.prototype.post;
 inspector.Session.prototype.post=function(method,...rest){posted.push(method);return originalPost.call(this,method,...rest);};
 for(const name of ["open","waitForDebugger"]){const original=inspector[name];inspector[name]=function(...args){listeners.push(name);return original.apply(this,args);};}
 const {startProfile}=await import(pathToFileURL(modulePath).href);
 const summarize=(report)=>({method:report.method,units:report.units,time_delta_unit:report.time_delta_unit,status:report.capability.status,reason:report.capability.reason,coverage:report.coverage,sample_count:report.sample_count,frame_count:report.frames.length,stack_count:report.stacks.length,interval:report.interval,losses:report.losses,truncated:report.truncated,stopped_by:report.stopped_by,scope:report.scope,clock_uncertainty_ns:report.clock.uncertainty_ns,non_profile:report.non_profile,ack:report.ack});
 const results={};

 // Row 1: busy JS + blocking I/O under one explicit profile, event-loop delay as a separate non-profile signal.
 const listenerBefore=inspector.url();
 const handle=await startProfile({durationMs:20000,intervalUs:1000,isolate:"main",projectRoot:root,eventLoopDelay:true});
 check("busy: profile started supported",handle.capability.status==="supported"&&handle.active);
 check("busy: no debugger listener while profiling",inspector.url()===undefined&&listenerBefore===undefined);
// The loop-delay monitor records nothing for its first timer interval, so let it tick once before blocking the loop.
await new Promise(r=>setTimeout(r,40));busyLoop(400);blockingIo(200);await new Promise(r=>setTimeout(r,40));
 const report=await handle.stop();
 results.busy=summarize(report);
 const fnSamples=new Map();
 for(const sample of report.samples){for(const index of report.stacks[sample.stack].frames.slice(0,1)){const f=report.frames[index];const key=f.artifact_id?`${f.function||"?"}@${f.artifact_id}`:f.function||f.module_id;fnSamples.set(key,(fnSamples.get(key)??0)+1);}}
 results.busy.leaf_functions=Object.fromEntries([...fnSamples.entries()].sort((a,b)=>b[1]-a[1]).slice(0,8));
 check("busy: supported with nonempty genuine samples",report.capability.status==="supported"&&report.sample_count>0&&report.samples.length===report.sample_count);
 check("busy: method and units distinct, no CPU unit",report.method==="runtime_engine_samples"&&report.units==="samples"&&report.time_delta_unit==="engine_microseconds"&&!/cpu/i.test(JSON.stringify(report)));
 check("busy: workload function sampled with project-relative identity",[...fnSamples.keys()].some(k=>k===`busyLoop@${relativeSelf}`));
 check("busy: achieved interval measured",typeof report.interval.achieved_us==="number"&&report.interval.achieved_us>0);
 check("busy: event-loop delay separate non-profile signal",report.non_profile.length===1&&report.non_profile[0].method==="event_loop_delay"&&report.non_profile[0].profile===false&&report.non_profile[0].count>0&&report.non_profile[0].max>=100_000_000);
 check("busy: clock uncertainty uncalibrated maximum",report.clock.uncertainty_ns==="18446744073709551615");
 const serialized=JSON.stringify(report);
check("busy: no absolute path, cwd or home in report",![root,root.replaceAll("\\","/"),process.cwd(),process.env.USERPROFILE,process.env.HOME,tmpdir()].filter(v=>typeof v==="string"&&v.length>3).some(v=>serialized.includes(v)));
 check("busy: no debugger listener after stop",inspector.url()===undefined);

 // Row 2: ownership refusal with a reason, lease released afterwards.
 const first=await startProfile({durationMs:20000,projectRoot:root});
 const second=await startProfile({durationMs:20000,projectRoot:root});
 const refused=await second.stop();
 results.ownership={first:first.capability.status,second:summarize(refused)};
 check("ownership: second lease denied profiler_owned with zero samples",!second.active&&refused.capability.status==="denied"&&refused.capability.reason==="profiler_owned"&&refused.sample_count===0&&refused.samples.length===0);
 await first.stop();
 const third=await startProfile({durationMs:2000,projectRoot:root});check("ownership: lease released after stop",third.capability.status==="supported");await third.stop();

 // Row 3: a raw foreign inspector profiler in the same isolate neither breaks ours nor is broken by it (V8 sessions are independent).
 const foreign=new inspector.Session();foreign.connect();
 const foreignPost=(m,p)=>new Promise((res,rej)=>foreign.post(m,p??{},(e,r)=>e?rej(e):res(r)));
 await foreignPost("Profiler.enable");await foreignPost("Profiler.start");
 const mine=await startProfile({durationMs:5000,projectRoot:root});busyLoop(120);const mineReport=await mine.stop();
 const foreignProfile=await foreignPost("Profiler.stop");await foreignPost("Profiler.disable");foreign.disconnect();
 results.foreign_session={own:summarize(mineReport),foreign_samples:foreignProfile.profile.samples.length};
 check("foreign session: both profilers produced samples independently",mineReport.capability.status==="supported"&&mineReport.sample_count>0&&foreignProfile.profile.samples.length>0);

 // Row 4: duration bound stops by itself, idempotent stop.
 const bounded=await startProfile({durationMs:60,projectRoot:root});
 await new Promise(r=>setTimeout(r,400));
 const boundedActive=bounded.active,b1=await bounded.stop(),b2=await bounded.stop();
 results.duration_bound={active_after_bound:boundedActive,summary:summarize(b1)};
 check("duration: stopped by itself, same report twice",boundedActive===false&&b1===b2&&b1.stopped_by==="duration"&&b1.capability.status==="supported");

 // Row 5: isolate scope is explicit: a declared scope that does not match is refused, and a worker profiles only its own isolate.
 const mismatch=await startProfile({durationMs:1000,isolate:"worker"});
 check("scope: declared worker scope on the main isolate is refused",mismatch.capability.status==="denied"&&mismatch.capability.reason==="isolate_scope_mismatch");
 const workerResult=await new Promise((resolveWorker,rejectWorker)=>{const w=new Worker(here,{workerData:{module:pathToFileURL(modulePath).href,root}});w.once("message",resolveWorker);w.once("error",rejectWorker);});
 results.worker=workerResult;
 check("scope: worker isolate profiled with its own thread identity",workerResult.status==="supported"&&workerResult.isolate==="worker"&&workerResult.thread_id>0&&workerResult.sample_count>0&&workerResult.thread_ok&&workerResult.coverage.workers==="none");

 // Row 6: refusal paths stay typed and sample-free.
 const invalid=await startProfile({durationMs:0});
 check("options: invalid duration denied invalid_options",invalid.capability.status==="denied"&&invalid.capability.reason==="invalid_options"&&(await invalid.stop()).sample_count===0);

 // Row 7: transport audit in the real runtime.
 const allowed=new Set(["Profiler.enable","Profiler.setSamplingInterval","Profiler.start","Profiler.stop","Profiler.disable"]);
 const outside=[...new Set(posted.filter(m=>!allowed.has(m)))];
 results.transport={methods:[...new Set(posted)].sort(),outside_allowlist:outside,listener_calls:listeners};
 check("transport: only the five Profiler methods were posted",outside.length===0);
 check("transport: inspector.open/waitForDebugger never called",listeners.length===0);

 const evidence={fixture:"node",runtime:{name:"node",version:process.version,v8:process.versions.v8,platform:process.platform,arch:process.arch,node_exec_argv:process.execArgv},bun_for_bundle:"pinned Bun used only to compile the module",results,checks,failed:failures};
 console.log(JSON.stringify(evidence));
 if(failures.length>0)console.error("failed checks: "+failures.join("; "));
 exit(failures.length===0?0:1);
}
