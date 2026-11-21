// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Real Bun process row for packages/bun/src/profile.ts. Run: bun fixtures/sdk/profiles/bun.ts (pinned Bun 1.3.14).
// Bun is exercised on its own (its JavaScriptCore profiler and per-process profiler state), never through Node results.
// Prints ONE JSON evidence line; exits 0 only if every assertion held.
import {closeSync,openSync,readSync} from "node:fs";
import inspector from "node:inspector";
import {tmpdir} from "node:os";
import {resolve} from "node:path";
import {Worker,isMainThread,parentPort,threadId} from "node:worker_threads";
import {startProfile,type ProfileReport} from "../../../packages/bun/src/profile.ts";

const here=import.meta.path,root=resolve(import.meta.dir,"../../..");
const relativeSelf="fixtures/sdk/profiles/bun.ts";

/** Deterministic workload: named JS busy loops plus genuinely blocking file reads and a blocking wait. */
function mainBusy(milliseconds:number):number{const end=performance.now()+milliseconds;let x=0;while(performance.now()<end){for(let i=0;i<20000;i++)x+=Math.sqrt(i)*Math.sin(i);}return x;}
function workerBusy(milliseconds:number):number{const end=performance.now()+milliseconds;let x=0;while(performance.now()<end){for(let i=0;i<20000;i++)x+=Math.cos(i);}return x;}
function blockingIo(milliseconds:number):number{
 const end=performance.now()+milliseconds,buffer=Buffer.alloc(65536),wait=new Int32Array(new SharedArrayBuffer(4));let total=0;
 while(performance.now()<end){const fd=openSync(here,"r");try{total+=readSync(fd,buffer,0,buffer.length,0);}finally{closeSync(fd);}Atomics.wait(wait,0,0,5);}
 return total;
}
const delay=(ms:number)=>new Promise<void>(resolveDelay=>setTimeout(resolveDelay,ms));

if(!isMainThread){
 // Worker isolate row: Bun keeps one profiler state per process, so a worker must be refused with a reason (never steal main's profile).
 const handle=await startProfile({durationMs:5000,intervalUs:1000,isolate:"worker",projectRoot:root});
 workerBusy(250);
 const report=await handle.stop();
 parentPort!.postMessage({status:report.capability.status,reason:report.capability.reason,isolate:report.scope.isolate,thread_id:report.scope.thread_id,sample_count:report.sample_count,thread_expected:threadId});
}else{
 const failures:string[]=[],checks:{name:string;ok:boolean}[]=[];
 const check=(name:string,condition:unknown):void=>{checks.push({name,ok:Boolean(condition)});if(!condition)failures.push(name);};
 const posted:string[]=[],listeners:string[]=[];
 const prototype=inspector.Session.prototype as unknown as {post:(this:unknown,method:string,...rest:unknown[])=>unknown};
 const originalPost=prototype.post;
 prototype.post=function(this:unknown,method:string,...rest:unknown[]){posted.push(method);return originalPost.call(this,method,...rest);};
 const summarize=(report:ProfileReport)=>({method:report.method,units:report.units,time_delta_unit:report.time_delta_unit,status:report.capability.status,reason:report.capability.reason,coverage:report.coverage,sample_count:report.sample_count,frame_count:report.frames.length,stack_count:report.stacks.length,interval:report.interval,losses:report.losses,truncated:report.truncated,stopped_by:report.stopped_by,scope:report.scope,clock_uncertainty_ns:report.clock.uncertainty_ns,non_profile:report.non_profile,ack:report.ack});
 const results:Record<string,unknown>={};
 const patchable=inspector as unknown as Record<string,(...args:unknown[])=>unknown>;
 for(const name of ["open","waitForDebugger"]){const original=patchable[name];if(typeof original==="function")patchable[name]=function(this:unknown,...args:unknown[]){listeners.push(name);return original.apply(this,args);};}
 // Row 1: busy JS + blocking I/O under one explicit profile; event-loop delay is a separate non-profile signal.
 const listenerBefore=inspector.url();
 const handle=await startProfile({durationMs:20000,intervalUs:1000,isolate:"main",projectRoot:root,eventLoopDelay:true});
 check("busy: profile started supported",handle.capability.status==="supported"&&handle.active);
 check("busy: no debugger listener while profiling",inspector.url()===undefined&&listenerBefore===undefined);
 await delay(40);mainBusy(400);blockingIo(200);await delay(40);
 const report=await handle.stop();
 const busy:Record<string,unknown>=summarize(report);
 const leaf=new Map<string,number>();
 for(const sample of report.samples){const index=report.stacks[sample.stack]?.frames[0],frame=index===undefined?undefined:report.frames[index];if(frame){const key=frame.artifact_id?`${frame.function||"?"}@${frame.artifact_id}`:frame.function||frame.module_id;leaf.set(key,(leaf.get(key)??0)+1);}}
 busy.leaf_functions=Object.fromEntries([...leaf.entries()].sort((a,b)=>b[1]-a[1]).slice(0,8));results.busy=busy;
 check("busy: supported with nonempty genuine samples",report.capability.status==="supported"&&report.sample_count>0&&report.samples.length===report.sample_count);
 check("busy: method and units distinct, no CPU unit",report.method==="runtime_engine_samples"&&report.units==="samples"&&report.time_delta_unit==="engine_microseconds"&&!/cpu/i.test(JSON.stringify(report)));
 check("busy: workload function sampled with project-relative identity",[...leaf.keys()].some(k=>k.endsWith(`@${relativeSelf}`)&&/^(mainBusy|blockingIo)@/.test(k)));
 check("busy: achieved interval measured",typeof report.interval.achieved_us==="number"&&report.interval.achieved_us>0);
 check("busy: event-loop delay separate non-profile signal",report.non_profile.length===1&&report.non_profile[0]?.method==="event_loop_delay"&&report.non_profile[0].profile===false&&(report.non_profile[0].count??0)>0&&(report.non_profile[0].max??0)>=100_000_000);
 check("busy: clock uncertainty uncalibrated maximum",report.clock.uncertainty_ns==="18446744073709551615");
 const serialized=JSON.stringify(report);
 check("busy: no absolute path, cwd or home in report",![root,root.replaceAll("\\","/"),process.cwd(),process.env.USERPROFILE,process.env.HOME,tmpdir()].filter((v):v is string=>typeof v==="string"&&v.length>3).some(v=>serialized.includes(v)));
 check("busy: no debugger listener after stop",inspector.url()===undefined);

 // Row 2: ownership refusal with a reason, lease released afterwards.
 const first=await startProfile({durationMs:20000,projectRoot:root}),second=await startProfile({durationMs:20000,projectRoot:root}),refused=await second.stop();
 results.ownership={first:first.capability.status,second:summarize(refused)};
 check("ownership: second lease denied profiler_owned with zero samples",!second.active&&refused.capability.status==="denied"&&refused.capability.reason==="profiler_owned"&&refused.sample_count===0&&refused.samples.length===0);
 await first.stop();
 const third=await startProfile({durationMs:2000,projectRoot:root});check("ownership: lease released after stop",third.capability.status==="supported");await third.stop();

 // Row 3: a foreign raw session shares Bun's single per-process profiler state. When it takes the state away, the profile reports it.
 const foreign=new inspector.Session();foreign.connect();
 const foreignPost=(method:string)=>new Promise<unknown>((res,rej)=>foreign.post(method,{},(error:Error|null,result?:unknown)=>error?rej(error):res(result)));
 const mine=await startProfile({durationMs:5000,projectRoot:root});
 await foreignPost("Profiler.enable");await foreignPost("Profiler.start");mainBusy(80);await foreignPost("Profiler.stop");await foreignPost("Profiler.disable");foreign.disconnect();
 const lost=await mine.stop();
 results.foreign_state={own:summarize(lost)};
 check("foreign state: the lost profile is reported as profiler_state_lost with zero samples",lost.capability.status==="error"&&lost.capability.reason==="profiler_state_lost"&&lost.sample_count===0&&lost.losses.some(l=>l.reason==="foreign_state"));
 const after=await startProfile({durationMs:2000,projectRoot:root});mainBusy(60);const afterReport=await after.stop();
 check("foreign state: next profile works again and lease was released",afterReport.capability.status==="supported"&&afterReport.sample_count>0);

 // Row 4: duration bound stops by itself, idempotent stop.
 const bounded=await startProfile({durationMs:60,projectRoot:root});
 await delay(400);
 const boundedActive=bounded.active,b1=await bounded.stop(),b2=await bounded.stop();
 results.duration_bound={active_after_bound:boundedActive,summary:summarize(b1)};
 check("duration: stopped by itself, same report twice",boundedActive===false&&b1===b2&&b1.stopped_by==="duration"&&b1.capability.status==="supported");

 // Row 5: scope. A declared scope that does not match is refused; a real Bun Worker is refused because the profiler state is per process,
 // and the main thread's own profile, running at the same time, stays intact and contains only main-thread code.
 const mismatch=await startProfile({durationMs:1000,isolate:"worker"});
 check("scope: declared worker scope on the main isolate is refused",mismatch.capability.status==="denied"&&mismatch.capability.reason==="isolate_scope_mismatch");
 const mainProfile=await startProfile({durationMs:20000,projectRoot:root});
 const workerDone=Promise.withResolvers<Record<string,unknown>>();
 const worker=new Worker(here);worker.on("message",message=>workerDone.resolve(message as Record<string,unknown>));worker.on("error",error=>workerDone.reject(error));
 mainBusy(300);
 const workerResult=await workerDone.promise;
 const concurrent=await mainProfile.stop();
 results.worker={refusal:workerResult,main_profile:summarize(concurrent)};
 check("scope: Bun worker isolate refused profiler_state_shared with zero samples",workerResult.status==="denied"&&workerResult.reason==="profiler_state_shared"&&workerResult.isolate==="worker"&&workerResult.sample_count===0);
 check("scope: main profile intact while the worker ran",concurrent.capability.status==="supported"&&concurrent.sample_count>0&&concurrent.frames.some(f=>f.function==="mainBusy")&&!concurrent.frames.some(f=>f.function==="workerBusy"));

 // Row 6: refusal paths stay typed and sample-free.
 const invalid=await startProfile({durationMs:0});
 check("options: invalid duration denied invalid_options",invalid.capability.status==="denied"&&invalid.capability.reason==="invalid_options"&&(await invalid.stop()).sample_count===0);

 // Row 7: transport audit in the real runtime.
 const allowed=new Set(["Profiler.enable","Profiler.setSamplingInterval","Profiler.start","Profiler.stop","Profiler.disable"]);
 const outside=[...new Set(posted.filter(m=>!allowed.has(m)))];
 results.transport={methods:[...new Set(posted)].sort(),outside_allowlist:outside,listener_calls:listeners};
 check("transport: only the five Profiler methods were posted",outside.length===0);
 check("transport: inspector.open/waitForDebugger never called by the SDK",listeners.length===0);

 const evidence={fixture:"bun",runtime:{name:"bun",version:Bun.version,revision:Bun.revision,platform:process.platform,arch:process.arch},results,checks,failed:failures};
 console.log(JSON.stringify(evidence));
 if(failures.length>0)console.error("failed checks: "+failures.join("; "));
 process.exit(failures.length===0?0:1);
}
