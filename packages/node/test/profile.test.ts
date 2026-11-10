// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Unit rows use a FAKE inspector transport with a method allowlist (declared in each test). The real Node 22 inspector row is the
// actual fixtures/sdk/profiles/node.mjs process, spawned at the end of this file; nothing here claims real-engine behavior otherwise.
import {test,expect} from "bun:test";
import {existsSync} from "node:fs";
import {resolve} from "node:path";
import {init} from "../src/index.ts";
import {createProfiler,type ProfilerDeps} from "../src/profile.ts";
import {parseSafeRecord} from "../../core/src/wire.ts";
import {config} from "../../core/test/fixture.ts";

const ALLOWED=new Set(["Profiler.enable","Profiler.setSamplingInterval","Profiler.start","Profiler.stop","Profiler.disable"]);
const frame=(functionName:string,url:string,line=0,column=0)=>({functionName,scriptId:"1",url,lineNumber:line,columnNumber:column});
function v8Profile(){
 const nodes=[
  {id:1,callFrame:frame("(root)","",-1,-1),children:[2,6,7,8,9]},
  {id:2,callFrame:frame("busyWork","file:///proj/src/work.js",9,4),children:[3,5]},
  {id:3,callFrame:frame("inner","file:///proj/src/work.js",19,2),children:[4]},
  {id:4,callFrame:frame("readFileSync","node:fs",300,1)},
  {id:5,callFrame:frame("weird name CANARY_FN_NAME","file:///proj/src/work.js",30,1)},
  {id:6,callFrame:frame("(idle)","",-1,-1)},
  {id:7,callFrame:frame("(garbage collector)","",-1,-1)},
  {id:8,callFrame:frame("dependencyFn","file:///proj/node_modules/pkg/index.js",1,1)},
  {id:9,callFrame:frame("secretFn","file:///home/alice/CANARY_ABSOLUTE/secret.js?token=CANARY_QUERY#frag",1,1)},
 ];
 return {nodes,startTime:5_000_000,endTime:5_010_000,samples:[3,3,4,5,6,7,8,9,3,2],timeDeltas:[1000,1100,900,1000,1000,1000,1000,1000,1000,1000]};
}
interface Script {profile?:unknown;fail?:Record<string,Error>;hang?:string[];connectError?:Error}
interface Fake {readonly log:string[];readonly denied:string[];readonly createSession:()=>{connect():void;disconnect():void;post(method:string,params:unknown,callback:(error:Error|null,result?:unknown)=>void):void};readonly created:number}
function fake(script:Script={}):Fake{
 const log:string[]=[],denied:string[]=[];let created=0;
 const createSession=()=>{created++;return {
  connect(){if(script.connectError)throw script.connectError;log.push("connect");},
  disconnect(){log.push("disconnect");},
  post(method:string,_params:unknown,callback:(error:Error|null,result?:unknown)=>void){
   if(!ALLOWED.has(method)){denied.push(method);throw Error("transport allowlist denied "+method);}
   log.push(method);
   if(script.hang?.includes(method))return;
   const failure=script.fail?.[method];if(failure){callback(failure);return;}
   callback(null,method==="Profiler.stop"?{profile:script.profile??v8Profile()}:{});
  },
 };};
 return {log,denied,createSession,get created(){return created;}};
}
function deps(f:Fake,over:Partial<ProfilerDeps>={}):ProfilerDeps{
 return {runtime:"node",version:"v22.23.4",build:"12.4.254.21-node.33",os:"linux",arch:"x64",isMainThread:true,threadId:0,
  createSession:f.createSession,inspectorUrl:()=>undefined,wallNs:()=>1_700_000_000_000_000_000n,
  setTimer:(callback:()=>void,ms:number,unref:boolean)=>{const t=setTimeout(callback,ms);if(unref)(t as {unref?:()=>void}).unref?.();return {cancel:()=>clearTimeout(t)};},
  commandTimeoutMs:100,registry:{owner:undefined},...over} as ProfilerDeps;
}
const options={durationMs:5000,intervalUs:1000,projectRoot:"/proj"};
const text=(value:unknown)=>JSON.stringify(value);

test("allowlisted in-process inspector sequence only: enable, interval, start, stop, disable, no listener or evaluation",async()=>{
 const f=fake(),{startProfile}=createProfiler(deps(f)),handle=await startProfile(options),report=await handle.stop();
 expect(f.log).toEqual(["connect","Profiler.enable","Profiler.setSamplingInterval","Profiler.start","Profiler.stop","Profiler.disable","disconnect"]);
 expect(f.denied).toEqual([]);
 expect(report.capability.status).toBe("supported");expect(report.capability.reason).toBe("ok");expect(report.stopped_by).toBe("caller");
 expect(f.created).toBe(1);
});
test("genuine engine samples keep distinct method, units and no OS CPU unit anywhere",async()=>{
 const f=fake(),{startProfile}=createProfiler(deps(f)),handle=await startProfile(options),report=await handle.stop();
 expect(report.method).toBe("runtime_engine_samples");expect(report.profile).toBe(true);expect(report.units).toBe("samples");expect(report.time_delta_unit).toBe("engine_microseconds");
 expect(report.sample_count).toBe(10);expect(report.samples).toHaveLength(10);expect(report.stack_order).toBe("leaf_first");
 expect(report.samples.map((s:{at_us:string})=>s.at_us)).toEqual(["1000","2100","3000","4000","5000","6000","7000","8000","9000","10000"]);
 expect(report.samples.every((s:{count:string;thread:string})=>s.count==="1"&&s.thread==="0")).toBe(true);
 expect(text(report)).not.toMatch(/cpu|nanosecond/i);
 expect(report.interval.requested_us).toBe(1000);expect(report.interval.achieved_us).toBe(1000);
 expect(report.coverage).toEqual({frames:"partial",threads:"partial",workers:"none",tasks:"none"});
 expect(report.ack).toEqual({status:"not_available",reason:"no_profile_admission_path"});
 expect(report.clock.uncertainty_ns).toBe("18446744073709551615");expect(report.clock.wall_start_ns).toBe("1700000000000000000");
});
test("frames carry code identity only: project-relative path, safe symbols, collapsed external placeholder, no paths/queries/canaries",async()=>{
 const f=fake(),{startProfile}=createProfiler(deps(f)),report=await (await startProfile(options)).stop();
 const serialized=text(report);
 for(const forbidden of ["CANARY","/home/alice","token=","#frag","node_modules","readFileSync","node:fs","/proj/"])expect(serialized).not.toContain(forbidden);
 const names=report.frames.map((x:{function:string;artifact_id:string;reason:string;module_id:string})=>`${x.module_id}|${x.function}|${x.artifact_id}|${x.reason}`);
 expect(names).toContain("src/work.js|busyWork|src/work.js|");
 expect(names).toContain("src/work.js|inner|src/work.js|");
 expect(names).toContain("src/work.js||src/work.js|not_captured");
 expect(names).toContain("engine|engine:idle||");expect(names).toContain("engine|engine:gc||");
 expect(names.filter((n:string)=>n.startsWith("external|"))).toEqual(["external|||not_captured"]);
 const inner=report.frames.findIndex((x:{function:string})=>x.function==="inner"),busy=report.frames.findIndex((x:{function:string})=>x.function==="busyWork");
 const stackOfInner=report.samples[0].stack;expect(report.stacks[stackOfInner].frames.slice(0,2)).toEqual([inner,busy]);
 const builtin=report.stacks[report.samples[2].stack].frames;expect(builtin).toHaveLength(3);expect(report.frames[builtin[0]].module_id).toBe("external");
 expect(report.frames.find((x:{function:string})=>x.function==="busyWork")).toMatchObject({line:10,column:5,offset:"0"});
});
test("a root that does not contain the code leaves every application frame external",async()=>{
 const f=fake(),{startProfile}=createProfiler(deps(f)),report=await (await startProfile({durationMs:5000,projectRoot:"/elsewhere"})).stop();
 expect(report.frames.some((x:{artifact_id:string})=>x.artifact_id!=="")).toBe(false);expect(text(report)).not.toContain("busyWork");
 const none=await (await createProfiler(deps(fake())).startProfile({durationMs:5000})).stop();expect(none.frames.some((x:{artifact_id:string})=>x.artifact_id!=="")).toBe(false);
});
test("a second lease is refused with profiler_owned without touching the inspector; release re-enables",async()=>{
 const f=fake(),{startProfile}=createProfiler(deps(f)),first=await startProfile(options),second=await startProfile(options);
 expect(f.created).toBe(1);expect(second.active).toBe(false);expect(second.capability.status).toBe("denied");expect(second.capability.reason).toBe("profiler_owned");
 const refused=await second.stop();expect(refused.sample_count).toBe(0);expect(refused.samples).toEqual([]);expect(refused.frames).toEqual([]);expect(refused.stopped_by).toBe("not_started");expect(refused.capability.reason).toBe("profiler_owned");
 expect((await first.stop()).sample_count).toBe(10);
 const third=await startProfile(options);expect(third.capability.status).toBe("supported");await third.stop();
});
test("ownership is process-global through the shared registry so a duplicate module copy conflicts",async()=>{
 const registry={owner:undefined as unknown},a=createProfiler(deps(fake(),{registry})),b=createProfiler(deps(fake(),{registry}));
 const first=await a.startProfile(options),second=await b.startProfile(options);expect(second.capability.reason).toBe("profiler_owned");await first.stop();
});
test("project roots work in Windows drive and UNC forms exactly as the engine names scripts; look-alike prefixes stay external",async()=>{
 const named=(url:string)=>({nodes:[{id:1,callFrame:frame("(root)","",-1,-1),children:[2]},{id:2,callFrame:frame("busyWork",url,3,0)}],startTime:1,endTime:2,samples:[2],timeDeltas:[10]});
 const artifact=async(root:string,url:string)=>{const report=await (await createProfiler(deps(fake({profile:named(url)}))).startProfile({durationMs:1000,projectRoot:root})).stop();return report.frames.map((f:{artifact_id:string})=>f.artifact_id);};
 expect(await artifact("C:\\Work\\App","file:///c:/work/app/src/a%20b.js")).toEqual([""]);
 expect(await artifact("C:\\Work\\App","file:///c:/work/app/src/ab.js")).toEqual(["src/ab.js"]);
 expect(await artifact("\\\\127.0.0.1\\ovnfs\\n0309","file://127.0.0.1/ovnfs/n0309/packages/x.ts")).toEqual(["packages/x.ts"]);
 expect(await artifact("//127.0.0.1/ovnfs/n0309/","file://127.0.0.1/ovnfs/n0309/packages/x.ts")).toEqual(["packages/x.ts"]);
 expect(await artifact("\\\\127.0.0.1\\ovnfs\\n0309","file://127.0.0.1/ovnfs/n0309-other/x.ts")).toEqual([""]);
 expect(await artifact("\\\\127.0.0.1\\ovnfs\\n0309","file://evil.example/ovnfs/n0309/x.ts")).toEqual([""]);
 expect(await artifact("/proj","file:///proj/../etc/x.js")).toEqual([""]);
 expect(await artifact("/proj","file:///projx/src/x.js")).toEqual([""]);
});
test("a foreign profiler that took the runtime state is reported as lost state, never as empty success",async()=>{
 const f=fake({fail:{"Profiler.stop":new Error("Profiler is not started. Call Profiler.start first.")}}),{startProfile}=createProfiler(deps(f)),report=await (await startProfile(options)).stop();
 expect(report.capability.status).toBe("error");expect(report.capability.reason).toBe("profiler_state_lost");expect(report.sample_count).toBe(0);expect(report.losses).toEqual([{reason:"foreign_state",count:"1"}]);
 expect(f.log.slice(-2)).toEqual(["Profiler.disable","disconnect"]);
 const again=await createProfiler(deps(fake({fail:{"Profiler.stop":Object.assign(Error("Inspector error -32000: No recording profiles found"),{code:"ERR_INSPECTOR_COMMAND"})}}))).startProfile(options);
 expect((await again.stop()).capability.reason).toBe("profiler_state_lost");
});
test("hung inspector start: bounded cleanup, error capability with timeout reason, lease released",async()=>{
 const f=fake({hang:["Profiler.start"]}),registry={owner:undefined as unknown},{startProfile}=createProfiler(deps(f,{registry,commandTimeoutMs:30}));
 const began=Date.now(),handle=await startProfile(options);
 expect(Date.now()-began).toBeLessThan(2000);expect(handle.active).toBe(false);expect(handle.capability.status).toBe("error");expect(handle.capability.reason).toBe("inspector_timeout");
 expect(f.log.at(-1)).toBe("disconnect");expect(registry.owner).toBeUndefined();expect(f.log).not.toContain("Profiler.disable");
 const next=await createProfiler(deps(fake(),{registry})).startProfile(options);expect(next.capability.status).toBe("supported");await next.stop();
});
test("hung inspector stop: bounded, still disconnects and releases, reports timeout without fabricating samples",async()=>{
 const f=fake({hang:["Profiler.stop"]}),registry={owner:undefined as unknown},{startProfile}=createProfiler(deps(f,{registry,commandTimeoutMs:30})),handle=await startProfile(options);
 const began=Date.now(),report=await handle.stop();
 expect(Date.now()-began).toBeLessThan(2000);expect(report.capability.status).toBe("error");expect(report.capability.reason).toBe("inspector_timeout");expect(report.stopped_by).toBe("timeout_cleanup");expect(report.sample_count).toBe(0);
 expect(f.log.at(-1)).toBe("disconnect");expect(registry.owner).toBeUndefined();expect(f.log).not.toContain("Profiler.disable");
});
test("duration bound stops by itself exactly once; stop() is idempotent and returns the same report",async()=>{
 const f=fake(),{startProfile}=createProfiler(deps(f)),handle=await startProfile({durationMs:20,projectRoot:"/proj"});
 expect(handle.active).toBe(true);await new Promise(r=>setTimeout(r,120));expect(handle.active).toBe(false);
 const a=await handle.stop(),b=await handle.stop();expect(a).toBe(b);expect(a.stopped_by).toBe("duration");expect(f.log.filter(x=>x==="Profiler.stop")).toHaveLength(1);expect(f.log.filter(x=>x==="disconnect")).toHaveLength(1);
});
test("sample cap truncates with a counted loss, never silently",async()=>{
 const f=fake(),{startProfile}=createProfiler(deps(f)),report=await (await startProfile({...options,maxSamples:4})).stop();
 expect(report.sample_count).toBe(4);expect(report.samples).toHaveLength(4);expect(report.truncated).toBe(true);expect(report.losses).toContainEqual({reason:"truncated",count:"6"});
});
test("engine sample gaps become counted losses derived from the observed deltas",async()=>{
 const profile=v8Profile();profile.timeDeltas=[1000,1000,5000,1000,1000,1000,1000,1000,1000,1000];
 const report=await (await createProfiler(deps(fake({profile}))).startProfile(options)).stop();
 expect(report.losses).toContainEqual({reason:"sample_gap",count:"4"});
});
test("invalid options and hostile accessors are refused as invalid_options without throwing or creating a session",async()=>{
 const f=fake(),{startProfile}=createProfiler(deps(f));let reads=0;
 const bad:unknown[]=[{durationMs:0},{durationMs:60_001},{durationMs:1.5},{durationMs:Number.NaN},{durationMs:100,intervalUs:5},{durationMs:100,intervalUs:100.5},{durationMs:100,intervalUs:2_000_000},{durationMs:100,maxSamples:9000},{durationMs:100,maxSamples:1.5},{durationMs:100,maxSamples:0},{durationMs:100,isolate:"both"},{durationMs:100,eventLoopDelay:"yes"},{durationMs:100,client:{}},{durationMs:100,projectRoot:"relative/path"},{durationMs:100,projectRoot:"/a\0b"},{},null,"x",
  Object.defineProperty({},"durationMs",{get(){reads++;throw Error("CANARY_GETTER");}})];
 for(const value of bad){const handle=await startProfile(value as never);expect(handle.active).toBe(false);expect(handle.capability.status).toBe("denied");expect(handle.capability.reason).toBe("invalid_options");const report=await handle.stop();expect(report.sample_count).toBe(0);expect(text(report)).not.toContain("CANARY");}
 expect(f.created).toBe(0);expect(reads).toBe(1);
});
test("declared isolate scope must match the actual isolate",async()=>{
 const f=fake(),main=createProfiler(deps(f)),worker=createProfiler(deps(f,{isMainThread:false,threadId:3}));
 expect((await main.startProfile({...options,isolate:"worker"})).capability.reason).toBe("isolate_scope_mismatch");
 expect((await worker.startProfile({...options,isolate:"main"})).capability.reason).toBe("isolate_scope_mismatch");expect(f.created).toBe(0);
 const ok=await worker.startProfile({...options,isolate:"worker"}),report=await ok.stop();expect(report.scope).toMatchObject({isolate:"worker",thread_id:3});expect(report.samples[0].thread).toBe("3");
});
test("missing or refusing inspector is unsupported with a reason and zero samples",async()=>{
 const refusing=fake({connectError:Object.assign(Error("no inspector"),{code:"ERR_INSPECTOR_NOT_AVAILABLE"})}),handle=await createProfiler(deps(refusing)).startProfile(options);
 expect(handle.capability.status).toBe("unsupported");expect(handle.capability.reason).toBe("inspector_unavailable");const report=await handle.stop();expect(report.sample_count).toBe(0);
 const none=await createProfiler(deps(fake(),{createSession:undefined as never})).startProfile(options);expect(none.capability.reason).toBe("inspector_unavailable");
 const generic=fake({fail:{"Profiler.enable":Error("boom CANARY_MESSAGE")}}),failed=await createProfiler(deps(generic)).startProfile(options);
 expect(failed.capability.status).toBe("error");expect(failed.capability.reason).toBe("inspector_error");expect(text(await failed.stop())).not.toContain("CANARY");expect(generic.log.at(-1)).toBe("disconnect");
});
test("a client owns the lease: close stops the profile, and a closed client is refused",async()=>{
 const client=init(config()),f=fake(),{startProfile}=createProfiler(deps(f)),handle=await startProfile({...options,client});
 expect(handle.active).toBe(true);await client.close();await new Promise(r=>setTimeout(r,50));
 expect(handle.active).toBe(false);expect(f.log).toContain("Profiler.stop");const report=await handle.stop();expect(report.stopped_by).toBe("client_close");expect(report.sample_count).toBe(10);
 const refused=await startProfile({...options,client});expect(refused.capability.status).toBe("denied");expect(refused.capability.reason).toBe("client_unavailable");expect(f.created).toBe(1);
});
test("the report's capability is a valid C04 capability record and states the runtime without version-only support claims",async()=>{
 const report=await (await createProfiler(deps(fake())).startProfile(options)).stop(),{id,...payload}=report.capability;
 const record=parseSafeRecord(JSON.stringify({id,kind:"capability",observed_at_ns:report.clock.wall_start_ns,policy_revision:"1",payload}));
 expect(record.payload.method).toBe("runtime_engine_samples");expect(record.payload.signal).toBe("profile_chunk");expect(record.payload.runtime).toBe("node");
 expect(Number(BigInt(payload.expires_ns)-BigInt(report.clock.wall_start_ns))).toBe(3_600_000_000_000);
 const refused=await (await createProfiler(deps(fake(),{registry:{owner:{}}})).startProfile(options)).stop(),{id:rid,...rp}=refused.capability;
 expect(()=>parseSafeRecord(JSON.stringify({id:rid,kind:"capability",observed_at_ns:"1700000000000000000",policy_revision:"1",payload:rp}))).not.toThrow();
 expect(rp.status).toBe("denied");expect(rp.coverage).toEqual({frames:"none",threads:"none",workers:"none",tasks:"none"});
});
test("event-loop delay is a separate non-profile measurement and adds no samples",async()=>{
 const histogram={disables:0,enable(){return true;},disable(){this.disables++;return true;},count:50,min:1_000_000,max:42_000_000,mean:5_000_000,exceeds:3,percentile:(p:number)=>p===50?4_000_000:41_000_000};
 const f=fake(),handle=await createProfiler(deps(f,{monitorEventLoopDelay:()=>histogram})).startProfile({...options,eventLoopDelay:true}),report=await handle.stop();
 expect(report.sample_count).toBe(10);expect(report.non_profile).toEqual([{method:"event_loop_delay",profile:false,signal:"metric",unit:"nanoseconds",resolution_ms:10,count:50,min:1_000_000,max:42_000_000,mean:5_000_000,p50:4_000_000,p99:41_000_000,exceeds:3}]);
 expect(histogram.disables).toBe(1);
 const off=await (await createProfiler(deps(fake())).startProfile(options)).stop();expect(off.non_profile).toEqual([]);
 const empty=await (await createProfiler(deps(fake(),{monitorEventLoopDelay:()=>({...histogram,count:0,min:9223372036854776000,max:0,mean:Number.NaN})})).startProfile({...options,eventLoopDelay:true})).stop();
 expect(empty.non_profile[0]).toMatchObject({count:0,min:null,max:null,mean:null,p50:null,p99:null});
});
test("a debugger listener that was already open is reported, never opened or closed by the profiler",async()=>{
 const report=await (await createProfiler(deps(fake(),{inspectorUrl:()=>"ws://127.0.0.1:9229/CANARY_TOKEN"})).startProfile(options)).stop();
 expect(report.scope.debugger_listener_present).toBe(true);expect(text(report)).not.toContain("CANARY_TOKEN");expect(text(report)).not.toContain("9229");
 expect((await (await createProfiler(deps(fake())).startProfile(options)).stop()).scope.debugger_listener_present).toBe(false);
});
test("a hostile or malformed engine profile never rejects stop(): typed inspector_error, lease released, no leaked detail",async()=>{
 const hostile=v8Profile(),registry={owner:undefined as unknown};
 (hostile.nodes as unknown[]).push(Object.defineProperty({},"id",{get(){throw Error("CANARY_PROFILE_GETTER");}}));
 const f=fake({profile:hostile}),handle=await createProfiler(deps(f,{registry})).startProfile(options),report=await handle.stop();
 expect(report.capability.status).toBe("error");expect(report.capability.reason).toBe("inspector_error");expect(report.sample_count).toBe(0);expect(text(report)).not.toContain("CANARY");
 expect(registry.owner).toBeUndefined();expect(f.log.at(-1)).toBe("disconnect");
 const truncated=await (await createProfiler(deps(fake({profile:{nodes:[],samples:[1],timeDeltas:[]}}),{registry})).startProfile(options)).stop();
 expect(truncated.capability.reason).toBe("inspector_error");expect(truncated.sample_count).toBe(0);
});
test("real Node 22 inspector fixture (actual process, own exit code) reports genuine engine samples",async()=>{
 const root=resolve(import.meta.dir,"../../.."),node=process.env.SOUNDPOST_NODE??["node-v22.23.4-win-x64/node.exe","linux/node/bin/node"].map(p=>resolve(root,".tools",p)).find(existsSync);
 if(!node)throw Error("qualification requires SOUNDPOST_NODE or the pinned Node 22.23.4 under .tools");
 const run=Bun.spawnSync([node,resolve(root,"fixtures/sdk/profiles/node.mjs")],{cwd:root,stdout:"pipe",stderr:"pipe"});
 expect(run.exitCode).toBe(0);const line=run.stdout.toString().trim().split("\n").at(-1)!,evidence=JSON.parse(line);
 expect(evidence.fixture).toBe("node");expect(evidence.runtime.name).toBe("node");expect(evidence.results.busy.sample_count).toBeGreaterThan(0);expect(evidence.results.busy.method).toBe("runtime_engine_samples");
},30_000);
test("stacks are depth-capped leaf-first, consecutive external frames collapse and query/fragment URLs inside the root stay external",async()=>{
 const deep:unknown[]=[{id:1,callFrame:frame("(root)","",-1,-1),children:[2]}];
 for(let i=2;i<=300;i++)deep.push({id:i,callFrame:frame("fn"+i,"file:///proj/src/deep.js",i,0),...(i<300?{children:[i+1]}:{})});
 const capped=await (await createProfiler(deps(fake({profile:{nodes:deep,startTime:1,endTime:2,samples:[300],timeDeltas:[10]}}))).startProfile(options)).stop();
 expect(capped.stacks[0]!.frames).toHaveLength(128);expect(capped.frames[capped.stacks[0]!.frames[0]!]!.function).toBe("fn300");
 const nodes=[{id:1,callFrame:frame("(root)","",-1,-1),children:[2]},{id:2,callFrame:frame("busyWork","file:///proj/src/work.js",1,0),children:[3]},{id:3,callFrame:frame("a","node:a",1,0),children:[4,5,6]},{id:4,callFrame:frame("b","node:b",1,0)},
  {id:5,callFrame:frame("q","file:///proj/src/work.js?canary=1",1,0)},{id:6,callFrame:frame("h","file:///proj/src/work.js#frag",1,0)}];
 const report=await (await createProfiler(deps(fake({profile:{nodes,startTime:1,endTime:2,samples:[4,5,6],timeDeltas:[10,10,10]}}))).startProfile(options)).stop();
 for(const sample of report.samples)expect(report.stacks[sample.stack]!.frames.map((i:number)=>report.frames[i]!.module_id)).toEqual(["external","src/work.js"]);
});
test("timer policy: inspector command timers keep the process alive for their short bound, the duration timer never does",async()=>{
 const timers:{ms:number;unref:boolean}[]=[],f=fake(),handle=await createProfiler(deps(f,{setTimer:(callback:()=>void,ms:number,unref:boolean)=>{timers.push({ms,unref});const t=setTimeout(callback,ms);return {cancel:()=>clearTimeout(t)};}})).startProfile(options);
 expect(timers.filter(t=>t.ms===100).length).toBeGreaterThanOrEqual(3);expect(timers.filter(t=>t.ms===100).every(t=>t.unref===false)).toBe(true);
 expect(timers.filter(t=>t.ms===5000)).toEqual([{ms:5000,unref:true}]);await handle.stop();
});
test("a client lease is registered once, released exactly once on every exit path, and a refused client leaks nothing",async()=>{
 const calls:string[]=[],owner={ownHookLease(){calls.push("own");},releaseHookLease(){calls.push("release");}},registry={owner:undefined as unknown},{startProfile}=createProfiler(deps(fake(),{registry}));
 await (await startProfile({...options,client:owner})).stop();expect(calls).toEqual(["own","release"]);
 const failing={ownHookLease(){throw Error("client closed");},releaseHookLease(){calls.push("release-failing");}},refused=await startProfile({...options,client:failing});
 expect(refused.capability.reason).toBe("client_unavailable");expect(registry.owner).toBeUndefined();expect(calls).toEqual(["own","release"]);
 const flaky={ownHookLease(){calls.push("own2");},releaseHookLease(){calls.push("release2");}},sessionFail=createProfiler(deps(fake({fail:{"Profiler.enable":Error("x")}}),{registry}));
 expect((await sessionFail.startProfile({...options,client:flaky})).capability.reason).toBe("inspector_error");expect(calls.slice(2)).toEqual(["own2","release2"]);
 expect((await startProfile(options)).capability.status).toBe("supported");
});
test("option bounds are exact on both sides and the boundary values themselves are accepted",async()=>{
 const f=fake(),{startProfile}=createProfiler(deps(f));
 for(const bad of [{durationMs:100,maxSamples:8193},{durationMs:100,intervalUs:99},{durationMs:100,intervalUs:1_000_001},{durationMs:60_001}]){const handle=await startProfile(bad);expect(handle.capability.reason).toBe("invalid_options");}
 expect(f.created).toBe(0);
 for(const edge of [{durationMs:60_000,intervalUs:100,maxSamples:8192},{durationMs:1,intervalUs:1_000_000,maxSamples:1}]){const handle=await startProfile(edge);expect(handle.capability.status).toBe("supported");await handle.stop();}
});
test("achieved interval excludes the first sample's lead-in delta and fractional engine deltas are rounded per sample",async()=>{
 const profile=v8Profile();profile.timeDeltas=[9000,1000,1000,1000,1000,1000,1000,1000,1000,1000];
 const report=await (await createProfiler(deps(fake({profile}))).startProfile(options)).stop();expect(report.interval.achieved_us).toBe(1000);expect(report.samples[0]!.at_us).toBe("9000");
 const fractional=v8Profile();fractional.timeDeltas=[236.4,940,853.5,882.2,1000,1000,1000,1000,1000,1000];
 const rounded=await (await createProfiler(deps(fake({profile:fractional}))).startProfile(options)).stop();
 expect(rounded.samples.slice(0,4).map((s:{at_us:string})=>s.at_us)).toEqual(["236","1176","2030","2912"]);
});
