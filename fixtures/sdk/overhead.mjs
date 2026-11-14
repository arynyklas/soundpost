// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Measures (never asserts aspirational values) the overhead of SDK capture on deterministic workloads, with repeated alternating
// runs, raw per-run numbers, variance and the machine class. Run under Node 22+:
//   node fixtures/sdk/overhead.mjs --requests-per-second 1000 [--duration-s 3] [--runs 5] [--profile-runs 7] [--out result.json]
// Budgets come from design section 13 and are only compared against, never edited here. Anything this script cannot measure on this
// machine is reported as `not_measured` with a reason, never as passed.
import {spawn,spawnSync} from "node:child_process";
import {existsSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from "node:fs";
import http from "node:http";
import os from "node:os";
import {dirname,join,resolve} from "node:path";
import {fileURLToPath,pathToFileURL} from "node:url";
import {gzipSync} from "node:zlib";
import crypto from "node:crypto";

const here=fileURLToPath(import.meta.url),root=resolve(dirname(here),"../..");
const args=process.argv.slice(2);
const option=(name,fallback)=>{const i=args.indexOf(name);return i>=0&&i+1<args.length?args[i+1]:fallback;};
const BUDGET={server_p95_latency_percent:5,server_cpu_percent:5,queue_bytes:2*1024*1024,browser_core_gzip_bytes:40*1024,browser_replay_gzip_bytes:60*1024};

// ---------------------------------------------------------------- shared deterministic request work (identical in every mode)
const payload=Buffer.alloc(1024,7);
function requestWork(seed,hashes){
 let digest=payload;for(let i=0;i<hashes;i++)digest=crypto.createHash("sha256").update(digest).update(String(seed)).digest();
 const body={};for(let i=0;i<16;i++)body["field"+i]=(digest[i]*(i+1))%977;
 return JSON.stringify(body);
}
const sleep=ms=>new Promise(r=>setTimeout(r,ms));

// ---------------------------------------------------------------- role: server (spawned by the parent)
async function roleServer(){
 const mode=option("--mode","baseline"),bundle=option("--bundle","");
 const hashes=Number(option("--hashes","3"));
 let listener=(req,res)=>{res.writeHead(200,{"content-type":"application/json"});res.end(requestWork(count++,hashes));};
 let count=0,client,sampler,maxQueueBytes=0;
 const queueBytes=()=>client?client.bufferedRecords().reduce((n,r)=>n+Buffer.byteLength(r),0):0;
 if(mode!=="baseline"){
  const sdk=await import(pathToFileURL(bundle).href);
  client=sdk.makeClient(mode==="capture-stalled"?"stalled":"acking");
  const wrap=sdk.installHttp(client,{operation:"request"}),inner=listener;
  listener=wrap.listener((req,res)=>{if(count%100===99)client.captureException(new Error("fixture handled error"));inner(req,res);});
  if(mode==="capture-stalled"||mode==="capture-sampled"){sampler=setInterval(()=>{maxQueueBytes=Math.max(maxQueueBytes,queueBytes());},50);sampler.unref();}
  // Delivered mode: export on a timer like a real application, so batching, receipts and acknowledgement are in the measured cost.
  if(mode==="capture-delivered"){const flusher=setInterval(()=>{void client.flush(1000).catch(()=>{});},100);flusher.unref();}
 }
 const server=http.createServer((req,res)=>{
  if(req.url==="/__cpu"){const c=process.cpuUsage(),elu=performance.eventLoopUtilization();res.end(JSON.stringify({user_us:c.user,system_us:c.system,elu_active_ms:elu.active,requests:count,queue_bytes:queueBytes(),max_queue_bytes:Math.max(maxQueueBytes,queueBytes()),diagnostics:client?client.diagnostics():{}}));return;}
  listener(req,res);
 });
 server.keepAliveTimeout=60000;
 server.listen(0,"127.0.0.1",()=>process.stdout.write("LISTENING "+server.address().port+"\n"));
 process.stdin.resume();process.stdin.on("end",()=>process.exit(0));
}

// ---------------------------------------------------------------- role: load (open loop, spawned by the parent)
function get(agent,port,path){
 return new Promise((resolveGet,rejectGet)=>{
  const t0=performance.now(),req=http.get({host:"127.0.0.1",port,path,agent},res=>{res.resume();res.on("end",()=>resolveGet(performance.now()-t0));});
  req.on("error",rejectGet);
 });
}
async function roleLoad(){
 const port=Number(option("--port","0")),rps=Number(option("--rps","1000")),seconds=Number(option("--seconds","3")),warm=Number(option("--warmup-s","1"));
 const agent=new http.Agent({keepAlive:true,maxSockets:128});
 const run=async(duration)=>{
  const latencies=[];let errors=0,sent=0;const t0=performance.now(),pending=new Set();
  while(performance.now()-t0<duration*1000){
   const due=Math.floor((performance.now()-t0)/1000*rps);
   while(sent<due){sent++;const p=get(agent,port,"/work/"+sent).then(ms=>latencies.push(ms),()=>{errors++;}).finally(()=>pending.delete(p));pending.add(p);}
   await sleep(1);
  }
  await Promise.all(pending);
  return {latencies,errors,sent,wall_s:(performance.now()-t0)/1000};
 };
 await run(warm);
 const before=JSON.parse(await new Promise(r=>{http.get({host:"127.0.0.1",port,path:"/__cpu",agent},res=>{let t="";res.on("data",d=>t+=d);res.on("end",()=>r(t));});}));
 const measured=await run(seconds);
 const after=JSON.parse(await new Promise(r=>{http.get({host:"127.0.0.1",port,path:"/__cpu",agent},res=>{let t="";res.on("data",d=>t+=d);res.on("end",()=>r(t));});}));
 agent.destroy();
 process.stdout.write(JSON.stringify({latencies_ms:measured.latencies.map(v=>Number(v.toFixed(3))),errors:measured.errors,sent:measured.sent,wall_s:measured.wall_s,server:{requests:after.requests-before.requests,cpu_us:after.user_us+after.system_us-before.user_us-before.system_us,user_us:after.user_us-before.user_us,system_us:after.system_us-before.system_us,elu_active_us:(after.elu_active_ms-before.elu_active_ms)*1000,queue_bytes_end:after.queue_bytes,max_queue_bytes:after.max_queue_bytes,diagnostics:after.diagnostics}})+"\n");
 process.exit(0);
}

// ---------------------------------------------------------------- role: profile-work (fixed deterministic CPU work with and without a profile)
async function roleProfileWork(){
 const runtime=option("--runtime","node"),rounds=Number(option("--rounds","6")),intervalUs=Number(option("--interval-us","1000")),target=option("--module","");
 const {startProfile}=await import(pathToFileURL(target).href);
 const work=()=>{let x=0;for(let r=0;r<40;r++)for(let i=0;i<400000;i++)x+=Math.sqrt(i)*Math.sin(i);return x;};
 work();work();
 const rows=[];
 for(let r=0;r<rounds;r++){
  for(const mode of r%2===0?["off","on"]:["on","off"]){
   const handle=mode==="on"?await startProfile({durationMs:60000,intervalUs}):undefined;
   const cpu0=process.cpuUsage(),t0=performance.now();work();const wall=performance.now()-t0,cpu=process.cpuUsage(cpu0);
   const report=handle?await handle.stop():undefined;
   rows.push({mode,wall_ms:Number(wall.toFixed(3)),cpu_ms:Number(((cpu.user+cpu.system)/1000).toFixed(3)),samples:report?report.sample_count:null,status:report?report.capability.status:null});
  }
 }
 process.stdout.write(JSON.stringify({runtime,runtime_version:runtime==="bun"?Bun.version:process.version,interval_us:intervalUs,rows})+"\n");
 process.exit(0);
}

// ---------------------------------------------------------------- statistics
const mean=v=>v.reduce((a,b)=>a+b,0)/v.length;
const stdev=v=>v.length<2?0:Math.sqrt(v.reduce((a,b)=>a+(b-mean(v))**2,0)/(v.length-1));
const quantile=(sorted,q)=>sorted.length?sorted[Math.min(sorted.length-1,Math.ceil(q*sorted.length)-1)]:null;
function summary(values){return {n:values.length,values:values.map(v=>Number(v.toFixed(4))),mean:Number(mean(values).toFixed(4)),stdev:Number(stdev(values).toFixed(4)),min:Math.min(...values),max:Math.max(...values),cv_percent:Number((100*stdev(values)/mean(values)).toFixed(3))};}
function compare(base,variant){
 const delta=mean(variant)-mean(base),percent=100*delta/mean(base),se=Math.sqrt(stdev(base)**2/base.length+stdev(variant)**2/variant.length);
 return {delta_percent:Number(percent.toFixed(3)),delta_abs:Number(delta.toFixed(4)),standard_error_abs:Number(se.toFixed(4)),delta_exceeds_two_standard_errors:Math.abs(delta)>2*se};
}
function machineClass(){
 const cpus=os.cpus(),spin=[];
 for(let i=0;i<15;i++){const t0=performance.now();let x=0;while(performance.now()-t0<50)x+=Math.sqrt(i+x);spin.push(x);}
 const timing=[];for(let i=0;i<15;i++){const t0=performance.now();let x=0;for(let k=0;k<2_000_000;k++)x+=Math.sqrt(k);timing.push(performance.now()-t0);void x;}
 return {platform:os.platform(),release:os.release(),arch:os.arch(),cpu_model:cpus[0]?.model??"unknown",logical_cpus:cpus.length,cpu_mhz_reported:cpus[0]?.speed??null,total_memory_mib:Math.round(os.totalmem()/1048576),free_memory_mib_at_start:Math.round(os.freemem()/1048576),load_average_1m:os.loadavg()[0],node:process.version,
  fixed_work_noise:{work:"2e6 sqrt iterations",runs_ms:timing.map(v=>Number(v.toFixed(3))),cv_percent:Number((100*stdev(timing)/mean(timing)).toFixed(3))},
  note:"Shared developer workstation (other processes and agents were running); virtualization status not inspected. This is NOT a pinned CI runner class."};
}

// ---------------------------------------------------------------- parent: orchestration
function runChild(execPath,argv,{stdinKeep=false}={}){
 const child=spawn(execPath,argv,{cwd:root,stdio:["pipe","pipe","pipe"]});
 let out="",err="";child.stdout.on("data",d=>out+=d);child.stderr.on("data",d=>err+=d);
 const done=new Promise((res,rej)=>{child.on("exit",code=>code===0||stdinKeep?res({code,out,err}):rej(new Error(`child exit ${code}: ${err.slice(0,300)}`)));child.on("error",rej);});
 return {child,done,get out(){return out;},get err(){return err;}};
}
async function serverScenario(bundle,mode,rps,seconds,hashes){
 const server=runChild(process.execPath,[here,"--role","server","--mode",mode,"--bundle",bundle,"--hashes",String(hashes)],{stdinKeep:true});
 const port=await new Promise((res,rej)=>{const t=setTimeout(()=>rej(new Error("server did not start")),20000);const poll=setInterval(()=>{const m=/LISTENING (\d+)/.exec(server.out);if(m){clearInterval(poll);clearTimeout(t);res(Number(m[1]));}},20);});
 const load=runChild(process.execPath,[here,"--role","load","--port",String(port),"--rps",String(rps),"--seconds",String(seconds)]);
 const done=await load.done;
 server.child.stdin.end();server.child.kill();await server.done.catch(()=>{});
 return JSON.parse(done.out.trim().split("\n").at(-1));
}
function latencyStats(latencies){const s=[...latencies].sort((a,b)=>a-b);return {count:s.length,p50_ms:quantile(s,0.5),p95_ms:quantile(s,0.95),p99_ms:quantile(s,0.99),max_ms:s.at(-1)};}
function bunPath(){return [process.env.SOUNDPOST_BUN,join(root,".tools/bun-1.3.14/package/bin/bun.exe"),join(root,".tools/bun-1.3.14/package/bin/bun"),"/opt/bun/bin/bun"].filter(Boolean).find(existsSync);}
function buildBundle(bun,entrySource,dir,name,target="node",extra=[]){
 const entry=join(dir,name+".entry.ts"),out=join(dir,name+(target==="browser"?".js":".mjs"));
 writeFileSync(entry,entrySource);
 const r=spawnSync(bun,["build",entry,`--target=${target}`,"--format=esm",...extra,"--outfile",out],{cwd:root,encoding:"utf8"});
 if(r.status!==0)throw new Error(`bundle ${name} failed: ${r.stderr.slice(0,400)}`);
 return out;
}
const fwd=p=>JSON.stringify(p.replaceAll("\\","/"));

async function parentMain(){
 const rps=Number(option("--requests-per-second","1000")),seconds=Number(option("--duration-s","3")),runs=Number(option("--runs","5")),profileRuns=Number(option("--profile-runs","7")),outPath=option("--out",""),only=option("--only","server,profile,bundle").split(",");
 const bun=bunPath();if(!bun)throw new Error("overhead measurement requires SOUNDPOST_BUN or the pinned Bun 1.3.14 to bundle the SDK");
 const dir=mkdtempSync(join(os.tmpdir(),"soundpost-overhead-"));
 const result={fixture:"overhead",schema:1,recorded_at:new Date().toISOString(),command:"node fixtures/sdk/overhead.mjs "+args.join(" "),budgets_from_design_section_13:BUDGET,machine_class:machineClass(),runtimes:{node:process.version,bun:spawnSync(bun,["--version"],{encoding:"utf8"}).stdout.trim()},rows:{}};
 try{
  if(only.includes("server")){
   const sdk=buildBundle(bun,`import {init,installHttp} from ${fwd(join(root,"packages/node/src/index.ts"))};
import {config,signed} from ${fwd(join(root,"packages/core/test/fixture.ts"))};
const receipt=(batch)=>({version:1,batch_id:batch.id,hash:batch.hash,cursor:{group:"9".repeat(32),index:"9007199254740993"},retain_until_ns:"9007199254740994",signal_deadlines:batch.kinds.map(kind=>({kind,retain_until_ns:"9007199254740994"})),dedup_until_ns:"9007199254740995"});
export function makeClient(kind:"acking"|"stalled"){
 const base=config(),keys:Record<string,number>={version:0,org:0,project:0,source:0,revision:0,expires_ns:0,errors:0,logs:0,replay:0,bodies:0,traces:0,jobs:0};
 const policy=signed(JSON.stringify({version:1,org:base.org,project:base.project,source:base.source,revision:"1",expires_ns:"9223372036854775807",errors:true,logs:true,replay:false,bodies:false,traces:true,jobs:false},Object.keys(keys).sort()));
 const transport={async send(batch:any){return kind==="stalled"?{kind:"retryable",retryAfterMs:30000}:{kind:"receipt",receipt:receipt(batch)};},async lookup(){return {kind:"not_found"};},close(){}};
 return init({...base,operations:["request"],policy,transport:transport as never});
}
export {installHttp};
`,dir,"sdk");
   const weights=option("--handler-hashes","3,100").split(",").map(Number);
   result.rows.node_http_server_core_capture=[];
   for(const hashes of weights){
    const collected={baseline:[],capture:[]};
    // Alternate A/B so slow drift hits both equally.
    for(let run=0;run<runs;run++){
     for(const mode of run%2===0?["baseline","capture"]:["capture","baseline"]){
      const r=await serverScenario(sdk,mode,rps,seconds,hashes);
      collected[mode].push({stats:latencyStats(r.latencies_ms),cpu_us_per_request:r.server.cpu_us/Math.max(1,r.server.requests),loop_active_us_per_request:r.server.elu_active_us/Math.max(1,r.server.requests),achieved_rps:r.sent/r.wall_s,errors:r.errors,server:r.server});
     }
    }
    const series=(mode,pick)=>collected[mode].map(pick);
    const metric=(pick)=>({baseline:summary(series("baseline",pick)),capture:summary(series("capture",pick)),...compare(series("baseline",pick),series("capture",pick))});
    const p95=metric(r=>r.stats.p95_ms),cpu=metric(r=>r.cpu_us_per_request),loop=metric(r=>r.loop_active_us_per_request);
    result.rows.node_http_server_core_capture.push({
     workload:`node:http loopback server, deterministic handler (${hashes}x sha256 over 1 KiB + JSON of 16 fields), open-loop load at ${rps} req/s from a separate process, ${seconds} s measured after 1 s warm-up, ${runs} alternating runs per mode; capture = Node SDK installHttp listener (root span per request, one handled error per 100 requests); the server never calls flush(), so once the 1024-record queue fills, spans are dropped as queue_full (saturated mode; delivery cost is in node_http_server_delivered_capture)`,
     handler_hashes:hashes,requests_per_second_requested:rps,
     p95_latency_ms:p95,p99_latency_ms:metric(r=>r.stats.p99_ms),p50_latency_ms:metric(r=>r.stats.p50_ms),
     process_cpu_us_per_request:{note:"process.cpuUsage; on Windows its resolution is the ~15.6 ms scheduler tick, so short windows can read 0 (see the raw values); treat as coarse",...cpu},
     event_loop_active_us_per_request:{note:"performance.eventLoopUtilization active time per request: high-resolution busy time of the single JS thread, a CPU proxy that excludes GC/helper threads",...loop},
     achieved_rps:{baseline:summary(series("baseline",r=>r.achieved_rps)),capture:summary(series("capture",r=>r.achieved_rps))},
     errors:{baseline:series("baseline",r=>r.errors),capture:series("capture",r=>r.errors)},
     budget:{p95_percent:BUDGET.server_p95_latency_percent,cpu_percent:BUDGET.server_cpu_percent},
     verdict:{p95:p95.delta_percent<=BUDGET.server_p95_latency_percent?"within_budget_point_estimate":"exceeds_budget",loop_active_cpu_proxy:loop.delta_percent<=BUDGET.server_cpu_percent?"within_budget_point_estimate":"exceeds_budget",process_cpu:cpu.delta_percent<=BUDGET.server_cpu_percent?"within_budget_point_estimate":"exceeds_budget",p95_difference_distinguishable_from_run_noise:p95.delta_exceeds_two_standard_errors,loop_difference_distinguishable_from_run_noise:loop.delta_exceeds_two_standard_errors,process_cpu_difference_distinguishable_from_run_noise:cpu.delta_exceeds_two_standard_errors},
    });
   }
   // Delivered mode: the same capture plus flush() every 100 ms through the in-process ACKing receipt transport (batching,
   // hashing, receipts and acknowledgement measured; no TLS or network). Same budget; recorded separately, never merged
   // into the saturated row.
   result.rows.node_http_server_delivered_capture=[];
   for(const hashes of weights){
    const collected={baseline:[],"capture-delivered":[]};
    for(let run=0;run<runs;run++){
     for(const mode of run%2===0?["baseline","capture-delivered"]:["capture-delivered","baseline"]){
      const r=await serverScenario(sdk,mode,rps,seconds,hashes);
      collected[mode].push({stats:latencyStats(r.latencies_ms),cpu_us_per_request:r.server.cpu_us/Math.max(1,r.server.requests),loop_active_us_per_request:r.server.elu_active_us/Math.max(1,r.server.requests),achieved_rps:r.sent/r.wall_s,errors:r.errors,server:r.server});
     }
    }
    const series=(mode,pick)=>collected[mode].map(pick);
    const metric=(pick)=>({baseline:summary(series("baseline",pick)),capture:summary(series("capture-delivered",pick)),...compare(series("baseline",pick),series("capture-delivered",pick))});
    const p95=metric(r=>r.stats.p95_ms),cpu=metric(r=>r.cpu_us_per_request),loop=metric(r=>r.loop_active_us_per_request);
    const lost=series("capture-delivered",r=>(r.server.diagnostics.queue_full??0));
    result.rows.node_http_server_delivered_capture.push({
     workload:`same server and load (${hashes} hashes), capture plus flush() every 100 ms through the ACKing receipt transport`,
     handler_hashes:hashes,requests_per_second_requested:rps,
     p95_latency_ms:p95,p99_latency_ms:metric(r=>r.stats.p99_ms),p50_latency_ms:metric(r=>r.stats.p50_ms),
     process_cpu_us_per_request:cpu,event_loop_active_us_per_request:loop,
     achieved_rps:{baseline:summary(series("baseline",r=>r.achieved_rps)),capture:summary(series("capture-delivered",r=>r.achieved_rps))},
     queue_full_drops:lost,
     errors:{baseline:series("baseline",r=>r.errors),capture:series("capture-delivered",r=>r.errors)},
     budget:{p95_percent:BUDGET.server_p95_latency_percent,cpu_percent:BUDGET.server_cpu_percent},
     verdict:{p95:p95.delta_percent<=BUDGET.server_p95_latency_percent?"within_budget_point_estimate":"exceeds_budget",process_cpu:cpu.delta_percent<=BUDGET.server_cpu_percent?"within_budget_point_estimate":"exceeds_budget",delivered_without_queue_full:lost.every(n=>n===0)},
    });
   }
   const sampled=await serverScenario(sdk,"capture-sampled",rps,seconds,weights[0]),stalled=await serverScenario(sdk,"capture-stalled",rps,seconds,weights[0]);
   result.rows.node_queue_acking_transport={workload:`same server (${weights[0]} hashes), ACKing fake transport, queue sampled every 50 ms`,max_queue_bytes:sampled.server.max_queue_bytes,budget_bytes:BUDGET.queue_bytes,within_budget:sampled.server.max_queue_bytes<=BUDGET.queue_bytes};
   result.rows.node_queue_cap_stalled_transport={workload:`same server (${weights[0]} hashes), transport never acknowledges (retryable), ${rps} req/s for ${seconds}+1 s`,max_queue_bytes:stalled.server.max_queue_bytes,queue_bytes_end:stalled.server.queue_bytes_end,budget_bytes:BUDGET.queue_bytes,within_budget:stalled.server.max_queue_bytes<=BUDGET.queue_bytes,diagnostics:stalled.server.diagnostics};
  }
  if(only.includes("profile")){
   const nodeModule=buildBundle(bun,`export {startProfile} from ${fwd(join(root,"packages/node/src/profile.ts"))};\n`,dir,"nodeprofile");
   const row=(runtimeName,exec,module,interval)=>{
    const r=spawnSync(exec,[here,"--role","profile-work","--runtime",runtimeName,"--module",module,"--interval-us",String(interval),"--rounds",String(profileRuns)],{cwd:root,encoding:"utf8",timeout:300000});
    if(r.status!==0)return {runtime:runtimeName,interval_us:interval,not_measured:"child failed: "+(r.stderr||"").slice(0,300)};
    const data=JSON.parse(r.stdout.trim().split("\n").at(-1)),off=data.rows.filter(x=>x.mode==="off"),on=data.rows.filter(x=>x.mode==="on");
    return {runtime:runtimeName,runtime_version:data.runtime_version,interval_us:interval,workload:"fixed work: 16e6 sqrt*sin iterations, same code with and without an explicit runtime_engine_samples profile (start before, stop after, stop cost excluded from the timed region), alternating order",wall_ms:{off:summary(off.map(x=>x.wall_ms)),on:summary(on.map(x=>x.wall_ms)),...compare(off.map(x=>x.wall_ms),on.map(x=>x.wall_ms))},cpu_ms:{off:summary(off.map(x=>x.cpu_ms)),on:summary(on.map(x=>x.cpu_ms)),...compare(off.map(x=>x.cpu_ms),on.map(x=>x.cpu_ms))},samples_per_profile:on.map(x=>x.samples),raw_rows:data.rows,budget:"none approved for runtime supplements (the design's 3% gate is the native profiler); numbers are reported raw"};
   };
   result.rows.node_runtime_profile=[1000,10000].map(i=>row("node",process.execPath,nodeModule,i));
   result.rows.bun_runtime_profile=[1000,10000].map(i=>row("bun",bun,join(root,"packages/bun/src/profile.ts"),i));
   const python=[process.env.SOUNDPOST_PYTHON,join(root,".venv/Scripts/python.exe"),join(root,".venv/bin/python")].filter(Boolean).find(existsSync);
   if(!python||!existsSync(join(root,"sdk/python/src/soundpost/profile.py")))result.rows.python_runtime_profile={not_measured:"no repo venv Python or sdk/python profile module found"};
   else{
    const script=join(dir,"python_workload.py");
    writeFileSync(script,`import json, sys, time
sys.path.insert(0, ${JSON.stringify(join(root,"sdk/python/src").replaceAll("\\","/"))})
from soundpost.profile import ProfileOptions, start_profile
class Client:
    def _own_hook_lease(self, lease): pass
    def _release_hook_lease(self, lease): pass
    def _record_signal_loss(self, *args): return False
    def flush(self, timeout=2.0): raise RuntimeError("no delivery in the overhead workload")
def small(i):
    return i + 1
def call_heavy():
    total = 0
    for i in range(400000):
        total = small(total)
    return total
def arithmetic():
    total = 0
    for i in range(1500000):
        total += i * i % 7
    return total
def work():
    call_heavy(); arithmetic()
method, rounds, interval = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
work(); work()
rows = []
for r in range(rounds):
    for mode in (("off", "on") if r % 2 == 0 else ("on", "off")):
        lease = start_profile(ProfileOptions(method=method, duration_s=60, interval_ms=interval, project_root=${JSON.stringify(dir.replaceAll("\\","/"))}), Client()) if mode == "on" else None
        c0 = time.process_time(); t0 = time.perf_counter(); work(); wall = (time.perf_counter() - t0) * 1000; cpu = (time.process_time() - c0) * 1000
        report = lease.stop() if lease else None
        rows.append({"mode": mode, "wall_ms": round(wall, 3), "cpu_ms": round(cpu, 3), "samples": (report["sample_count"] if report else None), "status": (report["capability"]["status"] if report else None), "events": (sum(int(e["count"]) for e in report["events"]) if report and report.get("events") else None)})
print(json.dumps({"runtime_version": sys.version.split()[0], "rows": rows}))
`);
    result.rows.python_runtime_profile=[["python_monitoring",10],["python_wall_samples",10],["python_wall_samples",2]].map(([method,interval])=>{
     const r=spawnSync(python,[script,method,String(profileRuns),String(interval)],{cwd:root,encoding:"utf8",timeout:600000});
     if(r.status!==0)return {method,interval_ms:interval,not_measured:"child failed: "+(r.stderr||"").slice(-300)};
     const data=JSON.parse(r.stdout.trim().split("\n").at(-1)),off=data.rows.filter(x=>x.mode==="off"),on=data.rows.filter(x=>x.mode==="on");
     return {runtime:"cpython",runtime_version:data.runtime_version,method,interval_ms:interval,workload:"fixed work: 400k calls of a small Python function plus a 1.5M-iteration arithmetic loop (call-heavy worst case for sys.monitoring), same code with and without an explicit profile, alternating order; the profile's own start/stop cost is excluded from the timed region",wall_ms:{off:summary(off.map(x=>x.wall_ms)),on:summary(on.map(x=>x.wall_ms)),...compare(off.map(x=>x.wall_ms),on.map(x=>x.wall_ms))},cpu_ms:{off:summary(off.map(x=>x.cpu_ms)),on:summary(on.map(x=>x.cpu_ms)),...compare(off.map(x=>x.cpu_ms),on.map(x=>x.cpu_ms))},profile_status:on.map(x=>x.status),samples_per_profile:on.map(x=>x.samples),events_per_profile:on.map(x=>x.events),raw_rows:data.rows,budget:"none approved for runtime supplements; raw numbers"};
    });
   }
  }
  if(only.includes("bundle")){
   const gz=file=>gzipSync(readFileSync(file),{level:9}).length,raw=file=>readFileSync(file).length;
   const core=buildBundle(bun,`export * from ${fwd(join(root,"packages/browser/src/index.ts"))};\n`,dir,"browsercore","browser",["--minify"]);
   const replay=buildBundle(bun,`export * from ${fwd(join(root,"packages/browser/src/replay.ts"))};\n`,dir,"browserreplay","browser",["--minify"]);
   const profile=existsSync(join(root,"packages/browser/src/profile.ts"))?buildBundle(bun,`export * from ${fwd(join(root,"packages/browser/src/profile.ts"))};\n`,dir,"browserprofile","browser",["--minify"]):undefined;
   result.rows.browser_bundle_sizes={method:"bun build --target=browser --minify (pinned Bun), zlib gzip level 9 of the single output file, one bundle per published entry: `@soundpost/browser` (core), `@soundpost/browser/replay`, `@soundpost/browser/profile`",
    note:"The core entry (packages/browser/src/index.ts) imports neither the replay recorder nor the profiler; each is its own entry an application opts into, and the replay bundle measured here is the replay entry alone. Budget: core <=40 KiB gzip, replay separate <=60 KiB gzip.",
    browser_index:{raw_bytes:raw(core),gzip_bytes:gz(core),budget_gzip_bytes:BUDGET.browser_core_gzip_bytes,within_budget:gz(core)<=BUDGET.browser_core_gzip_bytes},
    replay_only:{raw_bytes:raw(replay),gzip_bytes:gz(replay),budget_gzip_bytes:BUDGET.browser_replay_gzip_bytes,within_budget:gz(replay)<=BUDGET.browser_replay_gzip_bytes},
    profile_module:profile?{raw_bytes:raw(profile),gzip_bytes:gz(profile)}:{not_measured:"packages/browser/src/profile.ts absent"}};
   result.rows.browser_recorder_mutation_batch_p95={not_measured:"requires a real browser mutation-storm run; fixtures/sdk/replay/recorder.spec.ts asserts behavior, not this timing budget. Budget 5 ms p95 per batch is NOT claimed."};
  }
  result.rows.python_core_capture={not_measured:"Python handler capture overhead is not measured by this script (no Python HTTP workload is driven here); the 5% p95/CPU budget for Python core capture is NOT claimed."};
 }finally{rmSync(dir,{recursive:true,force:true});}
 const text=JSON.stringify(result,null,1);
 if(outPath)writeFileSync(outPath,text+"\n");
 process.stdout.write(text+"\n");
}

const role=option("--role","");
if(role==="server")await roleServer();
else if(role==="load")await roleLoad();
else if(role==="profile-work")await roleProfileWork();
else await parentMain();
