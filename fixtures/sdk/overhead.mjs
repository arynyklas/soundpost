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
const BUDGET={server_p95_latency_percent:5,server_cpu_percent:5,queue_bytes:2*1024*1024,browser_core_gzip_bytes:40*1024,browser_replay_gzip_bytes:60*1024,recorder_batch_p95_ms:5};

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
// ---------------------------------------------------------------- role: server-bun (spawned by the parent, run by Bun)
async function roleServerBun(){
 const mode=option("--mode","baseline"),bundle=option("--bundle",""),hashes=Number(option("--hashes","3"));
 let count=0,client;
 let handler=()=>new Response(requestWork(count++,hashes),{headers:{"content-type":"application/json"}});
 if(mode!=="baseline"){
  const sdk=await import(pathToFileURL(bundle).href);
  client=sdk.makeClient();
  const inner=handler;
  handler=sdk.installServe(client,{operation:"request"}).handler(request=>{if(count%100===99)client.captureException(new Error("fixture handled error"));return inner(request);});
  if(mode==="capture-delivered"){const flusher=setInterval(()=>{void client.flush(1000).catch(()=>{});},100);flusher.unref();}
 }
 const server=Bun.serve({hostname:"127.0.0.1",port:0,fetch(request,srv){
  if(request.url.endsWith("/__cpu")){const c=process.cpuUsage();return new Response(JSON.stringify({user_us:c.user,system_us:c.system,elu_active_ms:0,requests:count,queue_bytes:client?client.bufferedRecords().reduce((n,r)=>n+Buffer.byteLength(r),0):0,max_queue_bytes:0,diagnostics:client?client.diagnostics():{}}));}
  return handler(request,srv);
 }});
 process.stdout.write("LISTENING "+server.port+"\n");
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
// --cpu-prof-dir DIR: every non-baseline server child writes a V8 CPU profile (100 us sampling) there when it ends; profiling
// perturbs the run, so a profiled run is for attributing cost, never for the budget rows.
const cpuProfDir=option("--cpu-prof-dir","");
async function serverScenario(target,mode,rps,seconds,hashes){
 // `target` is a Node SDK bundle path (served by this node binary) or a function (mode,hashes)=>({exec,args}) for another runtime.
 const profiled=typeof target==="string"&&cpuProfDir!==""&&mode!=="baseline";
 const spec=typeof target==="string"?{exec:process.execPath,args:[...(profiled?["--cpu-prof","--cpu-prof-dir="+cpuProfDir,"--cpu-prof-interval=100","--cpu-prof-name=server-"+mode+"-"+hashes+"-"+Date.now()+".cpuprofile"]:[]),here,"--role","server","--mode",mode,"--bundle",target,"--hashes",String(hashes)]}:target(mode,hashes);
 const server=runChild(spec.exec,spec.args,{stdinKeep:true});
 const port=await new Promise((res,rej)=>{const t=setTimeout(()=>rej(new Error("server did not start")),20000);const poll=setInterval(()=>{const m=/LISTENING (\d+)/.exec(server.out);if(m){clearInterval(poll);clearTimeout(t);res(Number(m[1]));}},20);});
 const load=runChild(process.execPath,[here,"--role","load","--port",String(port),"--rps",String(rps),"--seconds",String(seconds)]);
 const done=await load.done;
 server.child.stdin.end();
 // A profiled child must exit by itself (process.exit(0) on stdin end) so the profile is written.
 if(profiled)await Promise.race([server.done,sleep(10000)]);
 server.child.kill();await server.done.catch(()=>{});
 return JSON.parse(done.out.trim().split("\n").at(-1));
}
/** Delivered-mode rows for a runtime other than Node: the same deterministic handler, load and alternating baseline/capture runs as node_http_server_delivered_capture, judged on the same budgets. `target` is a function (mode,hashes)=>{exec,args}; the server child prints `LISTENING <port>` and answers /__cpu with its CPU counters. No event-loop series: only Node has eventLoopUtilization. */
async function deliveredRows(target,weights,rps,seconds,runs,description){
 const rows=[];
 for(const hashes of weights){
  const collected={baseline:[],"capture-delivered":[]};
  for(let run=0;run<runs;run++){
   for(const mode of run%2===0?["baseline","capture-delivered"]:["capture-delivered","baseline"]){
    const r=await serverScenario(target,mode,rps,seconds,hashes);
    collected[mode].push({stats:latencyStats(r.latencies_ms),cpu_us_per_request:r.server.cpu_us/Math.max(1,r.server.requests),achieved_rps:r.sent/r.wall_s,errors:r.errors,server:r.server});
   }
  }
  const series=(mode,pick)=>collected[mode].map(pick);
  const metric=pick=>({baseline:summary(series("baseline",pick)),capture:summary(series("capture-delivered",pick)),...compare(series("baseline",pick),series("capture-delivered",pick))});
  const p95=metric(r=>r.stats.p95_ms),cpu=metric(r=>r.cpu_us_per_request),lost=series("capture-delivered",r=>(r.server.diagnostics.queue_full??0));
  rows.push({
   workload:`${description}; ${hashes}x sha256 over 1 KiB + JSON of 16 fields per request, open-loop load at ${rps} req/s from a separate process, ${seconds} s measured after 1 s warm-up, ${runs} alternating runs per mode; capture mode flushes every 100 ms through the ACKing receipt transport (batching, hashing, receipts and acknowledgement measured; no TLS or network)`,
   handler_hashes:hashes,requests_per_second_requested:rps,
   p95_latency_ms:p95,p99_latency_ms:metric(r=>r.stats.p99_ms),p50_latency_ms:metric(r=>r.stats.p50_ms),
   process_cpu_us_per_request:cpu,
   achieved_rps:{baseline:summary(series("baseline",r=>r.achieved_rps)),capture:summary(series("capture-delivered",r=>r.achieved_rps))},
   queue_full_drops:lost,
   errors:{baseline:series("baseline",r=>r.errors),capture:series("capture-delivered",r=>r.errors)},
   budget:{p95_percent:BUDGET.server_p95_latency_percent,cpu_percent:BUDGET.server_cpu_percent},
   verdict:{p95:p95.delta_percent<=BUDGET.server_p95_latency_percent?"within_budget_point_estimate":"exceeds_budget",process_cpu:cpu.delta_percent<=BUDGET.server_cpu_percent?"within_budget_point_estimate":"exceeds_budget",delivered_without_queue_full:lost.every(n=>n===0)},
  });
 }
 return rows;
}
/** The SDK bundle entry of a non-Node runtime: the same fixture policy, ACKing in-process transport and operation as the Node bundle, with the runtime package's own init and `installName` integration. */
function sdkEntry(index,installName){
 return `import {init,${installName}} from ${fwd(index)};
import {config,signed} from ${fwd(join(root,"packages/core/test/fixture.ts"))};
const receipt=(batch)=>({version:1,batch_id:batch.id,hash:batch.hash,cursor:{group:"9".repeat(32),index:"9007199254740993"},retain_until_ns:"9007199254740994",signal_deadlines:batch.kinds.map(kind=>({kind,retain_until_ns:"9007199254740994"})),dedup_until_ns:"9007199254740995"});
export function makeClient(){
 const base=config(),keys:Record<string,number>={version:0,org:0,project:0,source:0,revision:0,expires_ns:0,errors:0,logs:0,replay:0,bodies:0,traces:0,jobs:0};
 const policy=signed(JSON.stringify({version:1,org:base.org,project:base.project,source:base.source,revision:"1",expires_ns:"9223372036854775807",errors:true,logs:true,replay:false,bodies:false,traces:true,jobs:false},Object.keys(keys).sort()));
 const transport={async send(batch:any){return {kind:"receipt",receipt:receipt(batch)};},async lookup(){return {kind:"not_found"};},close(){}};
 return init({...base,operations:["request"],policy,transport:transport as never});
}
export {${installName}};
`;
}
/** The Python server child: a WSGI application behind http.server's threading server, wrapped by the SDK's WSGIMiddleware in capture mode. Same handler work as the Node and Bun servers. */
function pythonServerScript(sdkSrc){
 return `import base64, hashlib, io, json, os, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, ${JSON.stringify(sdkSrc.replaceAll("\\","/"))})
mode = sys.argv[sys.argv.index("--mode") + 1]
hashes = int(sys.argv[sys.argv.index("--hashes") + 1])
payload = bytes([7]) * 1024
def request_work(seed):
    digest = payload
    tag = str(seed).encode()
    for _ in range(hashes):
        digest = hashlib.sha256(digest + tag).digest()
    body = {}
    for i in range(16):
        body["field" + str(i)] = (digest[i] * (i + 1)) % 977
    return json.dumps(body, separators=(",", ":")).encode()
count = [0]
client = None
def app(environ, start_response):
    n = count[0]
    count[0] = n + 1
    if client is not None and n % 100 == 99:
        client.capture_exception(ValueError("fixture handled error"))
    body = request_work(n)
    start_response("200 OK", [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
    return [body]
if mode != "baseline":
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from soundpost import Config, SignedPolicy, Resource, init
    from soundpost.integrations.wsgi import WSGIMiddleware
    from soundpost.transport import Outcome
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    def b64(value): return base64.urlsafe_b64encode(value).rstrip(b"=").decode()
    org, project, source, build = "1" * 32, "2" * 32, "3" * 32, "4" * 32
    doc = json.dumps(dict(version=1, org=org, source=source, project=project, revision="1", expires_ns="9223372036854775807", errors=True, logs=True, replay=False, bodies=False, traces=True), sort_keys=True, separators=(",", ":")).encode()
    class Transport:
        def send(self, batch, deadline):
            receipt = {"version": 1, "batch_id": batch.id, "hash": batch.hash, "cursor": {"group": "9" * 32, "index": "9007199254740993"}, "retain_until_ns": "9007199254740994", "signal_deadlines": [{"kind": k, "retain_until_ns": "9007199254740994"} for k in batch.kinds], "dedup_until_ns": "9007199254740995"}
            return Outcome("receipt", receipt)
        def lookup(self, batch, deadline): return Outcome("not_found")
        def close(self): pass
    client = init(Config(org=org, project=project, source=source, endpoint="https://example.invalid/ingest/v1/batches", credential="SECRET", build=build,
        policy=SignedPolicy(1, "Ed25519", "test", b64(doc), b64(key.sign(doc))), trusted_keys={"test": key.public_key().public_bytes_raw()},
        resource=Resource("6" * 32, "7" * 32, build, "worker-1"), operations=("request",), transport=Transport()))
    app = WSGIMiddleware(app, client, operation="request")
    def flusher():
        import time
        while True:
            time.sleep(0.1)
            try: client.flush(1.0)
            except Exception: pass
    if mode == "capture-delivered":
        threading.Thread(target=flusher, daemon=True).start()
def cpu_json():
    t = os.times()
    return json.dumps({"requests": count[0], "user_us": t.user * 1e6, "system_us": t.system * 1e6, "elu_active_ms": 0, "queue_bytes": 0, "max_queue_bytes": 0, "diagnostics": client.diagnostics() if client is not None else {}}).encode()
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *args): pass
    def do_GET(self):
        if self.path == "/__cpu":
            body = cpu_json()
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
        environ = {"REQUEST_METHOD": "GET", "PATH_INFO": self.path, "SERVER_PROTOCOL": "HTTP/1.1", "wsgi.version": (1, 0), "wsgi.url_scheme": "http", "wsgi.input": io.BytesIO(b""), "wsgi.errors": sys.stderr, "wsgi.multithread": True, "wsgi.multiprocess": False, "wsgi.run_once": False}
        for name, value in self.headers.items():
            environ["HTTP_" + name.upper().replace("-", "_")] = value
        sent = []
        def start_response(status, headers, exc_info=None):
            sent[:] = [status, headers]
            return lambda data: None
        result = app(environ, start_response)
        try:
            body = b"".join(result)
        finally:
            close = getattr(result, "close", None)
            if close is not None: close()
        self.send_response(int(sent[0][:3]))
        for name, value in sent[1]: self.send_header(name, value)
        self.end_headers(); self.wfile.write(body)
class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 256
server = Server(("127.0.0.1", 0), Handler)
sys.stdout.write("LISTENING " + str(server.server_address[1]) + chr(10)); sys.stdout.flush()
server.serve_forever()
`;
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

/** Runs fixtures/sdk/replay/mutation-batch.spec.ts (real Chrome through Playwright) and returns the harness row: the spec's own MUTATION_BATCH_P95 report judged against the 5 ms p95 budget, or a not_measured statement of why the browser run produced no report. SOUNDPOST_CHROME names the browser (default Playwright's Chromium); SOUNDPOST_CHROME_ARGS passes launch flags. */
function recorderBatchRow(bunPathValue){
 const cli=join(root,"web/node_modules/@playwright/test/cli.js");
 if(!existsSync(cli))return {not_measured:"Playwright (web/node_modules/@playwright/test) is not installed in this checkout"};
 const r=spawnSync(process.execPath,[cli,"test","-c",join(root,"fixtures/sdk/replay/budget.config.ts"),"--reporter=json","mutation-batch.spec.ts"],{cwd:join(root,"web"),encoding:"utf8",timeout:600000,maxBuffer:64*1024*1024,env:{...process.env,SOUNDPOST_BUN:bunPathValue,NODE_PATH:join(root,"web/node_modules")}});
 return recorderBatchFromReport(r.stdout||"",r.status,(r.stderr||"").slice(-300));
}
/** Pure part of recorderBatchRow: report JSON text from `playwright test --reporter=json` -> the overhead row. The budget is compared here, never edited. */
function recorderBatchFromReport(stdout,exitCode,stderrTail=""){
 let report;try{report=JSON.parse(stdout);}catch{return {not_measured:"Playwright printed no parseable report (exit "+exitCode+"): "+stderrTail};}
 let text="";const walk=suite=>{for(const spec of suite.specs??[])for(const t of spec.tests??[])for(const res of t.results??[])for(const o of res.stdout??[])text+=o.text??"";for(const s of suite.suites??[])walk(s);};
 for(const s of report.suites??[])walk(s);
 const line=text.split("\n").find(l=>l.includes("MUTATION_BATCH_P95 {"));
 if(!line)return {not_measured:"the spec produced no MUTATION_BATCH_P95 report (exit "+exitCode+"): "+((report.errors??[]).map(e=>e.message).join("; ")||stderrTail).slice(0,300)};
 let data;try{data=JSON.parse(line.slice(line.indexOf("MUTATION_BATCH_P95 ")+"MUTATION_BATCH_P95 ".length));}catch{return {not_measured:"the MUTATION_BATCH_P95 line is not JSON"};}
 const rows=Array.isArray(data.rows)?data.rows:[];
 if(rows.length===0)return {not_measured:"the MUTATION_BATCH_P95 report has no burst rows"};
 const worst=Math.max(...rows.map(x=>x.p95_ms));
 return {workload:"real Chrome, canary page with replay consent: 60 bursts per size (10, 100, 400 nodes) of insert/rewrite/attribute/remove; the page's MutationObserver is wrapped so the recorder's own handler is timed with performance.now() per batch",
  browser:data.browser??null,playwright_exit_code:exitCode,budget_p95_ms:BUDGET.recorder_batch_p95_ms,rows,worst_p95_ms:worst,
  verdict:{p95:worst<=BUDGET.recorder_batch_p95_ms?"within_budget":"exceeds_budget"},
  note:"the recorder's 2 MiB queue bound is measured separately (browser_recorder_queue_bound)"};
}
/** Runs fixtures/sdk/replay/queue-bound.ts under Bun (the recorder filling the browser Client's real delivery queue behind a transport that never completes) and returns the row: the observed maxima judged against the 2 MiB bound, or a not_measured statement. */
function recorderQueueRow(bunPathValue){
 const r=spawnSync(bunPathValue,["run",join(root,"fixtures/sdk/replay/queue-bound.ts")],{cwd:root,encoding:"utf8",timeout:300000,maxBuffer:16*1024*1024});
 return recorderQueueFromOutput(r.stdout||"",r.status,(r.stderr||"").slice(-300));
}
/** Pure part of recorderQueueRow: the runner's stdout -> the overhead row. The budget is compared here, never edited. */
function recorderQueueFromOutput(stdout,exitCode,stderrTail=""){
 const line=stdout.split("\n").find(l=>l.startsWith("RECORDER_QUEUE_BOUND {"));
 if(!line)return {not_measured:"the queue-bound runner printed no RECORDER_QUEUE_BOUND report (exit "+exitCode+"): "+stderrTail};
 let data;try{data=JSON.parse(line.slice("RECORDER_QUEUE_BOUND ".length));}catch{return {not_measured:"the RECORDER_QUEUE_BOUND line is not JSON"};}
 if(typeof data.max_queue_bytes!=="number")return {not_measured:"the RECORDER_QUEUE_BOUND report has no max_queue_bytes"};
 return {...data,bun_exit_code:exitCode,budget_bytes:BUDGET.queue_bytes,verdict:{queue_bytes:data.max_queue_bytes<=BUDGET.queue_bytes?"within_budget":"exceeds_budget"}};
}

async function parentMain(){
 const rps=Number(option("--requests-per-second","1000")),seconds=Number(option("--duration-s","3")),runs=Number(option("--runs","5")),profileRuns=Number(option("--profile-runs","7")),outPath=option("--out",""),only=option("--only","server,bun,python,profile,bundle,recorder").split(",");
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
  }
  // Recorder cost per MutationObserver batch (03.09-W3): the committed real-browser spec fixtures/sdk/replay/mutation-batch.spec.ts run through Playwright; its MUTATION_BATCH_P95 line is the measurement, judged against the 5 ms p95 budget here. A failing budget is a measurement, so the spec's own exit code is recorded, not required to be 0.
  if(only.includes("recorder")){result.rows.browser_recorder_mutation_batch_p95=recorderBatchRow(bun);result.rows.browser_recorder_queue_bound=recorderQueueRow(bun);}
  else{result.rows.browser_recorder_mutation_batch_p95={not_measured:"--only did not include recorder"};result.rows.browser_recorder_queue_bound={not_measured:"--only did not include recorder"};}
  // Bun core server capture: the same deterministic handler and open-loop load against Bun.serve, with and without the Bun SDK's serve integration (installServe), flush() every 100 ms through the in-process ACKing transport.
  if(only.includes("bun")){
   const bunSdk=buildBundle(bun,sdkEntry(join(root,"packages/bun/src/index.ts"),"installServe"),dir,"bunsdk","bun");
   const rows=await deliveredRows((mode,hashes)=>({exec:bun,args:[here,"--role","server-bun","--mode",mode,"--bundle",bunSdk,"--hashes",String(hashes)]}),option("--handler-hashes","3,100").split(",").map(Number),rps,seconds,runs,"Bun.serve (Bun SDK installServe: root span per request, one handled error per 100 requests)");
   result.rows.bun_http_server_delivered_capture=rows.map(row=>({runtime:"bun",runtime_version:result.runtimes.bun,...row}));
  }
  // Python core server capture: a WSGI application (stdlib http.server front end, one thread per connection) with and without the Python SDK's WSGI middleware.
  if(only.includes("python")){
   const python=[process.env.SOUNDPOST_PYTHON,join(root,".venv/Scripts/python.exe"),join(root,".venv/bin/python")].filter(Boolean).find(existsSync);
   if(!python)result.rows.python_http_server_delivered_capture={not_measured:"no SOUNDPOST_PYTHON or repo venv Python found"};
   else{
    const script=join(dir,"python_server.py");writeFileSync(script,pythonServerScript(join(root,"sdk/python/src")));
    const version=spawnSync(python,["-c","import sys;print(sys.version.split()[0])"],{encoding:"utf8"}).stdout.trim();
    const probe=spawnSync(python,["-c","import cryptography"],{encoding:"utf8"});
    if(probe.status!==0)result.rows.python_http_server_delivered_capture={not_measured:"the Python at "+python+" cannot import cryptography (a dependency of the SDK): "+(probe.stderr||"").slice(-200)};
    else{
     const rows=await deliveredRows((mode,hashes)=>({exec:python,args:[script,"--mode",mode,"--hashes",String(hashes)]}),option("--handler-hashes","3,100").split(",").map(Number),rps,seconds,runs,"WSGI application on http.server (Python SDK WSGIMiddleware: root span per request, one handled error per 100 requests)");
     result.rows.python_http_server_delivered_capture=rows.map(row=>({runtime:"cpython",runtime_version:version,...row}));
    }
   }
  }
  if(!only.includes("python"))result.rows.python_http_server_delivered_capture={not_measured:"--only did not include python"};
  if(!only.includes("bun"))result.rows.bun_http_server_delivered_capture={not_measured:"--only did not include bun"};
 }finally{rmSync(dir,{recursive:true,force:true});}
 const text=JSON.stringify(result,null,1);
 if(outPath)writeFileSync(outPath,text+"\n");
 process.stdout.write(text+"\n");
}

const role=option("--role","");
if(role==="server")await roleServer();
else if(role==="server-bun")await roleServerBun();
else if(role==="load")await roleLoad();
else if(role==="profile-work")await roleProfileWork();
else await parentMain();
