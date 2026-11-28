// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Composes MEASURED runtime-supplement evidence into the SDK qualification manifest. It runs the real runtime fixtures
// (Node, Bun, CPython, real Chrome) with their own exit codes and records what they observed; it never copies expectations.
// One run observes one Node (the one it runs under) on one host, so the manifest is built from several runs:
//   node fixtures/sdk/qualify.mjs --run-out run.node22.json --run-only [--overhead result.json] [--skip node,bun,python,browser]   one sealed run, manifest untouched
//   node fixtures/sdk/qualify.mjs --merge run.node22.json,run.node24.json [--manifest fixtures/sdk/qualification.json] [--dry-run]   merge sealed runs
//   node fixtures/sdk/qualify.mjs [--manifest fixtures/sdk/qualification.json] [--run-out run.json]                                run, then merge that run
// Every run is stamped with the source digest of this tree (`go run ./build source-digest`) and sealed with a digest over its content and
// host; every merged row is bound to {run digest, runtime, host id, source stamp}; a run built against another source is refused; a rerun
// replaces exactly the rows it produced (rules and reasons: fixtures/sdk/qualify-merge.mjs).
// Only the top-level `measured_evidence` object is written; the pre-existing frozen dependency/target rows are never flipped.
// A row that cannot be run here is recorded as `unqualified` with its reason, never as passed.
import {spawnSync} from "node:child_process";
import {existsSync,readFileSync,writeFileSync} from "node:fs";
import os from "node:os";
import {dirname,join,resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {createHash} from "node:crypto";
import {MergeError,RUN_SCHEMA,makeHost,mergeRuns,sealRun} from "./qualify-merge.mjs";

const here=fileURLToPath(import.meta.url),root=resolve(dirname(here),"../..");
const args=process.argv.slice(2);
const option=(name,fallback)=>{const i=args.indexOf(name);return i>=0&&i+1<args.length?args[i+1]:fallback;};
const manifestPath=resolve(root,option("--manifest","fixtures/sdk/qualification.json")),overheadPath=option("--overhead",""),skip=option("--skip","").split(",").filter(Boolean),dryRun=args.includes("--dry-run");
const runOut=option("--run-out",""),runOnly=args.includes("--run-only"),mergeFiles=option("--merge","").split(",").filter(Boolean);
if(runOnly&&!runOut||runOnly&&mergeFiles.length||mergeFiles.length&&(runOut||overheadPath||skip.length)){process.stderr.write("qualify: --run-only needs --run-out and cannot be combined with --merge; --merge takes no --run-out, --overhead or --skip (it runs nothing)\n");process.exit(2);}
const LINUX_NODE_SHA256="1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce";// node-v22.23.4-linux-x64.tar.xz, nodejs.org SHASUMS256.txt
const clean=text=>String(text??"").replaceAll(root,"<repo>").replaceAll(root.replaceAll("\\","/"),"<repo>").replaceAll(os.homedir(),"<home>");
const rel=p=>clean(p);

function find(candidates){return candidates.filter(Boolean).find(existsSync);}
const bun=find([process.env.SOUNDPOST_BUN,join(root,".tools/bun-1.3.14/package/bin/bun.exe"),join(root,".tools/bun-1.3.14/package/bin/bun"),"/opt/bun/bin/bun"]);
const python=find([process.env.SOUNDPOST_PYTHON,join(root,".venv/Scripts/python.exe"),join(root,".venv/bin/python")]);

/** Runs one fixture process, keeps its real exit code and the last JSON line it printed. */
function run(id,command,argv,{prefix="",env={},timeout=600000}={}){
 const started=Date.now(),r=spawnSync(command,argv,{cwd:root,encoding:"utf8",timeout,env:{...process.env,...env},maxBuffer:64*1024*1024});
 const lines=(r.stdout||"").split(/\r?\n/).filter(l=>l.startsWith(prefix)&&l.slice(prefix.length).trim().startsWith("{"));
 let evidence;try{evidence=lines.length?JSON.parse(lines.at(-1).slice(prefix.length)):undefined;}catch{evidence=undefined;}
 return {id,command:[rel(command),...argv.map(rel)].join(" "),exit_code:r.status,signal:r.signal,duration_ms:Date.now()-started,evidence,stderr_tail:clean((r.stderr||"").slice(-400)),stdout:r.stdout||""};
}
function version(command,flag="--version"){const r=spawnSync(command,[flag],{encoding:"utf8"});return (r.stdout||r.stderr||"").trim().split("\n")[0];}
/** The identity of the tree this run belongs to. It fails closed: without a digest nothing is run and nothing is written. */
function sourceDigest(){
 const r=spawnSync("go",["run","./build","source-digest","--root",root],{cwd:root,encoding:"utf8"}),out=(r.stdout||"").trim();
 if(r.status!==0||!/^[0-9a-f]{64}$/.test(out)){process.stderr.write(`qualify: cannot compute the source stamp: \`go run ./build source-digest\` failed in ${root}\n${clean((r.stderr||"").slice(-400))}\n`);process.exit(2);}
 return out;
}

/** Runs every fixture this host can and returns what it observed and what it could not run. */
function collect(){

const rows=[],unqualified=[];
// A note about a runtime that could not be run here is answered by an observed row of that runtime from another run.
const NOTE_KIND={"node-runtime_engine_samples":"runtime:node","bun-runtime_engine_samples":"runtime:bun","cpython-python_monitoring+python_wall_samples":"runtime:cpython","chrome-js_self_profile":"runtime:chrome"};
const note=(row,reason)=>unqualified.push({row,reason,...(NOTE_KIND[row]?{kind:NOTE_KIND[row]}:{})});

// ------------------------------------------------------------------ Node
if(!skip.includes("node")){
 const r=run("node",process.execPath,[join(root,"fixtures/sdk/profiles/node.mjs")]);
 rows.push({id:`node-${process.version}-${process.platform}-${process.arch}-runtime_engine_samples`,runtime:"node",version:process.version,v8:process.versions.v8,platform:process.platform,arch:process.arch,method:"runtime_engine_samples",fixture:"fixtures/sdk/profiles/node.mjs",command:r.command,exit_code:r.exit_code,duration_ms:r.duration_ms,status:r.exit_code===0&&r.evidence&&r.evidence.failed?.length===0?"observed":"failed",failed_checks:r.evidence?.failed??null,check_count:r.evidence?.checks?.length??null,stderr_tail:r.stderr_tail,evidence:r.evidence?.results??null});
}else note("node-runtime_engine_samples","skipped by --skip");

// ------------------------------------------------------------------ Bun
if(!skip.includes("bun")&&bun){
 const r=run("bun",bun,[join(root,"fixtures/sdk/profiles/bun.ts")]);
 rows.push({id:`bun-${r.evidence?.runtime?.version??version(bun)}-${process.platform}-${process.arch}-runtime_engine_samples`,runtime:"bun",version:r.evidence?.runtime?.version??version(bun),revision:r.evidence?.runtime?.revision??null,platform:process.platform,arch:process.arch,method:"runtime_engine_samples",fixture:"fixtures/sdk/profiles/bun.ts",command:r.command,exit_code:r.exit_code,duration_ms:r.duration_ms,status:r.exit_code===0&&r.evidence&&r.evidence.failed?.length===0?"observed":"failed",failed_checks:r.evidence?.failed??null,check_count:r.evidence?.checks?.length??null,stderr_tail:r.stderr_tail,evidence:r.evidence?.results??null});
}else note("bun-runtime_engine_samples",skip.includes("bun")?"skipped by --skip":"pinned Bun 1.3.14 not found; advertised Bun profiling stays blocked.");

// ------------------------------------------------------------------ Python
if(!skip.includes("python")&&python){
 const r=run("python",python,[join(root,"fixtures/sdk/profiles/python.py")]);
 rows.push({id:`cpython-${r.evidence?.python??version(python)}-${process.platform}-${process.arch}-python_monitoring+python_wall_samples`,runtime:"cpython",version:r.evidence?.python??null,platform:process.platform,arch:process.arch,methods:["python_monitoring","python_wall_samples"],fixture:"fixtures/sdk/profiles/python.py",command:r.command,exit_code:r.exit_code,duration_ms:r.duration_ms,status:r.exit_code===0&&r.evidence?"observed":"failed",stderr_tail:r.stderr_tail,evidence:r.evidence?.results??null});
}else note("cpython-python_monitoring+python_wall_samples",skip.includes("python")?"skipped by --skip":"repo venv Python not found.");
note("cpython-free-threaded-jit-subinterpreters-pypy","start unqualified by design and were not exercised (the free-threaded refusal is covered only by a monkeypatched unit test, not a real free-threaded build).");

// ------------------------------------------------------------------ Browser (real Chrome through Playwright)
if(!skip.includes("browser")){
 const spec=join(root,"fixtures/sdk/profiles/browser.spec.ts");
 let browser;
 if(!existsSync(spec))note("chrome-js_self_profile","fixtures/sdk/profiles/browser.spec.ts is missing.");
 else if(process.platform==="linux"){
  const node=process.env.SOUNDPOST_LINUX_NODE??process.execPath,chrome=join(root,".tools/chrome-linux156/chrome-linux64/chrome");
  if(!existsSync(chrome)||!bun)note("chrome-js_self_profile","Linux Chrome 156 under .tools or the Linux Bun is missing.");
  else browser=run("browser",node,[join(root,"web/node_modules/@playwright/test/cli.js"),"test","-c","fixtures/sdk/profiles/playwright.config.ts","--project=chromium","--output="+join(os.tmpdir(),"soundpost-qualify-pw")],{prefix:"SOUNDPOST_PROFILE_EVIDENCE ",env:{SOUNDPOST_BUN:bun,SOUNDPOST_CHROME:chrome,NODE_PATH:join(root,"web/node_modules")}});
 }else if(process.platform==="win32"&&spawnSync("wsl.exe",["-d","Ubuntu","--exec","true"]).status===0){
  const drive=/^([A-Za-z]):[\\/](.*)$/.exec(root),wslRoot=drive?`/mnt/${drive[1].toLowerCase()}/${drive[2].replaceAll("\\","/")}`:undefined;
  const tarball=process.env.SOUNDPOST_LINUX_NODE_TARBALL??"/tmp/node22.tar.xz",extract="/tmp/soundpost-qualify-node";
  const shell=`set -e; ls /mnt/${drive?.[1].toLowerCase()??"x"} >/dev/null || mount -t drvfs ${drive?.[1].toUpperCase()??"X"}: /mnt/${drive?.[1].toLowerCase()??"x"} 2>/dev/null || true; `+
   `[ -x ${extract}/node-v22.23.4-linux-x64/bin/node ] || { [ "$(sha256sum ${tarball} | cut -d' ' -f1)" = "${LINUX_NODE_SHA256}" ] && mkdir -p ${extract} && tar -xJf ${tarball} -C ${extract}; }; `+
   `cd ${wslRoot} && HOME=/tmp/soundpost-qualify-home SOUNDPOST_BUN=/opt/bun/bin/bun SOUNDPOST_CHROME=${wslRoot}/.tools/chrome-linux156/chrome-linux64/chrome NODE_PATH=${wslRoot}/web/node_modules ${extract}/node-v22.23.4-linux-x64/bin/node ${wslRoot}/web/node_modules/@playwright/test/cli.js test -c fixtures/sdk/profiles/playwright.config.ts --project=chromium --output=/tmp/soundpost-qualify-pw`;
  if(!wslRoot)note("chrome-js_self_profile","repository root is not on a drive letter WSL can mount.");
  else browser=run("browser","wsl.exe",["-d","Ubuntu","--exec","sh","-c",shell],{prefix:"SOUNDPOST_PROFILE_EVIDENCE ",timeout:900000});
 }else note("chrome-js_self_profile","no Linux host or WSL with Chrome 156 available.");
 if(browser){
  const out=browser.stdout,passed=/(\d+) passed/.exec(out)?.[1],failed=/(\d+) failed/.exec(out)?.[1];
  const e=browser.evidence,chromeVersion=e?.with_header?.chrome??e?.chrome??null;
  rows.push({id:`chrome-${chromeVersion??"unknown"}-linux-x64-browser_js_self_profile`,runtime:"chrome",version:chromeVersion,platform:"linux (WSL2 Ubuntu, headless; the page's emulated user agent claims Windows)",arch:"x64",method:"browser_js_self_profile",fixture:"fixtures/sdk/profiles/browser.spec.ts",command:browser.command.replace(/SOUNDPOST_CHROME=\S+/,"SOUNDPOST_CHROME=<chrome156>").replace(/\/mnt\/[a-z]\/\S+?(?=\/(?:web|\.tools|fixtures)\b| &&)/g,"<repo>"),exit_code:browser.exit_code,duration_ms:browser.duration_ms,status:browser.exit_code===0&&e?"observed":"failed",playwright_summary:{passed:passed?Number(passed):null,failed:failed?Number(failed):0},stderr_tail:browser.stderr_tail,evidence:e??null});
 }
}else note("chrome-js_self_profile","skipped by --skip");
for(const row of ["chrome-142.0.7444.59 (frozen manifest target; Chrome 156.0 was executed instead)","edge-142","firefox-144.0.2 (no ordinary-page sampling API; unsupported capability only asserted with a fake in unit tests)","safari-26.0.1 (not available; WebKit in Playwright is not a Safari release certification)","chrome-windows-macos","browser-headed-run"])note(row,"not run on this machine.");

// ------------------------------------------------------------------ rows not exercised by this script
note("critical-paths-http-db-errors-artifacts-jobs-replay-through-real-backend","fixtures/sdk/{node,bun,python,jobs}/* need private fixture configuration (SOUNDPOST_FIXTURE_*), a PostgreSQL DSN and a running backend; qualify.mjs does not run them. Earlier per-task evidence exists in the 03.0x reports and is not repeated or inferred here.");
note("runtime-supplement-export-through-C03","not exercised by this script: its fixtures run without a delivery transport, so every report carries `ack` not_available. The delivery path itself exists (core `CaptureInput` includes capability/profile inputs, `Client.captureProfile` queues them, and internal/model/telemetry_validation.go admits capability records and runtime_cpu samples/events); its end-to-end run is a separate row.");
note("recorder-5ms-p95-per-mutation-batch","no real-browser timing run exists for this budget.");
note("python-core-server-capture-overhead","no Python HTTP workload overhead run exists.");
note("platform-runner-matrix","only this one workstation was used; no pinned Linux/macOS/Windows runner class matrix.");

// ------------------------------------------------------------------ overhead evidence (produced by fixtures/sdk/overhead.mjs)
let overhead={not_run:"pass --overhead <result.json> produced by `node fixtures/sdk/overhead.mjs --out result.json`"};
if(overheadPath&&existsSync(resolve(root,overheadPath))){
 const text=readFileSync(resolve(root,overheadPath),"utf8"),data=JSON.parse(text);
 overhead={source:"fixtures/sdk/overhead.mjs",recorded_at:data.recorded_at,command:data.command,sha256_of_result:createHash("sha256").update(text).digest("hex"),machine_class:data.machine_class,runtimes:data.runtimes,budgets:data.budgets_from_design_section_13,rows:data.rows};
}
return {rows,unqualified,overhead};
}

// ------------------------------------------------------------------ run, seal, merge, write
const sourceSha256=sourceDigest();
const machine={platform:os.platform(),release:os.release(),arch:os.arch(),cpu_model:os.cpus()[0]?.model??"unknown",logical_cpus:os.cpus().length,total_memory_mib:Math.round(os.totalmem()/1048576),hostname:os.hostname()};
let runs,summary="",allObserved=true;
if(mergeFiles.length)runs=mergeFiles.map(file=>JSON.parse(readFileSync(resolve(root,file),"utf8")));
else{
 const got=collect();
 const record=sealRun({schema:RUN_SCHEMA,tool:"fixtures/sdk/qualify.mjs",recorded_at:new Date().toISOString(),source_sha256:sourceSha256,host:makeHost(machine),
  runtimes:{node:process.version,bun:bun?version(bun):null,python:python?version(python):null},
  command:"node fixtures/sdk/qualify.mjs "+args.map(a=>a.includes("\\")||a.includes("/")?rel(resolve(root,a)):a).join(" "),
  rows:got.rows,overhead:got.overhead,unqualified:got.unqualified});
 if(runOut)writeFileSync(resolve(root,runOut),JSON.stringify(record,null,2)+"\n");
 runs=[record];
 summary=got.rows.map(r=>`${r.status.padEnd(8)} ${r.id} (exit ${r.exit_code})`).join("\n")+"\n"+`run ${record.run_digest} on ${record.host.hostname} (host ${record.host.id}), source ${sourceSha256}${runOut?`, written: ${rel(resolve(root,runOut))}`:""}\n`;
 allObserved=got.rows.length>0&&got.rows.every(r=>r.status==="observed");
}
if(runOnly){process.stdout.write(summary);process.exit(allObserved?0:1);}
let merged;
try{merged=mergeRuns(JSON.parse(readFileSync(manifestPath,"utf8")),runs,{sourceSha256});}
catch(error){if(error instanceof MergeError){process.stderr.write(`qualify: ${error.message}\n`);process.exit(2);}throw error;}
if(!dryRun)writeFileSync(manifestPath,JSON.stringify(merged,null,2)+"\n");
const evidence=merged.measured_evidence;
process.stdout.write(summary+`merged ${runs.length} run(s): ${evidence.runtime_supplement_rows.length} rows from ${evidence.runs.length} run(s), ${evidence.unqualified_rows.length} rows recorded as unqualified, ${evidence.retired_evidence.length} retired entries; manifest ${dryRun?"NOT written (--dry-run)":"written"}: ${rel(manifestPath)}\n`);
process.exit(allObserved?0:1);
