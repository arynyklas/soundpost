// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Diagnostic matrix, not qualification: every cell starts and closes a real Worker.
import {writeSync} from "node:fs";
type Terminal={kind:"closed";code:number}|{kind:"error"};
function phase(step:"worker.before"|"worker.after"|"worker.ready"|"worker.error"|"worker.closed"|"https.before"|"https.complete"|"https.off"|"post.before"|"post.after"|"terminate.before"|"terminate.after"|"failed"):void{writeSync(2,"SOUNDPOST_WORKER_CLOSE_PROBE parent."+step+"\n");}
async function main():Promise<void>{
 if(Bun.version!=="1.3.14"||!Bun.isMainThread)throw Error("pinned_main_process_required");
 const closeArg=process.argv[2],httpsArg=process.argv[3];if(process.argv.length!==4||!(closeArg==="--close=scope"||closeArg==="--close=process")||!(httpsArg==="--https=on"||httpsArg==="--https=off"))throw Error("closed_probe_modes_required");
 const mode=closeArg==="--close=scope"?"scope":"process",https=httpsArg==="--https=on";
 const endpoint=https?process.env.SOUNDPOST_FIXTURE_DEPENDENCY_URL:undefined;if(https&&(!endpoint||new URL(endpoint).protocol!=="https:"||new URL(endpoint).username||new URL(endpoint).password))throw Error("authorized_verified_https_dependency_required");
 const env=Object.fromEntries(["SystemRoot","NODE_EXTRA_CA_CERTS"].flatMap(name=>process.env[name]===undefined?[]:[[name,process.env[name]!]]));
 phase("worker.before");const worker=new Worker(new URL("./worker-close-probe-worker.ts",import.meta.url).href,{env});phase("worker.after");
 const ready=Promise.withResolvers<MessageEvent>(),terminal=Promise.withResolvers<Terminal>();let readySeen=false;
 worker.onmessage=event=>{if(readySeen)throw Error("unexpected_probe_message");readySeen=true;ready.resolve(event);};
 worker.onerror=()=>{phase("worker.error");ready.reject(Error("worker_error_before_ready"));terminal.resolve({kind:"error"});};
 worker.addEventListener("close",event=>{phase("worker.closed");terminal.resolve({kind:"closed",code:event.code});});
 try{
  const event=await ready.promise,data=event.data;if(!data||data.version!==1||data.phase!=="ready"||data.bun_version!=="1.3.14"||data.is_main_thread!==false||typeof data.bun_revision!=="string"||!/^[0-9a-f]{7,64}$/.test(data.bun_revision)||!['undefined','function','object','boolean','number','bigint','string','symbol'].includes(data.close_type))throw Error("invalid_closed_probe_ready");
  phase("worker.ready");console.log(JSON.stringify({fixture:"worker_close_diagnostic",runtime:Bun.version,revision:Bun.revision,platform:process.platform,arch:process.arch,worker_revision:data.bun_revision,scope_close_type:data.close_type,termination:mode,parent_https:https?"on":"off",qualification:false}));
  const network=(async()=>{if(!https){phase("https.off");return;}phase("https.before");const response=await fetch(endpoint!);if(!response.ok)throw Error("real_https_dependency_failed");const reader=response.body?.getReader();if(reader){try{while(!(await reader.read()).done){/* Consume without retaining or logging body bytes. */}}finally{reader.releaseLock();}}phase("https.complete");})();
  phase("post.before");worker.postMessage({version:1,mode});phase("post.after");
  const [result]=await Promise.all([terminal.promise,network]);if(result.kind!=="closed"||result.code!==0)throw Error("worker_did_not_close_normally");
  console.log(JSON.stringify({fixture:"worker_close_diagnostic_complete",runtime:Bun.version,termination:mode,parent_https:https?"on":"off",worker_exit:result.code,qualification:false}));
 }finally{phase("terminate.before");worker.terminate();phase("terminate.after");}
}
try{await main();}catch{phase("failed");process.exitCode=1;}
