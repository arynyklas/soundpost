// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Diagnostic control only: no Soundpost client, source config, credentials or TLS in this worker.
import {writeSync} from "node:fs";
const scope=globalThis as unknown as {onmessage:(event:MessageEvent)=>void;postMessage:(value:unknown)=>void};
function phase(step:"ready"|"message"|"scope.before"|"scope.after"|"process.before"):void{writeSync(2,"SOUNDPOST_WORKER_CLOSE_PROBE worker."+step+"\n");}
if(Bun.version!=="1.3.14"||Bun.isMainThread)throw Error("pinned_real_worker_required");
const closeOperation=Reflect.get(globalThis,"close");
scope.onmessage=async(event:MessageEvent):Promise<void>=>{
 const input=event.data;if(!input||typeof input!=="object"||Object.keys(input).length!==2||input.version!==1||!(input.mode==="scope"||input.mode==="process"))throw Error("closed_probe_command_required");
 await Promise.resolve();phase("message");
 if(input.mode==="scope"){phase("scope.before");Reflect.apply(closeOperation,globalThis,[]);phase("scope.after");}
 else{phase("process.before");process.exit(0);}
};
phase("ready");scope.postMessage({version:1,phase:"ready",close_type:typeof closeOperation,bun_version:Bun.version,bun_revision:Bun.revision,is_main_thread:Bun.isMainThread});
