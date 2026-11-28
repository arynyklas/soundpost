// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {init} from "../../../packages/browser/src/index.ts";
import {withWorkerContext} from "../../../packages/browser/src/workers.ts";
import type {Config} from "../../../packages/core/src/types.ts";
const scope=globalThis as unknown as {onmessage:(event:MessageEvent)=>void;postMessage:(value:unknown)=>void;close:()=>void};
// Independent public browser-source config, not authority carried by the worker envelope.
const response=await fetch("./worker-config.json",{credentials:"omit"});if(!response.ok)throw Error("worker_public_config_required");const raw=await response.json();if(raw.sourceClass!=="browser")throw Error("worker_public_source_required");
const trustedKeys=Object.fromEntries(Object.entries(raw.trustedKeys??raw.trusted_keys).map(([name,value])=>[name,Uint8Array.from(atob(String(value).replace(/-/g,"+").replace(/_/g,"/")),character=>character.charCodeAt(0))]));const config:Config={...raw,trustedKeys,operations:["worker","worker.unrelated"]};
scope.onmessage=async(event:MessageEvent):Promise<void>=>{const client=init(config),start=String(BigInt(Date.now())*1000000n);try{await withWorkerContext(client,event.data,()=>client.withSpan("worker",async()=>1));if(client.traceContext()!==undefined)throw Error("worker_context_leaked");await client.withSpan("worker.unrelated",async()=>{if(client.traceContext()!.traceId===event.data.trace_id)throw Error("worker_unrelated_inherited");});const records=client.bufferedRecords().map(text=>JSON.parse(text)),report=await client.flush(10000);scope.postMessage({records,report,start_ns:start,end_ns:String(BigInt(Date.now())*1000000n)});}finally{await client.close();scope.close();}};
scope.postMessage({ready:true});
