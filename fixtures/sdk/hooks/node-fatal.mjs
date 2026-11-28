// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Bundle with pinned Bun --target=node for Node22/24; this is local test IPC, not delivery.
import process from "node:process";
import {writeSync} from "node:fs";
import {init,installHooks} from "../../../packages/node/src/index.ts";
import {config} from "../../../packages/core/test/fixture.ts";
const enabled=process.argv.includes("--sdk"),mode=process.env.SOUNDPOST_FATAL_MODE??"throw";
let client,lease;
process.on("uncaughtExceptionMonitor",()=>writeSync(1,"PRIOR_MONITOR\n"));
if(mode==="application-handler")process.on("uncaughtException",()=>writeSync(1,"PRIOR_APPLICATION_HANDLER\n"));
if(mode==="episode-cross")process.on("uncaughtException",observed=>{writeSync(1,"PRIOR_APPLICATION_HANDLER\n");if(observed!==error)queueMicrotask(()=>{throw error;});});
if(mode==="capture-callback")process.setUncaughtExceptionCaptureCallback(()=>writeSync(1,"PRIOR_CAPTURE_CALLBACK\n"));
if(enabled){client=init(mode==="capture-failure"?{...config(),clockNs:()=>{throw Error("CANARY_SDK_FAILURE");}}:config());lease=installHooks(client);}
if(mode==="closed"){lease?.close();lease?.close();}
if(mode==="replaced"){
 process.removeAllListeners("uncaughtExceptionMonitor");
 process.on("uncaughtExceptionMonitor",()=>writeSync(1,"REPLACEMENT_MONITOR\n"));
 lease?.close();lease?.close();
}
process.on("uncaughtExceptionMonitor",(observed,origin)=>{
 if(mode==="episode-cross"&&observed!==error)return;
 if(client)writeSync(1,"SOUNDPOST_SAFE "+JSON.stringify({records:client.bufferedRecords(),diagnostics:client.diagnostics(),capabilities:lease.capabilities,monitor_origin:origin,matches_episode_error:observed===error})+"\n");
});
const error=new TypeError("CANARY_NATIVE_FATAL_MESSAGE");
// An ESM entrypoint's top-level throw rejects its module-evaluation promise:
// Node reports origin=unhandledRejection, unlike a later callback's ordinary throw.
if((mode==="episode"||mode==="episode-callback"||mode==="episode-cross")&&client){
 const episode=client.beginHandlingEpisode();episode.captureException(error);
 lease.useEpisode(episode,error,mode==="episode"?"unhandled_rejection":"uncaught_exception");
}
if(mode==="rejection")Promise.reject(error);
else if(mode==="episode-cross")queueMicrotask(()=>{throw new RangeError("CANARY_UNRELATED");});
else if(mode==="episode-callback")queueMicrotask(()=>{throw error;});
else throw error;
