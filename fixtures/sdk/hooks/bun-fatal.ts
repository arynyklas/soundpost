// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import process from "node:process";
import {writeSync} from "node:fs";
import {init,installHooks} from "../../../packages/bun/src/index.ts";
import {config} from "../../../packages/core/test/fixture.ts";
const mode=process.env.SOUNDPOST_FATAL_MODE??"throw";
// Bun 1.3.14 fires uncaughtExceptionMonitor for synchronous throws (top-level, timer, nextTick)
// but not for unhandled promise rejections; the capability reports that. No consuming
// uncaughtException/unhandledRejection listener and no exporter ACK is installed here.
if(process.argv.includes("--sdk")){
 const client=init(config()),lease=installHooks(client);
 if(mode==="closed"){lease.close();lease.close();}
 // Registered after the SDK's monitor, so it observes the post-capture state.
 process.on("uncaughtExceptionMonitor",()=>writeSync(1,"SOUNDPOST_SAFE "+JSON.stringify({records:client.bufferedRecords(),diagnostics:client.diagnostics(),capabilities:lease.capabilities})+"\n"));
 // A rejection never reaches the monitor in Bun; report the state at process exit instead.
 if(mode==="rejection")process.on("exit",()=>writeSync(1,"SOUNDPOST_SAFE "+JSON.stringify({records:client.bufferedRecords(),diagnostics:client.diagnostics(),capabilities:lease.capabilities})+"\n"));
}
const error=new TypeError("CANARY_NATIVE_FATAL_MESSAGE");
if(mode==="rejection")Promise.reject(error);
else if(mode==="timer")setTimeout(()=>{throw error;},1);
else throw error;
