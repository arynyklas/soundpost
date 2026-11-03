// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import process from "node:process";
import {writeSync} from "node:fs";
import {init,installHooks} from "../../../packages/bun/src/index.ts";
import {config} from "../../../packages/core/test/fixture.ts";
const mode=process.env.SOUNDPOST_FATAL_MODE??"throw";
// No fake fatal monitor, uncaughtException listener or exporter ACK.
if(process.argv.includes("--sdk")){
 const client=init(config()),lease=installHooks(client);
 if(mode==="closed"){lease.close();lease.close();}
 writeSync(1,"SOUNDPOST_SAFE "+JSON.stringify({records:client.bufferedRecords(),diagnostics:client.diagnostics(),capabilities:lease.capabilities})+"\n");
}
const error=new TypeError("CANARY_NATIVE_FATAL_MESSAGE");
if(mode==="rejection")Promise.reject(error);else throw error;
