// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Compile for Node; compare native exit code/origin/identity with and without --sdk.
import {createServer,request} from "node:http";
import {once} from "node:events";
import {init} from "../../../packages/node/src/index.ts";
import {installHttp} from "../../../packages/node/src/http.ts";
import {config,signed} from "../../../packages/core/test/fixture.ts";
import {canonical} from "../../../packages/core/src/policy.ts";
const error=new Error("CANARY_HTTP_FATAL"),enabled=process.argv.includes("--sdk"),mode=process.env.SOUNDPOST_FIXTURE_FATAL_MODE??"sync",base=config();let client;
process.on("uncaughtExceptionMonitor",(observed,origin)=>{process.stdout.write(JSON.stringify({fixture:"http_fatal",origin,same_error:observed===error,...(client?{safe_records:client.bufferedRecords(),diagnostics:client.diagnostics()}: {})})+"\n");});
let handler=mode==="promise"?()=>Promise.reject(error):()=>{throw error;};
if(enabled){client=init({...base,operations:["request"],policy:signed(canonical({version:1,org:base.org,project:base.project,source:base.source,revision:"1",expires_ns:"9223372036854775807",errors:true,logs:false,replay:false,bodies:false,traces:true,jobs:false}))});handler=installHttp(client,{operation:"request"}).listener(handler);}
const server=createServer(handler);server.listen(0,"127.0.0.1");await once(server,"listening");const call=request({host:"127.0.0.1",port:server.address().port});call.on("error",()=>{});call.end();
