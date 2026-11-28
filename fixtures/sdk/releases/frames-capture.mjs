// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Loads a real compiled release bundle that throws, captures the thrown error THROUGH the Node SDK client
// (descriptor-only stack read, decision D7) and flushes it to a real `soundpost serve`.
// Compile with `bun build --target=node`, then run under Node 22/24 or Bun:
//   node capture.mjs --config <sdk.json> --bundle <file> --root <dir> --artifact-id <path>=<id> [--hostile]
// --hostile installs an Error.prepareStackTrace and a stack-getter canary AFTER the throw and proves neither ran.
// Prints one JSON line: {event_id, acknowledged_batch_ids, pending, lost, user_code_invocations}.
import {readFileSync} from "node:fs";
import {pathToFileURL} from "node:url";
import {init} from "../../../packages/node/src/index.ts";

const arg=name=>{const i=process.argv.indexOf(name);return i<0?undefined:process.argv[i+1];};
const raw=JSON.parse(readFileSync(arg("--config"),"utf8"));
const ids=Object.fromEntries(process.argv.flatMap((v,i)=>v==="--artifact-id"?[process.argv[i+1].split("=")]:[]));
const trustedKeys=Object.fromEntries(Object.entries(raw.trusted_keys).map(([name,value])=>[name,Uint8Array.from(Buffer.from(value,"base64url"))]));
const client=init({org:raw.org,project:raw.project,source:raw.source,endpoint:raw.endpoint,credential:raw.credential,build:raw.build,policy:raw.policy,trustedKeys,
 resource:raw.resource,descriptor:raw.descriptor,deploymentErrors:true,artifactRoot:arg("--root"),artifactIds:ids});
let thrown;
try{await import(pathToFileURL(arg("--bundle")).href);}catch(error){thrown=error;}
if(thrown===undefined)throw Error("release_bundle_did_not_throw");
let invocations=0;
if(process.argv.includes("--hostile")){
 // Installed after the error exists and before capture: a stack read that formatted lazily would call these.
 Error.prepareStackTrace=()=>{invocations++;return "hostile";};
 Object.defineProperty(thrown,"message",{get(){invocations++;return "hostile";},configurable:true});
}
const eventId=client.captureException(thrown);
const report=await client.flush(15000);
await client.close();
console.log(JSON.stringify({event_id:eventId,acknowledged_batch_ids:report.acknowledgedBatchIds,pending:report.pending,lost:report.lost,user_code_invocations:invocations}));
process.exit(report.pending===0&&report.lost===0&&report.acknowledgedBatchIds.length>0&&invocations===0?0:1);
