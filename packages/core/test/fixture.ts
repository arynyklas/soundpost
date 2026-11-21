// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {ed25519} from "@noble/curves/ed25519";
import type {Config,SignedPolicy} from "../src/types.ts";
export function signed(text:string):SignedPolicy{
 const key=Uint8Array.from({length:32},(_,i)=>i),bytes=new TextEncoder().encode(text);
 const b64=(v:Uint8Array)=>btoa(Array.from(v,b=>String.fromCharCode(b)).join("")).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
 return {version:1,algorithm:"Ed25519",key_id:"test",payload:b64(bytes),signature:b64(ed25519.sign(bytes,key))};
}
export const ORG="1".repeat(32),PROJECT="2".repeat(32),SOURCE="3".repeat(32),BUILD="4".repeat(32),OTHER_PROJECT="5".repeat(32);
export function config(project=PROJECT):Config{
 const doc={version:1,org:ORG,source:SOURCE,project,revision:"1",expires_ns:"9223372036854775807",errors:true,logs:true,replay:true,bodies:true};
 return {org:ORG,project,source:SOURCE,endpoint:"https://example.invalid/ingest/v1/batches",credential:"SECRET",build:BUILD,resource:{service_id:"6".repeat(32),environment_id:"7".repeat(32),build_id:BUILD,instance_pseudonym:"worker-1",labels:[]},policy:signed(JSON.stringify(doc,Object.keys(doc).sort())),trustedKeys:{test:ed25519.getPublicKey(Uint8Array.from({length:32},(_,i)=>i))},clockNs:()=>"9007199254740993",templates:[{id:"operation.failed",revision:"1",line:"operation failed: {status}",fields:{status:[503]},severity:"error"}]};
}
