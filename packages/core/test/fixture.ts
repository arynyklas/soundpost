// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {ed25519} from "@noble/curves/ed25519";
import type {Config,SignedPolicy} from "../src/types.ts";
export function signed(text:string):SignedPolicy{
 const key=Uint8Array.from({length:32},(_,i)=>i),bytes=new TextEncoder().encode(text);
 const b64=(v:Uint8Array)=>Buffer.from(v).toString("base64url");
 return {version:1,algorithm:"Ed25519",key_id:"test",payload:b64(bytes),signature:b64(ed25519.sign(bytes,key))};
}
export function config(project="p"):Config{
 const doc={version:1,org:"org",source:"s",project,revision:"1",expires_ns:"9999999999999999999",errors:true,logs:true,replay:true,bodies:true};
 return {org:"org",project,source:"s",endpoint:"https://example.invalid/ingest/v1/batches",credential:"SECRET",build:"build",policy:signed(JSON.stringify(doc,Object.keys(doc).sort())),trustedKeys:{test:ed25519.getPublicKey(Uint8Array.from({length:32},(_,i)=>i))},clockNs:()=>"9007199254740993",templates:[{id:"operation.failed",revision:"1",line:"operation failed: {status}",fields:{status:[503]},severity:"error"}]};
}
