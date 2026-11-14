// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Real Vite build -> real private artifact upload -> independent authenticated read-back.
// Requires an actual Soundpost endpoint (HTTPS, the same C07 artifact route the product serves).
// Nothing here prints a credential, a response body or a source line; diagnostics are closed codes.
//
//   node fixtures/sdk/releases/build-and-verify.mjs --endpoint-env SOUNDPOST_FIXTURE_API [--receipt-out FILE | --verify-receipt FILE]
//
// Environment (names only; values are never echoed):
//   <endpoint-env>                                 base URL of the Soundpost server (https://host:port)
//   SOUNDPOST_FIXTURE_ORG / _PROJECT / _SOURCE / _BUILD   registered 32-hex identities
//   SOUNDPOST_FIXTURE_ARTIFACT_WRITE_CREDENTIAL    private artifact.write credential (distinct from the browser source key)
//   SOUNDPOST_FIXTURE_ARTIFACT_READ_CREDENTIAL     independent artifact.read credential
//   SOUNDPOST_FIXTURE_BUILD_RENAMED                optional second registered build ID (release rename)
//   SOUNDPOST_FIXTURE_SOURCE_GRANT=denied          optional: expect the source-content grant to be denied
//   NODE_EXTRA_CA_CERTS                            optional CA bundle for a private server certificate
import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {mkdtempSync,readFileSync,rmSync,writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join,resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {build} from "vite";
import {soundpostVite} from "../../../packages/build/src/index.ts";

const here=fileURLToPath(new URL(".",import.meta.url)),root=resolve(here,"../../..");
const stages=new Set(["arguments","environment","build","upload","read_back","resolve","rename","negative","restart"]);
let stage="arguments",code="unknown";
const mark=(next,detail)=>{if(!stages.has(next))throw Error("invalid_fixture_stage");stage=next;code=detail;};
const sha=value=>createHash("sha256").update(value).digest("hex");

function argument(name){const index=process.argv.indexOf(name);return index<0?undefined:process.argv[index+1];}
const VLQ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function originalLine(map,line,column){
 let source=0,origLine=0,best;
 map.mappings.split(";").forEach((row,index)=>{
  let generated=0;
  for(const segment of row.split(",")){
   if(segment==="")continue;
   const values=[];let shift=0,value=0;
   for(const char of segment){const digit=VLQ.indexOf(char);value|=(digit&31)<<shift;if(digit&32){shift+=5;}else{values.push(value&1?-(value>>1):value>>1);value=0;shift=0;}}
   generated+=values[0];
   if(values.length>=4){source+=values[1];origLine+=values[2];if(index===line&&generated<=column)best={source:map.sources[source],line:origLine+1};}
  }
 });
 return best;
}
function thrownPosition(file){
 const run=spawnSync(process.execPath,[file],{encoding:"utf8"});
 if(run.status===0||run.status===null)throw Error("fixture_did_not_throw");
 const match=run.stderr.split("\n").find(line=>/soundpostReleaseThrow/.test(line)&&/:\d+:\d+/.test(line))?.match(/:(\d+):(\d+)\)?\s*$/);
 if(!match)throw Error("missing_thrown_position");
 return {line:Number(match[1])-1,column:Number(match[2])-1};
}
async function post(endpoint,credential,init){
 return fetch(endpoint+"/api/v1/artifacts",{method:"POST",redirect:"error",headers:credential===undefined?{}:{authorization:"Bearer "+credential},...init});
}
async function readMap(endpoint,credential,ids,artifact){
 const response=await post(endpoint,credential,{headers:{authorization:"Bearer "+credential,"content-type":"application/json"},body:JSON.stringify({operation:"read",org:ids.org,project:ids.project,id:artifact})});
 return {status:response.status,bytes:new Uint8Array(await response.arrayBuffer())};
}
async function buildOnce(out,ids,build_,endpoint,writeCredential){
 const receipts=[];
 await build({configFile:false,root,logLevel:"silent",plugins:[soundpostVite({...ids,build:build_,upload:{endpoint,credential:writeCredential},onReceipt:receipt=>receipts.push(receipt)})],
  build:{outDir:out,emptyOutDir:true,minify:false,target:"es2022",lib:{entry:join(root,"fixtures/sdk/releases/source.ts"),formats:["es"],fileName:()=>"source.mjs"}}});
 if(receipts.length!==1)throw Error("expected_one_receipt");
 return receipts[0];
}
function resolveEvidence(out,mapBytes){
 const where=thrownPosition(join(out,"source.mjs")),found=originalLine(JSON.parse(new TextDecoder().decode(mapBytes)),where.line,where.column);
 assert.ok(found&&found.source.endsWith("source.ts"));assert.equal(found.line,6);
 return found;
}
function multipart(manifest,bytes){const form=new FormData();form.append("manifest",JSON.stringify(manifest));form.append("file",new Blob([bytes]),"x.map");return form;}

try{
 mark("arguments","endpoint_env_required");
 const endpointName=argument("--endpoint-env");if(!endpointName||!/^[A-Z0-9_]+$/.test(endpointName))throw Error("endpoint_env_required");
 mark("environment","https_endpoint_required");
 const endpoint=(process.env[endpointName]??"").replace(/\/$/,"");const url=new URL(endpoint);
 if(url.protocol!=="https:"||url.username||url.password||url.search||url.hash)throw Error("https_endpoint_required");
 mark("environment","identity_missing");
 const ids={org:process.env.SOUNDPOST_FIXTURE_ORG,project:process.env.SOUNDPOST_FIXTURE_PROJECT,source:process.env.SOUNDPOST_FIXTURE_SOURCE};
 const buildId=process.env.SOUNDPOST_FIXTURE_BUILD,write=process.env.SOUNDPOST_FIXTURE_ARTIFACT_WRITE_CREDENTIAL,read=process.env.SOUNDPOST_FIXTURE_ARTIFACT_READ_CREDENTIAL;
 if(!ids.org||!ids.project||!ids.source||!buildId||!write||!read)throw Error("identity_missing");
 mark("environment","credentials_not_independent");
 if(write===read)throw Error("credentials_not_independent");
 const out=mkdtempSync(join(tmpdir(),"soundpost-release-"));
 try{
  const verifyFile=argument("--verify-receipt");
  if(verifyFile!==undefined){
   // After an operator restart of the server: the previously committed artifact must still resolve from durable state.
   mark("restart","receipt_unreadable");
   const saved=JSON.parse(readFileSync(verifyFile,"utf8"));
   mark("restart","read_after_restart_failed");
   const after=await readMap(endpoint,read,ids,saved.id);assert.equal(after.status,200);
   mark("restart","map_hash_changed");assert.equal(sha(after.bytes),saved.public_map_sha256);
   console.log(JSON.stringify({fixture:"release_build_verify",mode:"verify_after_restart",restart_read_ok:true,artifact:saved.id}));
  }else{
   mark("build","vite_upload_failed");
   const receipt=await buildOnce(out,ids,buildId,endpoint,write);
   mark("upload","receipt_invalid");assert.match(receipt.id,/^[0-9a-f]{32}$/);
   const generated=readFileSync(join(out,"source.mjs")),emittedMap=readFileSync(join(out,"source.mjs.map"));
   assert.equal(sha(generated),receipt.generated_sha256);assert.equal(sha(emittedMap),receipt.map_sha256);
   assert.ok(!generated.toString().includes("sourceMappingURL"));assert.ok(!generated.toString().includes(write));
   mark("read_back","authenticated_read_failed");
   const stored=await readMap(endpoint,read,ids,receipt.id);assert.equal(stored.status,200);
   mark("read_back","source_content_returned_by_default");assert.ok(!new TextDecoder().decode(stored.bytes).includes("sourcesContent"));
   mark("resolve","original_line_not_resolved");const found=resolveEvidence(out,stored.bytes);
   // Backend seam negatives: the plugin itself refuses these, so they are sent raw with the real write credential.
   mark("negative","write_credential_read_allowed");assert.equal((await readMap(endpoint,write,ids,receipt.id)).status,404);
   mark("negative","cross_project_read_not_denied");assert.equal((await readMap(endpoint,read,{...ids,project:"f".repeat(32)},receipt.id)).status,404);
   mark("negative","absent_artifact_not_404");assert.equal((await readMap(endpoint,read,ids,"e".repeat(32))).status,404);
   mark("negative","unauthenticated_read_allowed");assert.equal((await post(endpoint,undefined,{headers:{"content-type":"application/json"},body:JSON.stringify({operation:"read",org:ids.org,project:ids.project,id:receipt.id})})).status,401);
   const mapBytes=new TextEncoder().encode(JSON.stringify({version:3,sources:["src/x.ts"],names:[],mappings:"AAAA"}));
   const manifest={version:1,...ids,build:buildId,debug_id:"negative-probe",generated_sha256:sha("g"),map_sha256:sha(mapBytes),path:"assets/x.js",source_content:false,size:String(mapBytes.length),retain_until_ns:String((BigInt(Date.now())+86400000n)*1000000n)};
   for(const [label,changes] of [["traversal_path",{path:"../escape.js"}],["hash_mismatch",{map_sha256:sha("other")}],["oversize_declared",{size:String(32*1024*1024+1)}]]){
    mark("negative","backend_accepted_"+label);
    const response=await post(endpoint,write,{body:multipart({...manifest,...changes},mapBytes)});assert.equal(response.status,400);
   }
   let deep={version:3,sources:["a.ts"],names:[],mappings:"AAAA"};for(let i=0;i<9;i++)deep={version:3,sections:[{offset:{line:0,column:0},map:deep}]};
   const deepBytes=new TextEncoder().encode(JSON.stringify(deep));
   mark("negative","backend_accepted_over_deep_map");
   assert.equal((await post(endpoint,write,{body:multipart({...manifest,map_sha256:sha(deepBytes),size:String(deepBytes.length)},deepBytes)})).status,400);
   if(process.env.SOUNDPOST_FIXTURE_SOURCE_GRANT==="denied"){
    const withContent=new TextEncoder().encode(JSON.stringify({version:3,sources:["src/x.ts"],names:[],mappings:"AAAA",sourcesContent:["PRIVATE_SOURCE_CANARY"]}));
    mark("negative","source_content_grant_not_denied");
    const response=await post(endpoint,write,{body:multipart({...manifest,source_content:true,map_sha256:sha(withContent),size:String(withContent.length)},withContent)});assert.notEqual(response.status,200);
   }
   const renamed=process.env.SOUNDPOST_FIXTURE_BUILD_RENAMED;let renameEvidence=false;
   if(renamed){
    mark("rename","release_rename_upload_failed");
    const second=mkdtempSync(join(tmpdir(),"soundpost-release-"));
    try{
     const again=await buildOnce(second,ids,renamed,endpoint,write);
     mark("rename","debug_identity_changed");assert.equal(again.debug_id,receipt.debug_id);assert.notEqual(again.id,receipt.id);
     const stored2=await readMap(endpoint,read,ids,again.id);assert.equal(stored2.status,200);resolveEvidence(second,stored2.bytes);renameEvidence=true;
    }finally{rmSync(second,{recursive:true,force:true});}
   }
   const out_=argument("--receipt-out");
   if(out_!==undefined)writeFileSync(out_,JSON.stringify({id:receipt.id,build:receipt.build,debug_id:receipt.debug_id,path:receipt.path,public_map_sha256:sha(stored.bytes)}),{mode:0o600});
   console.log(JSON.stringify({fixture:"release_build_verify",mode:"build_upload_read",real_vite:true,real_endpoint:true,original_line:found.line,original_source:found.source,source_content_default_absent:true,
    backend_negatives:["write_credential_read","cross_project_read","absent_artifact","unauthenticated_read","traversal_path","hash_mismatch","oversize_declared","over_deep_map",...(process.env.SOUNDPOST_FIXTURE_SOURCE_GRANT==="denied"?["source_content_grant_denied"]:[])],
    release_rename_checked:renameEvidence,server_symbolicator_checked:false}));
  }
 }finally{rmSync(out,{recursive:true,force:true});}
}catch{
 // Never print a thrown value: assertion text could carry map bytes or credentials.
 console.error(JSON.stringify({fixture:"release_build_verify",stage,code}));
 process.exitCode=1;
}
