// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {readFile,writeFile} from "node:fs/promises";
import {dirname,join,posix} from "node:path";
import {ArtifactError,LIMITS,inspectSourceMap,prepareArtifact,sha256Hex,validateManifest} from "./manifest.ts";
import type {ArtifactFile,ArtifactManifest,ArtifactReceipt,ResolvedBuildOptions,UploadOptions} from "./manifest.ts";

/** Branded, frozen upload configuration. The credential lives only in a closure: JSON, inspect and string conversion cannot echo it. */
export interface UploadConfig {readonly endpoint:string}
interface Sealed {readonly endpoint:string;readonly timeoutMs:number;readonly credential:()=>string}
const sealed=new WeakMap<object,Sealed>();
const LOOPBACK=new Set(["localhost","127.0.0.1","[::1]"]);
// eslint-disable-next-line no-control-regex
const TOKEN=/^[\u0021-\u007e]{1,4096}$/;

function readCredential(provider:()=>unknown):string {
 let value:unknown;
 try{value=provider();}catch{throw new ArtifactError("credential_invalid");}
 if(typeof value!=="string"||!TOKEN.test(value))throw new ArtifactError("credential_invalid");
 return value;
}
export function createUploadConfig(options:UploadOptions):UploadConfig {
 if(options===null||typeof options!=="object")throw new ArtifactError("options_invalid");
 const endpoint:unknown=options.endpoint,credential:unknown=options.credential,timeout:unknown=options.timeoutMs??120000;
 let url:URL;
 try{if(typeof endpoint!=="string")throw Error();url=new URL(endpoint);}catch{throw new ArtifactError("endpoint_invalid");}
 if((url.protocol!=="https:"&&url.protocol!=="http:")||url.username!==""||url.password!==""||url.search!==""||url.hash!=="")throw new ArtifactError("endpoint_invalid");
 if(url.protocol==="http:"&&!LOOPBACK.has(url.hostname))throw new ArtifactError("endpoint_insecure");
 if(typeof timeout!=="number"||!Number.isInteger(timeout)||timeout<1||timeout>600000)throw new ArtifactError("options_invalid");
 let provider:()=>string;
 if(typeof credential==="function"){provider=()=>readCredential(credential as ()=>unknown);}
 else{const value=readCredential(()=>credential);provider=()=>value;}
 if(typeof credential==="function")readCredential(provider);
 const config=Object.freeze({endpoint:url.origin+url.pathname.replace(/\/$/,"")});
 sealed.set(config,Object.freeze({endpoint:config.endpoint,timeoutMs:timeout,credential:provider}));
 return config;
}
function unseal(config:unknown):Sealed {
 const value=typeof config==="object"&&config!==null?sealed.get(config):undefined;
 if(value===undefined)throw new ArtifactError("options_invalid");
 return value;
}

/** Streams the bundle, enforces C07 limits, binds exact hashes, then uploads only the map with the private artifact-write credential. */
export async function uploadArtifacts(manifest:ArtifactManifest,files:AsyncIterable<ArtifactFile>,config:UploadConfig):Promise<ArtifactReceipt> {
 const target=unseal(config),checked=validateManifest(manifest);
 let count=0,total=0,generated:ArtifactFile|undefined;const maps:ArtifactFile[]=[];
 for await(const file of files){
  if(++count>LIMITS.maxFiles)throw new ArtifactError("too_many_files");
  total+=file.bytes.length;
  if(total>LIMITS.maxBytes)throw new ArtifactError("bundle_too_large");
  if(file.role==="generated"){if(file.path===checked.path)generated=file;}
  else if(file.role==="map")maps.push(file);
  else throw new ArtifactError("manifest_invalid");
 }
 if(generated===undefined)throw new ArtifactError("generated_missing");
 if(sha256Hex(generated.bytes)!==checked.generated_sha256)throw new ArtifactError("generated_hash_mismatch");
 if(maps.length===0)throw new ArtifactError("map_missing");
 const map=maps.find(candidate=>sha256Hex(candidate.bytes)===checked.map_sha256);
 if(map===undefined)throw new ArtifactError("map_hash_mismatch");
 if(String(map.bytes.length)!==checked.size)throw new ArtifactError("manifest_invalid");
 inspectSourceMap(map.bytes,checked.source_content);
 const form=new FormData();
 form.append("manifest",JSON.stringify(checked));
 form.append("file",new Blob([new Uint8Array(map.bytes)],{type:"application/json"}),"artifact.map");
 let response:Response;
 try{
  response=await fetch(target.endpoint+"/api/v1/artifacts",{method:"POST",body:form,redirect:"error",cache:"no-store",headers:{authorization:"Bearer "+target.credential()},signal:AbortSignal.timeout(target.timeoutMs)});
 }catch(error){
  if(error instanceof ArtifactError)throw error;
  throw new ArtifactError("upload_failed");
 }
 if(!response.ok){await response.body?.cancel().catch(()=>undefined);throw new ArtifactError("upload_rejected",String(response.status));}
 let reply:unknown;
 try{
  const raw=await response.text();
  if(raw.length>65536)throw Error();
  reply=JSON.parse(raw);
 }catch{throw new ArtifactError("receipt_invalid");}
 if(reply===null||typeof reply!=="object"||typeof (reply as {id?:unknown}).id!=="string"||!/^[0-9a-f]{32}$/.test((reply as {id:string}).id))throw new ArtifactError("receipt_invalid");
 const body=reply as {id:string;state?:unknown;manifest?:Record<string,unknown>};
 if(body.manifest!==undefined&&(typeof body.manifest!=="object"||body.manifest===null||body.manifest.build!==checked.build||body.manifest.debug_id!==checked.debug_id||body.manifest.map_sha256!==checked.map_sha256||body.manifest.path!==checked.path))throw new ArtifactError("receipt_invalid");
 return Object.freeze({id:body.id,build:checked.build,debug_id:checked.debug_id,path:checked.path,generated_sha256:checked.generated_sha256,map_sha256:checked.map_sha256,...(typeof body.state==="string"?{state:body.state}:{})});
}

export interface OutputAsset {readonly path:string;readonly mapPath:string|undefined}
async function* bundleFiles(manifest:ArtifactManifest,generated:Uint8Array,map:Uint8Array,mapPath:string):AsyncGenerator<ArtifactFile> {
 yield {path:manifest.path,role:"generated",bytes:generated};
 yield {path:mapPath,role:"map",bytes:map};
}
/**
 * Shared bundler tail: for every emitted JS asset, bind identities, rewrite the emitted
 * generated/map files to exactly the hashed bytes, then upload when a target is configured.
 * A JS asset without a map is a visible build failure, never a silent skip.
 */
export async function publishBuildOutput(input:{readonly dir:string;readonly root:string;readonly assets:readonly OutputAsset[];readonly options:ResolvedBuildOptions}):Promise<ArtifactReceipt[]> {
 const receipts:ArtifactReceipt[]=[];
 const config=input.options.upload===undefined?undefined:createUploadConfig(input.options.upload);
 for(const asset of input.assets){
  if(asset.mapPath===undefined)throw new ArtifactError("map_missing",asset.path);
  const [generated,map]=await Promise.all([readFile(join(input.dir,asset.path)),readFile(join(input.dir,asset.mapPath))]);
  const prepared=prepareArtifact({path:posix.normalize(asset.path.split("\\").join("/")),generated,map,mapDir:dirname(join(input.dir,asset.mapPath)),root:input.root,identity:input.options.identity,sourceContent:input.options.sourceContent,retainDays:input.options.retainDays});
  await Promise.all([writeFile(join(input.dir,asset.path),prepared.generated),writeFile(join(input.dir,asset.mapPath),prepared.map)]);
  if(config===undefined)continue;
  const receipt=await uploadArtifacts(prepared.manifest,bundleFiles(prepared.manifest,prepared.generated,prepared.map,asset.mapPath),config);
  receipts.push(receipt);
  input.options.onReceipt?.(receipt);
 }
 return receipts;
}
