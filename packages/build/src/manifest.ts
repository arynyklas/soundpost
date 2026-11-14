// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {createHash} from "node:crypto";
import {posix,isAbsolute,relative,resolve,dirname} from "node:path";

/** C07 limits, mirrored from the backend so a build fails before any byte leaves the machine. */
export const LIMITS = Object.freeze({maxBytes:32*1024*1024,maxFiles:1024,maxDepth:8,maxPath:4096,maxDebugId:256});

export type ArtifactErrorCode=
 |"options_invalid"|"manifest_invalid"|"path_invalid"|"credential_invalid"|"endpoint_invalid"|"endpoint_insecure"
 |"too_many_files"|"bundle_too_large"|"generated_missing"|"generated_hash_mismatch"|"map_missing"|"map_hash_mismatch"
 |"map_invalid"|"map_indexed"|"map_too_large"|"map_too_deep"|"map_path_unsafe"
 |"source_content_missing"|"source_content_unexpected"|"sourcemap_inline_unsupported"|"debug_id_conflict"
 |"upload_failed"|"upload_rejected"|"receipt_invalid";

/** Closed, visible failure reason. Messages are a code (and optionally a build-local path), never a response body, config or credential. */
export class ArtifactError extends Error {
 readonly code:ArtifactErrorCode;
 constructor(code:ArtifactErrorCode,detail?:string){super(detail===undefined?code:code+": "+detail);this.name="ArtifactError";this.code=code;}
}

/** Wire manifest: field-for-field the C07 `model.ArtifactManifest` JSON. */
export interface ArtifactManifest {
 readonly version:1;readonly org:string;readonly project:string;readonly source:string;readonly build:string;
 readonly debug_id:string;readonly generated_sha256:string;readonly map_sha256:string;readonly path:string;
 readonly source_content:boolean;readonly size:string;readonly retain_until_ns:string;
}
export interface ArtifactFile {readonly path:string;readonly role:"generated"|"map";readonly bytes:Uint8Array}
export interface ArtifactReceipt {
 readonly id:string;readonly build:string;readonly debug_id:string;readonly path:string;
 readonly generated_sha256:string;readonly map_sha256:string;readonly state?:string;
}
export interface UploadOptions {readonly endpoint:string;readonly credential:string|(()=>string);readonly timeoutMs?:number}
export interface BuildOptions {
 readonly org:string;readonly project:string;readonly source:string;readonly build:string;
 readonly upload?:UploadOptions;
 /** Default false: source text never leaves the build and is stripped from emitted maps. */
 readonly includeSourceContent?:boolean;
 readonly retainDays?:number;
 readonly onReceipt?:(receipt:ArtifactReceipt)=>void;
}

const ID=/^[0-9a-f]{32}$/,HASH=/^[0-9a-f]{64}$/,DECIMAL=/^[1-9][0-9]{0,18}$/;
// eslint-disable-next-line no-control-regex
const UNSAFE_TEXT=/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2064\ufeff]/;
export function sha256Hex(bytes:Uint8Array|string):string {return createHash("sha256").update(bytes).digest("hex");}

/** Same rule as the backend path identity: project-relative, clean, no scheme-ish or traversal characters. */
export function checkArtifactPath(path:unknown):string {
 if(typeof path!=="string"||path.length<1||path.length>LIMITS.maxPath||UNSAFE_TEXT.test(path)||/[\\:%?#]/.test(path)||path.startsWith("/")||posix.normalize(path)!==path||path===".."||path.startsWith("../")||path.endsWith("/")||path===".")throw new ArtifactError("path_invalid");
 return path;
}
/** Strict, closed manifest validation (same predicates as `artifacts.ValidateManifest`). */
export function validateManifest(value:unknown):ArtifactManifest {
 if(value===null||typeof value!=="object"||Array.isArray(value))throw new ArtifactError("manifest_invalid");
 const record=value as Record<string,unknown>,expected=["build","debug_id","generated_sha256","map_sha256","org","path","project","retain_until_ns","size","source","source_content","version"];
 if(Object.keys(record).sort().join()!==expected.join()||Object.values(Object.getOwnPropertyDescriptors(record)).some(field=>!("value" in field)))throw new ArtifactError("manifest_invalid");
 const text=(key:string,pattern:RegExp)=>{const field=record[key];if(typeof field!=="string"||!pattern.test(field))throw new ArtifactError("manifest_invalid");return field;};
 const debug=record.debug_id;
 if(record.version!==1||typeof record.source_content!=="boolean"||typeof debug!=="string"||debug.length<1||debug.length>LIMITS.maxDebugId||UNSAFE_TEXT.test(debug)||/[/\\:%?#]/.test(debug))throw new ArtifactError("manifest_invalid");
 for(const key of ["org","project","source","build"])text(key,ID);
 for(const key of ["generated_sha256","map_sha256"])text(key,HASH);
 const size=text("size",DECIMAL),retain=text("retain_until_ns",DECIMAL);
 if(BigInt(retain)>9223372036854775807n)throw new ArtifactError("manifest_invalid");
 checkArtifactPath(record.path);
 if(BigInt(size)>BigInt(LIMITS.maxBytes))throw new ArtifactError("map_too_large");
 return Object.freeze({...record}) as unknown as ArtifactManifest;
}

/** Raw-text nesting scan: bounds depth before any recursive parser can see the document. */
function jsonDepth(text:string):number {
 let depth=0,max=0,inString=false;
 for(let index=0;index<text.length;index++){
  const char=text.charCodeAt(index);
  if(inString){if(char===92)index++;else if(char===34)inString=false;continue;}
  if(char===34)inString=true;
  else if(char===123||char===91){depth++;if(depth>max)max=depth;}
  else if(char===125||char===93)depth--;
 }
 return max;
}
const SCHEME=/^[A-Za-z][A-Za-z0-9+.-]*:/;
function safeSourcePath(source:string):boolean {
 return source.length>0&&source.length<=LIMITS.maxPath&&!UNSAFE_TEXT.test(source)&&!source.includes("\\")&&!source.startsWith("/")&&!SCHEME.test(source)&&!source.split("/").includes("..");
}
export interface SourceMapView {readonly version:3;readonly sources:string[];readonly mappings:string;readonly sourcesContent?:(string|null)[];readonly [key:string]:unknown}

/** Parse and bound a map. Pure: checks size, depth, indexed/section forms, path safety and the source-content grant. */
export function inspectSourceMap(bytes:Uint8Array,sourceContent:boolean):SourceMapView {
 if(bytes.length>LIMITS.maxBytes)throw new ArtifactError("map_too_large");
 let text:string;
 try{text=new TextDecoder("utf-8",{fatal:true}).decode(bytes);}catch{throw new ArtifactError("map_invalid");}
 if(jsonDepth(text)>LIMITS.maxDepth)throw new ArtifactError("map_too_deep");
 let parsed:unknown;
 try{parsed=JSON.parse(text);}catch{throw new ArtifactError("map_invalid");}
 if(parsed===null||typeof parsed!=="object"||Array.isArray(parsed))throw new ArtifactError("map_invalid");
 const map=parsed as Record<string,unknown>;
 if(Object.hasOwn(map,"sections"))throw new ArtifactError("map_indexed");
 if(map.version!==3||!Array.isArray(map.sources)||typeof map.mappings!=="string"||(map.names!==undefined&&!Array.isArray(map.names)))throw new ArtifactError("map_invalid");
 if(map.sources.length>LIMITS.maxFiles)throw new ArtifactError("too_many_files");
 if(map.sources.some(source=>typeof source!=="string"))throw new ArtifactError("map_invalid");
 const sources=map.sources as string[];
 if(sources.some(source=>!safeSourcePath(source))||(map.sourceRoot!==undefined&&(typeof map.sourceRoot!=="string"||(map.sourceRoot!==""&&!safeSourcePath(map.sourceRoot)))))throw new ArtifactError("map_path_unsafe");
 const content=map.sourcesContent;
 if(sourceContent){
  if(!Array.isArray(content)||content.length!==sources.length||content.some(entry=>typeof entry!=="string"))throw new ArtifactError("source_content_missing");
 }else if(content!==undefined&&(!Array.isArray(content)||content.some(entry=>entry!==null)))throw new ArtifactError("source_content_unexpected");
 return map as unknown as SourceMapView;
}

const DEBUG_COMMENT=/\n?\/\/# debugId=[0-9a-f]{32}[ \t]*\n?$/,MAP_COMMENT=/\n?\/\/[#@] sourceMappingURL=[^\n]*[ \t]*\n?$/;
export interface PreparedArtifact {readonly manifest:ArtifactManifest;readonly generated:Uint8Array;readonly map:Uint8Array}
export interface PrepareInput {
 readonly path:string;readonly generated:Uint8Array;readonly map:Uint8Array;readonly mapDir:string;readonly root:string;
 readonly identity:{readonly org:string;readonly project:string;readonly source:string;readonly build:string};
 readonly sourceContent:boolean;readonly retainDays:number;
}
function normalizeSources(map:Record<string,unknown>,mapDir:string,root:string):void {
 if(!Array.isArray(map.sources))throw new ArtifactError("map_invalid");
 map.sources=(map.sources as unknown[]).map(entry=>{
  if(typeof entry!=="string")throw new ArtifactError("map_invalid");
  const clean=entry.replace(UNSAFE_TEXT,"_"),stripped=clean.replace(/^webpack:\/\/[^/]*\//,"");
  let path:string;
  if(stripped!==clean){const normal=posix.normalize(stripped);path=normal.startsWith("../")||normal===".."||normal.startsWith("/")?"":normal;}
  else if(SCHEME.test(clean)&&!/^[A-Za-z]:[\\/]/.test(clean))path="";
  else{const absolute=relative(root,resolve(mapDir,clean)).split("\\").join("/");path=absolute===""||absolute.startsWith("../")||absolute==="..."||isAbsolute(absolute)||/^[A-Za-z]:/.test(absolute)?"":absolute;}
  return path!==""?path:"external/"+(clean.split(/[\\/]/).filter(part=>part!==""&&part!=="."&&part!=="..").at(-1)??"source").replace(/[:%?#]/g,"_");
 });
 delete map.sourceRoot;
}
/**
 * Binds the immutable identities. The debug ID is derived from the generated bytes
 * (without any previous debug/map comment), so it is stable across release renames and
 * restarts. The returned bytes are exactly what is hashed, uploaded and written back.
 */
export function prepareArtifact(input:PrepareInput):PreparedArtifact {
 const path=checkArtifactPath(input.path);
 if(input.generated.length>LIMITS.maxBytes)throw new ArtifactError("bundle_too_large");
 if(input.map.length>LIMITS.maxBytes)throw new ArtifactError("map_too_large");
 let map:Record<string,unknown>;
 try{
  const text=new TextDecoder("utf-8",{fatal:true}).decode(input.map);
  if(jsonDepth(text)>LIMITS.maxDepth)throw new ArtifactError("map_too_deep");
  map=JSON.parse(text) as Record<string,unknown>;
 }catch(error){throw error instanceof ArtifactError?error:new ArtifactError("map_invalid");}
 if(map===null||typeof map!=="object"||Array.isArray(map))throw new ArtifactError("map_invalid");
 if(Object.hasOwn(map,"sections"))throw new ArtifactError("map_indexed");
 normalizeSources(map,input.mapDir,input.root);
 if(!input.sourceContent)delete map.sourcesContent;
 const text=new TextDecoder("utf-8",{fatal:false}).decode(input.generated),base=text.replace(MAP_COMMENT,"").replace(DEBUG_COMMENT,"").replace(MAP_COMMENT,"");
 const debug=sha256Hex(base).slice(0,32);
 if(typeof map.debugId==="string"&&map.debugId!==debug&&map.debugId!=="")throw new ArtifactError("debug_id_conflict");
 map.debugId=debug;
 const generated=new TextEncoder().encode(base.replace(/\n?$/,"\n")+"//# debugId="+debug+"\n"),mapBytes=new TextEncoder().encode(JSON.stringify(map));
 inspectSourceMap(mapBytes,input.sourceContent);
 const retain=(BigInt(Date.now())+BigInt(input.retainDays)*86400000n)*1000000n;
 const manifest=validateManifest({version:1,...input.identity,debug_id:debug,generated_sha256:sha256Hex(generated),map_sha256:sha256Hex(mapBytes),path,source_content:input.sourceContent,size:String(mapBytes.length),retain_until_ns:String(retain)});
 return Object.freeze({manifest,generated,map:mapBytes});
}

export interface ResolvedBuildOptions {
 readonly identity:{readonly org:string;readonly project:string;readonly source:string;readonly build:string};
 readonly sourceContent:boolean;readonly retainDays:number;readonly upload:UploadOptions|undefined;
 readonly onReceipt:((receipt:ArtifactReceipt)=>void)|undefined;
}
/** Closed option validation shared by both bundler plugins; copies identities so later caller mutation cannot change them. */
export function resolveBuildOptions(options:BuildOptions):ResolvedBuildOptions {
 if(options===null||typeof options!=="object"||Array.isArray(options))throw new ArtifactError("options_invalid");
 const allowed=new Set(["org","project","source","build","upload","includeSourceContent","retainDays","onReceipt"]);
 if(Object.keys(options).some(key=>!allowed.has(key)))throw new ArtifactError("options_invalid");
 const ids:Record<string,string>={};
 for(const key of ["org","project","source","build"] as const){const value=options[key];if(typeof value!=="string"||!ID.test(value))throw new ArtifactError("options_invalid");ids[key]=value;}
 const retainDays=options.retainDays??90;
 if(!Number.isInteger(retainDays)||retainDays<1||retainDays>3650)throw new ArtifactError("options_invalid");
 if(options.includeSourceContent!==undefined&&typeof options.includeSourceContent!=="boolean")throw new ArtifactError("options_invalid");
 if(options.onReceipt!==undefined&&typeof options.onReceipt!=="function")throw new ArtifactError("options_invalid");
 return Object.freeze({identity:Object.freeze({org:ids.org!,project:ids.project!,source:ids.source!,build:ids.build!}),sourceContent:options.includeSourceContent===true,retainDays,upload:options.upload,onReceipt:options.onReceipt});
}
export function mapDirectory(outputDir:string,mapPath:string):string {return dirname(resolve(outputDir,mapPath));}
/** Bundlers overwrite `error.code` (Rollup sets PLUGIN_ERROR), so plugins surface the closed reason as `reason`; unknown failures never pass through. */
export function asBuildFailure(error:unknown):Error {
 if(error instanceof ArtifactError)return Object.assign(new Error("[soundpost] "+error.message),{name:"SoundpostArtifactError",reason:error.code});
 return Object.assign(new Error("[soundpost] artifact_publish_failed"),{name:"SoundpostArtifactError",reason:"upload_failed"});
}
