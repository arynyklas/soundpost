// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {hashBytes} from "./routing.ts";
export interface SafeFrame {
 readonly artifact_id:string;readonly module_id:string;readonly function:string;
 readonly line:number;readonly column:number|null;readonly in_app:boolean;readonly async:boolean;
}
/** Closed reasons a native error contributed no frames (all are wire-valid graph reasons). */
export const originalStackLimitation="safe_original_stack_unavailable";
/** The engine's stack formatter could run user code (an installed Error.prepareStackTrace, or a name/message
 * accessor or proxy/foreign prototype the default formatter would call), so the stack was not read. */
export const stackFormatterHooked="stack_formatter_hooked";
/** The stack is not an engine-owned plain value: a getter defined by the program, a proxy, a non-string. */
export const stackNotPlain="stack_not_plain";
/** The engine produced a string but no frame line could be bounded into a project-safe frame. */
export const stackUnparsed="stack_unparsed";

const MAX_TEXT=65536,MAX_LINE=2048,MAX_FRAMES=128;
const getOwn=Object.getOwnPropertyDescriptor,getProto=Object.getPrototypeOf,apply=Reflect.apply;
const IntrinsicError=Error,FunctionPrototype=Function.prototype,ObjectPrototype=Object.prototype;
/** Prototypes the default formatter is known to read `name`/`message` from without user code. */
const intrinsicPrototypes:readonly object[]=[
 Error.prototype,TypeError.prototype,RangeError.prototype,ReferenceError.prototype,SyntaxError.prototype,
 URIError.prototype,EvalError.prototype,AggregateError.prototype,ObjectPrototype
];
/** Engine-created `stack` getters, captured once at load; a program-defined getter never equals them. */
const engineGetter=((): Function|undefined=>{
 try{const own=getOwn(new IntrinsicError("x"),"stack");return typeof own?.get==="function"?own.get:undefined;}catch{return undefined;}
})();
/** SpiderMonkey keeps `stack` as an accessor on Error.prototype. */
const prototypeGetter=((): Function|undefined=>{
 try{const shared=getOwn(IntrinsicError.prototype,"stack");return typeof shared?.get==="function"?shared.get:undefined;}catch{return undefined;}
})();

/** Node and Bun expose their own default formatter as Error.prepareStackTrace. It runs no program code, so it is
 * recognised by identity with the value present at load AND by printing as exactly the engine's function. */
const engineDefaultPrepare=/^(?:function ErrorPrepareStackTrace\(error, trace\) \{\s*return internalPrepareStackTrace\(error, trace\);\s*\}|function ErrorPrepareStackTrace\(\) \{\s*\[native code\]\s*\})$/;
const enginePrepare=((): unknown=>{
 try{
  const own=getOwn(IntrinsicError,"prepareStackTrace");
  const value:unknown=own&&"value" in own?own.value:undefined;
  return typeof value==="function"&&engineDefaultPrepare.test(Function.prototype.toString.call(value))?value:undefined;
 }catch{return undefined;}
})();
export interface StackBoundary {readonly isProxy?:(value:unknown)=>boolean}
/** Where artifact paths are relative to, and optionally the server-assigned ArtifactID of each uploaded path. */
export interface FrameNaming {readonly root?:string;readonly ids?:ReadonlyMap<string,string>}
export interface StackRead {readonly frames:readonly SafeFrame[];readonly reasons:readonly string[]}
const none=(reason:string):StackRead=>({frames:[],reasons:[reason]});

/** True only when formatting this error cannot reach user code: no Error.prepareStackTrace anywhere it is
 * looked up, and the name/message the default formatter stringifies are plain strings on non-proxy
 * prototypes. Returns the exact V8-style header the engine will print, or undefined. */
function pristineHeader(error:object,boundary:StackBoundary):string|undefined{
 const prepare=getOwn(IntrinsicError,"prepareStackTrace");
 if(prepare!==undefined&&!(enginePrepare!==undefined&&"value" in prepare&&prepare.value===enginePrepare))return undefined;
 if(getProto(IntrinsicError)!==FunctionPrototype)return undefined;
 if(getOwn(FunctionPrototype,"prepareStackTrace")!==undefined||getOwn(ObjectPrototype,"prepareStackTrace")!==undefined)return undefined;
 const lookup=(key:"name"|"message"):string|undefined|null=>{
  let holder:object|null=error;
  for(let depth=0;holder!==null&&depth<16;depth++){
   // The thrown value was branded native by the owned boundary. Every further prototype must be
   // provably an ordinary object: a runtime proxy test, or identity with a known intrinsic.
   if(depth>0){
    const proven=boundary.isProxy?boundary.isProxy(holder)===false:intrinsicPrototypes.includes(holder);
    if(!proven)return null;
   }
   const descriptor=getOwn(holder,key);
   if(descriptor){
    if(!("value" in descriptor))return null;
    const value:unknown=descriptor.value;
    return typeof value==="string"||value===undefined?value:null;
   }
   holder=getProto(holder) as object|null;
  }
  return holder===null?undefined:null;
 };
 const name=lookup("name"),message=lookup("message");
 if(name===null||message===null)return undefined;
 const n=name===undefined?"Error":name,m=message===undefined?"":message;
 return n===""?m:m===""?n:n+": "+m;
}

function engineString(error:object):string|undefined|null{
 const own=getOwn(error,"stack");
 if(own===undefined){
  if(prototypeGetter===undefined)return null;
  const value:unknown=apply(prototypeGetter,error,[]);
  return typeof value==="string"?value:null;
 }
 if("value" in own)return typeof own.value==="string"?own.value:null;
 if(engineGetter===undefined||own.get!==engineGetter)return null;
 const value:unknown=apply(own.get,error,[]);
 return typeof value==="string"?value:null;
}

/** What a client parsed from the stacks it has seen: sanitized frames only, found again by the SHA-256 of the header and stack text (a repeated error at one site, the common shape of an error storm, is a lookup instead of a parse of every line). The text itself, which carries the error message, is not kept. */
const stackMemos=new WeakMap<FrameNaming,Map<string,StackRead>>();
const MEMO_TEXT=16384,MEMO_ENTRIES=16;
/** Reads the stack of an error the owned boundary already branded native and non-proxy.
 * Never invokes a program-defined getter, Error.prepareStackTrace, name/message accessor or proxy trap. */
export function readStackFrames(error:object,boundary:StackBoundary,naming:FrameNaming,budget:number):StackRead{
 if(budget<=0)return none("frame_limit");
 const header=pristineHeader(error,boundary);
 if(header===undefined)return none(stackFormatterHooked);
 let text:string|null|undefined;
 try{text=engineString(error);}catch{return none(stackNotPlain);}
 if(typeof text!=="string")return none(stackNotPlain);
 const limit=Math.min(budget,MAX_FRAMES);
 if(text.length>MEMO_TEXT)return parseStack(text,header,naming,limit);
 let memo=stackMemos.get(naming);if(memo===undefined){memo=new Map();stackMemos.set(naming,memo);}
 const key=limit+":"+hashBytes(header+"\n"+text),known=memo.get(key);
 if(known!==undefined)return known;
 const read=parseStack(text,header,naming,limit);
 if(memo.size>=MEMO_ENTRIES)memo.delete(memo.keys().next().value!);
 memo.set(key,read);return read;
}

const SAFE_PATH=/^[A-Za-z0-9_./+-]{1,500}$/;
function cleanRelative(path:string):string|undefined{
 if(!SAFE_PATH.test(path)||path.startsWith("/")||path.endsWith("/"))return undefined;
 const parts=path.split("/");
 return parts.some(p=>p===""||p==="."||p===".."||p==="node_modules")?undefined:path;
}
/** Maps a generated-code location to an artifact-relative path, or a closed reason it cannot be named. */
export function artifactPath(url:string,root:string|undefined):{path:string}|{reason:string}{
 const query=url.search(/[?#]/),bare=query===-1?url:url.slice(0,query);let candidate:string;
 if(/^https?:\/\//.test(bare)){
  const afterHost=bare.indexOf("/",bare.indexOf("//")+2);
  if(afterHost===-1)return {reason:"frame_not_project_safe"};
  if(root!==undefined&&/^https?:\/\//.test(root)){
   const prefix=root.endsWith("/")?root:root+"/";
   if(!bare.startsWith(prefix))return {reason:"frame_not_project_safe"};
   candidate=bare.slice(prefix.length);
  }else candidate=bare.slice(afterHost+1);
 }else if(bare.startsWith("file:///")||/^[A-Za-z]:[\\/]/.test(bare)||bare.startsWith("/")||bare.startsWith("\\\\")){
  let local=bare.startsWith("file:///")?bare.slice(7):bare;
  try{if(bare.startsWith("file:///"))local=decodeURIComponent(local);}catch{return {reason:"frame_not_project_safe"};}
  local=local.replace(/\\/g,"/");
  if(/^\/[A-Za-z]:\//.test(local))local=local.slice(1);
  if(root===undefined||/^https?:\/\//.test(root))return {reason:"project_root_unconfigured"};
  const base=root.replace(/\\/g,"/").replace(/\/+$/,""),fold=/^[A-Za-z]:/.test(base);
  const a=fold?local.toLowerCase():local,b=fold?base.toLowerCase():base;
  if(!a.startsWith(b+"/"))return {reason:"frame_not_project_safe"};
  candidate=local.slice(base.length+1);
 }else return {reason:"frame_not_project_safe"};
 const path=cleanRelative(candidate);
 return path===undefined?{reason:"frame_not_project_safe"}:{path};
}

function safeFunction(raw:string):string{
 let name=raw.trim();
 const alias=name.indexOf(" [as ");if(alias!==-1)name=name.slice(0,alias);
 name=name.replace(/[^A-Za-z0-9_.:/<>+$ -]/g,"_").slice(0,256).trim();
 return name===""?"<anonymous>":name;
}

/** Splits `location:line:column` (trailing digits only). */
function position(location:string):{url:string;line:number;column:number}|undefined{
 const c2=location.lastIndexOf(":");if(c2<1)return undefined;
 const c1=location.lastIndexOf(":",c2-1);if(c1<1)return undefined;
 const column=location.slice(c2+1),line=location.slice(c1+1,c2);
 if(!/^\d{1,10}$/.test(column)||!/^\d{1,10}$/.test(line))return undefined;
 return {url:location.slice(0,c1),line:Number(line),column:Number(column)};
}

/** Bounded multi-engine frame parser: V8 (`at fn (loc)`), JavaScriptCore and SpiderMonkey (`fn@loc`).
 * Only generated location + a sanitized function name leave this function; no source text, URL query or host. */
export function parseStack(text:string,header:string,naming:FrameNaming,budget:number):StackRead{
 const bounded=text.length>MAX_TEXT?text.slice(0,MAX_TEXT):text;
 const v8=bounded.startsWith(header);
 // A V8-style stack starts with the formatted message: skip it exactly so message text can never forge a frame line.
 let body=v8?bounded.slice(header.length):bounded;
 const frames:SafeFrame[]=[],reasons=new Set<string>();
 let seenLine=false;
 while(body.length>0){
  const end=body.indexOf("\n");
  const raw=end===-1?body:body.slice(0,end);
  body=end===-1?"":body.slice(end+1);
  const line=raw.length>MAX_LINE?"":raw.trim();
  if(line==="")continue;
  let functionName="",location="",isAsync=false;
  if(v8){
   if(!line.startsWith("at "))continue;
   let rest=line.slice(3);
   if(rest.startsWith("async ")){isAsync=true;rest=rest.slice(6);}
   if(rest.endsWith(")")){
    const open=rest.indexOf(" (");
    if(open===-1)continue;
    functionName=rest.slice(0,open);location=rest.slice(open+2,-1);
   }else location=rest;
  }else{
   const at=line.indexOf("@");
   if(at===-1)continue;
   functionName=line.slice(0,at);location=line.slice(at+1);
  }
  seenLine=true;
  if(location.startsWith("eval at ")||location.includes(", <anonymous>")||location.includes("eval at ")){reasons.add("frame_not_project_safe");continue;}
  const where=position(location);
  if(where===undefined||where.line<1||where.line>4294967295||where.column>4294967295){reasons.add("frame_not_project_safe");continue;}
  const named=artifactPath(where.url,naming.root);
  if("reason" in named){reasons.add(named.reason);continue;}
  if(frames.length>=budget){reasons.add("frame_limit");break;}
  frames.push(Object.freeze({artifact_id:naming.ids?.get(named.path)??named.path,module_id:named.path,function:safeFunction(functionName),line:where.line,column:where.column>0?where.column-1:null,in_app:true,async:isAsync}));
 }
 if(frames.length===0&&!seenLine)reasons.add(stackUnparsed);
 else if(frames.length===0&&reasons.size===0)reasons.add(stackUnparsed);
 return {frames:Object.freeze(frames),reasons:Object.freeze([...reasons])};
}
