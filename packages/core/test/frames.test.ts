// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {test,expect} from "bun:test";
import {types} from "node:util";
import {dirname} from "node:path";
import {fileURLToPath} from "node:url";
import {extractException} from "../src/errors.ts";
import {parseStack,artifactPath} from "../src/frames.ts";
import {config} from "./fixture.ts";
import {resolve} from "../src/policy.ts";
const policy=resolve(config());
const boundary={isNativeError:types.isNativeError,isProxy:types.isProxy};
const here=dirname(fileURLToPath(import.meta.url));
/** Runs fn with Error.prepareStackTrace/captureStackTrace restored afterwards. Restoration is by assignment:
 * Bun keeps its own copy of an assigned formatter that a defineProperty restore does not clear. */
function withErrorStatics<T>(fn:()=>T):T{
 const prepare=Error.prepareStackTrace,capture=Error.captureStackTrace;
 try{return fn();}finally{
  Error.prepareStackTrace=prepare;
  Error.captureStackTrace=capture;
 }
}
function frameFromHere():Error{return new Error("frame source");}

test("an engine stack of a plain native error yields bounded project-relative frames",()=>{
 const graph=extractException(frameFromHere(),policy,boundary,{root:here});
 const frames=graph.nodes[0]!.frames;
 expect(frames.length).toBeGreaterThan(0);
  expect(frames[0]!.artifact_id).toBe("frames.test.ts");
 expect(frames[0]!.line).toBeGreaterThan(0);
 expect(graph.nodes[0]!.frames.every(f=>/^[A-Za-z0-9_./+-]+$/.test(f.artifact_id)&&f.in_app)).toBe(true);
 expect(JSON.stringify(graph)).not.toContain("frame source");
});

test("a program-defined stack getter is never called",()=>{
 let calls=0;
 const error=new Error("CANARY");
 Object.defineProperty(error,"stack",{get(){calls++;throw Error("getter");},configurable:true});
 const graph=extractException(error,policy,boundary,{root:here});
 expect(calls).toBe(0);expect(graph.nodes[0]!.frames).toHaveLength(0);expect(graph.reasons).toContain("stack_not_plain");
});

test("a proxy error runs no trap and yields no frames",()=>{
 let calls=0;
 const trap=()=>{calls++;throw Error("trap");};
 const proxy=new Proxy(new Error("CANARY"),{get:trap,getOwnPropertyDescriptor:trap,getPrototypeOf:trap,has:trap,ownKeys:trap});
 const graph=extractException(proxy,policy,boundary,{root:here});
 expect(calls).toBe(0);expect(graph.nodes[0]!.exception_class).toBe("UnknownError");expect(graph.nodes[0]!.frames).toHaveLength(0);
 // A native error whose prototype is a proxy must not be formatted either.
 const hostile=new Error("CANARY");
 Object.setPrototypeOf(hostile,new Proxy(Error.prototype,{get:trap,getOwnPropertyDescriptor:trap,getPrototypeOf:trap,has:trap}));
 const second=extractException(hostile,policy,boundary,{root:here});
 expect(calls).toBe(0);expect(second.nodes[0]!.frames).toHaveLength(0);expect(second.reasons).toContain("stack_formatter_hooked");
});

test("Error.prepareStackTrace set before creation or after creation is never invoked",()=>{
 withErrorStatics(()=>{
  let calls=0;
  Error.prepareStackTrace=()=>{calls++;throw Error("formatter");};
  const early=new Error("early");
  const first=extractException(early,policy,boundary,{root:here});
  Error.prepareStackTrace=undefined;
  const late=new Error("late");
  Error.prepareStackTrace=()=>{calls++;throw Error("formatter");};
  const second=extractException(late,policy,boundary,{root:here});
  expect(calls).toBe(0);
  for(const graph of [first,second]){expect(graph.nodes[0]!.frames).toHaveLength(0);expect(graph.reasons).toContain("stack_formatter_hooked");}
 });
});

test("a poisoned Error.captureStackTrace is never reached",()=>{
 withErrorStatics(()=>{
  let calls=0;
  Error.captureStackTrace=()=>{calls++;throw Error("poisoned");};
  const graph=extractException(frameFromHere(),policy,boundary,{root:here});
  expect(calls).toBe(0);expect(graph.nodes[0]!.frames.length).toBeGreaterThan(0);
 });
});

test("name and message accessors that the default formatter would call stop the read",()=>{
 let calls=0;
 const named=new Error("CANARY");
 Object.defineProperty(named,"name",{get(){calls++;return "N";},configurable:true});
 const messaged=new Error("CANARY");
 Object.defineProperty(messaged,"message",{get(){calls++;return "M";},configurable:true});
 class Custom extends Error{override get name():string{calls++;return "Custom";}}
 for(const error of [named,messaged,new Custom("CANARY")]){
  const graph=extractException(error,policy,boundary,{root:here});
  expect(graph.nodes[0]!.frames).toHaveLength(0);expect(graph.reasons).toContain("stack_formatter_hooked");
 }
 expect(calls).toBe(0);
});

test("a subclass with plain name and message is still read",()=>{
 class Plain extends Error{}
 Object.defineProperty(Plain.prototype,"name",{value:"Plain"});
 const graph=extractException(new Plain("m"),policy,boundary,{root:here});
 expect(graph.nodes[0]!.frames.length).toBeGreaterThan(0);
});

test("frames are budgeted to 128 across the whole graph",()=>{
 // Engines differ in how deep they print, so each node carries an own data stack of 100 synthetic frames.
 const synthetic=(cause?:Error):Error=>{
  const error=new Error("m",{cause});
  const lines=Array.from({length:100},(_,n)=>"    at fn"+n+" (file:///srv/app/dist/main.mjs:"+(n+1)+":1)").join("\n");
  Object.defineProperty(error,"stack",{value:"Error: m\n"+lines,configurable:true,writable:true});
  return error;
 };
 const graph=extractException(synthetic(synthetic(synthetic())),policy,boundary,{root:"/srv/app"});
 expect(graph.nodes.map(n=>n.frames.length)).toEqual([100,28,0]);
 expect(graph.reasons).toContain("frame_limit");
});

test("V8, JavaScriptCore and SpiderMonkey frame lines parse to the same bounded shape",()=>{
 const root="/srv/app";
 const v8="Error: boom\n    at Module.load (file:///srv/app/dist/main.mjs:10:5)\n    at async run (file:///srv/app/dist/main.mjs:20:15)\n    at file:///srv/app/dist/main.mjs:30:1\n    at node:internal/main:1:1\n    at eval (eval at f (file:///srv/app/dist/main.mjs:1:1), <anonymous>:1:1)";
 const a=parseStack(v8,"Error: boom",{root},128);
 expect(a.frames.map(f=>[f.artifact_id,f.function,f.line,f.column,f.async])).toEqual([
  ["dist/main.mjs","Module.load",10,4,false],["dist/main.mjs","run",20,14,true],["dist/main.mjs","<anonymous>",30,0,false]]);
 const jsc="load@https://app.example/assets/index-abc.js:3:9\n@https://app.example/assets/index-abc.js?x=1#y:4:2\nglobal code@https://app.example/assets/other.js:1:1\nnative code@[native code]";
 const b=parseStack(jsc,"Error: boom",{root:"https://app.example/"},128);
 expect(b.frames.map(f=>[f.artifact_id,f.function,f.line,f.column])).toEqual([
  ["assets/index-abc.js","load",3,8],["assets/index-abc.js","<anonymous>",4,1],["assets/other.js","global code",1,0]]);
 const withoutRoot=parseStack("load@https://cdn.example/a/b.js:5:6","Error",{root:""},128);
 expect(withoutRoot.frames[0]!.artifact_id).toBe("a/b.js");
 expect(parseStack("Error: x\n    at f (file:///srv/app/dist/main.mjs:1:1)","Error: x",{},128).reasons).toContain("project_root_unconfigured");
});

test("message text cannot forge a frame and unsafe locations are withheld",()=>{
 const message="line\n    at forged (file:///srv/app/dist/forged.mjs:1:1)";
 const header="Error: "+message;
 const stack=header+"\n    at real (file:///srv/app/dist/real.mjs:2:3)";
 const parsed=parseStack(stack,header,{root:"/srv/app"},128);
 expect(parsed.frames.map(f=>f.artifact_id)).toEqual(["dist/real.mjs"]);
 // A header that does not match means the text is parsed only as header-less engine output: V8 lines are ignored.
 expect(parseStack(stack,"Error: other",{root:"/srv/app"},128).frames).toHaveLength(0);
 for(const url of ["file:///etc/passwd","file:///srv/app/node_modules/x/i.js","file:///srv/app/../x.js","https://h/a%00.js","node:fs","webpack-internal:///./x.ts","data:text/javascript,1"])
  expect("path" in artifactPath(url,"/srv/app")).toBe(false);
 expect(artifactPath("file:///C:/Work/App/dist/a%20b.mjs","c:\\work\\app")).toEqual({reason:"frame_not_project_safe"});
 expect(artifactPath("file:///C:/Work/App/dist/a.mjs","c:\\work\\app")).toEqual({path:"dist/a.mjs"});
 const huge=parseStack("Error\n"+"    at f (file:///srv/app/x.js:1:1)\n".repeat(5000),"Error",{root:"/srv/app"},128);
 expect(huge.frames.length).toBeLessThanOrEqual(128);
});

test("a build-receipt association replaces the path with the real ArtifactID only for listed paths",()=>{
 const id="0123456789abcdef0123456789abcdef";
 const parsed=parseStack("Error\n    at a (file:///srv/app/dist/main.mjs:3:4)\n    at b (file:///srv/app/dist/other.mjs:5:6)","Error",{root:"/srv/app",ids:new Map([["dist/main.mjs",id]])},128);
 expect(parsed.frames.map(f=>[f.artifact_id,f.module_id])).toEqual([[id,"dist/main.mjs"],["dist/other.mjs","dist/other.mjs"]]);
});
