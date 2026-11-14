// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Measures, per runtime, how many times user code is invoked by the SDK's stack read (decision D7).
// Run with Node >=22.18 (native type stripping) or Bun:  node|bun fixtures/sdk/hooks/stack-probe.mjs
// Prints one JSON object; exits 1 if any user-code invocation is attributable to the SDK.
import {resolve} from "node:path";
import {types} from "node:util";
import {extractException} from "../../../packages/core/src/errors.ts";

const policy={};
const boundary={isNativeError:types.isNativeError,isProxy:types.isProxy};
const root=resolve(import.meta.dirname,"../../..");
const result={runtime:typeof Bun==="undefined"?"node "+process.versions.node:"bun "+Bun.version,cases:{}};
const statics={prepare:Error.prepareStackTrace,capture:Error.captureStackTrace};
const restore=()=>{Error.prepareStackTrace=statics.prepare;Error.captureStackTrace=statics.capture;};
function run(name,build){
 let calls=0;const tick=()=>{calls++;throw Error("user code ran");};
 let graph;
 try{graph=extractException(build(tick),policy,boundary,{root});}finally{restore();}
 result.cases[name]={user_code_invocations:calls,frames:graph.nodes[0].frames.length,reasons:graph.reasons};
}
run("baseline_plain_error",()=>new Error("m"));
run("prepare_before_create",tick=>{Error.prepareStackTrace=tick;return new Error("m");});
run("prepare_after_create",tick=>{const error=new Error("m");Error.prepareStackTrace=tick;return error;});
run("poisoned_captureStackTrace",tick=>{Error.captureStackTrace=tick;return new Error("m");});
run("getter_defined_stack",tick=>{const error=new Error("m");Object.defineProperty(error,"stack",{get:tick,configurable:true});return error;});
run("name_getter",tick=>{const error=new Error("m");Object.defineProperty(error,"name",{get:tick,configurable:true});return error;});
run("message_getter",tick=>{const error=new Error("m");Object.defineProperty(error,"message",{get:tick,configurable:true});return error;});
run("proxy_error",tick=>new Proxy(new Error("m"),{get:tick,getOwnPropertyDescriptor:tick,getPrototypeOf:tick,has:tick,ownKeys:tick}));
run("proxy_prototype",tick=>{const error=new Error("m");Object.setPrototypeOf(error,new Proxy(Error.prototype,{get:tick,getOwnPropertyDescriptor:tick,getPrototypeOf:tick,has:tick}));return error;});
console.log(JSON.stringify(result));
process.exit(Object.values(result.cases).some(c=>c.user_code_invocations!==0)?1:0);
