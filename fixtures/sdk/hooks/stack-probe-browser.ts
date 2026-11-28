// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Browser variant of stack-probe.mjs (decision D7): counts user-code invocations caused by the SDK's stack read in the
// real browser, using the browser entry's boundary (intrinsic Error.isError, no proxy test).
//   node fixtures/sdk/hooks/browser-run.mjs --executable <chrome> --bun <bun> --fixture fixtures/sdk/hooks/stack-probe-browser.ts --export runStackProbe
import {extractException} from "../../../packages/core/src/errors.ts";

export async function runStackProbe():Promise<Record<string,unknown>> {
 const brand:unknown=Object.getOwnPropertyDescriptor(Error,"isError")?.value;
 if(typeof brand!=="function")throw Error("Error.isError unavailable");
 const boundary={isNativeError:(value:unknown)=>Reflect.apply(brand,Error,[value])===true};
 const policy={} as never;
 const statics={prepare:Error.prepareStackTrace,capture:Error.captureStackTrace};
 const cases:Record<string,unknown>={};
 const run=(name:string,build:(tick:()=>never)=>unknown):void=>{
  let calls=0;const tick=():never=>{calls++;throw Error("user code ran");};
  try{
   const graph=extractException(build(tick),policy,boundary,{});
   cases[name]={user_code_invocations:calls,frames:graph.nodes[0]!.frames.length,reasons:graph.reasons};
  }finally{Error.prepareStackTrace=statics.prepare;Error.captureStackTrace=statics.capture;}
 };
 run("baseline_plain_error",()=>new Error("m"));
 run("prepare_before_create",tick=>{Error.prepareStackTrace=tick;return new Error("m");});
 run("prepare_after_create",tick=>{const error=new Error("m");Error.prepareStackTrace=tick;return error;});
 run("poisoned_captureStackTrace",tick=>{Error.captureStackTrace=tick;return new Error("m");});
 run("getter_defined_stack",tick=>{const error=new Error("m");Object.defineProperty(error,"stack",{get:tick,configurable:true});return error;});
 run("name_getter",tick=>{const error=new Error("m");Object.defineProperty(error,"name",{get:tick,configurable:true});return error;});
 run("message_getter",tick=>{const error=new Error("m");Object.defineProperty(error,"message",{get:tick,configurable:true});return error;});
 run("proxy_error",tick=>new Proxy(new Error("m"),{get:tick,getOwnPropertyDescriptor:tick,getPrototypeOf:tick,has:tick,ownKeys:tick}));
 run("proxy_prototype",tick=>{const error=new Error("m");Object.setPrototypeOf(error,new Proxy(Error.prototype,{get:tick,getOwnPropertyDescriptor:tick,getPrototypeOf:tick,has:tick}));return error;});
 run("custom_error_class_plain",()=>{class Custom extends Error{}return new Custom("m");});
 const total=Object.values(cases).reduce((n:number,c)=>n+(c as {user_code_invocations:number}).user_code_invocations,0);
 if(total!==0)throw Error("user code ran: "+JSON.stringify(cases));
 return {cases,user_code_invocations:total};
}
