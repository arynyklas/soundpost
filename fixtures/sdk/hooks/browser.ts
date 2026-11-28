// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {init,installHooks} from "../../../packages/browser/src/index.ts";
import {config} from "../../../packages/core/test/fixture.ts";
/** Execute bundled artifact in a real browser, not a DOM emulator. Uses actual
 * global thrown errors and rejected promises; native console output is baseline. */
export async function runBrowserHooksFixture():Promise<Readonly<Record<string,unknown>>>{
 const c=init(config()),prior:string[]=[];
 const errorPrior=():void=>{prior.push("error");};
 const rejectionPrior=():void=>{prior.push("rejection");};
 window.addEventListener("error",errorPrior);window.addEventListener("unhandledrejection",rejectionPrior);
 const onerror=window.onerror,onrejection=window.onunhandledrejection;
 const lease=installHooks(c);
 try{
  let getterCalls=0;
  const hostile=new Error("CANARY_BROWSER_MESSAGE");
  Object.defineProperty(hostile,"stack",{get(){getterCalls++;throw Error("CANARY_STACK");}});
  c.captureException(hostile);
  if(getterCalls!==0)throw Error("SDK stack getter executed");
  // Both events come from the runtime rather than synthetic Event dispatch.
  window.setTimeout(()=>{throw new Error("CANARY_BROWSER_GLOBAL");},0);
  window.setTimeout(()=>{void Promise.reject(new TypeError("CANARY_BROWSER_REJECTION"));},0);
  const deadline=performance.now()+5000;
  while(prior.length<2&&performance.now()<deadline){
   const {promise,resolve}=Promise.withResolvers<void>();window.setTimeout(resolve,10);await promise;
  }
  if(c.bufferedRecords().length!==3||prior.join(",")!=="error,rejection")throw Error("browser hook capture or prior order mismatch");
  const rethrow=new Error("CANARY_EPISODE"),episode=c.beginHandlingEpisode();
  const eventId=episode.captureException(rethrow);
  lease.useEpisode(episode,rethrow,"uncaught_exception");
  void Promise.reject(new TypeError("CANARY_UNRELATED_REJECTION"));
  while(prior.length<3&&performance.now()<deadline){
   const {promise,resolve}=Promise.withResolvers<void>();window.setTimeout(resolve,10);await promise;
  }
  if(c.bufferedRecords().length!==5)throw Error("unrelated rejection was incorrectly deduplicated");
  window.setTimeout(()=>{throw rethrow;},0);
  while(prior.length<4&&performance.now()<deadline){
   const {promise,resolve}=Promise.withResolvers<void>();window.setTimeout(resolve,10);await promise;
  }
  const records=c.bufferedRecords();
  if(records.length!==5||prior.join(",")!=="error,rejection,rejection,error")throw Error("episode source binding failed");
  const unrelated:unknown=JSON.parse(records[4]!);
  if(unrelated===null||typeof unrelated!=="object"||!("payload" in unrelated))throw Error("invalid unrelated record");
  const payload=unrelated.payload;
  if(payload===null||typeof payload!=="object"||!("mechanism" in payload)||payload.mechanism!=="unhandled_rejection")throw Error("unrelated rejection consumed armed episode");
  if(!("exception_class" in payload)||(payload.exception_class!=="TypeError"&&payload.exception_class!=="UnknownError"))throw Error("wrong unrelated rejection class");
  if(records.filter(record=>{
   const parsed:unknown=JSON.parse(record);
   return parsed!==null&&typeof parsed==="object"&&"id" in parsed&&parsed.id===eventId;
  }).length!==1)throw Error("episode occurrence duplicated");
  if(records.join("").includes("CANARY"))throw Error("SDK canary leaked");
  if(window.onerror!==onerror||window.onunhandledrejection!==onrejection)throw Error("prior handlers changed");
  lease.close();lease.close();
  if(window.onerror!==onerror||window.onunhandledrejection!==onrejection)throw Error("close changed prior handlers");
  return Object.freeze({safe_captures:records.length,sdk_canaries:0,prior:prior.slice(),capabilities:lease.capabilities});
 }finally{lease.close();await c.close();window.removeEventListener("error",errorPrior);window.removeEventListener("unhandledrejection",rejectionPrior);}
}
