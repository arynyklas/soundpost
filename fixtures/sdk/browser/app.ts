// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {init} from "../../../packages/browser/src/index.ts";
import {installFetch} from "../../../packages/browser/src/fetch.ts";
import {installNavigation} from "../../../packages/browser/src/navigation.ts";
import {serializeWorkerContext} from "../../../packages/browser/src/workers.ts";
import type {Config} from "../../../packages/core/src/types.ts";
export interface BrowserFixtureInput {config:Config;backend:string;foreign:string}
export async function runCriticalPath(input:BrowserFixtureInput) {
 const client=init(input.config),outbound=installFetch(client,{operation:"http.call",origins:[{origin:new URL(input.backend).origin,dependency:"dependency"}]}),navigation=installNavigation(client,{operations:["navigation"]}),start=String(BigInt(Date.now())*1000000n);let workerResult:unknown;
 try{await navigation.navigate("navigation",async context=>{
  // This await deliberately loses ambient context: the next boundary is explicit.
  await Promise.resolve();if(client.traceContext()!==undefined)throw Error("browser_ambient_context_guessed");
  const responses=await Promise.all([outbound.fetch(input.backend+"/critical?CANARY_BROWSER_URL",{headers:{"x-canary":"CANARY_BROWSER_HEADER"}},context),outbound.fetch(input.backend+"/critical",undefined,context)]);
  for(const response of responses)if(response.status!==201||await response.text()!=="critical-ok")throw Error("backend_behavior_changed");
  try{await outbound.fetch(input.foreign,{headers:{traceparent:"00-"+"1".repeat(32)+"-"+"2".repeat(16)+"-01",baggage:"CANARY_BAGGAGE","x-soundpost-context":"CANARY_FOREIGN_CONTEXT"}},context);}catch{/* A real foreign origin may deny CORS; absent propagation is still asserted by the driver. */}
  const worker=new Worker(new URL("./worker.js",import.meta.url),{type:"module"}),ready=Promise.withResolvers<MessageEvent>();worker.onmessage=ready.resolve;worker.onerror=ready.reject;await ready.promise;const result=Promise.withResolvers<MessageEvent>();worker.onmessage=result.resolve;worker.onerror=result.reject;worker.postMessage(serializeWorkerContext(context));try{workerResult=(await result.promise).data;}finally{worker.terminate();}
 });
 const records=client.bufferedRecords().map(text=>JSON.parse(text));if(/CANARY_|SELECT/.test(JSON.stringify({records,diagnostics:client.diagnostics()})))throw Error("browser_prequeue_privacy_failed");const report=await client.flush(10000);if(report.pending||report.lost||!report.receipts.length)throw Error("browser_durable_receipt_missing");return {records,report,worker:workerResult,start_ns:start,end_ns:String(BigInt(Date.now())*1000000n),userAgent:navigator.userAgent};
 }finally{navigation.close();outbound.close();await client.close();}
}
Object.assign(globalThis,{runCriticalPath});
