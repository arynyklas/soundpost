// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {checkedTraceContext,type Client} from "@soundpost/core";
import type {TraceContext,WorkerContext} from "@soundpost/core/types";
import type {IncomingMessage} from "node:http";
import {types} from "node:util";
/** A closed causal envelope. It cannot carry project, credentials or message data. */
export function serializeWorkerContext(context:TraceContext):WorkerContext {
 if(types.isProxy(context)||types.isProxy(Object.getOwnPropertyDescriptor(context,"clockDomain")?.value))throw Error("invalid_worker_context");const safe=checkedTraceContext(context);
 return Object.freeze({version:1,trace_id:safe.traceId,span_id:safe.spanId,sampled:safe.sampled,probability:safe.probability,clock:Object.freeze({...safe.clockDomain})});
}
export function parseWorkerContext(value:unknown):TraceContext {
 if(!value||typeof value!=="object"||types.isProxy(value)||Array.isArray(value))throw Error("invalid_worker_context");
 const descriptors=Object.getOwnPropertyDescriptors(value),keys=["version","trace_id","span_id","sampled","probability","clock"];
 if(Reflect.ownKeys(descriptors).length!==keys.length||keys.some(key=>!descriptors[key]||!("value" in descriptors[key]!)))throw Error("invalid_worker_context");
 const field=(key:string):unknown=>descriptors[key]!.value;
 if(field("version")!==1)throw Error("invalid_worker_context");
 if(types.isProxy(field("clock")))throw Error("invalid_worker_context");
 return checkedTraceContext({traceId:field("trace_id"),spanId:field("span_id"),sampled:field("sampled"),probability:field("probability"),clockDomain:field("clock")});
}
export async function withWorkerContext<T>(client:Client,context:unknown,callback:()=>Promise<T>):Promise<T> {
 return client.withTraceContext(parseWorkerContext(context),callback);
}
export function propagationHeaders(context:TraceContext):Readonly<{traceparent:string;companion:string}> {
 const safe=checkedTraceContext(context),clock=safe.clockDomain;
 return {traceparent:"00-"+safe.traceId+"-"+safe.spanId+(safe.sampled?"-01":"-00"),companion:"v1."+safe.probability+"."+clock.host+"."+clock.boot+"."+clock.runtime};
}
/** Foreign traceparent alone has no known sampling/clock companion: no invented link. */
export function parsePropagation(traceparent:unknown,companion:unknown):TraceContext|undefined {
 if(typeof traceparent!=="string"||typeof companion!=="string")return undefined;
 const parent=/^00-([0-9a-f]{32})-([0-9a-f]{16})-(00|01)$/.exec(traceparent),parts=/^v1\.([0-9a-f]{16})\.([0-9a-f]{32})\.([0-9a-f]{32})\.([0-9a-f]{32})$/.exec(companion);
 if(!parent||!parts)return undefined;
 try{return checkedTraceContext({traceId:parent[1],spanId:parent[2],sampled:parent[3]==="01",probability:parts[1],clockDomain:{host:parts[2],boot:parts[3],runtime:parts[4]}});}catch{return undefined;}
}
/** The parent context an incoming request carries, found in its raw header list so Node never has to build the lazy `headers` object for requests that carry no trace.
 * Answers exactly what parsePropagation answers over `headers`: Node joins a repeated header with ", ", which fails the strict shapes, so a repeat yields no parent here too. */
export function requestPropagation(request:IncomingMessage):TraceContext|undefined {
 const raw=request.rawHeaders;
 if(!Array.isArray(raw))return parsePropagation(request.headers.traceparent,request.headers["x-soundpost-context"]);
 let parent:string|undefined,companion:string|undefined,repeated=false;
 for(let index=0;index+1<raw.length;index+=2){
  const name=raw[index]!;
  if(name.length===11&&name.toLowerCase()==="traceparent"){if(parent!==undefined)repeated=true;parent=raw[index+1];}
  else if(name.length===19&&name.toLowerCase()==="x-soundpost-context"){if(companion!==undefined)repeated=true;companion=raw[index+1];}
 }
 return repeated?undefined:parsePropagation(parent,companion);
}
