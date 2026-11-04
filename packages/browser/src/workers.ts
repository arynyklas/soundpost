// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {checkedTraceContext,type Client} from "@soundpost/core";
import type {TraceContext,WorkerContext} from "@soundpost/core/types";
/** A closed causal envelope. It cannot carry project, credentials or message data. */
export function serializeWorkerContext(context:TraceContext):WorkerContext {
 const safe=checkedTraceContext(context);
 return Object.freeze({version:1,trace_id:safe.traceId,span_id:safe.spanId,sampled:safe.sampled,probability:safe.probability,clock:Object.freeze({...safe.clockDomain})});
}
export function parseWorkerContext(value:unknown):TraceContext {
 if(!value||typeof value!=="object"||Array.isArray(value))throw Error("invalid_worker_context");
 const descriptors=Object.getOwnPropertyDescriptors(value),keys=["version","trace_id","span_id","sampled","probability","clock"];
 if(Reflect.ownKeys(descriptors).length!==keys.length||keys.some(key=>!descriptors[key]||!("value" in descriptors[key]!)))throw Error("invalid_worker_context");
 const field=(key:string):unknown=>descriptors[key]!.value;
 if(field("version")!==1)throw Error("invalid_worker_context");
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
