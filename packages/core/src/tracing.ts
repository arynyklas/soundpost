// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {canonicalId,decimal,unixNano} from "./policy.ts";
import type {JobContext} from "./jobs.ts";
export interface ClockDomain {readonly host:string;readonly boot:string;readonly runtime:string}
export interface TraceClock {readonly wall_ns:string;readonly mono_ns:string;readonly domain:ClockDomain;readonly uncertainty_ns:string}
export interface TraceClockSource {():TraceClock;readonly domain:ClockDomain}
export interface TraceContext {readonly traceId:string;readonly spanId:string;readonly sampled:boolean;readonly probability:string;readonly clockDomain:ClockDomain}
export interface MetadataContext {readonly clockDomain:ClockDomain;current():TraceContext|undefined;run<T>(context:TraceContext|undefined,callback:()=>T):T;jobCurrent():JobContext|undefined;runJob<T>(context:JobContext|undefined,callback:()=>T):T;clock():TraceClock;close():void}
export interface WorkerContext {readonly version:1;readonly trace_id:string;readonly span_id:string;readonly sampled:boolean;readonly probability:string;readonly clock:ClockDomain}
export type SpanStatus="ok"|"error"|"cancelled"|"incomplete";
export interface SpanOptions {readonly dependency?:string;readonly kind?:"internal"|"server"|"client"|"producer"|"consumer";readonly parent?:TraceContext|null;readonly signal?:AbortSignal}
export interface NativeSpan {readonly trace_id:string;readonly span_id:string;readonly parent_id:string|null;readonly span_kind:NonNullable<SpanOptions["kind"]>;readonly operation:string;readonly start:TraceClock;readonly end:TraceClock|null;readonly status:SpanStatus;readonly dependency_alias:string;readonly links:readonly Readonly<{trace_id:string;span_id:string}>[];readonly sample_probability:string;readonly sample_decision:"keep"|"drop"}
export interface ActiveSpan {readonly context:TraceContext;run<T>(callback:()=>T):T;end(status:SpanStatus):void}
export function randomHex(bytes:number):string{return Array.from(crypto.getRandomValues(new Uint8Array(bytes)),value=>value.toString(16).padStart(2,"0")).join("");}
function fields(value:unknown,keys:readonly string[]):Record<string,PropertyDescriptor>{if(!value||typeof value!=="object"||Array.isArray(value))throw Error("invalid_trace_context");const descriptors=Object.getOwnPropertyDescriptors(value);if(Reflect.ownKeys(descriptors).length!==keys.length||keys.some(key=>!descriptors[key]||!("value" in descriptors[key]!)))throw Error("invalid_trace_context");return descriptors;}
export function probabilityValue(bits:unknown):number {if(typeof bits!=="string"||!/^[0-9a-f]{16}$/.test(bits))throw Error("invalid_trace_probability");const bytes=new DataView(new ArrayBuffer(8));bytes.setBigUint64(0,BigInt("0x"+bits),false);const value=bytes.getFloat64(0,false);if(!Number.isFinite(value)||value<0||value>1||Object.is(value,-0))throw Error("invalid_trace_probability");return value;}
const abortState=Object.getOwnPropertyDescriptor(AbortSignal.prototype,"aborted")!.get!;
export function signalAborted(signal:unknown):boolean{try{return Reflect.apply(abortState,signal,[])===true;}catch{return false;}}
export function checkedTraceContext(value:unknown):TraceContext {
 const descriptors=fields(value,["traceId","spanId","sampled","probability","clockDomain"]),traceId=canonicalId(descriptors.traceId!.value),spanId:unknown=descriptors.spanId!.value,sampled:unknown=descriptors.sampled!.value,probability:unknown=descriptors.probability!.value;
 if(typeof spanId!=="string"||!/^[0-9a-f]{16}$/.test(spanId)||spanId==="0".repeat(16)||typeof sampled!=="boolean")throw Error("invalid_trace_context");const chance=probabilityValue(probability);if(sampled&&chance===0)throw Error("invalid_trace_context");
 const domain=fields(descriptors.clockDomain!.value,["host","boot","runtime"]),clockDomain=Object.freeze({host:canonicalId(domain.host!.value),boot:canonicalId(domain.boot!.value),runtime:canonicalId(domain.runtime!.value)});
 return Object.freeze({traceId,spanId,sampled,probability:probability as string,clockDomain});
}
/** Exact binary/rational Bernoulli comparison, including subnormal float64 budgets.
 * A finite random-number bucket would falsely round tiny probabilities upward. */
export function sampleTraceDecision(probability:string,parentProbability?:string,random32?:()=>number):boolean {
 probabilityValue(probability);if(parentProbability!==undefined)probabilityValue(parentProbability);
 if(probability==="0000000000000000")return false;if(probability===(parentProbability??"3ff0000000000000"))return true;
 const fraction=(bits:string):readonly [bigint,bigint]=>{const raw=BigInt("0x"+bits),encoded=Number((raw>>52n)&2047n),significand=(raw&0xfffffffffffffn)+(encoded===0?0n:0x10000000000000n),exponent=encoded===0?-1074:encoded-1075;return exponent<0?[significand,1n<<BigInt(-exponent)]:[significand<<BigInt(exponent),1n];};
 const [numerator,denominator]=fraction(probability),[parentNumerator,parentDenominator]=fraction(parentProbability??"3ff0000000000000");if(parentNumerator===0n)throw Error("invalid_sampling_ratio");
 let remaining=numerator*parentDenominator;const divisor=denominator*parentNumerator;if(remaining>=divisor)return true;
 const word=new Uint32Array(1);for(;;){remaining<<=32n;const threshold=remaining/divisor;remaining%=divisor;const draw=random32?random32():crypto.getRandomValues(word)[0]!;if(!Number.isInteger(draw)||draw<0||draw>4294967295)throw Error("invalid_sampling_random");const integer=BigInt(draw);if(integer<threshold)return true;if(integer>threshold||remaining===0n)return false;}
}
export function createTraceClock(monotonic:()=>bigint,wall:()=>string=()=>String(BigInt(Date.now())*1000000n),uncertainty="18446744073709551615"):TraceClockSource {
 decimal(uncertainty);const domain=Object.freeze({host:randomHex(16),boot:randomHex(16),runtime:randomHex(16)});
 return Object.freeze(Object.assign(()=>Object.freeze({wall_ns:unixNano(wall()),mono_ns:decimal(String(monotonic())),domain,uncertainty_ns:uncertainty}),{domain}));
}
export function createSynchronousMetadataContext(wall?:()=>string):MetadataContext {
 let current:TraceContext|undefined,job:JobContext|undefined;const clock=createTraceClock(()=>BigInt(Math.trunc(performance.now()*1000000)),wall);
 return {clockDomain:clock.domain,current:()=>current,run<T>(context:TraceContext|undefined,callback:()=>T):T{const prior=current;current=context;try{return callback();}finally{current=prior;}},jobCurrent:()=>job,runJob<T>(context:JobContext|undefined,callback:()=>T):T{const prior=job;job=context;try{return callback();}finally{job=prior;}},clock,close(){current=undefined;job=undefined;}};
}
export class SpanRecorder {
 private readonly active=new Set<ActiveSpan>();private readonly operations:ReadonlySet<string>;private readonly dependencies:ReadonlySet<string>;private readonly probability:string;private readonly chance:number;
 constructor(private readonly context:MetadataContext,operations:readonly string[],dependencies:readonly string[],probability:string|undefined,private readonly enabled:()=>boolean,private readonly emit:(span:NativeSpan)=>void,private readonly loss:(reason:string)=>void){if(operations.length>128||dependencies.length>64||[...operations,...dependencies].some(value=>typeof value!=="string"||!/^[a-zA-Z0-9_.-]{1,128}$/.test(value)))throw Error("invalid_trace_aliases");this.operations=new Set(operations);this.dependencies=new Set(dependencies);this.probability=probability??"3ff0000000000000";this.chance=probabilityValue(this.probability);}
 current():TraceContext|undefined{return this.context.current();}
 run<T>(context:TraceContext|null,callback:()=>T):T{return this.context.run(context===null?undefined:checkedTraceContext(context),callback);}
 start(operation:string,options:SpanOptions={}):ActiveSpan {
  if(typeof operation!=="string"||!this.operations.has(operation))throw Error("unregistered_operation");
  const descriptors=Object.getOwnPropertyDescriptors(options);if(Object.values(descriptors).some(descriptor=>!("value" in descriptor)))throw Error("invalid_span_options");
  const dependency:unknown=descriptors.dependency?.value,kind:unknown=descriptors.kind?.value??"internal",parentValue:unknown=descriptors.parent?.value;
  if(dependency!==undefined&&(typeof dependency!=="string"||!this.dependencies.has(dependency)))throw Error("unregistered_dependency");if(typeof kind!=="string"||!["internal","server","client","producer","consumer"].includes(kind))throw Error("invalid_span_kind");
  const parent=parentValue===null?undefined:parentValue===undefined?this.context.current():checkedTraceContext(parentValue);
  const start=(()=>{try{return this.context.clock();}catch{this.loss("invalid_clock");return undefined;}})(),enabled=this.enabled()&&start!==undefined;
  // A trace's explicit head decision is inherited. A narrower deployment budget
  // never increases an upstream keep probability or resurrects an upstream drop.
  const parentChance=parent?probabilityValue(parent.probability):1,probability=parent&&parentChance<=this.chance?parent.probability:this.probability,sampled=enabled&&(parent?parent.sampled&&sampleTraceDecision(probability,parent.probability):sampleTraceDecision(probability));
  const context=Object.freeze({traceId:parent?.traceId??randomHex(16),spanId:randomHex(8),sampled,probability,clockDomain:this.context.clockDomain});let ended=false;
  const handle:ActiveSpan={context,run:<T>(callback:()=>T):T=>this.context.run(context,callback),end:(status:SpanStatus):void=>{
   if(ended)return;if(!["ok","error","cancelled","incomplete"].includes(status))throw Error("invalid_span_status");ended=true;this.active.delete(handle);
   if(!enabled||!start)return;if(!sampled){this.loss("trace_sampled_out");return;}
   let end:TraceClock|null=null;try{end=this.context.clock();if(end.domain.host!==start.domain.host||end.domain.boot!==start.domain.boot||end.domain.runtime!==start.domain.runtime||BigInt(end.mono_ns)<BigInt(start.mono_ns))throw Error("invalid_span_clock");}catch{this.loss("invalid_clock");status="incomplete";end=null;}
   this.emit({trace_id:context.traceId,span_id:context.spanId,parent_id:parent?.spanId??null,span_kind:kind as NativeSpan["span_kind"],operation,start,end,status,dependency_alias:typeof dependency==="string"?dependency:"",links:[],sample_probability:probability,sample_decision:"keep"});
  }};
  if(this.active.size>=1024){this.loss("trace_active_limit");handle.end("incomplete");}else this.active.add(handle);return handle;
 }
 close():void{for(const handle of [...this.active])handle.end("incomplete");this.context.close();}
}
