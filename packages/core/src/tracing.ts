// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {canonicalId,compareNano,decimal,unixNano} from "./policy.ts";
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
const hexByte:string[]=Array.from({length:256},(_,value)=>value.toString(16).padStart(2,"0")),entropy=new Uint8Array(4096);let entropyAt=entropy.length;
/** A Buffer view of the entropy pool when the host has Buffer (Node, Bun): hex-encoding a slice natively replaces one string concatenation per byte. */
interface HexSlice {toString(encoding:"hex",start:number,end:number):string}
interface HexHost {from(buffer:ArrayBufferLike,offset:number,length:number):HexSlice}
const hexView:HexSlice|undefined=(()=>{try{const host:HexHost|undefined=Reflect.get(globalThis,"Buffer");return host?.from(entropy.buffer,0,entropy.length);}catch{return undefined;}})();
/** Lowercase hex of `bytes` CSPRNG bytes. One getRandomValues call refills a 4 KiB pool that many IDs are cut from; no byte is handed out twice. */
export function randomHex(bytes:number):string{
 if(!Number.isInteger(bytes)||bytes<1||bytes>entropy.length)throw Error("invalid_random_length");
 if(entropyAt+bytes>entropy.length){crypto.getRandomValues(entropy);entropyAt=0;}
 const start=entropyAt;entropyAt+=bytes;
 if(hexView!==undefined)return hexView.toString("hex",start,entropyAt);
 let out="";for(let at=start;at<entropyAt;at++)out+=hexByte[entropy[at]!];
 return out;
}
function fields(value:unknown,keys:readonly string[]):Record<string,PropertyDescriptor>{if(!value||typeof value!=="object"||Array.isArray(value))throw Error("invalid_trace_context");const descriptors=Object.getOwnPropertyDescriptors(value);if(Reflect.ownKeys(descriptors).length!==keys.length||keys.some(key=>!descriptors[key]||!("value" in descriptors[key]!)))throw Error("invalid_trace_context");return descriptors;}
const probabilityMemo=new Map<string,number>();
export function probabilityValue(bits:unknown):number {
 if(typeof bits==="string"){const known=probabilityMemo.get(bits);if(known!==undefined)return known;}
 if(typeof bits!=="string"||!/^[0-9a-f]{16}$/.test(bits))throw Error("invalid_trace_probability");const bytes=new DataView(new ArrayBuffer(8));bytes.setBigUint64(0,BigInt("0x"+bits),false);const value=bytes.getFloat64(0,false);if(!Number.isFinite(value)||value<0||value>1||Object.is(value,-0))throw Error("invalid_trace_probability");
 if(probabilityMemo.size<64)probabilityMemo.set(bits,value);return value;
}
const abortState=Object.getOwnPropertyDescriptor(AbortSignal.prototype,"aborted")!.get!;
export function signalAborted(signal:unknown):boolean{try{return Reflect.apply(abortState,signal,[])===true;}catch{return false;}}
export function checkedTraceContext(value:unknown):TraceContext {
 if(typeof value==="object"&&value!==null&&builtContexts.has(value))return value as TraceContext;
 const descriptors=fields(value,["traceId","spanId","sampled","probability","clockDomain"]),traceId=canonicalId(descriptors.traceId!.value),spanId:unknown=descriptors.spanId!.value,sampled:unknown=descriptors.sampled!.value,probability:unknown=descriptors.probability!.value;
 if(typeof spanId!=="string"||!/^[0-9a-f]{16}$/.test(spanId)||spanId==="0".repeat(16)||typeof sampled!=="boolean")throw Error("invalid_trace_context");const chance=probabilityValue(probability);if(sampled&&chance===0)throw Error("invalid_trace_context");
 const domain=fields(descriptors.clockDomain!.value,["host","boot","runtime"]),clockDomain=Object.freeze({host:canonicalId(domain.host!.value),boot:canonicalId(domain.boot!.value),runtime:canonicalId(domain.runtime!.value)});
 const checked=Object.freeze({traceId,spanId,sampled,probability:probability as string,clockDomain});builtContexts.add(checked);return checked;
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
const spanKinds:Readonly<Record<string,true>>={internal:true,server:true,client:true,producer:true,consumer:true},spanStatuses:Readonly<Record<string,true>>={ok:true,error:true,cancelled:true,incomplete:true};
const MAX_U64=18446744073709551615n;
/** The raw readings behind a clock source this module built: wall time as canonical text, monotonic time as a checked BigInt, plus the canonical text a reading's clock object has around its monotonic and wall values. The lean span path stores these raw values and writes the text only when the span is serialized. */
export interface RawClock {readonly wall:()=>string;readonly mono:()=>bigint;readonly domain:ClockDomain;readonly prefix:string;readonly tail:string}
const rawClocks=new WeakMap<object,RawClock>(),builtContexts=new WeakSet<object>(),builtDomains=new WeakSet<object>();
export function createTraceClock(monotonic:()=>bigint,wall?:()=>string,uncertainty="18446744073709551615"):TraceClockSource {
 decimal(uncertainty);const domain=Object.freeze({host:randomHex(16),boot:randomHex(16),runtime:randomHex(16)});
 // The built-in wall clock is whole milliseconds scaled to nanoseconds: canonical by construction, so only a caller-supplied clock needs validating.
 const wallNs:()=>string=wall===undefined?()=>{const ms=Date.now();return ms>0?ms+"000000":unixNano(String(BigInt(ms)*1000000n));}:()=>unixNano(wall());
 // A bigint in range is canonical decimal by construction when printed; anything else must pass the decimal check first.
 const mono=():bigint=>{const reading=monotonic();return typeof reading==="bigint"&&reading>=0n&&reading<=MAX_U64?reading:BigInt(decimal(String(reading)));};
 const source=Object.freeze(Object.assign(()=>{const reading=mono();return Object.freeze({wall_ns:wallNs(),mono_ns:String(reading),domain,uncertainty_ns:uncertainty});},{domain}));
 builtDomains.add(domain);
 rawClocks.set(source,Object.freeze({wall:wallNs,mono,domain,prefix:'{"domain":{"boot":"'+domain.boot+'","host":"'+domain.host+'","runtime":"'+domain.runtime+'"},"mono_ns":"',tail:'","uncertainty_ns":"'+uncertainty+'","wall_ns":"'}));
 return source;
}
export function createSynchronousMetadataContext(wall?:()=>string):MetadataContext {
 let current:TraceContext|undefined,job:JobContext|undefined;const clock=createTraceClock(()=>BigInt(Math.trunc(performance.now()*1000000)),wall);
 return {clockDomain:clock.domain,current:()=>current,run<T>(context:TraceContext|undefined,callback:()=>T):T{const prior=current;current=context;try{return callback();}finally{current=prior;}},jobCurrent:()=>job,runJob<T>(context:JobContext|undefined,callback:()=>T):T{const prior=job;job=context;try{return callback();}finally{job=prior;}},clock,close(){current=undefined;job=undefined;}};
}
/** A span on the lean path: it keeps raw values (IDs, kind, status, wall text, monotonic BigInts) and the queue serializes it later, at flush time, with leanSpanPayload. */
export class LiveSpan implements ActiveSpan {
 ended=false;endWall:string|null=null;endMono=0n;status:SpanStatus="incomplete";
 constructor(readonly context:TraceContext,readonly raw:RawClock,readonly parentId:string|null,readonly kind:string,readonly operation:string,readonly dependency:string,readonly startWall:string,readonly startMono:bigint,readonly enabled:boolean,private readonly recorder:SpanRecorder){}
 run<T>(callback:()=>T):T{return this.recorder.runIn(this.context,callback);}
 end(status:SpanStatus):void{this.recorder.finish(this,status);}
}
// A lean span's canonical payload, in key order, split at its variable parts. Nothing here needs JSON escaping: IDs come from randomHex or a checked parent, operation and
// dependency from the registered alias sets (`[a-zA-Z0-9_.-]`), kind and status from closed sets, the probability is validated, and a clock reading is digits plus the
// clock's own canonical text.
const S0='{"dependency_alias":"',S1='","end":',S2=',"links":[],"operation":"',S3='","parent_id":',S4=',"sample_decision":"keep","sample_probability":"',S5='","span_id":"',S6='","span_kind":"',S7='","start":',S8=',"status":"',S9='","trace_id":"',S10='"}';
const FIXED_LENGTH=S0.length+S1.length+S2.length+S3.length+S4.length+S5.length+S6.length+S7.length+S8.length+S9.length+S10.length+16+16+32;
const POW10:bigint[]=Array.from({length:21},(_,exponent)=>10n**BigInt(exponent));let digitHint=16;
/** Decimal digit count of a non-negative BigInt below 2^64, without printing it. */
function digits(value:bigint):number{
 if(value<10n)return 1;
 let count=digitHint;
 if(value>=POW10[count]!){do count++;while(count<20&&value>=POW10[count]!);}else while(value<POW10[count-1]!)count--;
 digitHint=count;return count;
}
const clockLength=(raw:RawClock,mono:bigint,wall:string):number=>raw.prefix.length+digits(mono)+raw.tail.length+wall.length+2;
const clockText=(raw:RawClock,mono:bigint,wall:string):string=>raw.prefix+String(mono)+raw.tail+wall+'"}';
/** The exact length of leanSpanPayload(span), computed without building it. */
export function leanSpanLength(span:LiveSpan):number{
 return FIXED_LENGTH+span.dependency.length+span.operation.length+span.kind.length+span.status.length+(span.parentId===null?4:18)+(span.endWall===null?4:clockLength(span.raw,span.endMono,span.endWall))+clockLength(span.raw,span.startMono,span.startWall);
}
/** The canonical payload text of an ended lean span. */
export function leanSpanPayload(span:LiveSpan):string{
 const context=span.context;
 return S0+span.dependency+S1+(span.endWall===null?"null":clockText(span.raw,span.endMono,span.endWall))+S2+span.operation+S3+(span.parentId===null?"null":'"'+span.parentId+'"')+S4+context.probability+S5+context.spanId+S6+span.kind+S7+clockText(span.raw,span.startMono,span.startWall)+S8+span.status+S9+context.traceId+S10;
}
export class SpanRecorder {
 private readonly active=new Set<ActiveSpan>();private readonly operations:ReadonlySet<string>;private readonly dependencies:ReadonlySet<string>;private readonly probability:string;private readonly chance:number;private readonly always:boolean;
 constructor(private readonly context:MetadataContext,operations:readonly string[],dependencies:readonly string[],probability:string|undefined,private readonly enabled:()=>boolean,private readonly emit:(span:NativeSpan)=>void,private readonly emitLean:(span:LiveSpan)=>void,private readonly loss:(reason:string)=>void){if(operations.length>128||dependencies.length>64||[...operations,...dependencies].some(value=>typeof value!=="string"||!/^[a-zA-Z0-9_.-]{1,128}$/.test(value)))throw Error("invalid_trace_aliases");this.operations=new Set(operations);this.dependencies=new Set(dependencies);this.probability=probability??"3ff0000000000000";this.chance=probabilityValue(this.probability);this.always=this.probability==="3ff0000000000000";}
 current():TraceContext|undefined{return this.context.current();}
 run<T>(context:TraceContext|null,callback:()=>T):T{return this.context.run(context===null?undefined:checkedTraceContext(context),callback);}
 runIn<T>(context:TraceContext,callback:()=>T):T{return this.context.run(context,callback);}
 start(operation:string,options:SpanOptions={}):ActiveSpan {
  if(typeof operation!=="string"||!this.operations.has(operation))throw Error("unregistered_operation");
  const descriptors=Object.getOwnPropertyDescriptors(options);if(Object.values(descriptors).some(descriptor=>!("value" in descriptor)))throw Error("invalid_span_options");
  return this.begin(operation,descriptors.dependency?.value,descriptors.kind?.value??"internal",descriptors.parent?.value);
 }
 /** start() for an adapter that builds its own options: the same checks of operation, dependency, kind and parent, without reading an options object. */
 begin(operation:string,dependency:unknown,kind:unknown,parentValue:unknown):ActiveSpan {
  if(typeof operation!=="string"||!this.operations.has(operation))throw Error("unregistered_operation");
  if(dependency!==undefined&&(typeof dependency!=="string"||!this.dependencies.has(dependency)))throw Error("unregistered_dependency");if(typeof kind!=="string"||!Object.hasOwn(spanKinds,kind))throw Error("invalid_span_kind");
  const parent=parentValue===null?undefined:parentValue===undefined?this.context.current():checkedTraceContext(parentValue);
  // Contexts whose clock this module built, and parents it built or checked, take the lean path; any other context goes through the generic validated path below.
  const raw=rawClocks.get(this.context.clock);
  if(raw!==undefined&&raw.domain===this.context.clockDomain&&(parent===undefined||builtContexts.has(parent)))return this.beginLean(raw,operation,dependency,kind,parent);
  const start=(()=>{try{return this.context.clock();}catch{this.loss("invalid_clock");return undefined;}})(),enabled=this.enabled()&&start!==undefined;
  // A trace's explicit head decision is inherited. A narrower deployment budget
  // never increases an upstream keep probability or resurrects an upstream drop.
  const parentChance=parent?probabilityValue(parent.probability):1,probability=parent&&parentChance<=this.chance?parent.probability:this.probability,sampled=enabled&&(parent?parent.sampled&&sampleTraceDecision(probability,parent.probability):sampleTraceDecision(probability));
  const context=Object.freeze({traceId:parent?.traceId??randomHex(16),spanId:randomHex(8),sampled,probability,clockDomain:this.context.clockDomain});if((parent===undefined||builtContexts.has(parent))&&builtDomains.has(context.clockDomain))builtContexts.add(context);let ended=false;
  const handle:ActiveSpan={context,run:<T>(callback:()=>T):T=>this.context.run(context,callback),end:(status:SpanStatus):void=>{
   if(ended)return;if(!Object.hasOwn(spanStatuses,status))throw Error("invalid_span_status");ended=true;this.active.delete(handle);
   if(!enabled||!start)return;if(!sampled){this.loss("trace_sampled_out");return;}
   let end:TraceClock|null=null;try{end=this.context.clock();if(end.domain.host!==start.domain.host||end.domain.boot!==start.domain.boot||end.domain.runtime!==start.domain.runtime||compareNano(end.mono_ns,start.mono_ns)<0)throw Error("invalid_span_clock");}catch{this.loss("invalid_clock");status="incomplete";end=null;}
   this.emit({trace_id:context.traceId,span_id:context.spanId,parent_id:parent?.spanId??null,span_kind:kind as NativeSpan["span_kind"],operation,start,end,status,dependency_alias:typeof dependency==="string"?dependency:"",links:[],sample_probability:probability,sample_decision:"keep"});
  }};
  if(this.active.size>=1024){this.loss("trace_active_limit");handle.end("incomplete");}else this.active.add(handle);return handle;
 }
 private beginLean(raw:RawClock,operation:string,dependency:unknown,kind:string,parent:TraceContext|undefined):ActiveSpan {
  let startWall="0",startMono=0n,readable=true;
  try{startMono=raw.mono();startWall=raw.wall();}catch{this.loss("invalid_clock");readable=false;}
  const enabled=this.enabled()&&readable,probability=parent&&probabilityValue(parent.probability)<=this.chance?parent.probability:this.probability;
  // Same inheritance as the generic path: an explicit upstream head decision is kept, a narrower budget never raises an upstream keep probability or resurrects a drop.
  const sampled=enabled&&(parent?parent.sampled&&sampleTraceDecision(probability,parent.probability):this.always||sampleTraceDecision(probability));
  const context=Object.freeze({traceId:parent?.traceId??randomHex(16),spanId:randomHex(8),sampled,probability,clockDomain:raw.domain});builtContexts.add(context);
  const span=new LiveSpan(context,raw,parent?.spanId??null,kind,operation,typeof dependency==="string"?dependency:"",startWall,startMono,enabled,this);
  if(this.active.size>=1024){this.loss("trace_active_limit");span.end("incomplete");}else this.active.add(span);return span;
 }
 /** LiveSpan.end: the generic handle's end() for the lean path (same status check, same loss reasons, same incomplete fallback). */
 finish(span:LiveSpan,status:SpanStatus):void {
  if(span.ended)return;if(!Object.hasOwn(spanStatuses,status))throw Error("invalid_span_status");span.ended=true;this.active.delete(span);
  if(!span.enabled)return;if(!span.context.sampled){this.loss("trace_sampled_out");return;}
  try{span.endMono=span.raw.mono();span.endWall=span.raw.wall();if(span.endMono<span.startMono)throw Error("invalid_span_clock");}catch{this.loss("invalid_clock");status="incomplete";span.endWall=null;}
  span.status=status;this.emitLean(span);
 }
 close():void{for(const handle of [...this.active])handle.end("incomplete");this.context.close();}
}
