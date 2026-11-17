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
/** A trace context this module built or validated. The private brand cannot be forged: an object with the same fields, the same prototype or a copied property is not branded, so it is validated again. Checking it is one field probe; remembering each context in a WeakSet instead cost an ephemeron table entry per span, which every collection cycle has to resolve (a measurable share of Bun's collector work) and which V8 resizes as spans come and go. */
class BuiltContext implements TraceContext {
 readonly #brand=true;
 constructor(readonly traceId:string,readonly spanId:string,readonly sampled:boolean,readonly probability:string,readonly clockDomain:ClockDomain){}
 static is(value:object):boolean{return #brand in value;}
}
export function checkedTraceContext(value:unknown):TraceContext {
 if(typeof value==="object"&&value!==null&&BuiltContext.is(value))return value as TraceContext;
 const descriptors=fields(value,["traceId","spanId","sampled","probability","clockDomain"]),traceId=canonicalId(descriptors.traceId!.value),spanId:unknown=descriptors.spanId!.value,sampled:unknown=descriptors.sampled!.value,probability:unknown=descriptors.probability!.value;
 if(typeof spanId!=="string"||!/^[0-9a-f]{16}$/.test(spanId)||spanId==="0".repeat(16)||typeof sampled!=="boolean")throw Error("invalid_trace_context");const chance=probabilityValue(probability);if(sampled&&chance===0)throw Error("invalid_trace_context");
 const domain=fields(descriptors.clockDomain!.value,["host","boot","runtime"]),clockDomain=Object.freeze({host:canonicalId(domain.host!.value),boot:canonicalId(domain.boot!.value),runtime:canonicalId(domain.runtime!.value)});
 return Object.freeze(new BuiltContext(traceId,spanId,sampled,probability as string,clockDomain));
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
const rawClocks=new WeakMap<object,RawClock>(),builtDomains=new WeakSet<object>();
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
 /** Membership in the recorder's list of in-flight lean spans. */
 linked=false;activePrev:LiveSpan|undefined=undefined;activeNext:LiveSpan|undefined=undefined;
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
/** The constant text around each variable part of a lean span, joined with the vocabulary value that sits between two variable parts. A queued span's operation, dependency, kind, status and probability come from small closed sets (the queue's compact store keeps them as table indexes), so these are built once per value and not once per span: the payload is then 10 joins of variable and constant parts instead of 20. */
export const leanDependencyFragment=(dependency:string):string=>S0+dependency+S1;
export const leanOperationFragment=(operation:string):string=>S2+operation+S3;
export const leanProbabilityFragment=(probability:string):string=>S4+probability+S5;
export const leanKindFragment=(kind:string):string=>S6+kind+S7;
export const leanStatusFragment=(status:string):string=>S8+status+S9;
/** The canonical payload text of a lean span from its parts and the fragments of its vocabulary values: the one place the text is composed, whether the parts come from a LiveSpan or from the queue's compact store (lean_slab.ts). `endWall` null is a span without an end reading. */
export function composeLeanFragments(raw:RawClock,dependency:string,operation:string,kind:string,status:string,probability:string,traceId:string,spanId:string,parentId:string|null,startMono:bigint,startWall:string,endMono:bigint,endWall:string|null):string{
 return dependency+(endWall===null?"null":clockText(raw,endMono,endWall))+operation+(parentId===null?"null":'"'+parentId+'"')+probability+spanId+kind+clockText(raw,startMono,startWall)+status+traceId+S10;
}
/** composeLeanFragments from the plain values (a span that is not in the compact store). */
export function composeLeanPayload(raw:RawClock,dependency:string,operation:string,kind:string,status:string,probability:string,traceId:string,spanId:string,parentId:string|null,startMono:bigint,startWall:string,endMono:bigint,endWall:string|null):string{
 return composeLeanFragments(raw,leanDependencyFragment(dependency),leanOperationFragment(operation),leanKindFragment(kind),leanStatusFragment(status),leanProbabilityFragment(probability),traceId,spanId,parentId,startMono,startWall,endMono,endWall);
}
/** The canonical payload text of an ended lean span. */
export function leanSpanPayload(span:LiveSpan):string{
 const context=span.context;
 return composeLeanPayload(span.raw,span.dependency,span.operation,span.kind,span.status,context.probability,context.traceId,context.spanId,span.parentId,span.startMono,span.startWall,span.endMono,span.endWall);
}
export class SpanRecorder {
 private readonly active=new Set<ActiveSpan>();private leanHead:LiveSpan|undefined;private leanCount=0;private readonly operations:ReadonlySet<string>;private readonly dependencies:ReadonlySet<string>;private readonly probability:string;private readonly chance:number;private readonly always:boolean;
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
  if(raw!==undefined&&raw.domain===this.context.clockDomain&&(parent===undefined||BuiltContext.is(parent)))return this.beginLean(raw,operation,dependency,kind,parent);
  const start=(()=>{try{return this.context.clock();}catch{this.loss("invalid_clock");return undefined;}})(),enabled=this.enabled()&&start!==undefined;
  // A trace's explicit head decision is inherited. A narrower deployment budget
  // never increases an upstream keep probability or resurrects an upstream drop.
  const parentChance=parent?probabilityValue(parent.probability):1,probability=parent&&parentChance<=this.chance?parent.probability:this.probability,sampled=enabled&&(parent?parent.sampled&&sampleTraceDecision(probability,parent.probability):sampleTraceDecision(probability));
  const trusted=(parent===undefined||BuiltContext.is(parent))&&builtDomains.has(this.context.clockDomain),context=Object.freeze(trusted?new BuiltContext(parent?.traceId??randomHex(16),randomHex(8),sampled,probability,this.context.clockDomain):{traceId:parent?.traceId??randomHex(16),spanId:randomHex(8),sampled,probability,clockDomain:this.context.clockDomain});let ended=false;
  const handle:ActiveSpan={context,run:<T>(callback:()=>T):T=>this.context.run(context,callback),end:(status:SpanStatus):void=>{
   if(ended)return;if(!Object.hasOwn(spanStatuses,status))throw Error("invalid_span_status");ended=true;this.active.delete(handle);
   if(!enabled||!start)return;if(!sampled){this.loss("trace_sampled_out");return;}
   let end:TraceClock|null=null;try{end=this.context.clock();if(end.domain.host!==start.domain.host||end.domain.boot!==start.domain.boot||end.domain.runtime!==start.domain.runtime||compareNano(end.mono_ns,start.mono_ns)<0)throw Error("invalid_span_clock");}catch{this.loss("invalid_clock");status="incomplete";end=null;}
   this.emit({trace_id:context.traceId,span_id:context.spanId,parent_id:parent?.spanId??null,span_kind:kind as NativeSpan["span_kind"],operation,start,end,status,dependency_alias:typeof dependency==="string"?dependency:"",links:[],sample_probability:probability,sample_decision:"keep"});
  }};
  if(this.active.size+this.leanCount>=1024){this.loss("trace_active_limit");handle.end("incomplete");}else this.active.add(handle);return handle;
 }
 private beginLean(raw:RawClock,operation:string,dependency:unknown,kind:string,parent:TraceContext|undefined):ActiveSpan {
  let startWall="0",startMono=0n,readable=true;
  try{startMono=raw.mono();startWall=raw.wall();}catch{this.loss("invalid_clock");readable=false;}
  const enabled=this.enabled()&&readable,probability=parent&&probabilityValue(parent.probability)<=this.chance?parent.probability:this.probability;
  // Same inheritance as the generic path: an explicit upstream head decision is kept, a narrower budget never raises an upstream keep probability or resurrects a drop.
  const sampled=enabled&&(parent?parent.sampled&&sampleTraceDecision(probability,parent.probability):this.always||sampleTraceDecision(probability));
  // A root span's two IDs come from one 24-byte draw and one hex encoding (a child draws only its own span ID).
  let traceId:string,spanId:string;
  if(parent===undefined){const draw=randomHex(24);traceId=draw.slice(0,32);spanId=draw.slice(32);}else{traceId=parent.traceId;spanId=randomHex(8);}
  const context=Object.freeze(new BuiltContext(traceId,spanId,sampled,probability,raw.domain));
  const span=new LiveSpan(context,raw,parent?.spanId??null,kind,operation,typeof dependency==="string"?dependency:"",startWall,startMono,enabled,this);
  if(this.active.size+this.leanCount>=1024){this.loss("trace_active_limit");span.end("incomplete");}else this.link(span);return span;
 }
 /** LiveSpan.end: the generic handle's end() for the lean path (same status check, same loss reasons, same incomplete fallback). */
 finish(span:LiveSpan,status:SpanStatus):void {
  if(span.ended)return;if(!Object.hasOwn(spanStatuses,status))throw Error("invalid_span_status");span.ended=true;this.unlink(span);
  if(!span.enabled)return;if(!span.context.sampled){this.loss("trace_sampled_out");return;}
  try{span.endMono=span.raw.mono();span.endWall=span.raw.wall();if(span.endMono<span.startMono)throw Error("invalid_span_clock");}catch{this.loss("invalid_clock");status="incomplete";span.endWall=null;}
  span.status=status;this.emitLean(span);
 }
 close():void{const spans:ActiveSpan[]=[];for(let span=this.leanHead;span!==undefined;span=span.activeNext)spans.push(span);spans.reverse();for(const handle of [...spans,...this.active])handle.end("incomplete");this.context.close();}
 /** The in-flight lean spans form a doubly linked list through the spans themselves: a Set would insert and delete one hash-table entry per request, and its rehash and shrink steps are allocation and collector work on every request. */
 private link(span:LiveSpan):void{span.activeNext=this.leanHead;if(this.leanHead!==undefined)this.leanHead.activePrev=span;this.leanHead=span;span.linked=true;this.leanCount++;}
 private unlink(span:LiveSpan):void{
  if(!span.linked)return;span.linked=false;this.leanCount--;
  if(span.activePrev!==undefined)span.activePrev.activeNext=span.activeNext;else this.leanHead=span.activeNext;
  if(span.activeNext!==undefined)span.activeNext.activePrev=span.activePrev;
  span.activePrev=undefined;span.activeNext=undefined;
 }
}
