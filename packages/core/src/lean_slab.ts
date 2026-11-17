// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {composeLeanFragments,leanDependencyFragment,leanKindFragment,leanOperationFragment,leanProbabilityFragment,leanStatusFragment,type LiveSpan,type RawClock} from "./tracing.ts";
const KINDS=["internal","server","client","producer","consumer"] as const,STATUSES=["ok","error","cancelled","incomplete"] as const;
const KIND_FRAGMENTS=KINDS.map(leanKindFragment),STATUS_FRAGMENTS=STATUSES.map(leanStatusFragment),NO_DEPENDENCY=leanDependencyFragment("");
const hexCode=Uint8Array.from("0123456789abcdef",character=>character.charCodeAt(0));
const hexDigits:string[]=Array.from({length:256},(_,value)=>value.toString(16).padStart(2,"0"));
/** Lowercase hex text into bytes. Every ID reaching the slab was built by randomHex or passed canonicalId / the 16-digit check, so it is lowercase hex of the right length. */
function putHex(text:string,bytes:Uint8Array,at:number):void{
 for(let i=0;i<text.length;i+=2){const hi=text.charCodeAt(i),lo=text.charCodeAt(i+1);bytes[at+(i>>1)]=((hi<=57?hi-48:hi-87)<<4)|(lo<=57?lo-48:lo-87);}
}
interface HexSlice {toString(encoding:"hex",start:number,end:number):string}
interface HexHost {from(buffer:ArrayBufferLike,offset:number,length:number):HexSlice}
/**
 * The compact store of ended lean spans that wait in the delivery queue for the next flush (about one 100 ms flush interval of requests, up to the queue's record limit).
 *
 * A queued span used to be a LiveSpan, its frozen context, two hex ID strings, two wall-clock strings, two BigInts and a queue entry: about 500 bytes in nine heap objects per request.
 * Each of them survives the young-generation collections that run while it waits for the flush, so V8 grew its new space (twice the scavenge pause, and with it the p95) and JSC
 * marked all of them in every cycle. Here a span is a slot in a few typed arrays, which the collector never scans: IDs as bytes, clock readings as 64-bit integers, the small closed
 * vocabulary (kind, status, operation, dependency alias, probability, clock) as table indexes. The text is composed from the slot at flush time by the same
 * composeLeanPayload that serializes a LiveSpan, so the bytes cannot differ.
 */
export class LeanSlab {
 private readonly ids:Uint8Array;private readonly nums:BigUint64Array;private readonly words:Uint32Array;private readonly freeList:Uint32Array;private free:number;
 private readonly hexView:HexSlice|undefined;
 private readonly operations:string[]=[];private readonly dependencies:string[]=[];private readonly probabilities:string[]=[];private readonly raws:RawClock[]=[];
 /** The constant text around each vocabulary value (see leanOperationFragment), parallel to the tables above and built when a value is first stored. */
 private readonly operationFragments:string[]=[];private readonly dependencyFragments:string[]=[];private readonly probabilityFragments:string[]=[];
 constructor(readonly capacity:number){
  this.ids=new Uint8Array(capacity*32);this.nums=new BigUint64Array(capacity*4);this.words=new Uint32Array(capacity*2);this.freeList=new Uint32Array(capacity);
  for(let slot=0;slot<capacity;slot++)this.freeList[slot]=capacity-1-slot;this.free=capacity;
  try{const host:HexHost|undefined=Reflect.get(globalThis,"Buffer");this.hexView=host?.from(this.ids.buffer,0,this.ids.length);}catch{this.hexView=undefined;}
 }
 /** Slots in use. */
 get used():number{return this.capacity-this.free;}
 private index(table:string[],fragments:string[],make:(value:string)=>string,value:string,limit:number):number{
  for(let at=0;at<table.length;at++)if(table[at]===value)return at;
  if(table.length>=limit)return -1;table.push(value);fragments.push(make(value));return table.length-1;
 }
 private rawIndex(raw:RawClock):number{
  for(let at=0;at<this.raws.length;at++)if(this.raws[at]===raw)return at;
  if(this.raws.length>=256)return -1;this.raws.push(raw);return this.raws.length-1;
 }
 /** Copies an ended span into a free slot; -1 when no slot is free or a vocabulary table is full (the caller then serializes the span at once). */
 put(span:LiveSpan):number{
  if(this.free===0)return -1;
  const kind=KINDS.indexOf(span.kind as typeof KINDS[number]),status=STATUSES.indexOf(span.status as typeof STATUSES[number]);if(kind<0||status<0)return -1;
  const raw=this.rawIndex(span.raw),probability=this.index(this.probabilities,this.probabilityFragments,leanProbabilityFragment,span.context.probability,255),operation=this.index(this.operations,this.operationFragments,leanOperationFragment,span.operation,65535);
  const dependency=span.dependency===""?0:this.index(this.dependencies,this.dependencyFragments,leanDependencyFragment,span.dependency,65534)+1;
  if(raw<0||probability<0||operation<0||(span.dependency!==""&&dependency===0))return -1;
  const slot=this.freeList[--this.free]!,id=slot*32;
  putHex(span.context.traceId,this.ids,id);putHex(span.context.spanId,this.ids,id+16);
  const parent=span.parentId;if(parent!==null)putHex(parent,this.ids,id+24);
  const at=slot*4,end=span.endWall!==null;
  this.nums[at]=span.startMono;this.nums[at+1]=end?span.endMono:0n;this.nums[at+2]=BigInt(span.startWall);this.nums[at+3]=end?BigInt(span.endWall!):0n;
  this.words[slot*2]=(kind|status<<3|(parent!==null?1<<5:0)|(end?1<<6:0)|raw<<8|probability<<24)>>>0;this.words[slot*2+1]=(operation|dependency<<16)>>>0;
  return slot;
 }
 release(slot:number):void{this.freeList[this.free++]=slot;}
 private hex(start:number,length:number):string{
  if(this.hexView!==undefined)return this.hexView.toString("hex",start,start+length);
  let out="";for(let at=start;at<start+length;at++)out+=hexDigits[this.ids[at]!];return out;
 }
 /** The span's start reading in wall nanoseconds (the record's observed_at_ns), as canonical decimal text. */
 startWall(slot:number):string{return String(this.nums[slot*4+2]!);}
 /** Writes the 32 ASCII hex digits of the span's trace ID into `target` (the routing input's owner field) without building a string. */
 writeTraceId(slot:number,target:Uint8Array):void{
  const id=slot*32;
  for(let i=0;i<16;i++){const byte=this.ids[id+i]!;target[2*i]=hexCode[byte>>4]!;target[2*i+1]=hexCode[byte&15]!;}
 }
 /** The canonical payload text of the span in `slot`: byte-identical to leanSpanPayload of the LiveSpan it was copied from. `startWall` is the span's start reading as startWall(slot) returns it, for a caller that has it already. */
 payload(slot:number,startWall:string=this.startWall(slot)):string{
  const w0=this.words[slot*2]!,w1=this.words[slot*2+1]!,id=slot*32,at=slot*4,end=((w0>>>6)&1)===1;
 const dependency=w1>>>16;
 // The slot's three IDs (trace 16 bytes, span 8, parent 8: stale bytes when there is no parent, never read then) are encoded by one call and cut apart as strings.
 const ids=this.hex(id,32);
 return composeLeanFragments(this.raws[(w0>>>8)&255]!,dependency===0?NO_DEPENDENCY:this.dependencyFragments[dependency-1]!,this.operationFragments[w1&65535]!,KIND_FRAGMENTS[w0&7]!,STATUS_FRAGMENTS[(w0>>>3)&3]!,this.probabilityFragments[w0>>>24]!,ids.slice(0,32),ids.slice(32,48),((w0>>>5)&1)===1?ids.slice(48):null,this.nums[at]!,startWall,this.nums[at+1]!,end?String(this.nums[at+3]!):null);
 }
}
