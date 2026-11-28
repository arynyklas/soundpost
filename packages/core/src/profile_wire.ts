// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Maps a finished server-runtime profile report (Node and Bun `runtime_engine_samples`) onto the wire records the server's profile reader
// assembles (internal/profiles): one `capability` record, plus, only when the sampler genuinely ran (status "supported"), one or more
// `profile_chunk` records that name that capability by id and carry the same clock domain. A refused or failed run is the capability truth
// record alone: never a chunk, never samples.
//
// Vocabulary mapping (documented, not a new server method): the closed server chunk vocabulary is `runtime_cpu|native_cpu|native_offcpu`
// with units `samples|nanoseconds|events` (internal/model telemetry validation). Engine samples are chunk method `runtime_cpu`, units
// `samples`; the capability record keeps the SDK's own method (`runtime_engine_samples`), which is what says the samples are engine
// samples and NOT OS CPU time. Line and column are not sent (the closed server frame has no such field). Sample offsets are relative to the
// first sample and the report's unbounded clock uncertainty states that no wall alignment is claimed.
import type {CapabilityInput,ProfileInput} from "./types.ts";

const CHUNK_BYTES=180_000,MAX_CHUNK_SAMPLES=8192,MAX_UINT64=18446744073709551615n;
/** The part of a Node/Bun profile report the wire mapping reads. */
export interface RuntimeProfileReport {
 readonly units:"samples";
 readonly capability:{readonly id:string;readonly runtime:string;readonly version:string;readonly build:string;readonly os:string;readonly arch:string;readonly signal:"profile_chunk";readonly method:string;readonly status:string;readonly reason:string;
  readonly coverage:{readonly frames:string;readonly threads:string;readonly workers:string;readonly tasks:string};readonly clock_domain:{readonly host:string;readonly boot:string;readonly runtime:string};readonly expires_ns:string};
 readonly clock:{readonly domain:{readonly host:string;readonly boot:string;readonly runtime:string};readonly uncertainty_ns:string;readonly wall_start_ns:string;readonly wall_end_ns:string};
 readonly frames:readonly {readonly module_id:string;readonly function:string;readonly artifact_id:string;readonly offset:string;readonly reason:string}[];
 readonly stacks:readonly {readonly frames:readonly number[]}[];
 readonly samples:readonly {readonly at_us:string;readonly stack:number;readonly count:string;readonly thread:string}[];
 readonly truncated:boolean;
 readonly losses:readonly {readonly reason:string;readonly count:string}[];
}
export interface RuntimeProfileWire {readonly capability:CapabilityInput;readonly chunks:readonly ProfileInput[]}
export interface RuntimeProfileIds {readonly process:string;readonly id:()=>string}
type Frame={module_id:string;function:string;artifact_id:string;offset:string;reason:string};
type Sample={at_ns:string;stack:number;count:string;thread:string};
interface Chunk {frames:Frame[];stacks:{frames:number[]}[];samples:Sample[];frameIndex:Map<number,number>;stackIndex:Map<number,number>;bytes:number}
const fresh=():Chunk=>({frames:[],stacks:[],samples:[],frameIndex:new Map(),stackIndex:new Map(),bytes:0});
const size=(value:unknown):number=>JSON.stringify(value).length+1;// the profilers' own regexes make all content ASCII, so length is bytes

export function runtimeProfileWire(report:RuntimeProfileReport,ids:RuntimeProfileIds):RuntimeProfileWire{
 const c=report.capability,wallStart=report.clock.wall_start_ns;
 const wallEnd=BigInt(report.clock.wall_end_ns)>=BigInt(wallStart)?report.clock.wall_end_ns:wallStart;
 const capability:CapabilityInput={kind:"capability",id:c.id,observed_at_ns:wallEnd,payload:{
  runtime:c.runtime,version:c.version,build:c.build,os:c.os,arch:c.arch,signal:c.signal,method:c.method,status:c.status,reason:c.reason,
  coverage:{frames:c.coverage.frames,threads:c.coverage.threads,workers:c.coverage.workers,tasks:c.coverage.tasks},
  clock_domain:{host:c.clock_domain.host,boot:c.clock_domain.boot,runtime:c.clock_domain.runtime},expires_ns:c.expires_ns,
 }};
 if(c.status!=="supported")return {capability,chunks:[]};

 let lost=0n;for(const loss of report.losses)lost+=BigInt(loss.count);if(lost>MAX_UINT64)lost=MAX_UINT64;
 const profile=ids.id(),chunks:Chunk[]=[];let current=fresh();
 for(const sample of report.samples){
  const stack=report.stacks[sample.stack]!;
  for(;;){
   const newFrames=[...new Set(stack.frames)].filter(index=>!current.frameIndex.has(index));
   const wireFrames:Frame[]=newFrames.map(index=>{const f=report.frames[index]!;return {module_id:f.module_id,function:f.function,artifact_id:f.artifact_id,offset:f.offset,reason:f.reason};});
   const known=current.stackIndex.has(sample.stack);
   const wireSample=(local:number):Sample=>({at_ns:(BigInt(sample.at_us)*1000n).toString(),stack:local,count:sample.count,thread:/^[0-9]+$/.test(sample.thread)?sample.thread:"0"});
   const cost=wireFrames.reduce((n,f)=>n+size(f),0)+(known?0:size({frames:stack.frames})+8)+size(wireSample(0));
   if(current.samples.length>0&&(current.bytes+cost>CHUNK_BYTES||current.samples.length>=MAX_CHUNK_SAMPLES)){chunks.push(current);current=fresh();continue;}
   let local=current.stackIndex.get(sample.stack);
   if(local===undefined){
    for(const [i,index] of newFrames.entries()){current.frameIndex.set(index,current.frames.length);current.frames.push(wireFrames[i]!);}
    local=current.stacks.length;current.stacks.push({frames:stack.frames.map(index=>current.frameIndex.get(index)!)});current.stackIndex.set(sample.stack,local);
   }
   current.samples.push(wireSample(local));current.bytes+=cost;break;
  }
 }
 chunks.push(current);
 const out=chunks.map((chunk,position):ProfileInput=>({kind:"profile_chunk",id:ids.id(),observed_at_ns:wallEnd,payload:{
  profile_id:profile,process_id:ids.process,capability_id:c.id,method:"runtime_cpu",units:"samples",start_ns:wallStart,end_ns:wallEnd,
  clock:{wall_ns:wallStart,mono_ns:"0",domain:{host:report.clock.domain.host,boot:report.clock.domain.boot,runtime:report.clock.domain.runtime},uncertainty_ns:report.clock.uncertainty_ns},
  frames:chunk.frames,stacks:chunk.stacks,samples:chunk.samples,intervals:[],loss:(position===0?lost:0n).toString(),truncated:position===0&&report.truncated,
 }}));
 return {capability,chunks:out};
}
