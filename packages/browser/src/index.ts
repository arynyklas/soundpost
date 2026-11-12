// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {Client as CoreClient} from "@soundpost/core";
import type {Config} from "@soundpost/core/types";
import {createMetadataContext} from "./context.ts";
import {createRecorder} from "./replay/recorder.ts";
import type {EnqueueResult,ReplayChunk,ReplayConfig,ReplayRecorder} from "./replay/types.ts";
import {createProfiler,globalProfilerEnv,type ProfileHandle,type ProfileOptions,type ProfileReport} from "./profile.ts";
import {profileWire} from "./profile_wire.ts";
function randomId():string{for(;;){const id=Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,"0")).join("");if(id!=="0".repeat(32))return id;}}
export class Client extends CoreClient {
 constructor(config:Config){
  if(config.spool)throw Error("browser disk spool prohibited");
  // Error.isError is a runtime brand operation, unlike instanceof/toString/prototype walks.
  // Older browsers have no safe native brand: capture UnknownError plus explicit reason.
  const brand:unknown=Object.getOwnPropertyDescriptor(Error,"isError")?.value;
  super({...config,sourceClass:"browser"},typeof brand==="function"?{isNativeError:(value:unknown)=>Reflect.apply(brand,Error,[value])===true}:undefined,undefined,createMetadataContext(config.clockNs));
 }
 private replay:ReplayRecorder|undefined;
 /** Creates the owned recorder under this client's policy. Capture stays off until setReplayConsent(true). */
 startReplay(config:Omit<ReplayConfig,"projectPolicy"|"deploymentOptIn">,emit:(chunk:ReplayChunk)=>EnqueueResult):ReplayRecorder{
  if(this.replay)throw Error("replay recorder already started");
  // policyDecision.replay is project policy AND deployment opt-in already combined by core.
  const allowed=this.policyDecision.replay;
  return this.replay=createRecorder({...config,projectPolicy:allowed,deploymentOptIn:allowed},emit);
 }
 setReplayConsent(enabled:boolean):void{this.replay?.setConsent(enabled);}
 private processId:string|undefined;
 /** Starts one bounded JS Self-Profiling run whose finished report (including a refusal) is delivered through THIS client's queue:
  * the capability truth record always, the profile chunk(s) only when the sampler genuinely ran. Requires `deploymentProfiles: true`
  * and a source policy that lists profile_chunk and capability; otherwise nothing is enqueued and the drop is counted in diagnostics(). */
 startProfile(options:ProfileOptions):Promise<ProfileHandle>{return createProfiler(globalProfilerEnv(),report=>{this.submitProfile(report);}).startProfile(options);}
 /** Maps a finished report to wire records and enqueues them. Returns true only when everything was queued. */
 submitProfile(report:ProfileReport):boolean{
  let queued:boolean;
  try{const wire=profileWire(report,{process:this.processId??=randomId(),id:randomId});queued=this.captureProfile(wire.capability,wire.chunks);}
  catch{this.profileFailed();queued=false;}
  // Samples the profiler dropped from this run are a recorded loss whether or not the retained part was queued.
  try{
   let truncated=0n;for(const loss of report.losses)if(loss.reason==="truncated")truncated+=BigInt(loss.count);
   if(truncated>0n)this.captureProfileLoss(truncated,BigInt(report.clock.wall_end_ns)>=BigInt(report.clock.wall_start_ns)?report.clock.wall_end_ns:report.clock.wall_start_ns);
  }catch{this.profileFailed();}
  return queued;
 }
 override async close():Promise<void>{this.replay?.close();await super.close();}
}
export function init(config:Config):Client{return new Client(config);}
export {installHooks,HookLease} from "./hooks.ts";
export type {Config, Resource, RoutingDescriptor, EventId, PolicyDecision, FlushReport, Template, Severity} from "@soundpost/core/types";
export {installFetch,FetchLease} from "./fetch.ts";
export {installNavigation,NavigationLease} from "./navigation.ts";
export {serializeWorkerContext,withWorkerContext} from "./workers.ts";
export type {SpanOptions,TraceContext,WorkerContext} from "@soundpost/core/types";
export {createRecorder} from "./replay/recorder.ts";
export {ReplayStream} from "./replay/stream.ts";
export type {ReplayChunk,ReplayNode,ReplayConfig,ReplayRecorder,EnqueueResult} from "./replay/types.ts";
export {startProfile} from "./profile.ts";
export type {ProfileOptions,ProfileHandle,ProfileReport,ProfileCapability,ProfileFrame,ProfileSample,ProfileLongTask,ProfileLoss,ProfileReason,ProfileStatus,ProfileCoverageLevel,ProfileClockDomain} from "./profile.ts";
