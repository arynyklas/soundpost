// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {Client} from "./client.ts";
import type {Config} from "./types.ts";
import {runtimeProfileWire,type RuntimeProfileReport} from "./profile_wire.ts";
import {SpoolingDeliveryQueue} from "./queue_spool.ts";
import type {DeliveryQueue} from "./queue.ts";
import type {ReceiptTransport} from "./transport.ts";
import type {ExportContext} from "./types.ts";
import {randomHex} from "./tracing.ts";
/** The core client plus runtime (Node/Bun) profile admission and the encrypted-spool delivery queue. It is its own entry so the browser core bundle, which never admits a runtime profile, does not carry the wire mapping. */
export class RuntimeClient extends Client {
 private profileProcess:string|undefined;
 protected override createDelivery(config:Config,transport:ReceiptTransport,options:{context?:ExportContext}):DeliveryQueue{return new SpoolingDeliveryQueue(config,transport,options);}
 /** Maps a finished Node/Bun `runtime_engine_samples` report to its capability (+ profile chunk) records and enqueues them (see profile_wire.ts for the vocabulary mapping). True only when everything was queued; a mapping failure is counted
  * as profile_wire_failed. Samples the profiler dropped from the run are a recorded truncated loss whether or not the retained part was queued. Never throws. */
 captureRuntimeProfile(report:RuntimeProfileReport):boolean{
  let queued:boolean;
  try{const wire=runtimeProfileWire(report,{process:this.profileProcess??=randomHex(16),id:()=>randomHex(16)});queued=this.captureProfile(wire.capability,wire.chunks);}
  catch{this.profileFailed();queued=false;}
  try{
   let truncated=0n;for(const loss of report.losses)if(loss.reason==="truncated")truncated+=BigInt(loss.count);
   if(truncated>0n){const start=report.clock.wall_start_ns,end=report.clock.wall_end_ns;this.captureProfileLoss(truncated,BigInt(end)>=BigInt(start)?end:start);}
  }catch{this.profileFailed();}
  return queued;
 }
}
export function initRuntime(config:Config):RuntimeClient{return new RuntimeClient(config);}
export type {RuntimeProfileReport} from "./profile_wire.ts";
