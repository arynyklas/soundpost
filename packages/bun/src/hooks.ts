// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import process from "node:process";
import {HookEpisodeBindings,type Client,type HandlingEpisode} from "@soundpost/core";
import type {HookMechanism} from "@soundpost/core/types";
/**
 * Bun 1.3.14 emits `uncaughtExceptionMonitor` for synchronous uncaught throws (module top level,
 * timers, nextTick) and leaves exit behaviour unchanged, but never for unhandled promise
 * rejections (probed: rejection with the monitor installed produces no callback). The only
 * observer of a rejection is an `unhandledRejection` listener, which consumes it (exit 1 becomes
 * 0), so none is installed and the limitation is a named capability, not a silent gap.
 */
export class HookLease {
 readonly capabilities=Object.freeze({fatalMonitor:true,unhandledRejectionMonitor:false,reason:"bun_unhandled_rejection_monitor_unavailable",rejectionModeChanged:false});
 private closed=false;private readonly episodes:HookEpisodeBindings;
 private readonly monitor=(error:Error,origin:string):void=>{
  if(this.closed)return;
  try{
   const mechanism=origin==="unhandledRejection"?"unhandled_rejection":"uncaught_exception";
   const episode=this.episodes.take(error,mechanism);
   if(episode)episode.captureHook(error,mechanism,true);else this.client.captureHook(error,mechanism,true);
  }catch{this.client.hookCaptureFailed();}
 };
 constructor(private readonly client:Client){this.episodes=new HookEpisodeBindings(client);client.ownHookLease(this);process.on("uncaughtExceptionMonitor",this.monitor);}
 useEpisode(episode:HandlingEpisode,error:unknown,mechanism:HookMechanism):void{
  if(this.closed)throw Error("hook lease closed");
  if(mechanism!=="uncaught_exception"&&mechanism!=="unhandled_rejection")throw Error("invalid Bun hook mechanism");
  this.episodes.arm(episode,error,mechanism);
 }
 clearEpisode(episode:HandlingEpisode):void{this.episodes.clear(episode);}
 close():void{if(this.closed)return;this.closed=true;this.episodes.clear();process.removeListener("uncaughtExceptionMonitor",this.monitor);this.client.releaseHookLease(this);}
}
/** No consuming fatal/rejection handlers; application exit policy stays authoritative. */
export function installHooks(client:Client):HookLease{return new HookLease(client);}
