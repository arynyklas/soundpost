// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {HookEpisodeBindings,type Client,type HandlingEpisode} from "@soundpost/core";
import type {HookMechanism} from "@soundpost/core/types";
export class HookLease {
 readonly capabilities=Object.freeze({error:true,unhandledRejection:typeof PromiseRejectionEvent!=="undefined",fatalMonitor:false});
 private closed=false;private readonly episodes:HookEpisodeBindings;
 private readonly errorValue=typeof ErrorEvent!=="undefined"?Object.getOwnPropertyDescriptor(ErrorEvent.prototype,"error")?.get:undefined;
 private readonly reasonValue=typeof PromiseRejectionEvent!=="undefined"?Object.getOwnPropertyDescriptor(PromiseRejectionEvent.prototype,"reason")?.get:undefined;
 private capture(event:Event,getter:((this:unknown)=>unknown)|undefined,mechanism:"uncaught_exception"|"unhandled_rejection"):void{
  if(this.closed)return;
  try{
   const error=getter?.call(event),episode=this.episodes.take(error,mechanism);
   if(episode)episode.captureHook(error,mechanism,false);else this.client.captureHook(error,mechanism,false);
  }catch{this.client.hookCaptureFailed();}
 }
 private readonly onError=(event:Event):void=>this.capture(event,this.errorValue,"uncaught_exception");
 private readonly onRejection=(event:Event):void=>this.capture(event,this.reasonValue,"unhandled_rejection");
 constructor(private readonly client:Client,private readonly target:Window){
  this.episodes=new HookEpisodeBindings(client);client.ownHookLease(this);
  target.addEventListener("error",this.onError);target.addEventListener("unhandledrejection",this.onRejection);
 }
 useEpisode(episode:HandlingEpisode,error:unknown,mechanism:HookMechanism):void{
  if(this.closed)throw Error("hook lease closed");
  if(mechanism!=="uncaught_exception"&&mechanism!=="unhandled_rejection")throw Error("invalid browser hook mechanism");
  this.episodes.arm(episode,error,mechanism);
 }
 clearEpisode(episode:HandlingEpisode):void{this.episodes.clear(episode);}
 close():void{if(this.closed)return;this.closed=true;this.episodes.clear();this.target.removeEventListener("error",this.onError);this.target.removeEventListener("unhandledrejection",this.onRejection);this.client.releaseHookLease(this);}
}
/** Never assigns property handlers, prevents default or stops propagation. */
export function installHooks(client:Client,target:Window=window):HookLease{return new HookLease(client,target);}
