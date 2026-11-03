// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {Client,HandlingEpisode} from "@soundpost/core";
import type {HookMechanism} from "@soundpost/core/types";
/** Bun 1.3.14 is not Node fatal-monitor qualification. Installing a fatal-consuming
 * listener to imitate Node would change exit/rejection behavior. Install none. */
export class HookLease {
 readonly capabilities=Object.freeze({fatalMonitor:false,reason:"bun_fatal_monitor_unavailable",rejectionModeChanged:false});
 private closed=false;
 constructor(private readonly client:Client){client.ownHookLease(this);}
 useEpisode(_episode:HandlingEpisode,_error:unknown,_mechanism:HookMechanism):never{throw Error("bun_fatal_monitor_unavailable");}
 close():void{if(this.closed)return;this.closed=true;this.client.releaseHookLease(this);}
}
export function installHooks(client:Client):HookLease{return new HookLease(client);}
