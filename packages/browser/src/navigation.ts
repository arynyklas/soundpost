// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {Client} from "@soundpost/core";
import type {TraceContext} from "@soundpost/core/types";
export interface NavigationIntegrationConfig {readonly operations:readonly string[]}
const installed=new WeakMap<Client,NavigationLease>();
/** Elapsed application navigation/commit timing, never CPU or Long Task profiling.
 * Router callers supply an approved alias and explicitly carry context across await. */
export class NavigationLease {
 private closed=false;private readonly operations:ReadonlySet<string>;private readonly pending=new Set<()=>void>();
 constructor(private readonly client:Client,config:NavigationIntegrationConfig){if(installed.has(client))throw Error("navigation_already_installed");if(!config.operations.length||config.operations.length>128||config.operations.some(value=>!/^[a-zA-Z0-9_.-]{1,128}$/.test(value)))throw Error("invalid_navigation_config");this.operations=new Set(config.operations);client.ownHookLease(this);installed.set(client,this);}
 async navigate<T>(operation:string,callback:(context:TraceContext)=>Promise<T>,parent?:TraceContext):Promise<T>{
  if(this.closed)throw Error("navigation_lease_closed");if(!this.operations.has(operation))throw Error("unregistered_navigation");
  const span=this.client.startSpan(operation,{kind:"internal",parent:parent??null}),incomplete=():void=>span.end("incomplete");
  if(this.pending.size>=1024){span.end("incomplete");return callback(span.context);}
  this.pending.add(incomplete);
  try{const value=await span.run(()=>callback(span.context));span.end("ok");return value;}catch(error){span.run(()=>this.client.captureException(error));span.end("error");throw error;}finally{this.pending.delete(incomplete);}
 }
 close():void{if(this.closed)return;this.closed=true;for(const end of [...this.pending])end();this.pending.clear();installed.delete(this.client);this.client.releaseHookLease(this);}
}
export function installNavigation(client:Client,config:NavigationIntegrationConfig):NavigationLease{return new NavigationLease(client,config);}
