// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {Client as CoreClient} from "@soundpost/core";
import type {Config} from "@soundpost/core/types";
import {createMetadataContext} from "./context.ts";
export class Client extends CoreClient {
 constructor(config:Config){
  if(config.spool)throw Error("browser disk spool prohibited");
  // Error.isError is a runtime brand operation, unlike instanceof/toString/prototype walks.
  // Older browsers have no safe native brand: capture UnknownError plus explicit reason.
  const brand:unknown=Object.getOwnPropertyDescriptor(Error,"isError")?.value;
  super({...config,sourceClass:"browser"},typeof brand==="function"?{isNativeError:(value:unknown)=>Reflect.apply(brand,Error,[value])===true}:undefined,undefined,createMetadataContext(config.clockNs));
 }
}
export function init(config:Config):Client{return new Client(config);}
export {installHooks,HookLease} from "./hooks.ts";
export type {Config, Resource, RoutingDescriptor, EventId, PolicyDecision, FlushReport, Template, Severity} from "@soundpost/core/types";
export {installFetch,FetchLease} from "./fetch.ts";
export {installNavigation,NavigationLease} from "./navigation.ts";
export {serializeWorkerContext,withWorkerContext} from "./workers.ts";
export type {SpanOptions,TraceContext,WorkerContext} from "@soundpost/core/types";
