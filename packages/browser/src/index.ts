// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {Client as CoreClient} from "@soundpost/core";
import type {Config} from "@soundpost/core/types";
export class Client extends CoreClient {
 constructor(config:Config){
  // Error.isError is a runtime brand operation, unlike instanceof/toString/prototype walks.
  // Older browsers have no safe native brand: capture UnknownError plus explicit reason.
  const brand:unknown=Object.getOwnPropertyDescriptor(Error,"isError")?.value;
  super(config,typeof brand==="function"?{isNativeError:(value:unknown)=>Reflect.apply(brand,Error,[value])===true}:undefined);
 }
}
export function init(config:Config):Client{return new Client(config);}
export {installHooks,HookLease} from "./hooks.ts";
export type {Config, EventId, PolicyDecision, FlushReport, Template, Severity} from "@soundpost/core/types";
