// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {Client as CoreClient,createTimerCancellationBoundary} from "@soundpost/core";
import type {Config} from "@soundpost/core/types";
import {types} from "node:util";
import {AsyncLocalStorage} from "node:async_hooks";
import {createMetadataContext} from "./context.ts";
import {setTimeout as timerPromise} from "node:timers/promises";
const timerCancellation=createTimerCancellationBoundary(
 ()=>timerPromise(0,undefined,{signal:AbortSignal.abort()}),
 ()=>Reflect.apply(timerPromise,undefined,[0,undefined,{signal:7}]),
 error=>!types.isProxy(error)&&types.isNativeError(error));
export class Client extends CoreClient {
 constructor(config:Config){const scope=new AsyncLocalStorage<boolean>();super(config,{isNativeError:types.isNativeError,isProxy:types.isProxy,timerCancellation},{active:()=>scope.getStore()===true,run:<T>(callback:()=>T):T=>scope.run(true,callback),close:()=>scope.disable()},createMetadataContext(config.clockNs));}
}
export function init(config:Config):Client{return new Client(config);}
export {installHooks,HookLease} from "./hooks.ts";
export {openEncryptedSpool} from "../../node/src/spool.ts";
export type {Config, Resource, RoutingDescriptor, EventId, PolicyDecision, FlushReport, Template, Severity} from "@soundpost/core/types";
export {installHttp,HttpLease} from "./http.ts";
export {installFetch,FetchLease} from "./fetch.ts";
export {installPg,PgLease} from "./pg.ts";
export {installServe,ServeLease} from "./serve.ts";
export {serializeWorkerContext,withWorkerContext} from "./workers.ts";
export type {SpanOptions,TraceContext,WorkerContext} from "@soundpost/core/types";
