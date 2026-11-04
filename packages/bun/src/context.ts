// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {AsyncLocalStorage} from "node:async_hooks";
import {createTraceClock} from "@soundpost/core";
import type {MetadataContext,TraceContext,JobContext} from "@soundpost/core/types";
/** Bun's own per-client store; qualification requires a separate Bun process. */
export function createMetadataContext(wall?:()=>string):MetadataContext {
 const scope=new AsyncLocalStorage<TraceContext|undefined>(),jobs=new AsyncLocalStorage<JobContext|undefined>(),clock=createTraceClock(()=>process.hrtime.bigint(),wall);
 return {clockDomain:clock.domain,current:()=>scope.getStore(),run:<T>(context:TraceContext|undefined,callback:()=>T):T=>scope.run(context,callback),jobCurrent:()=>jobs.getStore(),runJob:<T>(context:JobContext|undefined,callback:()=>T):T=>jobs.run(context,callback),clock,close:()=>{scope.disable();jobs.disable();}};
}
