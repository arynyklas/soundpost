// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {MetadataContext,TraceContext,JobContext} from "@soundpost/core/types";
import {createTraceClock} from "@soundpost/core";
/** Only synchronous dynamic extent is knowable without browser async-local storage.
 * Capture a TraceContext before await and pass it explicitly at the next boundary. */
export function createMetadataContext(wall?:()=>string):MetadataContext {
 let current:TraceContext|undefined,job:JobContext|undefined;const clock=createTraceClock(()=>BigInt(Math.trunc(performance.now()*1000000)),wall);
 return {clockDomain:clock.domain,current:()=>current,run<T>(context:TraceContext|undefined,callback:()=>T):T{const prior=current;current=context;try{return callback();}finally{current=prior;}},jobCurrent:()=>job,runJob<T>(context:JobContext|undefined,callback:()=>T):T{const prior=job;job=context;try{return callback();}finally{job=prior;}},clock,close(){current=undefined;job=undefined;}};
}
