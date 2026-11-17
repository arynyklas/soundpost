// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {AsyncLocalStorage} from "node:async_hooks";
import {createTraceClock} from "@soundpost/core";
import type {ExportContext,MetadataContext,TraceContext,JobContext} from "@soundpost/core/types";
/** The scopes a client keeps: the trace, the job attempt and whether the code runs inside the exporter. */
interface Scopes {readonly trace:TraceContext|undefined;readonly job:JobContext|undefined;readonly exporting:boolean}
/** One store per client for all three scopes (the runtime visits every enabled store for each async resource it creates). This Node adapter makes no Bun qualification claim. */
export function createContexts(wall?:()=>string):{readonly metadata:MetadataContext;readonly exporter:ExportContext} {
 const store=new AsyncLocalStorage<Scopes>(),clock=createTraceClock(()=>process.hrtime.bigint(),wall);
 // The client closes its spans (metadata.close) before the delivery queue's last exporter run; the one disable belongs to the exporter, at the very end of the client's shutdown (the same order the Bun adapter needs: see packages/bun/src/context.ts).
 const close=():void=>store.disable();
 return {
  metadata:{clockDomain:clock.domain,current:()=>store.getStore()?.trace,run:<T>(trace:TraceContext|undefined,callback:()=>T):T=>{const scopes=store.getStore();return store.run({trace,job:scopes?.job,exporting:scopes?.exporting===true},callback);},jobCurrent:()=>store.getStore()?.job,runJob:<T>(job:JobContext|undefined,callback:()=>T):T=>{const scopes=store.getStore();return store.run({trace:scopes?.trace,job,exporting:scopes?.exporting===true},callback);},clock,close:()=>{}},
  exporter:{active:()=>store.getStore()?.exporting===true,run:<T>(callback:()=>T):T=>{const scopes=store.getStore();return store.run({trace:scopes?.trace,job:scopes?.job,exporting:true},callback);},close},
 };
}
export function createMetadataContext(wall?:()=>string):MetadataContext {const {metadata,exporter}=createContexts(wall);return {...metadata,close:exporter.close};}
