// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {canonicalId,decimal,unixNano} from "./policy.ts";
import {randomHex} from "./tracing.ts";
import type {MetadataContext} from "./tracing.ts";
export interface JobContext {readonly jobId:string;readonly runId:string;readonly attemptId:string}
export type AttemptState="started"|"succeeded"|"failed"|"cancelled";
export interface NativeJobAttempt {
 readonly job_id:string;readonly run_id:string;readonly attempt_id:string;readonly schedule_occurrence:string;
 readonly ordinal:string;readonly producer_epoch:string;readonly sequence:string;readonly state:AttemptState;
 readonly observed_ns:string;readonly terminal_ns:string|null;readonly cause_trace?:string;readonly cause_error?:string;
}
export function normalizeAttempt(value:unknown):NativeJobAttempt {
 if(!value||typeof value!=="object"||Array.isArray(value))throw Error("invalid_job_attempt");
 const descriptors=Object.getOwnPropertyDescriptors(value),required=["job_id","run_id","attempt_id","schedule_occurrence","ordinal","producer_epoch","sequence","state","observed_ns","terminal_ns"],optional=["cause_trace","cause_error"];
 if(required.some(key=>!Object.hasOwn(descriptors,key))||Reflect.ownKeys(descriptors).some(key=>typeof key!=="string"||(!required.includes(key)&&!optional.includes(key)))||Object.values(descriptors).some(field=>!("value" in field)))throw Error("invalid_job_attempt");
 const job=canonicalId(descriptors.job_id!.value),run=canonicalId(descriptors.run_id!.value),attempt=canonicalId(descriptors.attempt_id!.value),epoch=canonicalId(descriptors.producer_epoch!.value),ordinal=decimal(descriptors.ordinal!.value),sequence=decimal(descriptors.sequence!.value),schedule:unknown=descriptors.schedule_occurrence!.value,state:unknown=descriptors.state!.value,observed=unixNano(descriptors.observed_ns!.value),terminal:unknown=descriptors.terminal_ns!.value;
 if(ordinal==="0"||typeof schedule!=="string"||schedule.length<1||schedule.length>256||/[^A-Za-z0-9_.-]/.test(schedule)||typeof state!=="string"||!["started","succeeded","failed","cancelled"].includes(state))throw Error("invalid_job_attempt");
 if(state==="started"?terminal!==null:terminal===null||BigInt(unixNano(terminal))<BigInt(observed))throw Error("invalid_job_terminal");
 const trace=descriptors.cause_trace?canonicalId(descriptors.cause_trace.value):undefined,error=descriptors.cause_error?canonicalId(descriptors.cause_error.value):undefined;
 return Object.freeze({job_id:job,run_id:run,attempt_id:attempt,schedule_occurrence:schedule,ordinal,producer_epoch:epoch,sequence,state:state as AttemptState,observed_ns:observed,terminal_ns:terminal===null?null:unixNano(terminal),...(trace!==undefined?{cause_trace:trace}:{}),...(error!==undefined?{cause_error:error}:{})});
}
/** Own runtime primitives issue a cancellation brand, never a thrown-value guess.
 * The cache retains one prototype identity, not an Error or client. */
export function createTimerCancellationBoundary(abortProbe:()=>unknown,nonAbortProbe:()=>unknown,trustedNative:(error:unknown)=>boolean):(error:unknown)=>Promise<boolean> {
 const generic=new Set<object>([Error.prototype,TypeError.prototype,RangeError.prototype,ReferenceError.prototype,SyntaxError.prototype,URIError.prototype,EvalError.prototype,AggregateError.prototype,DOMException.prototype]);
 let ready:Promise<object|undefined>|undefined;
 const inspect=(probe:()=>unknown):Promise<object|undefined>=>Promise.resolve().then(probe).then(()=>undefined,error=>{
  if(!trustedNative(error))return undefined;
  const prototype:unknown=Object.getPrototypeOf(error);
  return prototype!==null&&typeof prototype==="object"?prototype:undefined;
 });
 return async(error:unknown):Promise<boolean>=>{
  if(!trustedNative(error))return false;
  if(ready===undefined)ready=new Promise<object|undefined>(resolve=>{
   const timeout=setTimeout(()=>resolve(undefined),50);
   Promise.all([inspect(abortProbe),inspect(nonAbortProbe)]).then(([abort,other])=>{
    clearTimeout(timeout);
    resolve(abort!==undefined&&other!==undefined&&!generic.has(abort)&&abort!==other?abort:undefined);
   },()=>{clearTimeout(timeout);resolve(undefined);});
  });
  const prototype=await ready;
  return prototype!==undefined&&Object.getPrototypeOf(error)===prototype;
 };
}
interface JobHooks {
 readonly clock:()=>string|undefined;readonly emit:(payload:NativeJobAttempt,observed:string)=>void;
 readonly capture:(error:unknown)=>string;readonly loss:(reason:string)=>void;
 readonly nativeError:(error:unknown)=>boolean;
 readonly timerCancellation:(error:unknown)=>Promise<boolean>;
}
const abortName=Object.getOwnPropertyDescriptor(DOMException.prototype,"name")!.get!;
/** Intrinsic/own-data paths stay separate from an independently runtime-issued
 * cancellation brand. No inherited properties or prototype chain are read. */
async function cancelled(error:unknown,nativeError:(error:unknown)=>boolean,timerCancellation:(error:unknown)=>Promise<boolean>):Promise<boolean> {
 try{if(Reflect.apply(abortName,error,[])==="AbortError")return true;}catch{}
 try{
  if(!nativeError(error))return false;
  const name=Object.getOwnPropertyDescriptor(error,"name"),code=Object.getOwnPropertyDescriptor(error,"code");
  if(name!==undefined&&!("value" in name)||code!==undefined&&!("value" in code))return false;
  if(name?.value==="AbortError"&&code?.value==="ABORT_ERR")return true;
  return await timerCancellation(error);
 }catch{return false;}
}
export class JobRecorder {
 private readonly registry=new Map<string,string>();private readonly epoch=randomHex(16);private sequence=0n;
 constructor(private readonly context:MetadataContext,registry:Readonly<Record<string,string>>|undefined,private readonly hooks:JobHooks){
  if(registry!==undefined){
   if(!registry||typeof registry!=="object"||Array.isArray(registry))throw Error("invalid_job_registry");
   const entries=Object.getOwnPropertyDescriptors(registry),keys=Reflect.ownKeys(entries);
   if(keys.length>1024)throw Error("invalid_job_registry");
   for(const key of keys){if(typeof key!=="string"||key.length<1||key.length>128||/[^A-Za-z0-9_.-]/.test(key)||!("value" in entries[key]!))throw Error("invalid_job_registry");this.registry.set(key,canonicalId(entries[key]!.value));}
  }
 }
 private emit(context:JobContext,ordinal:string,observed:string|undefined,state:AttemptState,terminal:string|null,trace:string|undefined,error?:string):void {
  if(observed===undefined)return;
  try{
   if(this.sequence===18446744073709551615n){this.hooks.loss("job_sequence_exhausted");return;}
   this.sequence++;
   this.hooks.emit({job_id:context.jobId,run_id:context.runId,attempt_id:context.attemptId,schedule_occurrence:"manual."+context.runId,ordinal,producer_epoch:this.epoch,sequence:String(this.sequence),state,observed_ns:observed,terminal_ns:terminal,...(trace!==undefined?{cause_trace:trace}:{}),...(error!==undefined?{cause_error:error}:{})},terminal??observed);
  }catch{this.hooks.loss("job_capture_failed");}
 }
 async run<T>(job:string,runId:string,ordinal:number,callback:()=>Promise<T>):Promise<T>{
  if(typeof job!=="string"||!this.registry.has(job))throw Error("unregistered_job");canonicalId(runId);
  if(!Number.isSafeInteger(ordinal)||ordinal<1)throw Error("invalid_job_ordinal");if(typeof callback!=="function")throw Error("invalid_job_callback");
  const context=Object.freeze({jobId:this.registry.get(job)!,runId,attemptId:randomHex(16)}),trace=this.context.current()?.traceId;
  let observed:string|undefined;try{observed=this.hooks.clock();}catch{this.hooks.loss("job_clock_unavailable");}
  this.emit(context,String(ordinal),observed,"started",null,trace);
  let state:AttemptState="succeeded",cause:string|undefined,completedAt:string|undefined,failed=false;
  try{return await this.context.runJob(context,callback);}
  catch(error){
   failed=true;try{completedAt=this.hooks.clock();}catch{this.hooks.loss("job_clock_unavailable");}
   state=await cancelled(error,this.hooks.nativeError,this.hooks.timerCancellation)?"cancelled":"failed";
   if(state==="failed")try{cause=this.context.runJob(context,()=>this.hooks.capture(error));}catch{this.hooks.loss("job_error_capture_failed");}
   throw error;
  }finally{
   try{
    const terminal=failed?completedAt:this.hooks.clock();
    if(terminal!==undefined&&observed!==undefined&&BigInt(terminal)>=BigInt(observed))this.emit(context,String(ordinal),observed,state,terminal,trace,cause);
    else this.hooks.loss("job_clock_unavailable");
   }catch{this.hooks.loss("job_capture_failed");}
  }
 }
}
