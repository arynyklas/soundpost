// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import {originalStackLimitation,type SafeFrame} from "./frames.ts";
import type {SourcePolicy} from "./policy.ts";
import type {ExceptionEdgeKind} from "./types.ts";
/** Supplied only by owned runtime entrypoints, never discovered on thrown values. */
export interface ErrorBoundary {readonly isNativeError:(value:unknown)=>boolean;readonly isProxy?:(value:unknown)=>boolean}
export interface ErrorNode {readonly id:number;readonly exception_class:string;readonly frames:readonly SafeFrame[];readonly context_suppressed:boolean}
export interface ErrorEdge {readonly from:number;readonly to:number;readonly kind:ExceptionEdgeKind;readonly ordinal?:number}
export interface ExceptionGraph {readonly nodes:readonly ErrorNode[];readonly edges:readonly ErrorEdge[];readonly reasons:readonly string[]}
const prototypes:readonly (readonly [object,string])[]=[
 [Error.prototype,"Error"],[TypeError.prototype,"TypeError"],[RangeError.prototype,"RangeError"],
 [ReferenceError.prototype,"ReferenceError"],[SyntaxError.prototype,"SyntaxError"],[URIError.prototype,"URIError"],
 [EvalError.prototype,"EvalError"],[AggregateError.prototype,"AggregateError"]
];
export function extractException(error:unknown,_policy:SourcePolicy,boundary?:ErrorBoundary):ExceptionGraph {
 const nodes:ErrorNode[]=[],edges:ErrorEdge[]=[],reasons=new Set<string>(),seen:unknown[]=[];
 const visit=(value:unknown,ancestors:ReadonlySet<number>):number|undefined=>{
  const prior=seen.findIndex(v=>v===value);
  if(prior!==-1){if(ancestors.has(prior))reasons.add("cycle");return prior;}
  if(nodes.length===16){reasons.add("node_limit");return;}
  const id=nodes.length;seen.push(value);
  const native=boundary?.isNativeError(value)===true;
  let name="UnknownError";
  if(native){
   // isNativeError rejects proxies; a true native object has no proxy internal methods.
   // Inspect exactly one prototype, never traverse a possibly hostile prototype chain.
   const proto:unknown=Object.getPrototypeOf(value);
   name=prototypes.find(([p])=>p===proto)?.[1]??"Error";
   if(!prototypes.some(([p])=>p===proto))reasons.add("foreign_or_custom_error_class");
   reasons.add(originalStackLimitation);
  }else reasons.add(boundary?"unknown_throw":"native_brand_unavailable");
  nodes.push(Object.freeze({id,exception_class:name,frames:Object.freeze([]),context_suppressed:false}));
  if(!native)return id;
  const link=(child:unknown,kind:"cause"|"group",ordinal?:number):void=>{
   const to=visit(child,new Set([...ancestors,id]));
   if(to!==undefined)edges.push(Object.freeze(ordinal===undefined?{from:id,to,kind}:{from:id,to,kind,ordinal}));
  };
  const cause=Object.getOwnPropertyDescriptor(value,"cause");
  if(cause){
   if(!("value" in cause))reasons.add("cause_accessor");
   else if(cause.value!==undefined&&cause.value!==null)link(cause.value,"cause");
  }
  // Native AggregateError's own `errors` value is not itself branded. Require a
  // runtime proxy test before any array descriptor operation; never call its iterator.
  const group=name==="AggregateError"?Object.getOwnPropertyDescriptor(value,"errors"):undefined;
  if(group){
   if(!("value" in group))reasons.add("group_accessor");
   else if(!boundary?.isProxy)reasons.add("safe_group_boundary_unavailable");
   else if(boundary.isProxy(group.value)||!Array.isArray(group.value))reasons.add("unsafe_group_container");
   else{
    const length=Object.getOwnPropertyDescriptor(group.value,"length")?.value as number;
    for(let i=0;i<Math.min(length,16);i++){
     const item=Object.getOwnPropertyDescriptor(group.value,String(i));
     if(item&&"value" in item)link(item.value,"group",i);else reasons.add("group_accessor");
    }
    if(length>16)reasons.add("group_limit");
   }
  }
  return id;
 };
 visit(error,new Set());
 return Object.freeze({nodes:Object.freeze(nodes),edges:Object.freeze(edges),reasons:Object.freeze([...reasons].sort())});
}
