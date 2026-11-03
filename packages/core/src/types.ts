// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
export type EventId = string;
export type Primitive = string | number | boolean | null;
export interface SignedPolicy {readonly version:1;readonly algorithm:"Ed25519";readonly key_id:string;readonly payload:string;readonly signature:string}
export type Severity="trace"|"debug"|"info"|"warn"|"error"|"fatal";
export interface Template {readonly id:string;readonly revision:string;readonly line:string;readonly fields:Readonly<Record<string,readonly Primitive[]>>;readonly severity:Severity}
export interface Config {
 readonly org:string;readonly project:string;readonly source:string;readonly endpoint:string;readonly credential:string;readonly build:string;
 readonly policy:SignedPolicy;readonly trustedKeys:Readonly<Record<string,Uint8Array>>;readonly templates?:readonly Template[];
 readonly operations?:readonly string[];readonly dependencies?:readonly string[];readonly origins?:readonly string[];readonly integrations?:readonly string[];
 readonly deploymentErrors?:boolean;readonly deploymentLogs?:boolean;readonly deploymentReplay?:boolean;readonly deploymentBodies?:boolean;
 readonly maxRecords?:number;readonly maxBytes?:number;readonly clockNs?:()=>string;
}
export interface PolicyDecision {readonly approved:boolean;readonly reason:string;readonly revision:string;readonly errors:boolean;readonly logs:boolean;readonly replay:boolean;readonly bodies:boolean}
export interface FlushReport {readonly acknowledgedBatchIds:readonly string[];readonly acknowledgedCursors:readonly string[];readonly pending:number;readonly lost:number;readonly deadlineExceeded:boolean}
export interface ErrorInput {readonly kind:"error";readonly id:string;readonly observed_at_ns:string;readonly exception_class:string;readonly code:string|null;readonly build_id:string}
export interface LogInput {readonly kind:"log";readonly id:string;readonly observed_at_ns:string;readonly template_id:string;readonly fields:Readonly<Record<string,unknown>>}
export type CaptureInput=ErrorInput|LogInput;
export interface SafeRecord {readonly kind:"error"|"log";readonly id:string;readonly observed_at_ns:string;readonly policy_revision:string;readonly payload:Readonly<Record<string,unknown>>}
