// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
import type {ExceptionGraph} from "./errors.ts";
import type {ReceiptTransport} from "./transport.ts";
import type {EncryptedSpool} from "./spool.ts";
import type {NativeSpan} from "./tracing.ts";
import type {NativeJobAttempt} from "./jobs.ts";
export type {JobContext,NativeJobAttempt,AttemptState} from "./jobs.ts";
export type {ClockDomain,TraceClock,TraceContext,MetadataContext,WorkerContext,SpanOptions,SpanStatus,ActiveSpan} from "./tracing.ts";
export interface Label {readonly name:string;readonly value:string}
export interface Resource {readonly service_id:string;readonly environment_id:string;readonly build_id:string;readonly instance_pseudonym:string;readonly labels?:readonly Label[]}
export interface RoutingDescriptor {readonly version:1;readonly org:string;readonly project:string;readonly source:string;readonly routing_version:1;readonly slots:64;readonly policy_revision:string}
export interface ExportContext {active():boolean;run<T>(callback:()=>T):T;close():void}
export type EventId = string;
export type Primitive = string | number | boolean | null;
export interface SignedPolicy {readonly version:1;readonly algorithm:"Ed25519";readonly key_id:string;readonly payload:string;readonly signature:string}
export type Severity="trace"|"debug"|"info"|"warn"|"error"|"fatal";
export interface Template {readonly id:string;readonly revision:string;readonly line:string;readonly fields:Readonly<Record<string,readonly Primitive[]>>;readonly severity:Severity}
export interface Config {
 readonly org:string;readonly project:string;readonly source:string;readonly endpoint:string;readonly credential:string;readonly build:string;
 readonly policy:SignedPolicy;readonly trustedKeys:Readonly<Record<string,Uint8Array>>;readonly templates?:readonly Template[];
 readonly operations?:readonly string[];readonly dependencies?:readonly string[];readonly origins?:readonly string[];readonly integrations?:readonly string[];
 readonly jobRegistry?:Readonly<Record<string,string>>;
 readonly deploymentErrors?:boolean;readonly deploymentLogs?:boolean;readonly deploymentReplay?:boolean;readonly deploymentBodies?:boolean;readonly deploymentTraces?:boolean;readonly deploymentJobs?:boolean;readonly deploymentLoss?:boolean;
 /** Deployment opt-in for delivering profile_chunk/capability records (off by default). There is no signed-policy flag for profiles: the source policy's Kinds is enforced by the server, so enable this only for a source whose policy lists both profile_chunk and capability. */
 readonly deploymentProfiles?:boolean;
 readonly maxRecords?:number;readonly maxBytes?:number;readonly clockNs?:()=>string;
 readonly traceSampleProbability?:string;
 readonly resource:Resource;readonly descriptor?:RoutingDescriptor;readonly producer?:string;readonly sourceClass?:"private"|"browser";
 readonly transport?:ReceiptTransport;readonly spool?:EncryptedSpool;
}
export interface PolicyDecision {readonly approved:boolean;readonly reason:string;readonly revision:string;readonly errors:boolean;readonly logs:boolean;readonly replay:boolean;readonly bodies:boolean;readonly traces:boolean;readonly jobs:boolean;readonly loss:boolean;readonly profiles:boolean}
export interface FlushReport {readonly acknowledgedBatchIds:readonly string[];readonly acknowledgedCursors:readonly string[];readonly receipts:readonly Readonly<Record<string,unknown>>[];readonly pending:number;readonly lost:number;readonly deadlineExceeded:boolean}
export interface ErrorInput {readonly kind:"error";readonly id:string;readonly observed_at_ns:string;readonly exception_class:string;readonly code:string|null;readonly build_id:string;readonly exception_graph:ExceptionGraph;readonly handled:boolean;readonly fatal:boolean;readonly mechanism:HookMechanism|"manual";readonly trace_id?:string;readonly span_id?:string;readonly run_id?:string}
export interface LogInput {readonly kind:"log";readonly id:string;readonly observed_at_ns:string;readonly template_id:string;readonly fields:Readonly<Record<string,unknown>>}
export interface SpanInput {readonly kind:"span";readonly id:string;readonly observed_at_ns:string;readonly span:NativeSpan}
export interface JobInput {readonly kind:"job_attempt";readonly id:string;readonly observed_at_ns:string;readonly payload:NativeJobAttempt}
/** A browser-built profile_chunk wire payload. The closed field set is enforced again by the queue's wire validation. */
export interface ProfileInput {readonly kind:"profile_chunk";readonly id:string;readonly observed_at_ns:string;readonly payload:Readonly<Record<string,unknown>>}
/** The capability truth record a profile chunk names by id (or the only record of a refused profile). */
export interface CapabilityInput {readonly kind:"capability";readonly id:string;readonly observed_at_ns:string;readonly payload:Readonly<Record<string,unknown>>}
export type CaptureInput=ErrorInput|LogInput|SpanInput|JobInput|ProfileInput|CapabilityInput;
export interface SafeRecord {readonly kind:"error"|"log"|"span"|"job_attempt"|"profile_chunk"|"capability";readonly id:string;readonly observed_at_ns:string;readonly policy_revision:string;readonly payload:Readonly<Record<string,unknown>>}
export type HookMechanism="uncaught_exception"|"unhandled_rejection"|"thread_exception"|"asyncio_exception";
export type ExceptionEdgeKind="cause"|"context"|"group";
export interface OwnedHookLease {close():void}
