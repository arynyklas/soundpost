// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Browser mirrors of POST /api/v1/profiles/view (internal/httpapi/profile_view.go, internal/profiles/types.go, internal/model/{telemetry,native_profile,clock}.go).
// Every uint64 / int64 / nanosecond value is a decimal string on the wire and stays a string here: it is converted with BigInt, never with `number`.
import type { Id, ViewSection, ViewState } from '../api/types';

export type ProfileMethod = 'runtime_cpu' | 'native_cpu' | 'native_offcpu';
export const PROFILE_METHODS: readonly ProfileMethod[] = ['runtime_cpu', 'native_cpu', 'native_offcpu'];
export type ProfileUnits = 'samples' | 'nanoseconds';
export const PROFILE_UNITS: readonly ProfileUnits[] = ['samples', 'nanoseconds'];
export type IntervalKind = 'blocked' | 'runnable' | 'unknown_offcpu';
export const INTERVAL_KINDS: readonly IntervalKind[] = ['blocked', 'runnable', 'unknown_offcpu'];
export type CapabilityStatus = 'supported' | 'denied' | 'unsupported' | 'error';
export const CAPABILITY_STATUSES: readonly CapabilityStatus[] = ['supported', 'denied', 'unsupported', 'error'];
export type CoverageLevel = 'complete' | 'partial' | 'none' | 'unknown';
export const COVERAGE_LEVELS: readonly CoverageLevel[] = ['complete', 'partial', 'none', 'unknown'];
export type NativeLossReason = 'records_lost' | 'samples_lost' | 'throttled' | 'unthrottled';
export const NATIVE_LOSS_REASONS: readonly NativeLossReason[] = ['records_lost', 'samples_lost', 'throttled', 'unthrottled'];
export type LinkRelation = 'explicit' | 'time_overlap_inference';
export const LINK_RELATIONS: readonly LinkRelation[] = ['explicit', 'time_overlap_inference'];
export type Completeness = 'complete' | 'partial';

export interface ClockDomain { host: Id; boot: Id; runtime: Id }
/** `wall_ns` is a signed decimal; `mono_ns` and `uncertainty_ns` are unsigned decimals of the clock domain. */
export interface TraceClock { wall_ns: string; mono_ns: string; uncertainty_ns: string; domain: ClockDomain }
export interface NativeDomain { host_id: string; boot_id: string }
/** `reason` is empty for a resolved frame. Module, function and artifact are text only: never a URL, a link or a fetch. */
export interface ProfileFrame { module_id: string; function: string; artifact_id: string; offset: string; reason: string }
export interface ProfileStack { frames: number[] }
export interface NativeTask { boot_id: string; pid_namespace: string; tgid: number; tid: number; process_start_ns: string; generation: string }
export interface NativeSample {
 task: NativeTask; method: string; unit: string; requested_hz: number; period: string;
 truncation?: string; coverage?: string; throttle_reason?: string; throttle_event_id?: string; throttle_stream_id?: string;
}
export interface ProfileSample { at_ns: string; stack: number; count: string; thread: string; native?: NativeSample }
export interface ProfileInterval {
 start_ns: string; end_ns: string; stack: number; kind: IntervalKind; thread: string; censored: boolean;
 native_task?: NativeTask; unit?: string; reason?: string; correction?: boolean;
}
export interface Coverage { frames: CoverageLevel; threads: CoverageLevel; workers: CoverageLevel; tasks: CoverageLevel }
export interface Capability {
 runtime: string; version: string; build: string; os: string; arch: string; signal: string; method: string;
 status: CapabilityStatus; reason: string; coverage: Coverage; clock_domain: ClockDomain; expires_ns: string;
}
export interface CapabilityRecord { id: Id; value: Capability }
export interface Cursor { group: Id; index: string }
export interface LossReport {
 source: Id; producer: Id; producer_epoch: Id; start_ns: string; end_ns: string; signal: string; reason: string; count: string;
 last_ack: Cursor | null; queue_bytes: string; queue_records: string;
}
export interface NativeLoss { at_ns: string; cpu: number; count: string; reason: NativeLossReason; throttle_event_id?: string; throttle_stream_id?: string }
export interface Reference { project_id: Id; build_id: Id; kind: string; id: Id; relation: LinkRelation }
/** A link the account may not open has no `reference`; nothing about its target is disclosed. */
export interface ResolvedReference { reference?: Reference; available: boolean }

/** `blocked_ns`, `runnable_ns` and `unknown_ns` are ABSENT when that quantity was not measured: absent is never zero. */
export interface ProfileView {
 profile_id: Id; process_id: Id; project_id: Id; method: ProfileMethod; units: ProfileUnits; clock: TraceClock; native_domain?: NativeDomain;
 frames: ProfileFrame[]; stacks: ProfileStack[]; samples: ProfileSample[]; intervals: ProfileInterval[];
 capabilities: CapabilityRecord[]; loss: LossReport[]; loss_count: string; native_loss?: NativeLoss[]; truncated: boolean;
 blocked_ns?: string; runnable_ns?: string; unknown_ns?: string;
 links: ResolvedReference[]; watermarks: Cursor[]; completeness: Completeness; reasons: string[]; next_cursor?: string;
}
/** `view` is absent for `not_available` (for example `profile_service_not_wired`) and `empty`. */
export interface ProfileResponse { org: Id; project: Id; profile: Id; state: ViewState; reason?: string; partial: boolean; view?: ProfileView; sections: ViewSection[] }

/** How a profile relates to a request. `exact` rests on an explicit link to that request; an overlap in time on a thread is never attributed to a request. */
export type Correlation = { kind: 'none' } | { kind: 'exact'; request: Id } | { kind: 'thread_overlap' };
