// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Browser mirrors of internal/httpapi/workflow_types.go. Nanosecond timestamps and
// IDs stay canonical strings: they are never routed through a JavaScript number.
export type Id = string;
export type InvestigationKind = 'queue' | 'incident' | 'issue' | 'release' | 'service' | 'trace' | 'job' | 'replay' | 'profile';
export const INVESTIGATION_KINDS: readonly InvestigationKind[] = ['queue', 'incident', 'issue', 'release', 'service', 'trace', 'job', 'replay', 'profile'];
export interface TimeRange { start: string; end: string }
/** The wire body of POST /api/v1/investigate. `org` is a selector the server
 * re-authorizes; no field is a credential, role or caller-supplied scope. */
export interface InvestigationRequest {
 org: Id;
 kind: InvestigationKind;
 projects: Id[];
 target?: Id;
 source?: Id;
 window: TimeRange;
 limit: number;
 cursor?: string;
}
export type ViewState = 'ready' | 'empty' | 'incomplete' | 'stale' | 'not_available';
export interface VisibleSource { id: Id; project: Id; class: string; kinds: string[]; replay: boolean; policy_revision: string | number }
export interface ProjectEvidence { project_id: Id; sources: VisibleSource[] }
export interface ViewSection { name: string; state: ViewState; reason?: string }
export interface TargetLink { kind: string; project_id: Id; id: Id; available: boolean }
export interface Freshness { completeness: string; watermarks: { group: Id; index: string }[]; cached: boolean }
export interface InvestigationView {
 kind: InvestigationKind;
 org: Id;
 window: TimeRange;
 state: ViewState;
 reason?: string;
 projects: ProjectEvidence[];
 metric_names: string[];
 more: boolean;
 next_cursor?: string;
 freshness?: Freshness;
 sections: ViewSection[];
 link?: TargetLink;
}
/** A typed failure: the C01 code, request ID and approved static detail only. */
export class ApiFault extends Error {
 constructor(readonly status: number, readonly code: string, readonly requestId: string, readonly detail: string) {
  super(`${code}`);
 }
}
/** The closed set of states every view must be able to show separately. Data
 * rides only on variants that may carry it: a partial or stale answer is
 * labelled and never ready, and an unauthorized one carries nothing. */
export type LoadState<T> =
 | { kind: 'loading' }
 | { kind: 'ready'; data: T }
 | { kind: 'empty'; data: T }
 | { kind: 'unauthorized'; status: number; requestId: string }
 | { kind: 'unsupported'; reason: string; data?: T }
 | { kind: 'stale'; data: T; reason: string }
 | { kind: 'incomplete'; data: T; reason: string }
 | { kind: 'rate_limited'; requestId: string }
 | { kind: 'error'; fault: ApiFault };
export const LOAD_STATE_KINDS = ['loading', 'ready', 'empty', 'unauthorized', 'unsupported', 'stale', 'incomplete', 'rate_limited', 'error'] as const;
