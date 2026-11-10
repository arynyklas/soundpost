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

// ---- Human actions, the incident workspace and the queue (internal/httpapi/actions.go) ----
// Versions and nanosecond timestamps are decimal strings on the wire.
export type ActionEntity = 'incident' | 'issue';
export type IncidentActionKind = 'assign' | 'ack' | 'resolve' | 'link' | 'impact' | 'snooze' | 'unsnooze' | 'maintenance' | 'maintenance_end';
export type ActionKind = IncidentActionKind | 'ignore' | 'unignore' | 'reopen' | 'grouping_migration';
export type Severity = 'minor' | 'major' | 'critical';
export type ConditionState = 'firing' | 'recovered' | 'unknown';
export type ConditionFreshness = 'fresh' | 'stale' | 'unknown';
export type LinkKind = 'condition' | 'issue' | 'release' | 'service' | 'incident';
export interface ImpactPayload { condition: Id; episode: Id; severity: Severity; state: ConditionState; freshness: ConditionFreshness }
export interface IncidentLink { kind: LinkKind; id: Id }
/** Closed payload: there is no actor, origin, organization or timestamp field; the server takes the actor from the session. */
export interface ActionPayload { reason?: string; owner?: Id; until?: string; impact?: ImpactPayload; link?: IncidentLink }
export interface ActionRequest {
 org: Id;
 command_id: Id;
 expected_version: string;
 project_id: Id;
 target_id: Id;
 entity_kind: ActionEntity;
 kind: ActionKind;
 payload: ActionPayload;
}
export interface ConditionView { id: Id; state: ConditionState; freshness: ConditionFreshness; observed_at: string }
export interface AckView { actor: Id; at: string; impact_revision: string; version: string; current: boolean }
export interface WindowView { actor: Id; reason: string; from: string; until: string; ended?: string; version: string; active: boolean }
export interface ImpactView { condition: Id; episode: Id; severity: Severity; state: ConditionState; freshness: ConditionFreshness }
export interface TimelineEntry { version: string; at: string; type: string; origin: 'human' | 'system'; actor: Id; reason?: string; owner?: Id; until?: string; impact?: ImpactView; link?: IncidentLink }
export interface NotificationView { reminders_paused: boolean; paused_by?: string; worse_impact_eligible: boolean; suppressed_by?: string; delivery: ViewSection }
export interface IncidentView {
 incident_id: Id;
 org: Id;
 project_id: Id;
 version: string;
 status: 'open' | 'resolved';
 owner?: Id;
 condition: ConditionView;
 episode_id: Id;
 severity: Severity;
 impact_revision: string;
 source_firing: boolean;
 ack?: AckView;
 snooze?: WindowView;
 maintenance?: WindowView;
 notification: NotificationView;
 links: IncidentLink[];
 previous?: Id;
 resolved_at?: string;
 observed_impacts: number;
 last_activity: string;
 timeline?: TimelineEntry[];
}
export interface ActionResponse {
 state: 'committed' | 'not_available';
 reason?: string;
 entity_kind: ActionEntity;
 kind: ActionKind;
 target_id: Id;
 revision?: string;
 incident?: IncidentView;
}
/** A lost optimistic-concurrency race (HTTP 409): nothing was applied, and the incident is at `currentVersion`. */
export class VersionConflict extends Error {
 constructor(readonly currentVersion: string, readonly requestId: string) { super('incident_version_conflict'); }
}
/** The request left the browser but its outcome is unknown (transport failure). The same command ID may be resent safely. */
export class OutcomeUnknown extends Error {
 constructor() { super('outcome_unknown'); }
}
export interface QueueView {
 org: Id;
 projects: Id[];
 state: ViewState;
 reason?: string;
 entries: IncidentView[];
 truncated: boolean;
 sections: ViewSection[];
}
export type OperationPhase = 'fencing' | 'complete' | 'held' | 'failed';
export interface LifecycleOperation {
 id: Id;
 state: ViewState;
 reason?: string;
 phase?: OperationPhase;
 physical?: 'pending' | 'held' | 'done';
 generation: string;
 pending_groups: number;
 applied_barriers: number;
 holds: number;
 safe_fault?: string;
 physical_deadline: string;
 backup_deadline: string;
 residual_stores?: string[];
}
