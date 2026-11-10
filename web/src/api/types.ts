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

// ---- C06 queries, discovery, exemplars, formatting and live streams (internal/query/{types,live_types}.go, internal/httpapi/{query,discovery,live}.go) ----
// IEEE-754 values travel as their exact 16-hex-digit bits (model.FloatBits); every int64/uint64 and nanosecond is a decimal
// string. Only bucket spans, histogram schemas and source-range offsets are JSON numbers, exactly as the server writes them.
export type QueryLanguage = 'promql' | 'logql';
export const QUERY_LANGUAGES: readonly QueryLanguage[] = ['promql', 'logql'];
export type FloatBits = string;
export interface Cursor { group: Id; index: string }
export interface Label { name: string; value: string }
export interface HistogramSpan { offset: number; length: number }
export interface IntegerHistogram {
 flavor: string;
 schema: number;
 zero_threshold: FloatBits;
 sum: FloatBits;
 count: string;
 zero_count: string;
 positive_spans: HistogramSpan[];
 negative_spans: HistogramSpan[];
 /** Delta-encoded signed decimal strings. */
 positive_buckets: string[];
 negative_buckets: string[];
 /** Absolute counts, when the server states them. */
 positive_counts?: string[];
 negative_counts?: string[];
 reset_hint: string;
 custom_bounds?: FloatBits[];
}
export interface FloatHistogram {
 flavor: string;
 schema: number;
 zero_threshold: FloatBits;
 sum: FloatBits;
 count: FloatBits;
 zero_count: FloatBits;
 positive_spans: HistogramSpan[];
 negative_spans: HistogramSpan[];
 positive_buckets: FloatBits[];
 negative_buckets: FloatBits[];
 reset_hint: string;
 custom_bounds?: FloatBits[];
}
/** Exactly one variant is present. */
export interface NativeHistogram { integer?: IntegerHistogram; float?: FloatHistogram }
/** Exactly one of `float` and `histogram` is present. A stale marker is never emitted as a sample: it is the absence of one. */
export interface Sample { time: string; float?: FloatBits; histogram?: NativeHistogram; start_timestamp?: string }
export interface VectorElement { labels: Label[]; sample: Sample }
export interface Series { labels: Label[]; samples: Sample[] }
/** `index` is the entry's position in the language-defined order of the whole project result. Stream labels and structured metadata stay separate. */
export interface LogEntry { index: string; time: string; id: Id; source?: Id; multiplicity: string; line: string; stream_labels: Label[]; structured_metadata: Label[] }
export interface LogStream { labels: Label[]; entries: LogEntry[] }
export type QueryValue =
 | { type: 'scalar'; scalar: Sample }
 | { type: 'string'; string: string }
 | { type: 'vector'; vector: VectorElement[] }
 | { type: 'matrix'; matrix: Series[] }
 | { type: 'streams'; streams: LogStream[] };
export interface SourceRange { start_byte: number; end_byte: number; start_rune: number; end_rune: number }
export interface Diagnostic { severity: 'info' | 'warning'; code: string; source_range?: SourceRange; safe_message: string }
export interface QueryStats {
 scans_started: string;
 pages_read: string;
 rows_read: string;
 bytes_read: string;
 series_returned: string;
 samples_returned: string;
 logs_returned: string;
 peak_memory_bytes: string;
 elapsed_ns: string;
 cached: boolean;
 limit_reached: boolean;
}
/** The typed reason one project produced no value; only present when the request opted into partial results. */
export interface ProjectFailure { code: string; category?: string; source_range?: SourceRange; safe_message: string }
export type Completeness = 'complete' | 'partial' | 'stale';
export const COMPLETENESS: readonly Completeness[] = ['complete', 'partial', 'stale'];
/** One project's independent evaluation. `value` is null only with a `failure`, and then the result is partial. */
export interface ProjectResult {
 project_id: Id;
 value: QueryValue | null;
 diagnostics: Diagnostic[];
 watermarks: Cursor[];
 completeness: Completeness;
 stats: QueryStats;
 failure?: ProjectFailure;
}
/** One result per requested project, ordered by project ID. Series never combine across projects and no project label is injected. */
export interface QueryResult { projects: ProjectResult[] }
export interface EvaluationWire { instant: boolean; time: string; start: string; end: string; step: string }
export interface BudgetWire { timeout_ns: string; memory_bytes: string; max_returned: string }
/** The flattened POST /api/v1/query body: scope fields next to the C06 Request. `permission` is only ever 'raw.read' with exactly one project and a named restricted `source`. */
export interface QueryRequest {
 org: Id;
 permission?: 'raw.read';
 language: QueryLanguage;
 profile: string;
 expression: string;
 evaluation: EvaluationWire;
 projects: Id[];
 feature_set: string;
 budget: BudgetWire;
 min_cursors?: Cursor[];
 allow_partial: boolean;
 source?: Id;
 log_limit?: string;
 log_order?: 'backward' | 'forward';
}
export type DiscoverSignal = 'metric' | 'log';
export type DiscoverKind = 'metric_names' | 'label_names' | 'label_values' | 'templates' | 'fields';
export const DISCOVER_KINDS: Record<DiscoverSignal, readonly DiscoverKind[]> = { metric: ['metric_names', 'label_names', 'label_values'], log: ['label_names', 'label_values', 'templates', 'fields'] };
export interface Matcher { name: string; op: '=' | '!=' | '=~' | '!~'; value: string }
export interface DiscoveryRequest {
 org: Id;
 projects: Id[];
 signal: DiscoverSignal;
 kind: DiscoverKind;
 field?: string;
 matchers: Matcher[];
 time: TimeRange;
 limit: number;
 cursor?: string;
 profile?: string;
 feature_set?: string;
 /** raw.read with a named restricted source, exactly as for a query. */
 permission?: 'raw.read';
 source?: Id;
}
/** One page of sorted distinct names. `next_cursor` is present exactly when `more` is true. */
export interface DiscoveryResult { items: string[]; more: boolean; next_cursor?: string; freshness: Freshness }
export interface ExemplarRequest { org: Id; projects: Id[]; profile: string; feature_set: string; expression: string; window: TimeRange; limit: number; cursor?: string }
export interface Exemplar { project_id: Id; labels: Label[]; sample: Sample; trace_id: Id; span_id?: string; record_id: Id }
export interface ExemplarResult { exemplars: Exemplar[]; more: boolean; next_cursor?: string; freshness: Freshness }
export interface FormatRequest { org: Id; projects: Id[]; language: QueryLanguage; profile: string; feature_set: string; expression: string }
export interface FormatResult { formatted: string; diagnostics: Diagnostic[] }
/** The 400 body of a language error: category, owned code and source range, never the query text. */
export interface LanguageFault { languageCode: string; category: string; range: SourceRange | null; detail: string }
/** A typed query failure. A language error also carries its category and source range; nothing else of the body is kept. */
export class QueryFault extends ApiFault {
 constructor(status: number, code: string, requestId: string, detail: string, readonly language: LanguageFault | null = null) { super(status, code, requestId, detail); }
}
/** POST /api/v1/live-tickets body (scope fields plus the stored live request). Expression and projects live here, never in the stream URL. */
export interface LiveTicketRequest { org: Id; projects: Id[]; profile: string; feature_set: string; expression: string; source?: Id; permission?: 'raw.read'; budget: BudgetWire; resume_stream_id?: Id }
export interface LiveTicket { ticket: Id; expires_at: string }
export type LiveEventType = 'open' | 'record' | 'gap' | 'heartbeat' | 'revoke' | 'error';
export const LIVE_EVENT_TYPES: readonly LiveEventType[] = ['open', 'record', 'gap', 'heartbeat', 'revoke', 'error'];
/** Exact bounds of a loss: the stream sequences not delivered (inclusive) and the committed-feed cursors around them. */
export interface LiveGap { reason: string; from_sequence: string; to_sequence: string; after?: Cursor[]; through?: Cursor[] }
export interface LiveEvent {
 type: LiveEventType;
 stream_id: Id;
 sequence?: string;
 project?: Id;
 entry?: LogEntry;
 labels?: Label[];
 cursors?: Cursor[];
 gap?: LiveGap;
 watermarks?: Cursor[];
 reason?: string;
 failure?: ProjectFailure;
}

// ---- Async raw-record export (internal/httpapi/exports.go, internal/exports) ----
export type ExportSignal = 'metric' | 'log' | 'span' | 'error' | 'job_attempt' | 'replay_chunk' | 'profile_chunk' | 'capability' | 'loss' | 'condition';
export const EXPORT_SIGNALS: readonly ExportSignal[] = ['metric', 'log', 'span', 'error', 'job_attempt', 'replay_chunk', 'profile_chunk', 'capability', 'loss', 'condition'];
export type ExportPhase = 'running' | 'complete' | 'failed';
export const EXPORT_PHASES: readonly ExportPhase[] = ['running', 'complete', 'failed'];
/** `safe_reason` is a closed vocabulary of static words (revoked, timeout, partial, too_large, unavailable), present exactly when the export failed. */
export interface ExportOperation { id: Id; kind: 'export'; phase: ExportPhase; generation: string; progress: string; chunks: string; safe_reason?: string }
/** The 202 answer of a create: the operation and the one-use download ticket bound to this scope. */
export interface ExportGrant { operation: ExportOperation; ticket: string }
