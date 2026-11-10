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

// ---- Error investigation evidence (internal/httpapi/evidence.go) ----
// Versions and nanosecond timestamps are decimal strings; hashes are 64 lowercase hexadecimal characters.
/** The sanitized frame identity the server keeps for a stack frame; the artifact is an exact ArtifactID, never a URL. */
export interface SafeFrame { module_id: string; function: string; artifact_id: string; line: number; column: number | null; in_app: boolean; async: boolean }
export type SourceVisibility = 'present' | 'withheld' | 'absent';
/** `context` exists only when state is present: source text is a plain string and is never markup. */
export interface SourceView { state: SourceVisibility; reason?: string; context?: string }
export interface CodeIdentity { source: string; function?: string; line: number; column: number }
export interface SymbolicatedFrame { original: SafeFrame; reason: string; resolved?: CodeIdentity; map_sha256?: string; source: SourceView }
export interface FramesView { org: Id; project: Id; build: Id; state: ViewState; reason?: string; frames: SymbolicatedFrame[]; sections: ViewSection[] }
export interface FramesRequest { org: Id; project: Id; build: Id; frames: SafeFrame[]; include_sources: boolean }
export interface DebugArtifact { artifact_id: Id; debug_id: string; sha256: string }
export interface ReleaseRecord { id: Id; build_id: Id; label: string; revision: string; build_time_ns: string; debug_artifacts: DebugArtifact[]; label_history: { revision: string; label: string }[] }
export type AncestryOrder = 'same' | 'ancestor' | 'descendant' | 'concurrent' | 'unknown';
export const ANCESTRY_ORDERS: readonly AncestryOrder[] = ['same', 'ancestor', 'descendant', 'concurrent', 'unknown'];
export interface ReleaseComparison { release: Id; order: AncestryOrder }
export interface ReleaseView { org: Id; project: Id; state: ViewState; reason?: string; release?: ReleaseRecord; parents: { id: Id; known: boolean }[]; children: Id[]; comparisons: ReleaseComparison[]; sections: ViewSection[] }
export interface OccurrenceEvidence { occurrence_id: Id; record_id: Id; grouping_version: number; fingerprint: string; event_time_ns: string; arrival_time_ns: string; build_id?: Id; release_id?: Id; ancestry: 'known' | 'unknown'; freshness: string; late: boolean }
export interface GroupingIdentity { grouping_version: number; fingerprint: string; workflow: string; revision: string; resolution_time_ns?: string; resolution_frontier: Id[]; observed_releases: Id[]; fixed_descendants: Id[]; migration_links: Id[] }
export interface IssueEvidenceView { org: Id; project: Id; issue: Id; state: ViewState; reason?: string; grouping?: GroupingIdentity; occurrences: OccurrenceEvidence[]; late_history: OccurrenceEvidence[]; sections: ViewSection[] }

// ---- Trace view and critical path (POST /api/v1/traces/view; internal/httpapi/traces.go, internal/traces/critical_path.go) ----
// Nanosecond values are decimal strings. A duration is an interval, never a single authoritative total.
export type SpanId = string;
export interface DurationBounds { known: boolean; min_ns: string; max_ns: string; basis?: string }
export interface SpanLinkReport { trace_id: Id; span_id: SpanId; same_trace: boolean; resolved: boolean }
export interface SpanReport {
 span_id: SpanId; parent_id: SpanId | null; span_kind: string; operation: string; status: string; dependency_alias?: string;
 start_wall_ns: string; end_wall_ns: string | null; duration: DurationBounds; flags: string[];
 sample_probability: number; sample_decision: string; job_id?: Id; replay_id?: Id; profile_id?: Id; links: SpanLinkReport[];
}
export interface PathSegment { span_id: SpanId; depth: number; self: DurationBounds; ambiguous: boolean; parallel_siblings_off_path: number; async_children_off_path: number }
export interface TreePath { root_span_id: SpanId; orphan: boolean; duration: DurationBounds; segments: PathSegment[] }
export interface EdgeIssue { kind: string; span_id?: SpanId; other_span_ids?: SpanId[]; count?: number }
export interface ClockIssue { span_id: SpanId; parent_id: SpanId; kind: 'starts_before_parent' | 'ends_after_parent'; certain: boolean; cross_domain: boolean; uncertainty_ns: string }
export interface SamplingReport { kept: number; dropped: number; min_probability: number; sampled: boolean; invalid_probability: number }
export interface PathResult {
 trace_id: Id; span_count: number; spans: SpanReport[]; trees: TreePath[]; observed: DurationBounds; edges: EdgeIssue[]; clock_issues: ClockIssue[];
 unlike_clock_domains: boolean; max_uncertainty_ns: string; sampling: SamplingReport; complete: boolean; reasons: string[];
}
export interface TraceView { org: Id; project: Id; trace: Id; state: ViewState; reason?: string; partial: boolean; path?: PathResult; sections: ViewSection[] }

// ---- Job run and attempt investigation (POST /api/v1/jobs/list, /api/v1/jobs/view; internal/httpapi/jobs_view.go, internal/jobs/types.go) ----
// Nanosecond times, durations, versions, ordinals and counters of the journal are decimal strings; IDs are 32 lowercase hexadecimal characters.
// The job's current health, a run's recovery and producer loss are three separate fields; none is derived from another.
export type JobHealthStatus = 'succeeded' | 'failed' | 'cancelled' | 'running' | 'running_too_long' | 'late' | 'missed' | 'unknown';
export const JOB_HEALTH_STATUSES: readonly JobHealthStatus[] = ['succeeded', 'failed', 'cancelled', 'running', 'running_too_long', 'late', 'missed', 'unknown'];
export type JobAttemptState = 'started' | 'succeeded' | 'failed' | 'cancelled';
export const JOB_ATTEMPT_STATES: readonly JobAttemptState[] = ['started', 'succeeded', 'failed', 'cancelled'];
export type JobRunStatus = 'running' | 'succeeded' | 'recovered' | 'failed' | 'cancelled';
export const JOB_RUN_STATUSES: readonly JobRunStatus[] = ['running', 'succeeded', 'recovered', 'failed', 'cancelled'];
export type JobObserverState = 'none' | 'fresh' | 'stale' | 'unhealthy';
export const JOB_OBSERVER_STATES: readonly JobObserverState[] = ['none', 'fresh', 'stale', 'unhealthy'];
export type JobTruncationReason = 'page_limit' | 'runs_limit' | 'loss_limit';
export interface JobTruncation { reason: JobTruncationReason; shown: number; total?: number; next?: Id }
export interface JobSchedule { cron: string; timezone: string }
/** Zero grace, runtime and stale-after durations are the server's "not set" values; the page words them. */
export interface JobDefinition { revision: string; effective_from_ns: string; schedule?: JobSchedule; grace_ns: string; max_runtime_ns: string; observer_stale_after_ns: string; overlap: string }
export interface JobObserverEvidence { observer: Id; observed_at_ns: string; complete_through_ns: string; healthy: boolean; stale: boolean }
export interface JobHealthEvidence {
 occurrence?: string; run?: Id; attempt?: Id; attempt_state?: JobAttemptState; attempt_count?: number; expected_at_ns?: string; window_end_ns?: string;
 cause_trace?: Id; cause_error?: Id; definition_revision?: string; observer?: JobObserverEvidence; gaps?: Id[]; skipped_local_times?: string[];
}
export interface JobHealth { status: JobHealthStatus; as_of_ns: string; complete: boolean; reasons: string[]; evidence: JobHealthEvidence }
export interface JobSummaryView { job: Id; version: string; erased: boolean; definition?: JobDefinition; health: JobHealth; runs: number; attempts: number }
export interface JobsListView { org: Id; project: Id; state: ViewState; reason?: string; permission: string; evaluated_at_ns?: string; jobs: JobSummaryView[]; more: boolean; truncation?: JobTruncation; sections: ViewSection[] }
export interface JobOccurrenceView { key: string; scheduled: boolean; at_ns?: string; fold: number }
export interface JobRunView {
 id: Id; occurrence: JobOccurrenceView; status: JobRunStatus; recovered: boolean; first_started_ns: string; final_attempt: Id; attempt_count: number; failed_attempts: number;
 basis_of_health: boolean; superseded_by?: string; overlaps: Id[]; overlap_count: number;
}
export interface JobTerminalResult { state: JobAttemptState; at_ns: string }
export interface JobCorrection { version: string; state: JobAttemptState; reason: string; actor: Id; at_ns: string; command: Id }
export interface JobAttemptView {
 id: Id; ordinal: string; started: boolean; observed_ns: string; terminal?: JobTerminalResult; effective: JobAttemptState; corrections: JobCorrection[]; events_accepted: number;
 cause_trace?: Id; cause_error?: Id; final: boolean; after_newer_occurrence: boolean;
}
export interface JobRunDetail extends JobRunView { attempts: JobAttemptView[] }
export interface JobSourceView { version: string; cursor?: Cursor }
export interface JobObserverView { state: JobObserverState; expected_schedule: boolean; evidence?: JobObserverEvidence }
export interface JobInterval { id: Id; start_ns: string; end_ns: string; reason: string }
export interface JobLossView { intervals: JobInterval[]; total: number; affects_current_health: boolean; truncation?: JobTruncation }
export interface JobCompaction { runs: string; through_ns: string }
export interface JobView {
 org: Id; project: Id; job: Id; state: ViewState; reason?: string; permission: string; evaluated_at_ns?: string; source?: JobSourceView; erased: boolean;
 definition?: JobDefinition; definition_revisions: number; health?: JobHealth; observer?: JobObserverView; loss?: JobLossView; total_runs: number; total_attempts: number;
 compaction?: JobCompaction; latest_occurrence?: string; runs: JobRunView[]; runs_truncation?: JobTruncation; run?: JobRunDetail; sections: ViewSection[];
}
