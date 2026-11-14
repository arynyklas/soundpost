// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { ANCESTRY_ORDERS, ApiFault, COMPLETENESS, EXPORT_PHASES, INVESTIGATION_KINDS, LIVE_EVENT_TYPES, OutcomeUnknown, QueryFault, VersionConflict, type ActionRequest, type ActionResponse, type AncestryOrder, type Completeness, type DiscoveryRequest, type DiscoveryResult, type ExemplarRequest, type ExemplarResult, type ExportGrant, type ExportOperation, type ExportPhase, type ExportSignal, type FormatRequest, type FormatResult, type FramesRequest, type FramesView, type Id, type IncidentView, type InvestigationKind, type InvestigationRequest, type InvestigationView, type IssueEvidenceView, type LifecycleOperation, type LiveEvent, type LiveEventType, type LiveTicket, type LiveTicketRequest, type LoadState, type QueryRequest, type QueryResult, type QueueView, type ReleaseView, type SafeFrame, type ViewState, type VisibleSource } from './types';
import { SseProtocolError, readSse, type SseFrame } from './sse';
import type { TraceView } from './types';
import { parseTraceView } from '../traces/model';
import { lineSplitter, parseReplayLine, type ReplayLine } from '../replays/model';
import { parseProfileResponse } from '../profiles/model';
import type { ProfileResponse } from '../profiles/types';
import { JOB_ATTEMPT_STATES, JOB_HEALTH_STATUSES, JOB_OBSERVER_STATES, JOB_RUN_STATUSES, type JobAttemptState, type JobAttemptView, type JobDefinition, type JobHealth, type JobObserverEvidence, type JobRunDetail, type JobRunView, type JobsListView, type JobView, type ViewSection as JobViewSection } from './types';

// The CSRF token lives only here, in memory, handed over by the session
// boundary. It is never persisted and never placed in a URL.
let csrf = '';
export function bindSession(token: string): void { csrf = token; }

const VIEW_STATES: readonly ViewState[] = ['ready', 'empty', 'incomplete', 'stale', 'not_available'];
const SAFE_DETAIL = /^[a-z0-9_ .:-]{0,120}$/i;

/** Keeps only the C01 code, request ID and a bounded plain detail; a body that
 * is not a typed failure becomes a generic one, never raw server text. */
export async function apiFault(response: Response): Promise<ApiFault> {
 let code = 'unavailable';
 let detail = '';
 try {
  const body: unknown = await response.json();
  if (typeof body === 'object' && body !== null) {
   const record = body as Record<string, unknown>;
   if (typeof record.code === 'string' && /^[a-z_]{1,40}$/.test(record.code)) code = record.code;
   if (typeof record.detail === 'string' && SAFE_DETAIL.test(record.detail)) detail = record.detail;
  }
 } catch { /* not JSON: keep the generic fault */ }
 const header = response.headers.get('X-Request-ID') ?? '';
 return new ApiFault(response.status, code, /^[0-9a-f]{32}$/.test(header) ? header : '', detail);
}

function isRecord(v: unknown): v is Record<string, unknown> { return typeof v === 'object' && v !== null && !Array.isArray(v); }

/** Accepts a view only when it is for exactly the requested scope: a view of
 * another organization, kind or project is a fault, never rendered. */
export function parseView(raw: unknown, req: InvestigationRequest): InvestigationView {
 const bad = (): never => { throw new ApiFault(200, 'invalid_response', '', 'response does not match the request'); };
 if (!isRecord(raw)) return bad();
 if (raw.kind !== req.kind || raw.org !== req.org || !INVESTIGATION_KINDS.includes(raw.kind as InvestigationKind)) return bad();
 if (typeof raw.state !== 'string' || !VIEW_STATES.includes(raw.state as ViewState)) return bad();
 if (!Array.isArray(raw.projects) || !Array.isArray(raw.sections) || !Array.isArray(raw.metric_names) || typeof raw.more !== 'boolean') return bad();
 for (const p of raw.projects) {
  if (!isRecord(p) || typeof p.project_id !== 'string' || !req.projects.includes(p.project_id) || !Array.isArray(p.sources)) return bad();
 }
 for (const s of raw.sections) {
  if (!isRecord(s) || typeof s.name !== 'string' || !VIEW_STATES.includes(s.state as ViewState)) return bad();
 }
 if (!raw.metric_names.every((n): boolean => typeof n === 'string')) return bad();
 if (isRecord(raw.window) && (raw.window.start !== req.window.start || raw.window.end !== req.window.end)) return bad();
 if (isRecord(raw.link) && (typeof raw.link.id !== 'string' || (req.target !== undefined && raw.link.id !== req.target) || typeof raw.link.project_id !== 'string' || !req.projects.includes(raw.link.project_id))) return bad();
 return raw as unknown as InvestigationView;
}

/** POST /api/v1/investigate. The body is typed and carries no query text; the
 * response is validated against the request before anyone may render it. */
export async function investigate(req: InvestigationRequest, signal: AbortSignal): Promise<InvestigationView> {
 const response = await fetch('/api/v1/investigate', {
  method: 'POST', credentials: 'same-origin', cache: 'no-store', signal,
  headers: { Accept: 'application/json', 'Content-Type': 'application/json', ...(csrf ? { 'X-CSRF-Token': csrf } : {}) },
  body: JSON.stringify(req),
 });
 if (!response.ok) throw await apiFault(response);
 return parseView(await response.json() as unknown, req);
}

export interface Capabilities { sources: VisibleSource[] }
/** GET /api/v1/capabilities: only the active sources this credential may read. */
export async function capabilities(org: Id, project: Id, signal: AbortSignal): Promise<Capabilities> {
 const response = await fetch(`/api/v1/capabilities?${new URLSearchParams({ org, project })}`, { credentials: 'same-origin', cache: 'no-store', signal, headers: { Accept: 'application/json' } });
 if (!response.ok) throw await apiFault(response);
 const body: unknown = await response.json();
 if (!isRecord(body) || !Array.isArray(body.sources) || !body.sources.every((s): boolean => isRecord(s) && s.project === project)) throw new ApiFault(200, 'invalid_response', '', 'response does not match the request');
 return { sources: body.sources as VisibleSource[] };
}

export function isAbort(error: unknown): boolean {
 return error instanceof DOMException && error.name === 'AbortError';
}

/** Maps a view to the load state it may be shown as. not_available is an
 * explicit unsupported state, never an empty success. */
export function stateOfView(view: InvestigationView): LoadState<InvestigationView> {
 switch (view.state) {
  case 'ready': return { kind: 'ready', data: view };
  case 'empty': return { kind: 'empty', data: view };
  case 'incomplete': return { kind: 'incomplete', data: view, reason: view.reason ?? 'incomplete' };
  case 'stale': return { kind: 'stale', data: view, reason: view.reason ?? 'stale' };
  case 'not_available': return { kind: 'unsupported', reason: view.reason ?? 'not_available', data: view };
 }
}

/** A denied or missing scope is one state: the browser cannot tell them apart
 * and must not suggest the difference. */
export function stateOfFault(error: unknown): LoadState<never> {
 if (!(error instanceof ApiFault)) return { kind: 'error', fault: new ApiFault(0, 'network', '', '') };
 switch (error.status) {
  case 401: case 403: case 404: return { kind: 'unauthorized', status: error.status === 401 ? 401 : 404, requestId: error.requestId };
  case 429: return { kind: 'rate_limited', requestId: error.requestId };
  case 501: return { kind: 'unsupported', reason: error.code };
  default: return { kind: 'error', fault: error };
 }
}

// ---- Human actions, incidents, queue and lifecycle operations (internal/httpapi/actions.go) ----
const DEC = /^(0|[1-9][0-9]{0,19})$/;
const SEVERITIES = ['minor', 'major', 'critical'];
const CONDITION_STATES = ['firing', 'recovered', 'unknown'];
const FRESHNESS = ['fresh', 'stale', 'unknown'];
const idLike = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{32}$/.test(v);
const decLike = (v: unknown): v is string => typeof v === 'string' && DEC.test(v);
const badResponse = (): never => { throw new ApiFault(200, 'invalid_response', '', 'response does not match the request'); };

/** Accepts an incident only for exactly the requested organization, project and ID. */
export function parseIncident(raw: unknown, want: { org: Id; project: Id; id: Id }): IncidentView {
 if (!isRecord(raw) || raw.incident_id !== want.id || raw.org !== want.org || raw.project_id !== want.project) return badResponse();
 if (!decLike(raw.version) || !decLike(raw.impact_revision) || !decLike(raw.last_activity) || (raw.status !== 'open' && raw.status !== 'resolved')) return badResponse();
 if (!SEVERITIES.includes(raw.severity as string) || typeof raw.source_firing !== 'boolean' || typeof raw.observed_impacts !== 'number' || !Array.isArray(raw.links)) return badResponse();
 const c = raw.condition;
 if (!isRecord(c) || !idLike(c.id) || !CONDITION_STATES.includes(c.state as string) || !FRESHNESS.includes(c.freshness as string) || !decLike(c.observed_at)) return badResponse();
 if (c.state === 'firing' !== raw.source_firing) return badResponse();
 const n = raw.notification;
 if (!isRecord(n) || typeof n.reminders_paused !== 'boolean' || typeof n.worse_impact_eligible !== 'boolean' || !isRecord(n.delivery) || !VIEW_STATES.includes(n.delivery.state as ViewState)) return badResponse();
 if (raw.owner !== undefined && !idLike(raw.owner)) return badResponse();
 if (raw.timeline !== undefined) {
  if (!Array.isArray(raw.timeline) || raw.timeline.length !== Number(raw.version)) return badResponse();
  for (const e of raw.timeline) if (!isRecord(e) || !decLike(e.version) || !decLike(e.at) || typeof e.type !== 'string' || !idLike(e.actor) || (e.origin !== 'human' && e.origin !== 'system')) return badResponse();
 }
 for (const w of [raw.snooze, raw.maintenance]) if (w !== undefined && (!isRecord(w) || !decLike(w.from) || !decLike(w.until) || typeof w.active !== 'boolean' || typeof w.reason !== 'string' || !idLike(w.actor))) return badResponse();
 if (raw.ack !== undefined && (!isRecord(raw.ack) || !idLike(raw.ack.actor) || !decLike(raw.ack.at) || typeof raw.ack.current !== 'boolean')) return badResponse();
 return raw as unknown as IncidentView;
}

/** Accepts a response only for the action that was sent. A committed answer must carry the committed incident at the committed revision. */
export function parseAction(raw: unknown, req: ActionRequest): ActionResponse {
 if (!isRecord(raw) || raw.entity_kind !== req.entity_kind || raw.kind !== req.kind || raw.target_id !== req.target_id) return badResponse();
 if (raw.state === 'not_available') return typeof raw.reason === 'string' && raw.incident === undefined && raw.revision === undefined ? raw as unknown as ActionResponse : badResponse();
 if (raw.state !== 'committed' || !decLike(raw.revision)) return badResponse();
 const incident = parseIncident(raw.incident, { org: req.org, project: req.project_id, id: req.target_id });
 if (incident.version !== raw.revision || incident.timeline === undefined) return badResponse();
 return { ...(raw as unknown as ActionResponse), incident };
}

/** POST /api/v1/actions. A 409 with the incident-version detail is a VersionConflict carrying the current revision; a 501 is the explicit not_available answer; a transport failure is OutcomeUnknown (the same command ID may be resent: the server returns the original result). */
export async function act(req: ActionRequest, signal: AbortSignal): Promise<ActionResponse> {
 let response: Response;
 try {
  response = await fetch('/api/v1/actions', {
   method: 'POST', credentials: 'same-origin', cache: 'no-store', signal,
   headers: { Accept: 'application/json', 'Content-Type': 'application/json', ...(csrf ? { 'X-CSRF-Token': csrf } : {}) },
   body: JSON.stringify(req),
  });
 } catch (error) {
  if (isAbort(error)) throw error;
  throw new OutcomeUnknown();
 }
 if (response.status === 409) {
  const copy = response.clone();
  const body: unknown = await copy.json().catch(() => null);
  if (isRecord(body) && body.code === 'conflict' && body.detail === 'incident_version_conflict' && decLike(body.current_version)) {
   throw new VersionConflict(body.current_version, /^[0-9a-f]{32}$/.test(String(body.request_id ?? '')) ? String(body.request_id) : '');
  }
 }
 if (!response.ok && response.status !== 501) throw await apiFault(response);
 return parseAction(await response.json() as unknown, req);
}

/** POST /api/v1/incidents/get. */
export async function getIncident(org: Id, project: Id, id: Id, signal: AbortSignal): Promise<IncidentView> {
 const response = await fetch('/api/v1/incidents/get', {
  method: 'POST', credentials: 'same-origin', cache: 'no-store', signal,
  headers: { Accept: 'application/json', 'Content-Type': 'application/json', ...(csrf ? { 'X-CSRF-Token': csrf } : {}) },
  body: JSON.stringify({ org, project_id: project, target_id: id }),
 });
 if (!response.ok) throw await apiFault(response);
 return parseIncident(await response.json() as unknown, { org, project, id });
}

/** Accepts a queue only for the requested organization and projects, with every entry inside them. */
export function parseQueue(raw: unknown, org: Id, projects: Id[]): QueueView {
 if (!isRecord(raw) || raw.org !== org || !VIEW_STATES.includes(raw.state as ViewState) || !Array.isArray(raw.entries) || !Array.isArray(raw.sections) || typeof raw.truncated !== 'boolean') return badResponse();
 if (!Array.isArray(raw.projects) || raw.projects.length !== projects.length || !raw.projects.every((p, i): boolean => p === projects[i])) return badResponse();
 for (const s of raw.sections) if (!isRecord(s) || typeof s.name !== 'string' || !VIEW_STATES.includes(s.state as ViewState)) return badResponse();
 const entries = raw.entries.map((e: unknown): IncidentView => {
  const id = isRecord(e) ? e.incident_id : undefined;
  const project = isRecord(e) ? e.project_id : undefined;
  if (!idLike(id) || !idLike(project) || !projects.includes(project)) return badResponse();
  return parseIncident(e, { org, project, id });
 });
 return { ...(raw as unknown as QueueView), entries };
}

/** POST /api/v1/queue. */
export async function getQueue(org: Id, projects: Id[], limit: number, signal: AbortSignal): Promise<QueueView> {
 const response = await fetch('/api/v1/queue', {
  method: 'POST', credentials: 'same-origin', cache: 'no-store', signal,
  headers: { Accept: 'application/json', 'Content-Type': 'application/json', ...(csrf ? { 'X-CSRF-Token': csrf } : {}) },
  body: JSON.stringify({ org, projects, limit }),
 });
 if (!response.ok) throw await apiFault(response);
 return parseQueue(await response.json() as unknown, org, projects);
}

const PHASES = ['fencing', 'complete', 'held', 'failed'];
export function parseOperation(raw: unknown, id: Id): LifecycleOperation {
 if (!isRecord(raw) || raw.id !== id || !VIEW_STATES.includes(raw.state as ViewState)) return badResponse();
 if (raw.state === 'ready' && (!PHASES.includes(raw.phase as string) || !decLike(raw.physical_deadline) || !decLike(raw.backup_deadline) || typeof raw.applied_barriers !== 'number' || typeof raw.pending_groups !== 'number')) return badResponse();
 return raw as unknown as LifecycleOperation;
}

/** GET /api/v1/lifecycle/operations/{id}: scoped polling of one deletion/restriction operation. */
export async function getOperation(org: Id, id: Id, signal: AbortSignal): Promise<LifecycleOperation> {
 const response = await fetch(`/api/v1/lifecycle/operations/${id}?${new URLSearchParams({ org })}`, { credentials: 'same-origin', cache: 'no-store', signal, headers: { Accept: 'application/json' } });
 if (!response.ok) throw await apiFault(response);
 return parseOperation(await response.json() as unknown, id);
}

// ---- C06 queries, live tickets and the fetch-based live stream (internal/httpapi/{query,discovery,live}.go) ----
const I64 = /^(0|-?[1-9][0-9]{0,18})$/;
const BITS = /^[0-9a-f]{16}$/;
const LANGUAGE_CODE = /^[A-Za-z0-9_.:-]{1,80}$/;
const REASON = /^[a-z_]{1,40}$/;
const U64_MAX = 18446744073709551615n;
const I64_MIN = -9223372036854775808n;
const I64_MAX = 9223372036854775807n;
/** Canonical decimal uint64 string. */
const u64Like = (v: unknown): v is string => typeof v === 'string' && DEC.test(v) && (v.length < 20 || BigInt(v) <= U64_MAX);
/** Canonical decimal int64 string (nanosecond timestamps and signed buckets): never a JSON number. */
const i64Like = (v: unknown): v is string => typeof v === 'string' && I64.test(v) && (v.length < 19 || (BigInt(v) >= I64_MIN && BigInt(v) <= I64_MAX));
const bitsLike = (v: unknown): v is string => typeof v === 'string' && BITS.test(v);
const textLike = (v: unknown, max: number): v is string => typeof v === 'string' && v.length <= max;
/** The Go server writes a nil slice as null: it is an empty list, anything else that is not an array is a fault. */
const listOf = (v: unknown): unknown[] => v === null || v === undefined ? [] : Array.isArray(v) ? v : badResponse();

function labelsOf(v: unknown): { name: string; value: string }[] {
 const list = listOf(v);
 for (const l of list) if (!isRecord(l) || typeof l.name !== 'string' || typeof l.value !== 'string') return badResponse();
 return list as { name: string; value: string }[];
}
function cursorsOf(v: unknown): { group: Id; index: string }[] {
 const list = listOf(v);
 for (const c of list) if (!isRecord(c) || !idLike(c.group) || !u64Like(c.index)) return badResponse();
 return list as { group: Id; index: string }[];
}
function rangeOf(v: unknown): { start_byte: number; end_byte: number; start_rune: number; end_rune: number } | null {
 if (!isRecord(v)) return null;
 const { start_byte: sb, end_byte: eb, start_rune: sr, end_rune: er } = v;
 if (![sb, eb, sr, er].every((n) => typeof n === 'number' && Number.isInteger(n) && n >= 0) || (sb as number) > (eb as number) || (sr as number) > (er as number)) return null;
 return { start_byte: sb as number, end_byte: eb as number, start_rune: sr as number, end_rune: er as number };
}
/** A source range, when present, must be well formed; a malformed range is a fault in the response, not a guess. */
function optionalRange(v: unknown): { start_byte: number; end_byte: number; start_rune: number; end_rune: number } | undefined {
 if (v === undefined || v === null) return undefined;
 return rangeOf(v) ?? badResponse();
}

function spanTotal(spans: unknown): number {
 let total = 0;
 for (const s of listOf(spans)) {
  if (!isRecord(s) || typeof s.offset !== 'number' || !Number.isInteger(s.offset) || typeof s.length !== 'number' || !Number.isInteger(s.length) || s.length < 0 || s.length > 4294967295) return badResponse();
  total += s.length;
 }
 return total;
}
function bucketsOf(v: unknown, expect: number, kind: (x: unknown) => boolean): void {
 const list = listOf(v);
 if (list.length !== expect || !list.every(kind)) badResponse();
}
/** Exactly one variant; every bucket list must be accounted for by its spans, so a histogram can never be drawn with a missing bucket. */
function histogramOf(v: unknown): void {
 if (!isRecord(v) || (v.integer === undefined) === (v.float === undefined)) return badResponse();
 const h = v.integer !== undefined ? v.integer : v.float;
 if (!isRecord(h) || !textLike(h.flavor, 32) || typeof h.schema !== 'number' || !Number.isInteger(h.schema) || !textLike(h.reset_hint, 32) || !bitsLike(h.zero_threshold) || !bitsLike(h.sum)) return badResponse();
 const positive = spanTotal(h.positive_spans), negative = spanTotal(h.negative_spans);
 if (v.integer !== undefined) {
  if (!u64Like(h.count) || !u64Like(h.zero_count)) return badResponse();
  bucketsOf(h.positive_buckets, positive, i64Like);
  bucketsOf(h.negative_buckets, negative, i64Like);
  if (h.positive_counts !== undefined) bucketsOf(h.positive_counts, positive, u64Like);
  if (h.negative_counts !== undefined) bucketsOf(h.negative_counts, negative, u64Like);
 } else {
  if (!bitsLike(h.count) || !bitsLike(h.zero_count)) return badResponse();
  bucketsOf(h.positive_buckets, positive, bitsLike);
  bucketsOf(h.negative_buckets, negative, bitsLike);
 }
 if (h.custom_bounds !== undefined && !listOf(h.custom_bounds).every(bitsLike)) return badResponse();
 for (const key of ['positive_spans', 'negative_spans', 'positive_buckets', 'negative_buckets']) if (h[key] === null) h[key] = [];
}
function sampleOf(v: unknown): void {
 if (!isRecord(v) || !i64Like(v.time) || ((v.float === undefined) === (v.histogram === undefined))) return badResponse();
 if (v.float !== undefined && !bitsLike(v.float)) return badResponse();
 if (v.histogram !== undefined) histogramOf(v.histogram);
 if (v.start_timestamp !== undefined && !i64Like(v.start_timestamp)) return badResponse();
}
function entryOf(v: unknown): void {
 if (!isRecord(v) || !u64Like(v.index) || !i64Like(v.time) || !idLike(v.id) || !u64Like(v.multiplicity) || typeof v.line !== 'string') return badResponse();
 if (v.source !== undefined && !idLike(v.source)) return badResponse();
 v.stream_labels = labelsOf(v.stream_labels);
 v.structured_metadata = labelsOf(v.structured_metadata);
}
function valueOf(v: unknown, language: string): void {
 if (!isRecord(v) || typeof v.type !== 'string') return badResponse();
 const keys = ['scalar', 'string', 'vector', 'matrix', 'streams'].filter((k) => v[k] !== undefined);
 if (keys.length !== 1 || keys[0] !== v.type) return badResponse();
 switch (v.type) {
  case 'scalar': return sampleOf(v.scalar);
  case 'string': if (typeof v.string !== 'string') badResponse(); return;
  case 'vector':
   v.vector = listOf(v.vector);
   for (const e of v.vector as unknown[]) { if (!isRecord(e)) return badResponse(); e.labels = labelsOf(e.labels); sampleOf(e.sample); }
   return;
  case 'matrix':
   v.matrix = listOf(v.matrix);
   for (const s of v.matrix as unknown[]) { if (!isRecord(s)) return badResponse(); s.labels = labelsOf(s.labels); s.samples = listOf(s.samples); for (const x of s.samples as unknown[]) sampleOf(x); }
   return;
  case 'streams':
   if (language !== 'logql') return badResponse();
   v.streams = listOf(v.streams);
   for (const s of v.streams as unknown[]) { if (!isRecord(s)) return badResponse(); s.labels = labelsOf(s.labels); s.entries = listOf(s.entries); for (const e of s.entries as unknown[]) entryOf(e); }
   return;
  default: return badResponse();
 }
}
function diagnosticsOf(v: unknown): void {
 for (const d of listOf(v)) {
  if (!isRecord(d) || (d.severity !== 'info' && d.severity !== 'warning') || !textLike(d.code, 200) || !textLike(d.safe_message, 1024)) return badResponse();
  optionalRange(d.source_range);
 }
}
function failureOf(v: unknown): void {
 if (!isRecord(v) || !textLike(v.code, 200) || !textLike(v.safe_message, 1024) || (v.category !== undefined && !textLike(v.category, 200))) return badResponse();
 optionalRange(v.source_range);
}
const STAT_NUMBERS = ['scans_started', 'pages_read', 'rows_read', 'bytes_read', 'series_returned', 'samples_returned', 'logs_returned', 'peak_memory_bytes'];

/** Accepts a result only for exactly the projects that were requested, once each: a result for another project, a missing
 * one or a repeated one is a fault and is never rendered or merged. Every number is checked as the exact string the
 * server writes. A JSON null where Go wrote a nil slice is normalised to an empty list. */
export function parseQueryResult(raw: unknown, req: QueryRequest): QueryResult {
 if (!isRecord(raw) || !Array.isArray(raw.projects) || raw.projects.length !== req.projects.length) return badResponse();
 const seen = new Set<string>();
 for (const p of raw.projects as unknown[]) {
  if (!isRecord(p) || !idLike(p.project_id) || !req.projects.includes(p.project_id) || seen.has(p.project_id)) return badResponse();
  seen.add(p.project_id);
  if (!COMPLETENESS.includes(p.completeness as Completeness)) return badResponse();
  diagnosticsOf(p.diagnostics);
  p.diagnostics = listOf(p.diagnostics);
  p.watermarks = cursorsOf(p.watermarks);
  const s = p.stats;
  if (!isRecord(s) || !STAT_NUMBERS.every((k) => u64Like(s[k])) || !i64Like(s.elapsed_ns) || typeof s.cached !== 'boolean' || typeof s.limit_reached !== 'boolean') return badResponse();
  if (p.failure !== undefined) failureOf(p.failure);
  if (p.value === null || p.value === undefined) {
   if (p.failure === undefined || p.completeness !== 'partial') return badResponse();
   p.value = null;
  } else {
   if (p.failure !== undefined) return badResponse();
   valueOf(p.value, req.language);
  }
 }
 return raw as unknown as QueryResult;
}

/** A typed query failure. A language error keeps its category, code and source range; everything else keeps only the C01 code,
 * request id and an approved plain detail. No body text is ever kept as is. */
export async function queryFaultOf(response: Response): Promise<QueryFault> {
 let body: unknown = null;
 try { body = await response.json(); } catch { /* not JSON: keep the generic fault */ }
 const record = isRecord(body) ? body : {};
 const code = typeof record.code === 'string' && /^[a-z_]{1,40}$/.test(record.code) ? record.code : 'unavailable';
 const detail = typeof record.detail === 'string' && SAFE_DETAIL.test(record.detail) ? record.detail : '';
 const header = response.headers.get('X-Request-ID') ?? '';
 const requestId = idLike(header) ? header : idLike(record.request_id) ? record.request_id : '';
 if (code === 'language' && typeof record.language_code === 'string' && typeof record.category === 'string') {
  const safe = (v: string): string => v === '' || LANGUAGE_CODE.test(v) ? v : 'unknown';
  const text = typeof record.detail === 'string' ? record.detail.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 240) : '';
  return new QueryFault(response.status, code, requestId, '', { languageCode: safe(record.language_code), category: safe(record.category), range: rangeOf(record.source_range), detail: text });
 }
 return new QueryFault(response.status, code, requestId, detail);
}

/** Maps a typed query failure to its load state. A denied project, a foreign scope and a missing one are one state. A budget
 * (HTTP 429 code quota), a deadline, a cancellation and stale data keep their own code: they are errors, never a rate-limit
 * notice and never a shortened answer. */
export function stateOfQueryFault(error: unknown): LoadState<never> {
 if (!(error instanceof ApiFault)) return { kind: 'error', fault: new ApiFault(0, 'network', '', '') };
 switch (error.status) {
  case 401: case 403: case 404: return { kind: 'unauthorized', status: error.status === 401 ? 401 : 404, requestId: error.requestId };
  case 501: return { kind: 'unsupported', reason: error.code };
  default: return { kind: 'error', fault: error };
 }
}

function jsonPost(path: string, body: unknown, signal: AbortSignal): Promise<Response> {
 return fetch(path, {
  method: 'POST', credentials: 'same-origin', cache: 'no-store', signal,
  headers: { Accept: 'application/json', 'Content-Type': 'application/json', ...(csrf ? { 'X-CSRF-Token': csrf } : {}) },
  body: JSON.stringify(body),
 });
}

/** POST /api/v1/query. The full query text stays in this POST body. A result for any other project set is a fault. */
export async function query(req: QueryRequest, signal: AbortSignal): Promise<QueryResult> {
 const response = await jsonPost('/api/v1/query', req, signal);
 if (!response.ok) throw await queryFaultOf(response);
 return parseQueryResult(await response.json() as unknown, req);
}

/** POST /api/v1/live-tickets: the stored live request in the body; the ticket is a one-use, 60-second, session-bound identifier. */
export async function createLiveTicket(req: LiveTicketRequest, signal: AbortSignal): Promise<LiveTicket> {
 const response = await jsonPost('/api/v1/live-tickets', req, signal);
 if (!response.ok) throw await queryFaultOf(response);
 const body: unknown = await response.json();
 if (!isRecord(body) || !idLike(body.ticket) || !i64Like(body.expires_at)) return badResponse();
 return { ticket: body.ticket, expires_at: body.expires_at };
}

function sequenceOf(v: unknown): string | undefined {
 if (v === undefined) return undefined;
 return u64Like(v) && v !== '0' ? v : badResponse();
}
/** One SSE frame is one typed event. The SSE event name, the SSE id and the payload must agree; the id exists exactly when the
 * payload carries a sequence, and only record and gap events carry one, so Last-Event-ID can name exactly the last event handled. */
export function parseLiveEvent(frame: SseFrame): LiveEvent {
 let raw: unknown;
 try { raw = JSON.parse(frame.data); } catch { return badResponse(); }
 if (!isRecord(raw) || typeof raw.type !== 'string' || !LIVE_EVENT_TYPES.includes(raw.type as LiveEventType) || frame.event !== raw.type || !idLike(raw.stream_id)) return badResponse();
 const sequence = sequenceOf(raw.sequence);
 if (frame.id !== (sequence ?? null)) return badResponse();
 const type = raw.type as LiveEventType;
 if (sequence !== undefined && type !== 'record' && type !== 'gap') return badResponse();
 if (raw.watermarks !== undefined) raw.watermarks = cursorsOf(raw.watermarks);
 if (raw.cursors !== undefined) raw.cursors = cursorsOf(raw.cursors);
 switch (type) {
  case 'record':
   if (sequence === undefined || !idLike(raw.project)) return badResponse();
   entryOf(raw.entry);
   if (raw.labels !== undefined) raw.labels = labelsOf(raw.labels);
   break;
  case 'gap': {
   const g = raw.gap;
   if (!isRecord(g) || !textLike(g.reason, 64) || !u64Like(g.from_sequence) || !u64Like(g.to_sequence) || BigInt(g.from_sequence) > BigInt(g.to_sequence)) return badResponse();
   if (g.after !== undefined) g.after = cursorsOf(g.after);
   if (g.through !== undefined) g.through = cursorsOf(g.through);
   break;
  }
  case 'revoke': case 'error':
   if (raw.reason !== undefined && (typeof raw.reason !== 'string' || !REASON.test(raw.reason))) return badResponse();
   if (raw.failure !== undefined) failureOf(raw.failure);
   break;
  default: break;
 }
 return raw as unknown as LiveEvent;
}

async function* liveEvents(body: ReadableStream<Uint8Array>): AsyncGenerator<LiveEvent> {
 try {
  for await (const frame of readSse(body)) yield parseLiveEvent(frame);
 } catch (error) {
  if (error instanceof SseProtocolError) throw new ApiFault(200, 'invalid_response', '', error.code);
  throw error;
 }
}

/** GET /api/v1/live?ticket=<id> as a fetch stream. The ticket is the only URL parameter; the cookie session needs the CSRF
 * header, which a native EventSource cannot send. `lastEventId` is the sequence of the last event the caller handled; there is
 * no automatic reconnection: ending the stream ends the iteration and reconnecting is the caller's explicit act. */
export async function openLive(ticket: Id, lastEventId: string | null, signal: AbortSignal): Promise<AsyncIterable<LiveEvent>> {
 if (!idLike(ticket) || (lastEventId !== null && !decLike(lastEventId))) return badResponse();
 const response = await fetch(`/api/v1/live?ticket=${ticket}`, {
  method: 'GET', credentials: 'same-origin', cache: 'no-store', signal,
  headers: { Accept: 'text/event-stream', ...(csrf ? { 'X-CSRF-Token': csrf } : {}), ...(lastEventId !== null ? { 'Last-Event-ID': lastEventId } : {}) },
 });
 if (!response.ok) throw await queryFaultOf(response);
 if (!(response.headers.get('Content-Type') ?? '').startsWith('text/event-stream') || response.body === null) throw new ApiFault(response.status, 'invalid_response', '', 'not an event stream');
 return liveEvents(response.body);
}

// ---- discovery, exemplars and format (POST /api/v1/{discover,exemplars,query/format}) ----
function freshnessOf(v: unknown): void {
 if (!isRecord(v) || !COMPLETENESS.includes(v.completeness as Completeness) || typeof v.cached !== 'boolean') return badResponse();
 v.watermarks = cursorsOf(v.watermarks);
}
/** A page never exceeds the requested limit, and its cursor exists exactly when more pages do. */
function pagedOf(raw: unknown, key: 'items' | 'exemplars', limit: number): Record<string, unknown> {
 if (!isRecord(raw) || typeof raw.more !== 'boolean') return badResponse();
 raw[key] = listOf(raw[key]);
 if ((raw[key] as unknown[]).length > limit) return badResponse();
 if (raw.more ? typeof raw.next_cursor !== 'string' || raw.next_cursor.length === 0 || raw.next_cursor.length > 16384 : raw.next_cursor !== undefined) return badResponse();
 freshnessOf(raw.freshness);
 return raw;
}
export function parseDiscovery(raw: unknown, req: DiscoveryRequest): DiscoveryResult {
 const out = pagedOf(raw, 'items', req.limit);
 if (!(out.items as unknown[]).every((i) => textLike(i, 4096))) return badResponse();
 return out as unknown as DiscoveryResult;
}
export function parseExemplars(raw: unknown, req: ExemplarRequest): ExemplarResult {
 const out = pagedOf(raw, 'exemplars', req.limit);
 for (const e of out.exemplars as unknown[]) {
  if (!isRecord(e) || !idLike(e.project_id) || !req.projects.includes(e.project_id) || !idLike(e.trace_id) || !idLike(e.record_id)) return badResponse();
  if (e.span_id !== undefined && (typeof e.span_id !== 'string' || !/^[0-9a-f]{16}$/.test(e.span_id))) return badResponse();
  e.labels = labelsOf(e.labels);
  sampleOf(e.sample);
 }
 return out as unknown as ExemplarResult;
}
export function parseFormat(raw: unknown): FormatResult {
 if (!isRecord(raw) || typeof raw.formatted !== 'string') return badResponse();
 diagnosticsOf(raw.diagnostics);
 raw.diagnostics = listOf(raw.diagnostics);
 return raw as unknown as FormatResult;
}
/** POST /api/v1/discover: one authenticated page of names; the cursor is opaque and bound to these exact parameters. */
export async function discover(req: DiscoveryRequest, signal: AbortSignal): Promise<DiscoveryResult> {
 const response = await jsonPost('/api/v1/discover', req, signal);
 if (!response.ok) throw await queryFaultOf(response);
 return parseDiscovery(await response.json() as unknown, req);
}
/** POST /api/v1/exemplars: exemplars of the series the expression selects. Their trace links are never built from these ids: see the link check in the Explore page. */
export async function exemplars(req: ExemplarRequest, signal: AbortSignal): Promise<ExemplarResult> {
 const response = await jsonPost('/api/v1/exemplars', req, signal);
 if (!response.ok) throw await queryFaultOf(response);
 return parseExemplars(await response.json() as unknown, req);
}
/** POST /api/v1/query/format: the formatted text parses to the same typed tree under the named profile and feature set. */
export async function formatExpression(req: FormatRequest, signal: AbortSignal): Promise<FormatResult> {
 const response = await jsonPost('/api/v1/query/format', req, signal);
 if (!response.ok) throw await queryFaultOf(response);
 return parseFormat(await response.json() as unknown);
}

// ---- async raw-record export (POST /api/v1/exports: create, status, download) ----
const EXPORT_REASON = /^[a-z_]{1,40}$/;
/** An operation is accepted only as a consistent statement: complete means at least one chunk and no reason, failed carries
 * its reason, running carries neither. When `id` is given the answer must be that very operation. */
export function parseExportOperation(raw: unknown, id?: Id): ExportOperation {
 if (!isRecord(raw) || !idLike(raw.id) || (id !== undefined && raw.id !== id) || raw.kind !== 'export' || !EXPORT_PHASES.includes(raw.phase as ExportPhase)) return badResponse();
 if (!u64Like(raw.generation) || !u64Like(raw.progress) || !u64Like(raw.chunks)) return badResponse();
 if (raw.safe_reason !== undefined && (typeof raw.safe_reason !== 'string' || !EXPORT_REASON.test(raw.safe_reason))) return badResponse();
 if ((raw.phase === 'failed') !== (raw.safe_reason !== undefined)) return badResponse();
 if (raw.phase === 'complete' && raw.chunks === '0') return badResponse();
 return raw as unknown as ExportOperation;
}
/** The 202 answer of a create: a running operation and its bounded one-use ticket. */
export function parseExportGrant(raw: unknown): ExportGrant {
 if (!isRecord(raw) || typeof raw.ticket !== 'string' || raw.ticket.length === 0 || raw.ticket.length > 4096) return badResponse();
 const operation = parseExportOperation(raw.operation);
 if (operation.phase !== 'running') return badResponse();
 return { operation, ticket: raw.ticket };
}
/** Create an export of one project's raw records of one signal in the window. Authorized now and again on completion and on every downloaded chunk. */
export async function createExport(org: Id, project: Id, signal: ExportSignal, window: { start: string; end: string }, abort: AbortSignal): Promise<ExportGrant> {
 const response = await jsonPost('/api/v1/exports', { operation: 'create', org, project, signal, start_ns: window.start, end_ns: window.end }, abort);
 if (!response.ok) throw await apiFault(response);
 return parseExportGrant(await response.json() as unknown);
}
export async function exportStatus(org: Id, project: Id, id: Id, abort: AbortSignal): Promise<ExportOperation> {
 const response = await jsonPost('/api/v1/exports', { operation: 'status', org, project, id }, abort);
 if (!response.ok) throw await apiFault(response);
 return parseExportOperation(await response.json() as unknown, id);
}
/** The download re-authorizes the scope, the ticket, the policy epoch and the delete generation for every chunk; a revoked or deleted export yields a fault and no bytes. */
export async function downloadExport(org: Id, project: Id, id: Id, ticket: string, abort: AbortSignal): Promise<Blob> {
 const response = await jsonPost('/api/v1/exports', { operation: 'download', org, project, id, ticket }, abort);
 if (!response.ok) throw await apiFault(response);
 if (!(response.headers.get('Content-Type') ?? '').startsWith('application/x-ndjson')) throw new ApiFault(response.status, 'invalid_response', '', 'not an export');
 return response.blob();
}

// ---- Error investigation evidence (POST /api/v1/evidence/{frames,release,issue}) ----
const HASH = /^[0-9a-f]{64}$/;
const hashLike = (v: unknown): v is string => typeof v === 'string' && HASH.test(v);
const stateLike = (v: unknown): v is ViewState => VIEW_STATES.includes(v as ViewState);
const idList = (v: unknown): v is Id[] => Array.isArray(v) && v.length <= 4096 && v.every(idLike);
const sectionsLike = (v: unknown): boolean => Array.isArray(v) && v.length <= 32 && v.every((s) => isRecord(s) && typeof s.name === 'string' && stateLike(s.state));

function isSafeFrame(f: unknown): f is SafeFrame {
 return isRecord(f) && textLike(f.module_id, 600) && textLike(f.function, 600) && textLike(f.artifact_id, 600) && typeof f.line === 'number' && Number.isInteger(f.line) && f.line >= 0
  && (f.column === null || (typeof f.column === 'number' && Number.isInteger(f.column) && f.column >= 0)) && typeof f.in_app === 'boolean' && typeof f.async === 'boolean';
}

/** Accepts frames only for exactly the requested scope and the frames that were sent, in order, so a view of another scope or a
 * silently shorter, longer or reordered list is a fault and never rendered. A mapped position needs a map hash; source text only exists when the source is present. */
export function parseFrames(raw: unknown, req: FramesRequest): FramesView {
 if (!isRecord(raw) || raw.org !== req.org || raw.project !== req.project || raw.build !== req.build || !stateLike(raw.state) || !Array.isArray(raw.frames) || raw.frames.length !== req.frames.length || !sectionsLike(raw.sections)) return badResponse();
 raw.frames.forEach((entry: unknown, i: number) => {
  if (!isRecord(entry) || !isSafeFrame(entry.original) || typeof entry.reason !== 'string' || !/^[a-z_]{1,48}$/.test(entry.reason) || !isRecord(entry.source)) return badResponse();
  const sent = req.frames[i]!;
  const o = entry.original;
  if (o.artifact_id !== sent.artifact_id || o.line !== sent.line || o.column !== sent.column || o.function !== sent.function || o.module_id !== sent.module_id) return badResponse();
  const s = entry.source;
  if (!['present', 'withheld', 'absent'].includes(s.state as string) || (s.state === 'present') !== (typeof s.context === 'string') || (s.context !== undefined && (typeof s.context !== 'string' || s.context.length > 1 << 20))) return badResponse();
  if (s.state === 'present' && !req.include_sources) return badResponse();
  const mapped = entry.reason === 'resolved';
  const r = entry.resolved;
  if (mapped !== (r !== undefined) || mapped !== (entry.map_sha256 !== undefined)) return badResponse();
  if (r !== undefined && (!isRecord(r) || !textLike(r.source, 4096) || typeof r.line !== 'number' || typeof r.column !== 'number' || (r.function !== undefined && !textLike(r.function, 600)) || !hashLike(entry.map_sha256))) return badResponse();
 });
 return raw as unknown as FramesView;
}

/** Symbolicate sanitized frames of one build under the caller's own scope. The browser never names a URL and never fetches a map: the server resolves an exact ArtifactID through the owned service. */
export async function getFrames(req: FramesRequest, signal: AbortSignal): Promise<FramesView> {
 const response = await jsonPost('/api/v1/evidence/frames', req, signal);
 if (!response.ok) throw await apiFault(response);
 return parseFrames(await response.json() as unknown, req);
}

export function parseReleaseEvidence(raw: unknown, want: { org: Id; project: Id; release: Id; compare: Id[] }): ReleaseView {
 if (!isRecord(raw) || raw.org !== want.org || raw.project !== want.project || !stateLike(raw.state) || !Array.isArray(raw.parents) || !idList(raw.children) || !Array.isArray(raw.comparisons) || !sectionsLike(raw.sections)) return badResponse();
 if (!raw.parents.every((p: unknown) => isRecord(p) && idLike(p.id) && typeof p.known === 'boolean')) return badResponse();
 if (raw.comparisons.length !== (raw.release === undefined ? 0 : want.compare.length)) return badResponse();
 raw.comparisons.forEach((c: unknown, i: number) => { if (!isRecord(c) || c.release !== want.compare[i] || !ANCESTRY_ORDERS.includes(c.order as AncestryOrder)) return badResponse(); });
 const r = raw.release;
 if (raw.state === 'not_available' ? r !== undefined : !isRecord(r)) return badResponse();
 if (isRecord(r)) {
  if (r.id !== want.release || !idLike(r.build_id) || !textLike(r.label, 256) || !decLike(r.revision) || !decLike(r.build_time_ns) || !Array.isArray(r.debug_artifacts) || !Array.isArray(r.label_history)) return badResponse();
  if (!r.debug_artifacts.every((d: unknown) => isRecord(d) && idLike(d.artifact_id) && textLike(d.debug_id, 256) && hashLike(d.sha256)) || !r.label_history.every((h: unknown) => isRecord(h) && decLike(h.revision) && textLike(h.label, 256))) return badResponse();
 }
 return raw as unknown as ReleaseView;
}

/** Release identity, label history, declared parents and the partial-order relation to the releases named in `compare` (at most 16). */
export async function getReleaseEvidence(org: Id, project: Id, release: Id, compare: Id[], signal: AbortSignal): Promise<ReleaseView> {
 const response = await jsonPost('/api/v1/evidence/release', { org, project, release, ...(compare.length ? { compare } : {}) }, signal);
 if (!response.ok) throw await apiFault(response);
 return parseReleaseEvidence(await response.json() as unknown, { org, project, release, compare });
}

function occurrenceLike(o: unknown, late: boolean): boolean {
 return isRecord(o) && idLike(o.occurrence_id) && idLike(o.record_id) && typeof o.grouping_version === 'number' && hashLike(o.fingerprint) && decLike(o.event_time_ns) && decLike(o.arrival_time_ns)
  && (o.ancestry === 'known' || o.ancestry === 'unknown') && (o.ancestry === 'unknown' || idLike(o.release_id)) && typeof o.freshness === 'string' && o.late === late;
}
export function parseIssueEvidence(raw: unknown, want: { org: Id; project: Id; issue: Id }): IssueEvidenceView {
 if (!isRecord(raw) || raw.org !== want.org || raw.project !== want.project || raw.issue !== want.issue || !stateLike(raw.state) || !Array.isArray(raw.occurrences) || !Array.isArray(raw.late_history) || !sectionsLike(raw.sections)) return badResponse();
 if (!raw.occurrences.every((o: unknown) => occurrenceLike(o, false)) || !raw.late_history.every((o: unknown) => occurrenceLike(o, true))) return badResponse();
 const g = raw.grouping;
 if (raw.state === 'not_available' ? g !== undefined : !isRecord(g)) return badResponse();
 if (isRecord(g) && (typeof g.grouping_version !== 'number' || !hashLike(g.fingerprint) || typeof g.workflow !== 'string' || !decLike(g.revision) || !idList(g.resolution_frontier) || !idList(g.observed_releases) || !idList(g.fixed_descendants) || !idList(g.migration_links))) return badResponse();
 return raw as unknown as IssueEvidenceView;
}

/** Grouping version and hash, stored occurrences and the separately listed late history of one persisted issue. */
export async function getIssueEvidence(org: Id, project: Id, issue: Id, signal: AbortSignal): Promise<IssueEvidenceView> {
 const response = await jsonPost('/api/v1/evidence/issue', { org, project, issue }, signal);
 if (!response.ok) throw await apiFault(response);
 return parseIssueEvidence(await response.json() as unknown, { org, project, issue });
}

/** The spans of one trace in the window, analyzed by the server into a critical path with duration bounds and limits. The scope is the caller's own; the body names only the organization, project, trace and window. */
export async function getTrace(org: Id, project: Id, trace: Id, window: { start: string; end: string }, signal: AbortSignal): Promise<TraceView> {
 const response = await jsonPost('/api/v1/traces/view', { org, project, trace, window: { start: window.start, end: window.end } }, signal);
 if (!response.ok) throw await apiFault(response);
 return parseTraceView(await response.json() as unknown, { org, project, trace });
}

/** One profile under the caller's own scope: its separate profiles.read grant is checked by the server; the body names only the organization, project, profile and window. */
export async function getProfile(org: Id, project: Id, profile: Id, window: { start: string; end: string }, signal: AbortSignal): Promise<ProfileResponse> {
 const response = await jsonPost('/api/v1/profiles/view', { org, project, profile, window: { start: window.start, end: window.end } }, signal);
 if (!response.ok) throw await apiFault(response);
 return parseProfileResponse(await response.json() as unknown, { org, project, profile });
}

/** POST /api/v1/replays/stream: the lines of one replay as the server releases them (NDJSON). A refusal before the first line is a typed fault; after it the stream itself says revoke, error, truncated or end. The generator ends at the server's terminal line; abort the signal to stop reading. */
export async function* streamReplay(org: Id, project: Id, replay: Id, signal: AbortSignal): AsyncGenerator<ReplayLine> {
 const want = { org, project, replay };
 const response = await jsonPost('/api/v1/replays/stream', { org, project, replay }, signal);
 if (!response.ok) throw await apiFault(response);
 if (!(response.headers.get('Content-Type') ?? '').startsWith('application/x-ndjson') || response.body === null) throw new ApiFault(200, 'invalid_response', '', 'response does not match the request');
 const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
 const split = lineSplitter();
 try {
  for (;;) {
   const { done, value } = await reader.read();
   if (done) return;
   for (const text of split(value)) {
    const line = parseReplayLine(text, want);
    yield line;
    if (line.type === 'end' || line.type === 'revoke' || line.type === 'error' || line.type === 'truncated' || line.type === 'not_available') return;
   }
  }
 } finally {
  await reader.cancel().catch(() => undefined);
 }
}

/** Revalidates a replay this page holds without reading any chunk: resolves while the account may still read it and throws the typed fault (404 once access ended or the replay was deleted). */
export async function probeReplay(org: Id, project: Id, replay: Id, signal: AbortSignal): Promise<void> {
 const response = await jsonPost('/api/v1/replays/stream', { org, project, replay, probe: true }, signal);
 if (!response.ok) throw await apiFault(response);
 await response.text();
}

// ---- Job run and attempt investigation (POST /api/v1/jobs/list, /api/v1/jobs/view; internal/httpapi/jobs_view.go) ----
// A response is accepted only for exactly the request that was sent and only when its parts agree with each other. A health that cannot
// stand on its evidence (missed without an external schedule observer, ready without complete evidence, a recovered run without a failed
// attempt, an attempt whose effective result is not its newest correction) is a fault and is never rendered. Nanosecond times, versions
// and ordinals stay canonical decimal strings: they are only compared as BigInt, never as a JavaScript number.
const JOBS_PERMISSION = 'telemetry.read';
const MAX_JOBS_PAGE = 50;
const MAX_JOB_RUNS = 100;
const DEFAULT_JOB_RUNS = 25;
const MAX_JOB_LOSS = 64;
const MAX_JOB_OVERLAPS = 8;
const MAX_JOB_COUNT = 200000;
const WIRE_CODE = /^[a-z0-9_]{1,64}$/;
const JOB_UNAVAILABLE_REASONS: readonly string[] = ['job_service_not_wired', 'job_store_not_readable'];
const TERMINAL_ATTEMPT_STATES: readonly JobAttemptState[] = ['succeeded', 'failed', 'cancelled'];

function need(ok: boolean): asserts ok { if (!ok) badResponse(); }
const rec = (v: unknown): Record<string, unknown> => isRecord(v) ? v : badResponse();
const bounded = (v: unknown, max: number): unknown[] => Array.isArray(v) && v.length <= max ? v : badResponse();
const wtext = (v: unknown, max: number): v is string => typeof v === 'string' && v.length >= 1 && v.length <= max;
const wcount = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= max;
const wu64 = u64Like;
const wi64 = i64Like;
const wnonneg = (v: unknown): v is string => wi64(v) && !v.startsWith('-');
const wenum = <T extends string>(set: readonly T[], v: unknown): v is T => typeof v === 'string' && (set as readonly string[]).includes(v);
const distinct = (items: readonly unknown[]): boolean => new Set(items).size === items.length;

function viewReason(v: Record<string, unknown>): string | undefined {
 if (v.reason === undefined) return undefined;
 need(typeof v.reason === 'string' && WIRE_CODE.test(v.reason));
 return v.reason;
}

function jobSections(v: unknown): JobViewSection[] {
 const sections = bounded(v, 32);
 for (const s of sections) {
  const o = rec(s);
  need(wtext(o.name, 64) && wenum(VIEW_STATES, o.state) && (o.reason === undefined || (typeof o.reason === 'string' && WIRE_CODE.test(o.reason))));
 }
 return sections as JobViewSection[];
}

function jobDefinition(v: unknown): JobDefinition {
 const d = rec(v);
 need(wu64(d.revision) && d.revision !== '0' && wnonneg(d.effective_from_ns) && wnonneg(d.grace_ns) && wnonneg(d.max_runtime_ns) && wnonneg(d.observer_stale_after_ns) && wtext(d.overlap, 64));
 if (d.schedule !== undefined) {
  const s = rec(d.schedule);
  need(wtext(s.cron, 256) && wtext(s.timezone, 128));
 }
 return d as unknown as JobDefinition;
}

function jobObserverEvidence(v: unknown): JobObserverEvidence {
 const o = rec(v);
 need(idLike(o.observer) && wi64(o.observed_at_ns) && wi64(o.complete_through_ns) && typeof o.healthy === 'boolean' && typeof o.stale === 'boolean');
 need(BigInt(o.complete_through_ns) <= BigInt(o.observed_at_ns));
 return o as unknown as JobObserverEvidence;
}

/** `scheduled` is whether the job's definition has a calendar schedule: only a scheduled job can be late or missed, and only on evidence of the external schedule observer. */
function jobHealth(v: unknown, scheduled: boolean): JobHealth {
 const h = rec(v);
 need(wenum(JOB_HEALTH_STATUSES, h.status) && wi64(h.as_of_ns) && typeof h.complete === 'boolean');
 const reasons = bounded(h.reasons, 32);
 need(reasons.every((r) => typeof r === 'string' && WIRE_CODE.test(r)) && distinct(reasons));
 const e = rec(h.evidence);
 need(e.occurrence === undefined || wtext(e.occurrence, 512));
 need((e.run === undefined || idLike(e.run)) && (e.attempt === undefined || idLike(e.attempt)) && (e.cause_trace === undefined || idLike(e.cause_trace)) && (e.cause_error === undefined || idLike(e.cause_error)));
 need((e.attempt_state === undefined || wenum(JOB_ATTEMPT_STATES, e.attempt_state)) && (e.attempt_count === undefined || wcount(e.attempt_count, 256)));
 need((e.expected_at_ns === undefined || wi64(e.expected_at_ns)) && (e.window_end_ns === undefined || wi64(e.window_end_ns)) && (e.definition_revision === undefined || wu64(e.definition_revision)));
 if (e.observer !== undefined) jobObserverEvidence(e.observer);
 if (e.gaps !== undefined) { const gaps = bounded(e.gaps, 256); need(gaps.every(idLike) && distinct(gaps)); }
 if (e.skipped_local_times !== undefined) need(bounded(e.skipped_local_times, 8).every((t) => wtext(t, 64)));
 // A succeeded verdict is never produced from incomplete evidence, and a job that was never expected cannot be late or missed.
 need(h.status !== 'succeeded' || h.complete === true);
 need((h.status !== 'missed' && h.status !== 'late') || (scheduled && e.observer !== undefined));
 return h as unknown as JobHealth;
}

/** Accepts a job listing only for exactly the requested organization and project, in strictly ascending job ID order after the requested cursor, with a page_limit truncation that resumes exactly at its last job. */
export function parseJobsList(raw: unknown, want: { org: Id; project: Id; after?: Id; limit: number }): JobsListView {
 const v = rec(raw);
 need(v.org === want.org && v.project === want.project && wenum(VIEW_STATES, v.state) && v.permission === JOBS_PERMISSION && typeof v.more === 'boolean' && (v.evaluated_at_ns === undefined || wi64(v.evaluated_at_ns)));
 const reason = viewReason(v);
 const sections = jobSections(v.sections);
 const jobs = bounded(v.jobs, Math.min(want.limit, MAX_JOBS_PAGE));
 let previous = want.after ?? '';
 for (const item of jobs) {
  const j = rec(item);
  need(idLike(j.job) && j.job > previous && wu64(j.version) && typeof j.erased === 'boolean' && wcount(j.runs, MAX_JOB_COUNT) && wcount(j.attempts, MAX_JOB_COUNT) && j.attempts >= j.runs);
  const definition = j.definition === undefined ? undefined : jobDefinition(j.definition);
  jobHealth(j.health, definition?.schedule !== undefined);
  previous = j.job;
 }
 switch (v.state) {
  case 'not_available':
   need(reason !== undefined && JOB_UNAVAILABLE_REASONS.includes(reason) && jobs.length === 0 && !v.more && v.truncation === undefined);
   need(sections.length === 1 && sections[0]?.name === 'jobs' && sections[0].state === 'not_available');
   break;
  case 'ready': need(reason === undefined && jobs.length > 0); break;
  case 'empty': need(reason === 'no_jobs' && jobs.length === 0 && !v.more && v.truncation === undefined); break;
  default: need(reason !== undefined);
 }
 if (!v.more) need(v.truncation === undefined);
 else {
  const t = rec(v.truncation);
  need(jobs.length > 0 && t.reason === 'page_limit' && t.shown === jobs.length && t.total === undefined && t.next === rec(jobs[jobs.length - 1]).job);
 }
 return v as unknown as JobsListView;
}

function jobRunSummary(v: unknown, health: JobHealth): JobRunView {
 const r = rec(v);
 need(idLike(r.id) && wenum(JOB_RUN_STATUSES, r.status) && typeof r.recovered === 'boolean' && wi64(r.first_started_ns) && idLike(r.final_attempt) && typeof r.basis_of_health === 'boolean');
 need(wcount(r.attempt_count, 256) && r.attempt_count >= 1 && wcount(r.failed_attempts, r.attempt_count) && wcount(r.overlap_count, MAX_JOB_COUNT));
 const o = rec(r.occurrence);
 need(wtext(o.key, 512) && typeof o.scheduled === 'boolean' && (o.fold === 0 || o.fold === 1) && (o.scheduled ? wi64(o.at_ns) : o.at_ns === undefined));
 need(r.superseded_by === undefined || (wtext(r.superseded_by, 512) && r.superseded_by !== o.key));
 const overlaps = bounded(r.overlaps, MAX_JOB_OVERLAPS);
 need(overlaps.every((id) => idLike(id) && id !== r.id) && distinct(overlaps) && overlaps.length === Math.min(r.overlap_count, MAX_JOB_OVERLAPS));
 // Recovery is one run's own attempts; it is exactly the status "recovered", and it needs a failed attempt in that run.
 need(r.recovered === (r.status === 'recovered') && (r.status !== 'recovered' && r.status !== 'failed' || r.failed_attempts >= 1));
 need(r.basis_of_health === (health.evidence.run === r.id));
 return r as unknown as JobRunView;
}

function jobAttempt(v: unknown): JobAttemptView {
 const a = rec(v);
 need(idLike(a.id) && wu64(a.ordinal) && typeof a.started === 'boolean' && wi64(a.observed_ns) && wenum(JOB_ATTEMPT_STATES, a.effective) && typeof a.final === 'boolean' && typeof a.after_newer_occurrence === 'boolean' && wcount(a.events_accepted, 1024));
 need((a.cause_trace === undefined || idLike(a.cause_trace)) && (a.cause_error === undefined || idLike(a.cause_error)));
 let original: JobAttemptState | undefined;
 if (a.terminal !== undefined) {
  const t = rec(a.terminal);
  need(wenum(TERMINAL_ATTEMPT_STATES, t.state) && wi64(t.at_ns));
  original = t.state;
 }
 const corrections = bounded(a.corrections, 16);
 let newest = 0n, state: JobAttemptState | undefined = original;
 for (const item of corrections) {
  const c = rec(item);
  need(wu64(c.version) && BigInt(c.version) > newest && wenum(TERMINAL_ATTEMPT_STATES, c.state) && wtext(c.reason, 1024) && idLike(c.actor) && wi64(c.at_ns) && idLike(c.command));
  newest = BigInt(c.version);
  state = c.state;
 }
 // The original result is never rewritten; only a terminal attempt can be corrected, and the effective result is the newest correction's.
 need(corrections.length === 0 || original !== undefined);
 need(a.effective === (state ?? 'started'));
 need(!a.after_newer_occurrence || original !== undefined);
 return a as unknown as JobAttemptView;
}

const FINAL_STATUS: Record<JobAttemptState, readonly string[]> = { started: ['running'], succeeded: ['succeeded', 'recovered'], failed: ['failed'], cancelled: ['cancelled'] };

function jobRunDetail(v: unknown, health: JobHealth, id: Id): JobRunDetail {
 const summary = jobRunSummary(v, health);
 const r = rec(v);
 need(summary.id === id);
 const attempts = bounded(r.attempts, 256).map(jobAttempt);
 need(attempts.length === summary.attempt_count && distinct(attempts.map((a) => a.id)));
 need(attempts.every((a, i) => i === 0 || BigInt(attempts[i - 1]?.ordinal ?? '0') <= BigInt(a.ordinal)));
 const last = attempts[attempts.length - 1];
 need(last !== undefined && last.id === summary.final_attempt && attempts.every((a) => a.final === (a === last)));
 const failed = attempts.filter((a) => a.effective === 'failed').length;
 need(failed === summary.failed_attempts && FINAL_STATUS[last.effective].includes(summary.status));
 // Recovered: the final attempt succeeded after an earlier attempt failed; the failed attempt stays in the list.
 need((summary.status === 'recovered') === (last.effective === 'succeeded' && attempts.slice(0, -1).some((a) => a.effective === 'failed')));
 return r as unknown as JobRunDetail;
}

/** Accepts a job view only for exactly the requested organization, project, job (and run), in which the health, observer, loss, runs and attempts agree with each other. A view that is not_available carries no job data at all: it is never an empty job. */
export function parseJobView(raw: unknown, want: { org: Id; project: Id; job: Id; run?: Id; runsLimit?: number }): JobView {
 const v = rec(raw);
 need(v.org === want.org && v.project === want.project && v.job === want.job && wenum(VIEW_STATES, v.state) && v.permission === JOBS_PERMISSION && typeof v.erased === 'boolean' && (v.evaluated_at_ns === undefined || wi64(v.evaluated_at_ns)));
 const cap = want.runsLimit ?? DEFAULT_JOB_RUNS;
 need(Number.isInteger(cap) && cap >= 1 && cap <= MAX_JOB_RUNS);
 const reason = viewReason(v);
 const sections = jobSections(v.sections);
 need(wcount(v.total_runs, MAX_JOB_COUNT) && wcount(v.total_attempts, MAX_JOB_COUNT) && wcount(v.definition_revisions, 1000) && v.total_attempts >= v.total_runs);
 const runs = bounded(v.runs, cap);
 if (v.state === 'not_available') {
  need(reason !== undefined && JOB_UNAVAILABLE_REASONS.includes(reason) && !v.erased && runs.length === 0 && v.total_runs === 0 && v.total_attempts === 0 && v.definition_revisions === 0);
  need(v.source === undefined && v.definition === undefined && v.health === undefined && v.observer === undefined && v.loss === undefined && v.compaction === undefined && v.run === undefined && v.runs_truncation === undefined && v.latest_occurrence === undefined);
  need(sections.length === 1 && sections[0]?.name === 'job' && sections[0].state === 'not_available');
  return v as unknown as JobView;
 }
 need(v.source !== undefined && v.health !== undefined && v.observer !== undefined && v.loss !== undefined && v.compaction !== undefined && (v.definition === undefined ? v.definition_revisions === 0 : v.definition_revisions >= 1));
 const source = rec(v.source);
 need(wu64(source.version));
 if (source.cursor !== undefined) { const c = rec(source.cursor); need(idLike(c.group) && wu64(c.index)); }
 const definition = v.definition === undefined ? undefined : jobDefinition(v.definition);
 const health = jobHealth(v.health, definition?.schedule !== undefined);
 const compaction = rec(v.compaction);
 need(wu64(compaction.runs) && wnonneg(compaction.through_ns) && (v.latest_occurrence === undefined || wtext(v.latest_occurrence, 512)));

 // The state is the verdict's own completeness: ready only on complete evidence, incomplete otherwise, empty only for erased history.
 need((v.state === 'empty') === v.erased);
 switch (v.state) {
  case 'ready': need(reason === undefined && health.complete); break;
  case 'incomplete': need(reason === 'job_evidence_incomplete' && !health.complete); break;
  case 'empty': need(reason === 'job_history_erased'); break;
  default: need(reason !== undefined);
 }

 const observer = rec(v.observer);
 need(wenum(JOB_OBSERVER_STATES, observer.state) && observer.expected_schedule === (definition?.schedule !== undefined));
 const seen = health.evidence.observer;
 if (observer.evidence === undefined) need(observer.state === 'none' && seen === undefined);
 else {
  const e = jobObserverEvidence(observer.evidence);
  need(seen !== undefined && seen.observer === e.observer && seen.observed_at_ns === e.observed_at_ns && seen.complete_through_ns === e.complete_through_ns && seen.healthy === e.healthy && seen.stale === e.stale);
  need(observer.state === (!e.healthy ? 'unhealthy' : e.stale ? 'stale' : 'fresh'));
 }

 const loss = rec(v.loss);
 const intervals = bounded(loss.intervals, MAX_JOB_LOSS);
 for (const item of intervals) { const i = rec(item); need(idLike(i.id) && wi64(i.start_ns) && wi64(i.end_ns) && BigInt(i.start_ns) < BigInt(i.end_ns) && wtext(i.reason, 1024)); }
 need(distinct(intervals.map((i) => rec(i).id)) && wcount(loss.total, MAX_JOB_COUNT) && loss.total >= intervals.length && typeof loss.affects_current_health === 'boolean');
 need(loss.affects_current_health === ((health.evidence.gaps?.length ?? 0) > 0));
 if (loss.truncation === undefined) need(loss.total === intervals.length);
 else { const t = rec(loss.truncation); need(t.reason === 'loss_limit' && t.shown === intervals.length && t.total === loss.total && t.next === undefined && loss.total > intervals.length); }

 const summaries = runs.map((r) => jobRunSummary(r, health));
 need(distinct(summaries.map((r) => r.id)) && summaries.filter((r) => r.basis_of_health).length <= 1);
 need(v.latest_occurrence === undefined || summaries.every((r) => r.superseded_by === undefined || r.superseded_by === v.latest_occurrence));
 if (v.runs_truncation === undefined) need(summaries.length === v.total_runs);
 else { const t = rec(v.runs_truncation); need(t.reason === 'runs_limit' && t.shown === summaries.length && summaries.length === cap && t.total === v.total_runs && t.next === undefined && v.total_runs > summaries.length); }

 if (want.run === undefined) need(v.run === undefined);
 else {
  const detail = jobRunDetail(v.run, health, want.run);
  need(detail.attempt_count <= v.total_attempts);
  const listed = summaries.find((r) => r.id === detail.id);
  need(listed === undefined || (listed.status === detail.status && listed.recovered === detail.recovered && listed.final_attempt === detail.final_attempt && listed.attempt_count === detail.attempt_count && listed.failed_attempts === detail.failed_attempts && listed.basis_of_health === detail.basis_of_health));
 }
 return v as unknown as JobView;
}

/** One page of a project's jobs in job ID order, strictly after `after` ('' starts at the beginning), under the caller's own scope. */
export async function listJobs(org: Id, project: Id, after: Id | '', limit: number, signal: AbortSignal): Promise<JobsListView> {
 const cursor = after === '' ? {} : { after };
 const response = await jsonPost('/api/v1/jobs/list', { org, project, ...cursor, limit }, signal);
 if (!response.ok) throw await apiFault(response);
 return parseJobsList(await response.json() as unknown, { org, project, ...cursor, limit });
}

/** One job: its current health, observer, loss and runs; with `run`, that run's every attempt. The scope is the caller's own and the body names only the organization, project, job, run and run limit. */
export async function getJob(org: Id, project: Id, job: Id, options: { run?: Id; runsLimit?: number }, signal: AbortSignal): Promise<JobView> {
 const body = { org, project, job, ...(options.run === undefined ? {} : { run: options.run }), ...(options.runsLimit === undefined ? {} : { runs_limit: options.runsLimit }) };
 const response = await jsonPost('/api/v1/jobs/view', body, signal);
 if (!response.ok) throw await apiFault(response);
 return parseJobView(await response.json() as unknown, { org, project, job, ...(options.run === undefined ? {} : { run: options.run }), ...(options.runsLimit === undefined ? {} : { runsLimit: options.runsLimit }) });
}
