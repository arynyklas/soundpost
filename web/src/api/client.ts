// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { ApiFault, INVESTIGATION_KINDS, OutcomeUnknown, VersionConflict, type ActionRequest, type ActionResponse, type Id, type IncidentView, type InvestigationKind, type InvestigationRequest, type InvestigationView, type LifecycleOperation, type LoadState, type QueueView, type ViewState, type VisibleSource } from './types';

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
