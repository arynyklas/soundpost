// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { ApiFault, INVESTIGATION_KINDS, type Id, type InvestigationKind, type InvestigationRequest, type InvestigationView, type LoadState, type ViewState, type VisibleSource } from './types';

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
