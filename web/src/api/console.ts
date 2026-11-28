// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Client of the console API contract (docs/operations/console-api.md, owner decision D92). Every route is a POST with a JSON body.
// A route this installation does not serve yet answers a plain-text 404/405 (not a typed JSON error): that is the explicit `not_built`
// result, which a screen shows as "not available yet". It is never an empty list and never zero.
import { ApiFault, type Id, type ViewState } from './types';
import { apiFault, jsonPost } from './client';

export type ConsoleResult<T> = { kind: 'ok'; data: T } | { kind: 'not_built' } | { kind: 'fault'; fault: ApiFault };

export function isRecord(v: unknown): v is Record<string, unknown> { return typeof v === 'object' && v !== null && !Array.isArray(v); }
const DEC = /^(0|[1-9][0-9]{0,19})$/;
export const isDec = (v: unknown): v is string => typeof v === 'string' && DEC.test(v);
export const isHexId = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{32}$/.test(v);
const VIEW_STATES: readonly ViewState[] = ['ready', 'empty', 'incomplete', 'stale', 'not_available'];
export const invalidResponse = (): never => { throw new ApiFault(200, 'invalid_response', '', 'response does not match the request'); };

/** POSTs to a console route. `parse` validates the body and throws an ApiFault `invalid_response` for a body that is not for this request. */
export async function consolePost<T>(path: string, body: unknown, signal: AbortSignal, parse: (raw: unknown) => T): Promise<ConsoleResult<T>> {
 let response: Response;
 try { response = await jsonPost(path, body, signal); } catch (e) { if (e instanceof DOMException && e.name === 'AbortError') throw e; return { kind: 'fault', fault: new ApiFault(0, 'network', '', '') }; }
 if (response.status === 405 || (response.status === 404 && !(response.headers.get('Content-Type') ?? '').includes('json'))) return { kind: 'not_built' };
 if (!response.ok) return { kind: 'fault', fault: await apiFault(response) };
 try { return { kind: 'ok', data: parse(await response.json()) }; } catch (e) { return { kind: 'fault', fault: e instanceof ApiFault ? e : new ApiFault(200, 'invalid_response', '', '') }; }
}

// ---- list envelope (section "Conventions") ----
export interface ListSection { name: string; state: ViewState; reason?: string }
export interface ListEnvelope<T> { org: Id; projects: Id[]; state: ViewState; reason?: string; items: T[]; more: boolean; nextCursor?: string; sections: ListSection[] }
export interface ListRequest { org: Id; projects: readonly Id[]; window?: { start: string; end: string }; limit?: number; cursor?: string; query?: string; sort?: string }

export function parseList<T>(raw: unknown, want: { org: Id; projects: readonly Id[] }, item: (raw: Record<string, unknown>) => T): ListEnvelope<T> {
 if (!isRecord(raw) || raw.org !== want.org || !VIEW_STATES.includes(raw.state as ViewState) || !Array.isArray(raw.items)) return invalidResponse();
 const items: T[] = [];
 for (const it of raw.items) { if (!isRecord(it)) return invalidResponse(); if (typeof it.project_id === 'string' && !want.projects.includes(it.project_id)) return invalidResponse(); items.push(item(it)); }
 const sections: ListSection[] = Array.isArray(raw.sections) ? raw.sections.filter(isRecord).filter((s) => typeof s.name === 'string' && VIEW_STATES.includes(s.state as ViewState)).map((s) => ({ name: s.name as string, state: s.state as ViewState, ...(typeof s.reason === 'string' ? { reason: s.reason } : {}) })) : [];
 return { org: want.org, projects: [...want.projects], state: raw.state as ViewState, ...(typeof raw.reason === 'string' ? { reason: raw.reason } : {}), items, more: raw.more === true, ...(typeof raw.next_cursor === 'string' && raw.next_cursor !== '' ? { nextCursor: raw.next_cursor } : {}), sections };
}
const str = (v: unknown): string => (typeof v === 'string' ? v : '');
const optStr = (v: unknown): string | undefined => (typeof v === 'string' && v !== '' ? v : undefined);
const idList = (v: unknown): Id[] => (Array.isArray(v) ? v.filter(isHexId) : []);
const dec = (v: unknown): string => (isDec(v) ? v : invalidResponse());
const optDec = (v: unknown): string | null => (isDec(v) ? v : null);
const idOf = (v: unknown): Id => (isHexId(v) ? v : invalidResponse());

function listRequest(req: ListRequest, extra: Record<string, unknown>): Record<string, unknown> {
 return { org: req.org, projects: req.projects, ...(req.window ? { window: req.window } : {}), ...(req.limit ? { limit: req.limit } : {}), ...(req.cursor ? { cursor: req.cursor } : {}), ...(req.query ? { query: req.query } : {}), ...(req.sort ? { sort: req.sort } : {}), ...extra };
}

// ---- 5. issues ----
export interface GitlabLinkView { url: string; gitlab_project: string; iid: string }
export interface IssueListItem { project_id: Id; issue_id: Id; workflow: string; revision: string; owner?: Id; title: string | null; titleState: 'ready' | 'not_available'; firstSeen: string | null; lastSeen: string | null; occurrences: string | null; compacted: boolean; releases: Id[]; gitlab?: GitlabLinkView }
export interface IssueListFilter { workflow?: readonly ('open' | 'resolved' | 'ignored')[]; owner?: Id | 'none'; release?: Id; regressed?: boolean; last_seen_after?: string; last_seen_before?: string }
export function parseGitlabLink(v: unknown): GitlabLinkView | undefined {
 return isRecord(v) && typeof v.url === 'string' && typeof v.gitlab_project === 'string' && (typeof v.iid === 'string' || typeof v.iid === 'number') ? { url: v.url, gitlab_project: v.gitlab_project, iid: String(v.iid) } : undefined;
}
export function listIssues(req: ListRequest, filter: IssueListFilter, signal: AbortSignal): Promise<ConsoleResult<ListEnvelope<IssueListItem>>> {
 return consolePost('/api/v1/issues/list', listRequest(req, filter as Record<string, unknown>), signal, (raw) => parseList(raw, req, (it) => {
  const external = Array.isArray(it.external) ? it.external.filter(isRecord).find((e) => e.provider === 'gitlab' && e.state === 'linked') : undefined;
  const gitlab = external ? parseGitlabLink({ url: external.url, gitlab_project: external.project, iid: external.iid }) : undefined;
  const owner = optStr(it.owner);
  return { project_id: idOf(it.project_id), issue_id: idOf(it.issue_id), workflow: str(it.workflow), revision: dec(it.revision), ...(owner && isHexId(owner) ? { owner } : {}), title: optStr(it.title) ?? null, titleState: it.title_state === 'ready' ? 'ready' : 'not_available', firstSeen: optDec(it.first_seen), lastSeen: optDec(it.last_seen), occurrences: optDec(it.occurrences), compacted: it.compacted === true, releases: idList(it.releases), ...(gitlab ? { gitlab } : {}) };
 }));
}

// ---- 5. releases and 7. deploys ----
export interface DeployView { environment: Id; deployedAt: string }
export interface ReleaseListItem { project_id: Id; release_id: Id; build_id?: Id; label: string; buildTime: string | null; parents: Id[]; deploys: DeployView[]; deployState: 'known' | 'unknown'; newIssues: string | null; regressedIssues: string | null; resolvedIssues: string | null; countsIncomplete: boolean }
export function listReleases(req: ListRequest, filter: { environment?: Id; deployed_after?: string; has_regressions?: boolean }, signal: AbortSignal): Promise<ConsoleResult<ListEnvelope<ReleaseListItem>>> {
 return consolePost('/api/v1/releases/list', listRequest(req, filter), signal, (raw) => parseList(raw, req, (it) => {
  const build = optStr(it.build_id);
  return { project_id: idOf(it.project_id), release_id: idOf(it.release_id), ...(build && isHexId(build) ? { build_id: build } : {}), label: str(it.label), buildTime: optDec(it.build_time), parents: idList(it.parents), deploys: Array.isArray(it.deploys) ? it.deploys.filter(isRecord).filter((d) => isHexId(d.environment) && isDec(d.deployed_at)).map((d) => ({ environment: d.environment as Id, deployedAt: d.deployed_at as string })) : [], deployState: it.deploy_state === 'known' ? 'known' : 'unknown', newIssues: optDec(it.new_issues), regressedIssues: optDec(it.regressed_issues), resolvedIssues: optDec(it.resolved_issues), countsIncomplete: it.counts_state === 'incomplete' };
 }));
}
export interface DeployRecord { project_id: Id; release_id: Id; environment: Id; first_deployed_at: string; last_deployed_at: string; count: string }
export async function listDeploys(org: Id, projects: readonly Id[], release: Id | undefined, signal: AbortSignal): Promise<ConsoleResult<DeployRecord[]>> {
 return consolePost('/api/v1/releases/deploys', { op: 'list', org, projects, ...(release ? { release } : {}) }, signal, (raw) => {
  if (!isRecord(raw) || !Array.isArray(raw.items)) return invalidResponse();
  return raw.items.filter(isRecord).map((d) => ({ project_id: idOf(d.project_id), release_id: idOf(d.release_id), environment: idOf(d.environment), first_deployed_at: dec(d.first_deployed_at), last_deployed_at: dec(d.last_deployed_at), count: dec(String(d.count ?? '1')) }));
 });
}
export function recordDeploy(req: { org: Id; project: Id; release: Id; environment: Id; deployedAt?: string; commandId: Id }, signal: AbortSignal): Promise<ConsoleResult<Record<string, unknown>>> {
 return consolePost('/api/v1/releases/deploys', { op: 'record', org: req.org, project: req.project, release: req.release, environment: req.environment, ...(req.deployedAt ? { deployed_at: req.deployedAt } : {}), command_id: req.commandId }, signal, (raw) => (isRecord(raw) ? raw : invalidResponse()));
}

// ---- 5. replays and profiles ----
export interface ReplayListItem { project_id: Id; replay_id: Id; session_id: string; firstAt: string | null; lastAt: string | null; chunks: string | null; recording: 'complete' | 'partial' | 'gap' | 'unknown'; gaps: string | null }
export function listReplays(req: ListRequest, signal: AbortSignal): Promise<ConsoleResult<ListEnvelope<ReplayListItem>>> {
 return consolePost('/api/v1/replays/list', listRequest(req, {}), signal, (raw) => parseList(raw, req, (it) => ({ project_id: idOf(it.project_id), replay_id: idOf(it.replay_id), session_id: str(it.session_id), firstAt: optDec(it.first_at), lastAt: optDec(it.last_at), chunks: optDec(it.chunks), recording: it.recording === 'complete' || it.recording === 'partial' || it.recording === 'gap' ? it.recording : 'unknown', gaps: optDec(it.gaps) })));
}
export interface ProfileListItem { project_id: Id; profile_id: Id; source_id: Id | null; method?: string; unit: 'samples' | 'nanoseconds' | 'events' | 'unknown'; firstAt: string | null; lastAt: string | null; coverage: 'complete' | 'partial' | 'unknown'; unsupportedReason?: string }
export function listProfiles(req: ListRequest, signal: AbortSignal): Promise<ConsoleResult<ListEnvelope<ProfileListItem>>> {
 return consolePost('/api/v1/profiles/list', listRequest(req, {}), signal, (raw) => parseList(raw, req, (it) => {
  const method = optStr(it.method), why = optStr(it.unsupported_reason);
  return { project_id: idOf(it.project_id), profile_id: idOf(it.profile_id), source_id: isHexId(it.source_id) ? it.source_id : null, ...(method ? { method } : {}), unit: it.unit === 'samples' || it.unit === 'nanoseconds' || it.unit === 'events' ? it.unit : 'unknown', firstAt: optDec(it.first_at), lastAt: optDec(it.last_at), coverage: it.coverage === 'complete' || it.coverage === 'partial' ? it.coverage : 'unknown', ...(why ? { unsupportedReason: why } : {}) };
 }));
}

// ---- 6. service RED ----
export interface RedPoint { t: string; v: number | null }
export interface RedPart { state: ViewState; points: RedPoint[]; [k: string]: unknown }
export interface RedView {
 state: ViewState; reason?: string; window: { start: string; end: string }; stepSeconds: number;
 rate: { state: ViewState; perSecond: number | null; points: RedPoint[] };
 errors: { state: ViewState; ratio: number | null; count: string | null; points: RedPoint[] };
 duration: { state: ViewState; p50Ms: number | null; p95Ms: number | null; p99Ms: number | null; /** p99 per bucket. */ points: RedPoint[]; p50Points: RedPoint[]; p95Points: RedPoint[] };
 requests: string | null; gaps: { start: string; end: string }[];
}
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const state = (v: unknown): ViewState => (VIEW_STATES.includes(v as ViewState) ? (v as ViewState) : 'not_available');
const points = (v: unknown): RedPoint[] => (Array.isArray(v) ? v.filter(isRecord).filter((p) => isDec(p.t)).map((p) => ({ t: p.t as string, v: num(p.v) })) : []);
const percentilePoints = (v: unknown, key: string): RedPoint[] => (Array.isArray(v) ? v.filter(isRecord).filter((p) => isDec(p.t)).map((p) => ({ t: p.t as string, v: num(p[key]) })) : []);
export function getRed(req: { org: Id; projects: readonly Id[]; service: Id; environment?: Id; window: { start: string; end: string }; stepSeconds?: number }, signal: AbortSignal): Promise<ConsoleResult<RedView>> {
 return consolePost('/api/v1/services/red', { org: req.org, projects: req.projects, service: req.service, ...(req.environment ? { environment: req.environment } : {}), window: req.window, ...(req.stepSeconds ? { step_seconds: req.stepSeconds } : {}) }, signal, (raw) => {
  if (!isRecord(raw) || !isRecord(raw.rate) || !isRecord(raw.errors) || !isRecord(raw.duration)) return invalidResponse();
  return {
   state: state(raw.state), ...(typeof raw.reason === 'string' ? { reason: raw.reason } : {}), window: req.window, stepSeconds: num(raw.step_seconds) ?? 60,
   rate: { state: state(raw.rate.state), perSecond: num(raw.rate.per_second), points: points(raw.rate.points) },
   errors: { state: state(raw.errors.state), ratio: num(raw.errors.ratio), count: optDec(raw.errors.count), points: points(raw.errors.points) },
   duration: { state: state(raw.duration.state), p50Ms: num(raw.duration.p50_ms), p95Ms: num(raw.duration.p95_ms), p99Ms: num(raw.duration.p99_ms), points: percentilePoints(raw.duration.points, 'p99_ms'), p50Points: percentilePoints(raw.duration.points, 'p50_ms'), p95Points: percentilePoints(raw.duration.points, 'p95_ms') },
   requests: optDec(raw.requests),
   gaps: Array.isArray(raw.gaps) ? raw.gaps.filter(isRecord).filter((g) => isDec(g.start) && isDec(g.end)).map((g) => ({ start: g.start as string, end: g.end as string })) : [],
  };
 });
}

// ---- 8. related incidents (display only) ----
export interface RelatedProposal { project_id: Id; incident_id: Id; status: string; severity: string; shared: { kind: 'service' | 'release' | 'issue'; id: Id }[] }
export function getRelated(org: Id, project: Id, incident: Id, signal: AbortSignal): Promise<ConsoleResult<RelatedProposal[]>> {
 return consolePost('/api/v1/incidents/related', { org, project_id: project, incident_id: incident }, signal, (raw) => {
  if (!isRecord(raw) || !Array.isArray(raw.proposals)) return invalidResponse();
  return raw.proposals.filter(isRecord).map((p) => ({ project_id: idOf(p.project_id), incident_id: idOf(p.incident_id), status: str(p.status), severity: str(p.severity), shared: Array.isArray(p.shared) ? p.shared.filter(isRecord).filter((s) => (s.kind === 'service' || s.kind === 'release' || s.kind === 'issue') && isHexId(s.id)).map((s) => ({ kind: s.kind as 'service' | 'release' | 'issue', id: s.id as Id })) : [] }));
 });
}

// ---- 10(a). Markdown copy ----
export type MarkdownFormat = 'link' | 'description' | 'timeline';
export interface MarkdownAnswer { markdown: string }
export interface MarkdownUnavailable { state: 'not_available'; reason: string }
export function getMarkdown(entity: 'incident' | 'issue', req: { org: Id; project: Id; id: Id; format: MarkdownFormat }, signal: AbortSignal): Promise<ConsoleResult<MarkdownAnswer | MarkdownUnavailable>> {
 return consolePost(entity === 'incident' ? '/api/v1/incidents/markdown' : '/api/v1/issues/markdown', { org: req.org, project_id: req.project, id: req.id, format: req.format }, signal, (raw) => {
  if (!isRecord(raw)) return invalidResponse();
  if (raw.state === 'not_available') return { state: 'not_available', reason: str(raw.reason) } as MarkdownUnavailable;
  return typeof raw.markdown === 'string' ? { markdown: raw.markdown } : invalidResponse();
 });
}

// ---- 3. directory: display names ----
export interface DirectoryView { org: Id; orgName?: string; projects: { id: Id; name: string }[]; members: { id: Id; displayName?: string }[]; canSetNames: boolean }
export function getDirectory(org: Id, projects: readonly Id[] | undefined, signal: AbortSignal): Promise<ConsoleResult<DirectoryView>> {
 return consolePost('/api/v1/directory', { org, ...(projects ? { projects } : {}) }, signal, (raw) => {
  if (!isRecord(raw) || raw.org !== org || !Array.isArray(raw.projects) || !Array.isArray(raw.members)) return invalidResponse();
  return {
   org, canSetNames: raw.can_set_names === true, ...(optStr(raw.org_name) ? { orgName: optStr(raw.org_name) as string } : {}),
   projects: raw.projects.filter(isRecord).filter((p) => isHexId(p.id)).map((p) => ({ id: p.id as Id, name: str(p.name) })),
   members: raw.members.filter(isRecord).filter((m) => isHexId(m.id)).map((m) => { const name = optStr(m.display_name); return { id: m.id as Id, ...(name ? { displayName: name } : {}) }; }),
  };
 });
}
export type NameState = 'set' | 'cleared';
/** The answer of the name route is `{user, state: "set" | "cleared"}` (the text is never echoed). An answer for another user or with another state is not an answer to this request. */
export function setMemberName(req: { org: Id; commandId: Id; user: Id; displayName: string }, signal: AbortSignal): Promise<ConsoleResult<{ user: Id; state: NameState }>> {
 return consolePost('/api/v1/directory/names', { org: req.org, command_id: req.commandId, user: req.user, display_name: req.displayName }, signal, (raw) => {
  if (!isRecord(raw) || raw.user !== req.user || (raw.state !== 'set' && raw.state !== 'cleared')) return invalidResponse();
  return { user: req.user, state: raw.state };
 });
}
