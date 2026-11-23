// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Client of section 10 of the console API contract (docs/operations/console-api.md, owner decision D92): the native one-way "Create GitLab issue"
// (`/api/v1/gitlab/issues`: preview, create, recheck, link_from) and the GitLab connection settings (`/api/v1/gitlab/settings`: read, save,
// disconnect, test). The Markdown copy (section 10a) is `getMarkdown` in console.ts. Nothing here reads GitLab state back: Soundpost keeps only
// the link. A route this installation does not serve yet is the explicit `not_built` answer, never an empty success.
import { ApiFault, type Id } from './types';
import { consolePost, invalidResponse, isDec, isHexId, isRecord, parseGitlabLink, type ConsoleResult, type GitlabLinkView } from './console';

export type { GitlabLinkView } from './console';

export type GitlabEntityKind = 'incident' | 'issue';
export interface GitlabEntity { kind: GitlabEntityKind; id: Id }

const str = (v: unknown): string => (typeof v === 'string' ? v : '');
const strList = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
const entityOf = (v: unknown): GitlabEntity | undefined => (isRecord(v) && (v.kind === 'incident' || v.kind === 'issue') && isHexId(v.id) ? { kind: v.kind, id: v.id } : undefined);
const entityBody = (e: GitlabEntity): Record<string, string> => ({ kind: e.kind, id: e.id });

// ---- 10(c). create / preview / recheck / link_from ----

/** What a create would send, and what is already stored. `gitlabProject` is the GitLab project the Soundpost project is mapped to (null: not mapped). */
export interface GitlabPreview {
 title: string;
 description: string;
 labels: string[];
 gitlabProject: string | null;
 /** The link already stored on this entity or on its linked error issue. */
 existing?: GitlabLinkView;
 existingOn?: GitlabEntity;
 /** An earlier create that did not settle: `creating` (another request holds the entity), `unknown` (it may have reached GitLab, nothing was retried) or `refused` (definite, with its code). */
 previous?: { state: 'creating' | 'unknown' | 'refused'; code?: string };
}
export type GitlabPreviewAnswer = { state: 'ready'; preview: GitlabPreview } | { state: 'not_available'; reason: string };

export function parsePreview(raw: unknown): GitlabPreviewAnswer {
 if (!isRecord(raw)) return invalidResponse();
 if (raw.state === 'not_available') return { state: 'not_available', reason: str(raw.reason) };
 if (typeof raw.title !== 'string' || typeof raw.description !== 'string') return invalidResponse();
 const existingRaw = raw.existing;
 const existing = isRecord(existingRaw) && existingRaw.state !== undefined && existingRaw.state !== 'linked' ? undefined : parseGitlabLink(isRecord(existingRaw) && isRecord(existingRaw.link) ? existingRaw.link : existingRaw);
 const on = isRecord(existingRaw) ? entityOf(existingRaw.entity) ?? entityOf(existingRaw.from) : undefined;
 const project = typeof raw.gitlab_project === 'string' && raw.gitlab_project !== '' ? raw.gitlab_project : null;
 const prior = isRecord(existingRaw) && (existingRaw.state === 'creating' || existingRaw.state === 'unknown' || existingRaw.state === 'refused') ? existingRaw.state : undefined;
 const priorCode = isRecord(existingRaw) && typeof existingRaw.code === 'string' && existingRaw.code !== '' ? existingRaw.code : undefined;
 return { state: 'ready', preview: { title: raw.title, description: raw.description, labels: strList(raw.labels), gitlabProject: project, ...(existing ? { existing } : {}), ...(existing && on ? { existingOn: on } : {}), ...(prior ? { previous: { state: prior, ...(priorCode ? { code: priorCode } : {}) } } : {}) } };
}

/** The closed outcomes of a create, recheck or link_from. `unknown`: the request may have reached GitLab; nothing is retried automatically. */
export type GitlabOutcome =
 | { state: 'linked'; link: GitlabLinkView; created: boolean }
 | { state: 'unknown' }
 | { state: 'refused'; code: string }
 | { state: 'in_progress' }
 | { state: 'not_found' };
// The contract's `not_linked` (recheck found no issue with the marker) is the same outcome as `not_found`.
export type GitlabAnswer = GitlabOutcome | { state: 'not_built' } | { state: 'fault'; fault: ApiFault };

export function parseOutcome(raw: unknown): GitlabOutcome {
 if (!isRecord(raw)) return invalidResponse();
 switch (raw.state) {
  case 'linked': {
   const link = parseGitlabLink(isRecord(raw.link) ? raw.link : raw);
   return link ? { state: 'linked', link, created: raw.created === true } : invalidResponse();
  }
  case 'unknown': return { state: 'unknown' };
  case 'in_progress': return { state: 'in_progress' };
  case 'not_found': case 'not_linked': return { state: 'not_found' };
  case 'refused': return { state: 'refused', code: str(raw.code) !== '' ? str(raw.code) : str(raw.reason) };
  default: return invalidResponse();
 }
}

/** Maps a transport-level answer to an outcome. A lost connection after a create was sent is `unknown`, never a failure to retry blindly; a 409 is "another create holds the entity". */
export function answerOf(result: ConsoleResult<GitlabOutcome>, request: 'create' | 'recheck' | 'link_from'): GitlabAnswer {
 if (result.kind === 'ok') return result.data;
 if (result.kind === 'not_built') return { state: 'not_built' };
 const f = result.fault;
 if (f.status === 0) return request === 'create' ? { state: 'unknown' } : { state: 'fault', fault: f };
 if (f.status === 409) return { state: 'in_progress' };
 if (f.detail.startsWith('gitlab_')) return { state: 'refused', code: f.detail };
 return { state: 'fault', fault: f };
}

export function gitlabPreview(req: { org: Id; project: Id; entity: GitlabEntity }, signal: AbortSignal): Promise<ConsoleResult<GitlabPreviewAnswer>> {
 return consolePost('/api/v1/gitlab/issues', { op: 'preview', org: req.org, project_id: req.project, entity: entityBody(req.entity) }, signal, parsePreview);
}
export interface GitlabCreate { org: Id; project: Id; entity: GitlabEntity; commandId: Id; title?: string; description?: string; labels?: readonly string[] }
export async function gitlabCreate(req: GitlabCreate, signal: AbortSignal): Promise<GitlabAnswer> {
 const body = { op: 'create', org: req.org, project_id: req.project, entity: entityBody(req.entity), command_id: req.commandId, ...(req.title !== undefined ? { title: req.title } : {}), ...(req.description !== undefined ? { description: req.description } : {}), ...(req.labels !== undefined ? { labels: req.labels } : {}) };
 return answerOf(await consolePost('/api/v1/gitlab/issues', body, signal, parseOutcome), 'create');
}
/** Looks the issue up by its marker only; never creates. */
export async function gitlabRecheck(req: { org: Id; project: Id; entity: GitlabEntity }, signal: AbortSignal): Promise<GitlabAnswer> {
 return answerOf(await consolePost('/api/v1/gitlab/issues', { op: 'recheck', org: req.org, project_id: req.project, entity: entityBody(req.entity) }, signal, parseOutcome), 'recheck');
}
/** Links the entity to the GitLab issue already stored on another entity (an incident to its linked error issue's GitLab issue). */
export async function gitlabLinkFrom(req: { org: Id; project: Id; entity: GitlabEntity; from: GitlabEntity }, signal: AbortSignal): Promise<GitlabAnswer> {
 return answerOf(await consolePost('/api/v1/gitlab/issues', { op: 'link_from', org: req.org, project_id: req.project, entity: entityBody(req.entity), from: entityBody(req.from) }, signal, parseOutcome), 'link_from');
}

/** The GitLab issue a stored link entry on an incident timeline names, or undefined. The incident view carries the link as a timeline entry of type `external_link` (or `external_end`/`external_adopt` once linked). */
export function externalLinkOf(timeline: readonly unknown[] | undefined): GitlabLinkView | undefined {
 let found: GitlabLinkView | undefined;
 for (const entry of timeline ?? []) {
  if (!isRecord(entry) || (entry.type !== 'external_link' && entry.type !== 'external_end' && entry.type !== 'external_adopt')) continue;
  const ext = isRecord(entry.external) ? entry.external : undefined;
  const candidate = (ext && ext.result === 'linked' ? parseGitlabLink({ url: ext.url, gitlab_project: ext.project, iid: ext.iid }) : undefined) ?? parseGitlabLink(entry.external_link) ?? parseGitlabLink(entry);
  if (candidate) found = candidate;
 }
 return found;
}

// ---- 10. settings ----
export interface GitlabMapping { projectId: Id; gitlabProject: string; createFrom: GitlabEntityKind[]; labels: string[] }
export interface GitlabSettings { connected: boolean; baseHost: string; mappings: GitlabMapping[]; token: { hasToken: boolean; expiresAt?: string; scopes?: string[] }; epoch?: string; canEdit?: boolean }

export function parseSettings(raw: unknown): GitlabSettings {
 if (!isRecord(raw) || typeof raw.connected !== 'boolean' || !Array.isArray(raw.mappings) || !isRecord(raw.token) || typeof raw.token.has_token !== 'boolean') return invalidResponse();
 const mappings = raw.mappings.filter(isRecord).filter((m) => isHexId(m.project_id) && typeof m.gitlab_project === 'string').map((m): GitlabMapping => ({
  projectId: m.project_id as Id, gitlabProject: m.gitlab_project as string,
  createFrom: Array.isArray(m.create_from) ? m.create_from.filter((k): k is GitlabEntityKind => k === 'incident' || k === 'issue') : [],
  labels: strList(m.labels),
 }));
 const token = raw.token;
 const expires = typeof token.expires_at === 'string' && token.expires_at !== '' ? token.expires_at : undefined;
 return {
  connected: raw.connected, baseHost: str(raw.base_host), mappings,
  token: { hasToken: token.has_token === true, ...(expires ? { expiresAt: expires } : {}), ...(Array.isArray(token.scopes) ? { scopes: strList(token.scopes) } : {}) },
  ...(isDec(raw.epoch) ? { epoch: raw.epoch } : {}),
  ...(typeof raw.can_edit === 'boolean' ? { canEdit: raw.can_edit } : {}),
 };
}
export function gitlabSettingsRead(org: Id, signal: AbortSignal): Promise<ConsoleResult<GitlabSettings>> {
 return consolePost('/api/v1/gitlab/settings', { op: 'read', org }, signal, parseSettings);
}

export interface GitlabSave { org: Id; commandId: Id; expectedEpoch: string; reason: string; baseUrl: string; /** Write-only: omitted keeps the stored token. */ token?: string; mappings: readonly GitlabMapping[] }
export interface GitlabWritten { epoch?: string }
const writtenOf = (raw: unknown): GitlabWritten => (isRecord(raw) && isDec(raw.epoch) ? { epoch: raw.epoch } : {});
export function gitlabSettingsSave(req: GitlabSave, signal: AbortSignal): Promise<ConsoleResult<GitlabWritten>> {
 const connection = { base_url: req.baseUrl, ...(req.token !== undefined && req.token !== '' ? { token: req.token } : {}), mappings: req.mappings.map((m) => ({ project_id: m.projectId, gitlab_project: m.gitlabProject, create_from: m.createFrom, labels: m.labels })) };
 return consolePost('/api/v1/gitlab/settings', { op: 'save', org: req.org, command_id: req.commandId, expected_epoch: req.expectedEpoch, reason: req.reason, connection }, signal, writtenOf);
}
export function gitlabSettingsDisconnect(req: { org: Id; commandId: Id; expectedEpoch: string; reason: string }, signal: AbortSignal): Promise<ConsoleResult<GitlabWritten>> {
 return consolePost('/api/v1/gitlab/settings', { op: 'disconnect', org: req.org, command_id: req.commandId, expected_epoch: req.expectedEpoch, reason: req.reason }, signal, writtenOf);
}

/** The answer of the connection test: GitLab's own `GET /personal_access_tokens/self`, reported as is. */
export interface GitlabTest { ok: boolean; scopes: string[]; expiresAt?: string; code?: string }
export function parseTest(raw: unknown): GitlabTest {
 if (!isRecord(raw) || typeof raw.ok !== 'boolean') return invalidResponse();
 return { ok: raw.ok, scopes: strList(raw.scopes), ...(typeof raw.expires_at === 'string' && raw.expires_at !== '' ? { expiresAt: raw.expires_at } : {}), ...(typeof raw.code === 'string' && raw.code !== '' ? { code: raw.code } : {}) };
}
export function gitlabSettingsTest(org: Id, signal: AbortSignal): Promise<ConsoleResult<GitlabTest>> {
 return consolePost('/api/v1/gitlab/settings', { op: 'test', org }, signal, parseTest);
}
