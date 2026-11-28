// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { apiFault, isAbort, jsonPost } from '../api/client';
import { ApiFault, OutcomeUnknown } from '../api/types';
import type { Id } from '../api/types';

/** The client and the pure models of the organization, team, source policy and single sign-on settings pages. They sit on the closed
 * admin routes (POST /api/v1/admin/read, POST /api/v1/admin/commands, POST /api/v1/sources/policy, GET /api/v1/operations/{id}): every
 * answer is checked against the organization it was asked for and copied field by field, so a field this client does not know (a
 * secret that should never have been sent) is never held. */
const ID = /^[0-9a-f]{32}$/;
const DEC = /^(0|[1-9][0-9]{0,19})$/;
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const bad = (): never => { throw new ApiFault(200, 'invalid_response', '', 'response does not match the request'); };
const isId = (v: unknown): v is Id => typeof v === 'string' && ID.test(v);
const isDec = (v: unknown): v is string => typeof v === 'string' && DEC.test(v);
const strings = (v: unknown, max = 256): string[] => (Array.isArray(v) && v.every((s) => typeof s === 'string' && s.length <= max) ? v as string[] : bad());

export const PERMISSIONS: readonly { id: string; label: string }[] = [
 { id: 'telemetry.read', label: 'Read telemetry' }, { id: 'telemetry.ingest', label: 'Ingest telemetry' }, { id: 'raw.read', label: 'Read restricted raw data' },
 { id: 'artifacts.read', label: 'Read artifacts' }, { id: 'artifacts.write', label: 'Write artifacts' }, { id: 'replay.read', label: 'Read replays' }, { id: 'profiles.read', label: 'Read profiles' },
 { id: 'issues.write', label: 'Change issues' }, { id: 'incidents.write', label: 'Act on incidents' }, { id: 'rules.write', label: 'Change rules' }, { id: 'policy.write', label: 'Change project policy' },
];

export interface TeamConfig { members: Id[]; projects: Id[]; permissions: string[]; enabled: boolean }
export interface AdminOrg {
 id: Id; name: string;
 projects: Record<Id, string>;
 members: Record<Id, boolean>;
 admins: Record<Id, boolean>;
 /** "user:project" -> permissions. */
 grants: Record<string, string[]>;
 teams: Record<Id, TeamConfig>;
}
export interface AdminAudit { id: Id; principal: Id; action: string; reason: string; timeNs: string; targets: Id[]; allowed: boolean }
export interface AdminSourceView {
 id: Id; project: Id; browser: boolean; origins: string[]; expires_ns: string; revoked: boolean; retired: boolean; closing: boolean;
 policy: { revision: string; enabled: boolean; class: string; kinds: string[]; replay: boolean; max_bytes: string; max_series: string; templates: { id: string; revision: string }[] };
 /** The whole admitted policy exactly as read: a policy change is this object with its revision advanced. */
 raw: Record<string, unknown>;
}
export interface AdminSetting { key: string; config: Record<string, unknown> }
/** `epoch` is the organization policy epoch this answer was read at: the precondition an admin command on it carries. */
export interface AdminRead { revision: string; epoch: string; org?: AdminOrg; audits: AdminAudit[]; settings: AdminSetting[]; sources: AdminSourceView[] }
export type AdminKind = 'organization' | 'audit' | 'source' | 'team' | 'source_policy' | 'sso' | 'destination' | 'retention';

function parseTeam(raw: unknown): TeamConfig {
 if (!isRecord(raw) || typeof raw.enabled !== 'boolean') return bad();
 return { members: (Array.isArray(raw.members) ? raw.members : []).map((m): Id => (isId(m) ? m : bad())), projects: (Array.isArray(raw.projects) ? raw.projects : []).map((p): Id => (isId(p) ? p : bad())), permissions: strings(raw.permissions ?? [], 64), enabled: raw.enabled };
}
function flags(raw: unknown): Record<Id, boolean> {
 if (raw === undefined || raw === null) return {};
 if (!isRecord(raw)) return bad();
 const out: Record<Id, boolean> = {};
 for (const [k, v] of Object.entries(raw)) { if (!isId(k) || typeof v !== 'boolean') return bad(); out[k] = v; }
 return out;
}
function parseOrg(raw: unknown, want: Id): AdminOrg {
 if (!isRecord(raw) || raw.id !== want || typeof raw.name !== 'string') return bad();
 const projects: Record<Id, string> = {};
 if (raw.projects !== undefined && raw.projects !== null) {
  if (!isRecord(raw.projects)) return bad();
  for (const [k, v] of Object.entries(raw.projects)) { if (!isId(k) || typeof v !== 'string') return bad(); projects[k] = v; }
 }
 const grants: Record<string, string[]> = {};
 if (raw.grants !== undefined && raw.grants !== null) {
  if (!isRecord(raw.grants)) return bad();
  for (const [k, v] of Object.entries(raw.grants)) { if (!/^[0-9a-f]{32}:[0-9a-f]{32}$/.test(k)) return bad(); grants[k] = strings(v, 64); }
 }
 const teams: Record<Id, TeamConfig> = {};
 if (raw.teams !== undefined && raw.teams !== null) {
  if (!isRecord(raw.teams)) return bad();
  for (const [k, v] of Object.entries(raw.teams)) { if (!isId(k)) return bad(); teams[k] = parseTeam(v); }
 }
 return { id: raw.id, name: raw.name, projects, members: flags(raw.members), admins: flags(raw.admins), grants, teams };
}
function parseAudit(raw: unknown): AdminAudit {
 if (!isRecord(raw) || !isId(raw.id) || !isId(raw.principal) || typeof raw.action !== 'string' || typeof raw.reason !== 'string' || !isDec(raw.time_ns)) return bad();
 return { id: raw.id, principal: raw.principal, action: raw.action, reason: raw.reason, timeNs: raw.time_ns, targets: (Array.isArray(raw.targets) ? raw.targets : []).filter(isId), allowed: raw.outcome === 'allowed' };
}
function parseSource(raw: unknown): AdminSourceView {
 if (!isRecord(raw) || !isId(raw.id) || !isId(raw.project) || typeof raw.browser !== 'boolean' || typeof raw.revoked !== 'boolean' || typeof raw.retired !== 'boolean' || typeof raw.closing !== 'boolean' || !isDec(raw.expires_ns)) return bad();
 const p = raw.policy;
 if (!isRecord(p) || !isDec(p.revision) || typeof p.enabled !== 'boolean' || typeof p.class !== 'string' || typeof p.replay !== 'boolean' || !isDec(p.max_bytes) || !isDec(p.max_series)) return bad();
 const templates = (Array.isArray(p.templates) ? p.templates : []).map((t): { id: string; revision: string } => (isRecord(t) && typeof t.id === 'string' && isDec(t.revision) ? { id: t.id, revision: t.revision } : bad()));
 return { id: raw.id, project: raw.project, browser: raw.browser, origins: strings(raw.origins ?? [], 512), expires_ns: raw.expires_ns, revoked: raw.revoked, retired: raw.retired, closing: raw.closing, policy: { revision: p.revision, enabled: p.enabled, class: p.class, kinds: strings(p.kinds ?? [], 32), replay: p.replay, max_bytes: p.max_bytes, max_series: p.max_series, templates }, raw: p };
}

/** Accepts an admin view only for the organization asked about. */
export function parseAdminRead(raw: unknown, org: Id, kind: AdminKind): AdminRead {
 if (!isRecord(raw) || !isDec(raw.revision) || !isDec(raw.epoch)) return bad();
 const out: AdminRead = { revision: raw.revision, epoch: raw.epoch, audits: [], settings: [], sources: [] };
 if (kind === 'organization') {
  const orgs = raw.organizations;
  if (!Array.isArray(orgs) || orgs.length !== 1) return bad();
  out.org = parseOrg(orgs[0], org);
 }
 if (kind === 'audit') out.audits = (Array.isArray(raw.audits) ? raw.audits : []).map(parseAudit);
 if (kind === 'source') out.sources = (Array.isArray(raw.sources) ? raw.sources : []).map(parseSource);
 if (kind === 'team' || kind === 'source_policy' || kind === 'sso' || kind === 'destination' || kind === 'retention') {
  const settings = raw.settings;
  if (settings !== undefined && settings !== null) {
   if (!isRecord(settings)) return bad();
   for (const [key, config] of Object.entries(settings)) {
    if (!key.startsWith(`${kind}:`) || !isId(key.slice(kind.length + 1)) || !isRecord(config)) return bad();
    out.settings.push({ key, config });
   }
   out.settings.sort((a, b) => a.key.localeCompare(b.key));
  }
 }
 return out;
}

/** POST /api/v1/admin/read for one organization. A non-administrator of it, another organization's administrator and a missing organization are the one not-found. */
export async function adminRead(org: Id, kind: AdminKind, signal: AbortSignal): Promise<AdminRead> {
 const response = await jsonPost('/api/v1/admin/read', { org_id: org, kind }, signal);
 if (!response.ok) throw await apiFault(response);
 return parseAdminRead(await response.json() as unknown, org, kind);
}

/** `expected_epoch` is the organization policy epoch the page read: a change made to the organization since is refused and nothing is changed. */
export interface AdminCommand { org: Id; command_id: Id; expected_epoch: string; kind: string; payload: Record<string, unknown> }
export interface AdminCommitted { revision?: string; phase?: string; operation?: Id }

/** POST /api/v1/admin/commands. A 200 or 202 with a revision is the one committed answer; a 202 (fencing) names the operation to watch. Any refusal is a fault with its status
 * (409: the organization changed since the page read it, nothing changed; 403: needs a fresh sign-in or the right); a transport failure is OutcomeUnknown and the same command ID may be resent. */
export async function adminCommand(req: AdminCommand, signal: AbortSignal): Promise<AdminCommitted> {
 let response: Response;
 try {
  response = await jsonPost('/api/v1/admin/commands', { command_id: req.command_id, expected_epoch: req.expected_epoch, org_id: req.org, kind: req.kind, payload: req.payload }, signal);
 } catch (error) {
  if (isAbort(error)) throw error;
  throw new OutcomeUnknown();
 }
 if (!response.ok) throw await apiFault(response);
 const raw: unknown = await response.json();
 if (!isRecord(raw) || !isDec(raw.revision)) return bad();
 const first = Array.isArray(raw.affected_ids) ? raw.affected_ids[0] : undefined;
 return { revision: raw.revision, ...(typeof raw.phase === 'string' && raw.phase !== '' ? { phase: raw.phase } : {}), ...(isId(first) ? { operation: first } : {}) };
}

export interface SourcePolicyChangeRequest { command_id: Id; source: Id; expected_revision: string; policy: Record<string, unknown>; reason: string }
export interface SourceFenceView { operation: Id; source: Id; org: Id; phase: string }
function parseFence(raw: unknown, want: { source?: Id; org?: Id; operation?: Id }): SourceFenceView {
 if (!isRecord(raw) || !isId(raw.operation) || !isId(raw.source) || !isId(raw.org) || typeof raw.phase !== 'string' || !/^[a-z_]{1,32}$/.test(raw.phase)) return bad();
 if ((want.source && raw.source !== want.source) || (want.org && raw.org !== want.org) || (want.operation && raw.operation !== want.operation)) return bad();
 return { operation: raw.operation, source: raw.source, org: raw.org, phase: raw.phase };
}
/** POST /api/v1/sources/policy: the new admitted policy of one source, by revision. It is accepted (202) and the source is fenced while it takes effect. */
export async function changeSourcePolicy(req: SourcePolicyChangeRequest, signal: AbortSignal): Promise<SourceFenceView> {
 let response: Response;
 try {
  response = await jsonPost('/api/v1/sources/policy', req, signal);
 } catch (error) {
  if (isAbort(error)) throw error;
  throw new OutcomeUnknown();
 }
 if (!response.ok) throw await apiFault(response);
 return parseFence(await response.json() as unknown, { source: req.source, operation: req.command_id });
}
/** GET /api/v1/operations/{id}?org=: the progress of a source policy operation. */
export async function getSourceFence(org: Id, operation: Id, signal: AbortSignal): Promise<SourceFenceView> {
 const response = await fetch(`/api/v1/operations/${operation}?${new URLSearchParams({ org })}`, { credentials: 'same-origin', cache: 'no-store', signal, headers: { Accept: 'application/json' } });
 if (!response.ok) throw await apiFault(response);
 return parseFence(await response.json() as unknown, { org, operation });
}

/** What one admin command means for the person. Every kind but unknown_outcome says nothing was changed. */
export type AdminFailureKind = 'conflict' | 'forbidden' | 'not_found' | 'invalid' | 'signed_out' | 'stale' | 'unknown_outcome' | 'failed';
export function describeAdminFailure(error: unknown): { kind: AdminFailureKind; text: string } {
 if (error instanceof OutcomeUnknown) return { kind: 'unknown_outcome', text: 'The request left this browser but its outcome is unknown. It may or may not have been applied. Save again to resend the same command: the server applies a command once and returns the original result.' };
 if (error instanceof ApiFault) {
  switch (error.status) {
   case 409: return error.code === 'stale'
    ? { kind: 'stale', text: 'This source is already being changed or has closed, so nothing was changed. Reload and look at its state.' }
    : { kind: 'conflict', text: 'This organization (or the policy being changed) was changed by someone else after this page read it, so nothing was changed. The current state is shown; review it and apply your change again.' };
   case 403: return { kind: 'forbidden', text: 'This change needs a sign-in within the last five minutes and the right to make it. Nothing was changed. Sign in again, then retry.' };
   case 404: return { kind: 'not_found', text: 'This organization or item was not found or is not available to this account. Nothing was changed.' };
   case 400: return { kind: 'invalid', text: `The server refused these values${error.detail && error.detail !== error.code ? ` (${error.detail.replace(/_/g, ' ')})` : ''}. Nothing was changed.` };
   case 401: return { kind: 'signed_out', text: 'Your session has ended. Sign in again. Nothing was changed.' };
  }
 }
 return { kind: 'failed', text: 'The change could not be confirmed. Nothing is shown as saved; reload to see the current state.' };
}

// ---- drafts -> admin payloads -------------------------------------------------------------------------------------------------

export type Built<T> = { ok: true; value: T } | { ok: false; error: string };
export function splitIds(text: string): Id[] { return [...new Set(text.split(/[\s,]+/).filter((s) => s !== ''))]; }
export function allIds(ids: string[]): boolean { return ids.every((i) => ID.test(i)); }

/** Team configuration: member user IDs, projects of this organization, permissions, enabled. */
export function buildTeam(members: string, projects: Id[], permissions: string[], enabled: boolean): Built<TeamConfig> {
 const ids = splitIds(members);
 if (!allIds(ids)) return { ok: false, error: 'Members are user IDs of 32 lowercase hexadecimal characters, separated by commas or spaces.' };
 if (ids.length > 256) return { ok: false, error: 'A team has at most 256 members.' };
 if (projects.length === 0) return { ok: false, error: 'Choose at least one project: a team grants nothing outside its projects.' };
 if (permissions.length === 0) return { ok: false, error: 'Choose at least one permission.' };
 return { ok: true, value: { members: ids, projects: [...projects].sort(), permissions: PERMISSIONS.filter((p) => permissions.includes(p.id)).map((p) => p.id), enabled } };
}

/** A browser origin: https scheme and host (and port) only, no path, query, fragment or credentials. */
export function validOrigin(origin: string): boolean {
 try {
  const u = new URL(origin);
  return u.protocol === 'https:' && u.hostname !== '' && u.username === '' && u.password === '' && u.search === '' && u.hash === '' && (u.pathname === '/' || u.pathname === '') && origin === u.origin;
 } catch { return false; }
}
export interface SourcePolicySetting { project_id: Id; origins: string[]; restricted: boolean; readers: Id[]; enabled: boolean }
export function buildSourcePolicySetting(project: string, origins: string, restricted: boolean, readers: string, enabled: boolean): Built<SourcePolicySetting> {
 if (!ID.test(project)) return { ok: false, error: 'Choose a project.' };
 const list = [...new Set(origins.split(/[\s,]+/).filter((o) => o !== ''))];
 if (!list.every(validOrigin)) return { ok: false, error: 'Origins are https origins without a path, such as https://app.example.test, separated by spaces or commas.' };
 const people = splitIds(readers);
 if (!allIds(people)) return { ok: false, error: 'Readers are user IDs of 32 lowercase hexadecimal characters.' };
 if (restricted && people.length === 0) return { ok: false, error: 'A restricted source needs at least one named reader: nobody else may read it.' };
 return { ok: true, value: { project_id: project, origins: list.sort(), restricted, readers: people, enabled } };
}

/** A new admitted source policy: the policy as read with the toggles applied and its revision advanced by one. */
export function nextSourcePolicy(source: AdminSourceView, toggles: { enabled: boolean; replay: boolean }): Record<string, unknown> {
 return { ...source.raw, revision: (BigInt(source.policy.revision) + 1n).toString(), enabled: toggles.enabled, replay: toggles.replay };
}

export interface SsoConfig { Issuer: string; ClientID: string; RedirectURL: string; Subjects: Record<string, Id> }
export interface SsoDraft { issuer: string; clientId: string; redirectUrl: string; subjects: string }
/** Mapping lines are `subject = user ID`. The client secret is never part of the configuration: it is sent once, write-only, beside it. */
export function buildSso(d: SsoDraft): Built<SsoConfig> {
 const https = (v: string): boolean => { try { const u = new URL(v); return u.protocol === 'https:' && u.hostname !== '' && u.username === '' && u.password === '' && u.hash === ''; } catch { return false; } };
 if (!https(d.issuer.trim())) return { ok: false, error: 'The issuer must be an https address.' };
 if (d.clientId.trim() === '' || d.clientId.length > 256) return { ok: false, error: 'A client ID is required.' };
 if (!https(d.redirectUrl.trim())) return { ok: false, error: 'The redirect URL must be an https address.' };
 const subjects: Record<string, Id> = {};
 for (const line of d.subjects.split('\n').map((l) => l.trim()).filter((l) => l !== '')) {
  const at = line.indexOf('=');
  const subject = at < 0 ? '' : line.slice(0, at).trim(), user = at < 0 ? '' : line.slice(at + 1).trim();
  if (subject === '' || subject.length > 256 || !ID.test(user) || subject in subjects) return { ok: false, error: `Mapping line “${line.slice(0, 60)}” is not “identity subject = user ID” (a user ID is 32 lowercase hexadecimal characters; a subject maps once).` };
  subjects[subject] = user;
 }
 return { ok: true, value: { Issuer: d.issuer.trim(), ClientID: d.clientId.trim(), RedirectURL: d.redirectUrl.trim(), Subjects: subjects } };
}
export function ssoDraft(config: Record<string, unknown>): SsoDraft {
 const subjects = isRecord(config.Subjects) ? Object.entries(config.Subjects).filter((e): e is [string, string] => typeof e[1] === 'string').map(([s, u]) => `${s} = ${u}`).join('\n') : '';
 return { issuer: typeof config.Issuer === 'string' ? config.Issuer : '', clientId: typeof config.ClientID === 'string' ? config.ClientID : '', redirectUrl: typeof config.RedirectURL === 'string' ? config.RedirectURL : '', subjects };
}

/** A display name: at most 80 bytes of valid text without control characters; empty clears it. */
export function validDisplayName(name: string): boolean {
 return new TextEncoder().encode(name).length <= 80 && !/\p{Cc}/u.test(name);
}
