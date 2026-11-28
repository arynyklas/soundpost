// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import type { GitlabEntityKind, GitlabMapping, GitlabSettings } from '../api/gitlab';
import type { Id } from '../api/types';
import { validEndpoint, type Built } from './policy';

/** The pure half of the GitLab settings screen: drafts are text, builders turn them into the save the route takes or say why not, and every state is a sentence.
 * Nothing here reads GitLab: Soundpost keeps the link of an issue it created and nothing else. */
export const MAX_LABELS = 20;
export const MAX_TOKEN_BYTES = 512;
const GITLAB_PROJECT = /^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)+$/;

export interface MappingDraft { project: Id | ''; gitlabProject: string; incident: boolean; issue: boolean; labels: string }
export const emptyMapping = (project: Id | ''): MappingDraft => ({ project, gitlabProject: '', incident: true, issue: true, labels: '' });
export const draftsOf = (s: GitlabSettings | undefined): MappingDraft[] => (s ? s.mappings.map((m) => ({ project: m.projectId, gitlabProject: m.gitlabProject, incident: m.createFrom.includes('incident'), issue: m.createFrom.includes('issue'), labels: m.labels.join(', ') })) : []);

export interface ConnectionDraft { baseUrl: string; token: string; mappings: MappingDraft[] }
export interface Connection { baseUrl: string; token?: string; mappings: GitlabMapping[] }

/** The whole connection as the save takes it (the route replaces the connection as one): an https address, a token (kept when left empty on a connection that has one) and the project mappings. */
export function buildConnection(d: ConnectionDraft, hasToken: boolean): Built<Connection> {
 const baseUrl = d.baseUrl.trim();
 if (!validEndpoint(baseUrl)) return { ok: false, error: 'The GitLab address must be https without credentials, query or fragment, such as https://gitlab.example.test.' };
 if (d.token === '' && !hasToken) return { ok: false, error: 'A connection needs an access token with the api scope: it is sealed on save and never shown again.' };
 if (new TextEncoder().encode(d.token).length > MAX_TOKEN_BYTES) return { ok: false, error: 'The token is too long.' };
 const mappings: GitlabMapping[] = [];
 for (const m of d.mappings) {
  if (m.project === '') return { ok: false, error: 'Choose the Soundpost project of each mapping.' };
  if (mappings.some((x) => x.projectId === m.project)) return { ok: false, error: 'A Soundpost project is mapped to one GitLab project only.' };
  const path = m.gitlabProject.trim().replace(/^\/+|\/+$/g, '');
  if (!GITLAB_PROJECT.test(path) || path.length > 255) return { ok: false, error: `“${m.gitlabProject.trim().slice(0, 60)}” is not a GitLab project path such as group/project.` };
  const createFrom: GitlabEntityKind[] = [...(m.incident ? ['incident' as const] : []), ...(m.issue ? ['issue' as const] : [])];
  if (createFrom.length === 0) return { ok: false, error: `Choose what ${path} creates issues from: incidents, error issues or both.` };
  const labels = [...new Set(m.labels.split(/[,\n]/).map((l) => l.trim()).filter((l) => l !== ''))];
  if (labels.length > MAX_LABELS || labels.some((l) => l.length > 64)) return { ok: false, error: `At most ${MAX_LABELS} labels of at most 64 characters, separated by commas.` };
  mappings.push({ projectId: m.project, gitlabProject: path, createFrom, labels });
 }
 return { ok: true, value: { baseUrl, ...(d.token !== '' ? { token: d.token } : {}), mappings } };
}

export interface Words { label: string; tone: 'ok' | 'high' | 'crit' | 'line' | 'unk'; text: string }
/** Whether the installation is connected, in words. A connection with no stored token is not a working connection. */
export function connectionWords(s: Pick<GitlabSettings, 'connected' | 'token'>): Words {
 if (!s.connected) return { label: 'Not connected', tone: 'line', text: 'Nothing is sent to GitLab. Copying a link or a description still works.' };
 if (!s.token.hasToken) return { label: 'Connected, no token', tone: 'high', text: 'The connection has no stored token, so no issue can be created.' };
 return { label: 'Connected', tone: 'ok', text: 'Issues can be created from the mapped projects. Use “Test connection” to check the token now.' };
}

const DAY = 86_400_000;
/** When the token expires, in words, relative to `nowMs`. An expiry the server did not report is not guessed, and one that cannot be read is shown as received. */
export function expiryWords(expiresAt: string | undefined, nowMs: number): Words {
 if (expiresAt === undefined) return { label: 'Not reported', tone: 'unk', text: 'GitLab did not report an expiry for this token.' };
 const t = Date.parse(expiresAt);
 if (!Number.isFinite(t)) return { label: expiresAt, tone: 'unk', text: 'The expiry could not be read as a date.' };
 const days = Math.ceil((t - nowMs) / DAY);
 if (days < 0) return { label: 'Expired', tone: 'crit', text: `The token expired ${-days} day${days === -1 ? '' : 's'} ago: creating issues is refused until it is replaced.` };
 if (days === 0) return { label: 'Expires today', tone: 'crit', text: 'The token expires today.' };
 return { label: `in ${days} day${days === 1 ? '' : 's'}`, tone: days <= 14 ? 'high' : 'ok', text: `The token expires on ${expiresAt.slice(0, 10)}.` };
}

/** What a GitLab project mapping creates issues from, in words. */
export function createFromWords(kinds: readonly GitlabEntityKind[]): string {
 const parts = [...(kinds.includes('incident') ? ['Incidents'] : []), ...(kinds.includes('issue') ? ['Error issues'] : [])];
 return parts.length === 0 ? 'Nothing (the create button is hidden)' : parts.join(', ');
}

/** The one-way rules of the integration, as the product keeps them. */
export const BOUNDARY: readonly { icon: 'send' | 'lock' | 'link' | 'bell' | 'commit' | 'info'; head: string; text: string }[] = [
 { icon: 'send', head: 'Sent', text: 'the title and description you can edit before creating (identifiers, severity, linked entities), labels, and a link back to Soundpost.' },
 { icon: 'link', head: 'Kept', text: 'the link to the GitLab issue, on the incident or issue it was created from. One GitLab issue per entity, ever.' },
 { icon: 'lock', head: 'Never read back', text: 'GitLab state, assignees and comments are not read. Nothing is synced.' },
 { icon: 'bell', head: 'Never auto-resolved', text: 'closing an issue in GitLab resolves nothing in Soundpost, and resolving in Soundpost closes nothing in GitLab.' },
 { icon: 'commit', head: 'No suspect commits', text: 'no commit is guessed or linked from GitLab.' },
 { icon: 'info', head: 'Unknown outcome', text: 'if GitLab’s answer is lost, the link says “outcome unknown” and Soundpost looks the issue up by its marker before it tries again: never a duplicate.' },
];
