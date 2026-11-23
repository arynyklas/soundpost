// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The words of the GitLab features: Markdown copy and the one-way "Create GitLab issue". Every state is spelled in words. A closed code is
// explained; an unknown code is never shown as a raw server string. Soundpost keeps only the link: it never reads a GitLab issue back.
import type { ConsoleResult, MarkdownAnswer, MarkdownFormat, MarkdownUnavailable } from '../api/console';
import type { GitlabAnswer, GitlabEntityKind } from '../api/gitlab';
import type { ApiFault } from '../api/types';

export const COPY_ITEMS: readonly { format: MarkdownFormat; label: string; entities: readonly GitlabEntityKind[] }[] = [
 { format: 'link', label: 'Link', entities: ['incident', 'issue'] },
 { format: 'description', label: 'Task description as Markdown', entities: ['incident', 'issue'] },
 { format: 'timeline', label: 'Timeline as Markdown', entities: ['incident'] },
];
export const copyItemsFor = (entity: GitlabEntityKind): typeof COPY_ITEMS => COPY_ITEMS.filter((i) => i.entities.includes(entity));

const COPIED: Record<MarkdownFormat, string> = { link: 'Link copied.', description: 'Task description copied as Markdown.', timeline: 'Timeline copied as Markdown.' };

export type CopyOutcome =
 | { kind: 'copied'; format: MarkdownFormat; markdown: string }
 | { kind: 'unavailable'; format: MarkdownFormat; reason: string }
 | { kind: 'not_built' }
 | { kind: 'fault'; fault: ApiFault };

export function copyOutcomeOf(format: MarkdownFormat, result: ConsoleResult<MarkdownAnswer | MarkdownUnavailable>): CopyOutcome {
 if (result.kind === 'not_built') return { kind: 'not_built' };
 if (result.kind === 'fault') return { kind: 'fault', fault: result.fault };
 return 'markdown' in result.data ? { kind: 'copied', format, markdown: result.data.markdown } : { kind: 'unavailable', format, reason: result.data.reason };
}

function faultWords(fault: ApiFault): string {
 if (fault.status === 401) return 'Your session has ended. Sign in again.';
 if (fault.status === 403 || fault.status === 404) return 'This record was not found or is not available to this account.';
 if (fault.status === 429) return 'Too many requests. Wait a moment and try again.';
 return `The request failed${fault.code ? ` (code ${fault.code})` : ''}.`;
}

/** `clipboard` is whether the browser let the text onto the clipboard; the Markdown is then shown so it can be copied by hand. */
export function copyWords(outcome: CopyOutcome, clipboard: boolean): string {
 switch (outcome.kind) {
  case 'copied': return clipboard ? COPIED[outcome.format] : 'The browser did not allow copying. The Markdown is shown below so it can be copied by hand.';
  case 'not_built': return 'Copy as Markdown is not available yet: this installation does not serve it. Nothing was copied.';
  case 'unavailable':
   return outcome.reason === 'public_origin_not_configured'
    ? 'The link is not available: this installation’s public address is not configured, so Soundpost cannot build a link. An administrator sets it in the server settings. Nothing was copied.'
    : 'This Markdown is not available for this record. Nothing was copied.';
  case 'fault': return `Nothing was copied. ${faultWords(outcome.fault)}`;
 }
}

const REFUSED: Record<string, string> = {
 gitlab_forbidden: 'GitLab refused the request: the token has no permission to create issues in this project.',
 gitlab_not_found: 'GitLab says the project was not found. Check the project mapping in the GitLab settings.',
 gitlab_unauthorized: 'GitLab rejected the token: it is invalid, revoked or expired. An organization admin replaces it in the GitLab settings.',
 gitlab_invalid: 'GitLab did not accept the request as valid.',
 gitlab_unprocessable: 'GitLab could not process the issue (a label or a field it refuses).',
 gitlab_rate_limited: 'GitLab is rate limiting this connection. Wait and try again.',
 gitlab_redirect_refused: 'GitLab answered with a redirect, which Soundpost never follows. Check the GitLab address in the settings.',
 gitlab_egress_blocked: 'The address of the GitLab instance is not allowed by this installation’s egress rules. An administrator has to allow it.',
 gitlab_tls_failed: 'The TLS connection to GitLab failed: its certificate is not trusted by this installation.',
 gitlab_unreachable: 'GitLab could not be reached. Nothing was written there.',
 gitlab_not_connected: 'GitLab is not connected for this organization.',
 gitlab_mapping_missing: 'This Soundpost project is not mapped to a GitLab project.',
 gitlab_mapping_kind: 'The GitLab mapping of this project does not allow creating issues from this kind of record.',
};
export function refusedWords(code: string): string { return REFUSED[code] ?? 'GitLab or the connection refused the request.'; }

/** An earlier create that did not settle, as the preview reports it. `unknown` is never a failure: the issue may exist. */
export function previousWords(previous: { state: 'creating' | 'unknown' | 'refused'; code?: string }): string {
 switch (previous.state) {
  case 'creating': return 'Another request is creating this GitLab issue now. Wait a moment, then check whether it was created. Nothing is created twice.';
  case 'unknown': return 'An earlier request to create this GitLab issue may have reached GitLab, so the issue may exist. Nothing was retried. Check whether it was created before creating another.';
  case 'refused': return `An earlier request was refused. ${refusedWords(previous.code ?? '')} Nothing was created.`;
 }
}

export type AnswerTone = 'ok' | 'crit' | 'high' | 'info' | 'unk';
export interface AnswerWords { tone: AnswerTone; title: string; text: string; code?: string }

/** The outcome of create, recheck or link_from in words. `unknown` is never softened into a failure to retry. */
export function answerWords(answer: GitlabAnswer, entity: GitlabEntityKind): AnswerWords {
 const noun = entity === 'incident' ? 'incident' : 'error issue';
 switch (answer.state) {
  case 'linked': return answer.created
   ? { tone: 'ok', title: 'GitLab issue created and linked', text: `${answer.link.gitlab_project}#${answer.link.iid} is linked on this ${noun}. Soundpost keeps only the link and does not read the GitLab issue back.` }
   : { tone: 'ok', title: 'Already linked', text: `${answer.link.gitlab_project}#${answer.link.iid} is already linked on this ${noun}. No second GitLab issue was created.` };
  case 'unknown': return { tone: 'unk', title: 'Outcome unknown', text: 'The request may have reached GitLab, so the issue may exist. Nothing is retried automatically and no second issue is created blindly. Check whether it was created: that looks the issue up before anything else.' };
  case 'refused': return { tone: 'crit', title: 'GitLab refused', text: `${refusedWords(answer.code)} No issue was created.`, ...(answer.code ? { code: answer.code } : {}) };
  case 'in_progress': return { tone: 'high', title: 'Another create is running', text: `Another request holds this ${noun}. Wait a moment, then check whether it was created. Nothing was created by this request.` };
  case 'not_found': return { tone: 'info', title: 'No GitLab issue found', text: 'Nothing with this Soundpost marker exists in the mapped GitLab project. Nothing was created by this check; you can create the issue now.' };
  case 'not_built': return { tone: 'unk', title: 'GitLab issue creation is not available yet', text: 'This installation does not serve it. Nothing was created.' };
  case 'fault': return { tone: 'crit', title: 'Not created', text: faultWords(answer.fault), ...(answer.fault.code ? { code: answer.fault.code } : {}) };
 }
}

const PREVIEW_UNAVAILABLE: Record<string, string> = {
 gitlab_not_connected: 'GitLab is not connected for this organization. An organization admin connects it in the GitLab settings.',
 gitlab_mapping_missing: 'This Soundpost project is not mapped to a GitLab project. An organization admin maps it in the GitLab settings.',
 gitlab_mapping_kind: 'The GitLab mapping of this project does not allow creating issues from this kind of record. An organization admin changes it in the GitLab settings.',
 gitlab_project_not_mapped: 'This Soundpost project is not mapped to a GitLab project. An organization admin maps it in the GitLab settings.',
};
export function previewUnavailableWords(reason: string): string { return PREVIEW_UNAVAILABLE[reason] ?? 'GitLab issue creation is not available for this project.'; }

const MAX_LABEL = 64;
/** Labels are typed as one comma-separated line; empty parts are dropped and duplicates keep their first position. */
export function parseLabels(text: string): string[] {
 const seen = new Set<string>();
 for (const raw of text.split(',')) { const l = raw.trim(); if (l !== '' && l.length <= MAX_LABEL) seen.add(l); }
 return [...seen];
}
export const labelsText = (labels: readonly string[]): string => labels.join(', ');

/** A GitLab address is a link only when it is a web address; anything else (a `javascript:` URL, a relative path) is shown as plain text. */
export function safeHref(url: string): string | undefined {
 try { const u = new URL(url); return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : undefined; } catch { return undefined; }
}
