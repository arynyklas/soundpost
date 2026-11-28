// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The issue list apart from React: the query a person builds, the request it becomes, and every state of the list in words. A number the
// server cannot state is `not available`, never 0; a title it cannot read is `Title not available`.
import type { IssueListFilter, IssueListItem, ListEnvelope, ListRequest, ListSection } from '../api/console';
import type { Id } from '../api/types';
import { formatNs, scopeKey, type ViewContext } from '../app/context';
import { reasonText } from '../app/StatusPanel';
import type { Tone } from '../ui/primitives';

export type WorkflowChoice = 'open' | 'resolved' | 'ignored' | 'all';
export type IssueSort = 'last_seen' | 'first_seen' | 'occurrences';
/** What a person has asked the list to show. `owner` is a member ID, `none` for unassigned, or '' for any owner. */
export interface IssueQuery { workflow: WorkflowChoice; regressed: boolean; owner: Id | 'none' | ''; search: string; sort: IssueSort }

export const DEFAULT_ISSUE_QUERY: IssueQuery = { workflow: 'open', regressed: false, owner: '', search: '', sort: 'last_seen' };
export const ISSUE_PAGE_LIMIT = 50;

export const WORKFLOW_CHOICES: readonly { value: WorkflowChoice; label: string }[] = [
 { value: 'open', label: 'Open' }, { value: 'resolved', label: 'Resolved' }, { value: 'ignored', label: 'Ignored' }, { value: 'all', label: 'All' },
];
export const SORT_CHOICES: readonly { value: IssueSort; label: string }[] = [
 { value: 'last_seen', label: 'Last seen' }, { value: 'first_seen', label: 'First seen' }, { value: 'occurrences', label: 'Occurrences' },
];

/** The filter of the request. Nothing is sent for a choice that means "any". */
export function issueFilter(q: IssueQuery): IssueListFilter {
 return { ...(q.workflow !== 'all' ? { workflow: [q.workflow] } : {}), ...(q.regressed ? { regressed: true } : {}), ...(q.owner !== '' ? { owner: q.owner } : {}) };
}

export function issueListRequest(context: ViewContext, q: IssueQuery): ListRequest {
 const search = q.search.trim();
 return { org: context.org, projects: context.projects, limit: ISSUE_PAGE_LIMIT, sort: q.sort, ...(search !== '' ? { query: search } : {}) };
}

/** The identity of one list read: a new scope, refresh or query is a new read. */
export function issueListKey(context: ViewContext, q: IssueQuery): string {
 return `${scopeKey(context)}|${context.generation}|${JSON.stringify(q)}`;
}
export const issueItemKey = (item: IssueListItem): string => `${item.project_id}:${item.issue_id}`;

export interface WorkflowWord { text: string; tone: Tone }
/** The workflow state of an issue in words. A state this console does not know is said to be unknown, not guessed. */
export function workflowWord(workflow: string): WorkflowWord {
 switch (workflow) {
  case 'open': return { text: 'Open', tone: 'high' };
  case 'resolved': return { text: 'Resolved', tone: 'ok' };
  case 'ignored': return { text: 'Ignored', tone: 'unk' };
  default: return { text: 'Unknown workflow state', tone: 'unk' };
 }
}

/** The exception type and message of the newest stored occurrence, or the plain statement that it cannot be read. */
export function titleText(item: Pick<IssueListItem, 'title' | 'titleState'>): string {
 return item.titleState === 'ready' && item.title !== null && item.title !== '' ? item.title : 'Title not available';
}

const grouped = new Intl.NumberFormat('en-US');
/** A decimal counter from the server, grouped for reading; `null` (the server could not state it) is `not available`, never 0. */
export function countText(value: string | null): string {
 if (value === null) return 'not available';
 try { return grouped.format(BigInt(value)); } catch { return 'not available'; }
}

/** A nanosecond instant in the scope's zone, or `not available`. A value outside the range of a date reads as such rather than breaking the row. */
export function seenText(ns: string | null, timezone: string): string {
 if (ns === null) return 'not available';
 try { return formatNs(ns, timezone); } catch { return 'not available'; }
}

const LIST_REASONS: Readonly<Record<string, string>> = {
 search_scan_capped: 'The title search read only the newest stored occurrences before it reached its scan limit, so issues that match may be missing. Search by the start of an issue ID, or narrow the filters, to be sure.',
 separate_grant_required: 'This list needs a grant your account does not hold on every selected project.',
 cursor_invalid: 'The page position no longer matches this search. Start again from the first page.',
};
/** One sentence for the reason of a list or of one of its parts. */
export function listReasonText(reason: string | undefined): string {
 if (reason === undefined) return 'Not available.';
 return LIST_REASONS[reason] ?? reasonText(reason);
}

export interface ListNotice { tone: 'warn' | 'info' | 'unk'; label: string; text: string }
/** What a list answer says about itself when it is not plainly ready: partial, stale or not available, each in words. */
export function listNotice(env: Pick<ListEnvelope<unknown>, 'state' | 'reason'>): ListNotice | null {
 switch (env.state) {
  case 'incomplete': return { tone: 'warn', label: 'Partial', text: listReasonText(env.reason ?? 'incomplete') };
  case 'stale': return { tone: 'warn', label: 'Stale', text: listReasonText(env.reason ?? 'stale') };
  case 'not_available': return { tone: 'unk', label: 'Not available', text: listReasonText(env.reason ?? 'not_available') };
  default: return null;
 }
}

const SECTION_STATE: Readonly<Record<string, string>> = { ready: 'Ready', empty: 'Empty', incomplete: 'Partial', stale: 'Stale', not_available: 'Not available' };
/** The parts of a list that did not fully answer, or that state a reason, each with its own state and reason; a part that is not built is said so, never hidden. A plain ready part, or an empty one without a reason, is already said by the list itself (rows, or the empty card). */
export function sectionNotes(sections: readonly ListSection[]): string[] {
 return sections.filter((s) => s.state !== 'ready' && !(s.state === 'empty' && s.reason === undefined)).map((s) => `${s.name.replace(/_/g, ' ')}: ${SECTION_STATE[s.state] ?? 'Unknown'}${s.reason ? `. ${listReasonText(s.reason)}` : ''}`);
}

/** How many issues are on screen and whether the server says more follow. */
export function shownText(shown: number, more: boolean): string {
 return more ? `Showing ${shown} issue${shown === 1 ? '' : 's'}. More follow; Load more reads the next page.` : `Showing ${shown} issue${shown === 1 ? '' : 's'}. No more follow.`;
}

/** The chips a person can use to filter by owner: any, unassigned, and the members whose display name is known. A member without a display name cannot be chosen here. */
export function ownerChoices(members: ReadonlyMap<Id, string>): { value: Id | 'none' | ''; label: string }[] {
 return [{ value: '', label: 'Any owner' }, { value: 'none', label: 'Unassigned' }, ...[...members].sort((a, b) => a[1].localeCompare(b[1])).map(([id, name]) => ({ value: id, label: name }))];
}
