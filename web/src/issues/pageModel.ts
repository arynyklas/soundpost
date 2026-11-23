// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// What the issue page says, apart from React: the lineage chips, the workflow and regression story, what each action does to the other
// entities, and the owner assignment request. Every sentence is derived from what the server stored; nothing is guessed.
import { isHexId, type IssueListItem } from '../api/console';
import type { ActionRequest, Id, IncidentView, IssueEvidenceView } from '../api/types';
import { formatNs } from '../app/context';
import type { IconName } from '../ui/Icon';
import { shortId, type LineageItem } from '../ui/primitives';
import type { IssueOutcome } from './actionModel';
import { workflowWord } from './listModel';

/** The owner of an issue: the stored grouping's owner when the server states one, else the one the issue list states. */
export function ownerOfIssue(view: IssueEvidenceView | undefined, summary: IssueListItem | undefined): Id | undefined {
 const owner = (view?.grouping as { owner?: unknown } | undefined)?.owner;
 return isHexId(owner) ? owner : summary?.owner;
}

/** The incidents of the queue that name this issue among their links. Only what the queue read holds; an incident beyond its bound is not known here. */
export function linkedIncidents(entries: readonly IncidentView[], issue: Id): IncidentView[] {
 return entries.filter((i) => i.links.some((l) => l.kind === 'issue' && l.id === issue));
}

export interface IncidentWord { text: string; tone: 'crit' | 'info' | 'ok' }
/** One incident's state in words: resolved, acknowledged, or still waiting for a person. */
export function incidentWords(i: Pick<IncidentView, 'status' | 'ack'>): IncidentWord {
 if (i.status === 'resolved') return { text: 'resolved', tone: 'ok' };
 return i.ack ? { text: 'acknowledged', tone: 'info' } : { text: 'not acknowledged', tone: 'crit' };
}

export interface LineageLinks { incident: (project: Id, id: Id) => string; release: (id: Id) => string; service: (id: Id) => string; rules: string }
export interface LineageInput {
 project: Id;
 issue: Id;
 workflow: string | undefined;
 /** The queue's incidents; `null` when the queue could not be read, which is not the same as "no incident". */
 incidents: readonly IncidentView[] | null;
 /** The releases this issue's occurrences ran in, as the server names them. */
 releases: readonly Id[];
 links: LineageLinks;
}

const FIRING: Readonly<Record<string, { text: string; tone: 'crit' | 'ok' | 'unk' }>> = { firing: { text: 'firing', tone: 'crit' }, recovered: { text: 'recovered', tone: 'ok' }, unknown: { text: 'unknown', tone: 'unk' } };

/** Rule → Incident → Issue → Release → Service for this issue. A link the server does not state is shown as not available, never dropped and never invented. */
export function issueLineage(input: LineageInput): LineageItem[] {
 const { incidents, links } = input;
 const none = (kind: string, icon: IconName, name: string): LineageItem => ({ kind, name, icon, unavailable: true });
 const read = incidents !== null;
 const linked = incidents === null ? [] : linkedIncidents(incidents, input.issue);
 const first = linked[0];
 const more = (n: number): string => (n > 1 ? ` · +${n - 1} more` : '');
 const rule: LineageItem = first
  ? { kind: 'Rule', name: shortId(first.condition.id), icon: 'rule', href: links.rules, state: `${(FIRING[first.condition.state] ?? FIRING.unknown!).text}${more(linked.length)}`, tone: (FIRING[first.condition.state] ?? FIRING.unknown!).tone }
  : none('Rule', 'rule', read ? 'none linked' : 'not available');
 const incident: LineageItem = first
  ? { kind: 'Incident', name: shortId(first.incident_id), icon: 'bell', href: links.incident(first.project_id, first.incident_id), state: `${incidentWords(first).text}${more(linked.length)}`, tone: incidentWords(first).tone }
  : none('Incident', 'bell', read ? 'none linked' : 'not available');
 const w = input.workflow === undefined ? undefined : workflowWord(input.workflow);
 const issue: LineageItem = { kind: 'Issue', name: shortId(input.issue), icon: 'bug', current: true, ...(w ? { state: w.text.toLowerCase(), tone: w.tone === 'ok' ? 'ok' as const : w.tone === 'high' ? 'high' as const : 'unk' as const } : {}) };
 const rel = input.releases[0];
 const release: LineageItem = rel
  ? { kind: 'Release', name: shortId(rel), icon: 'tag', href: links.release(rel), state: input.releases.length > 1 ? `+${input.releases.length - 1} more` : 'observed' }
  : none('Release', 'tag', 'none named');
 const service = linked.flatMap((i) => i.links).find((l) => l.kind === 'service');
 const svc: LineageItem = service
  ? { kind: 'Service', name: shortId(service.id), icon: 'box', href: links.service(service.id) }
  : none('Service', 'box', read ? 'none linked' : 'not available');
 return [rule, incident, issue, release, svc];
}

export interface StoryLine { key: string; icon: IconName; tone: 'ok' | 'high' | 'unk' | 'info'; text: string; /** Releases the sentence names, shown as links. */ releases?: readonly Id[] }

/** The workflow and regression story of the issue, from the stored grouping and the stored regression evaluations only. */
export function regressionStory(view: IssueEvidenceView, timezone: string): StoryLine[] {
 const g = view.grouping;
 if (g === undefined) return [{ key: 'unknown', icon: 'question', tone: 'unk', text: 'The stored grouping is not available, so the workflow story is not stated.' }];
 const lines: StoryLine[] = [];
 const w = workflowWord(g.workflow);
 lines.push({ key: 'workflow', icon: g.workflow === 'resolved' ? 'check' : g.workflow === 'ignored' ? 'snooze' : 'bug', tone: g.workflow === 'resolved' ? 'ok' : g.workflow === 'ignored' ? 'unk' : 'high', text: `${w.text} at revision ${g.revision}.` });
 if (g.resolution_time_ns !== undefined) {
  let at = g.resolution_time_ns;
  try { at = formatNs(g.resolution_time_ns, timezone); } catch { /* the raw count is shown */ }
  lines.push({ key: 'resolved', icon: 'check', tone: 'ok', text: `Resolved at ${at}.` });
  lines.push(g.resolution_frontier.length > 0
   ? { key: 'frontier', icon: 'tag', tone: 'info', text: `Fix named in ${g.resolution_frontier.length === 1 ? 'release' : 'releases'}:`, releases: g.resolution_frontier }
   : { key: 'frontier', icon: 'info', tone: 'unk', text: 'No fix release was named, so only the resolution time decides whether a later occurrence is a recurrence.' });
 }
 if (view.regression === undefined) {
  lines.push({ key: 'regression', icon: 'question', tone: 'unk', text: 'The stored regression evaluations are not available here, so no regression is claimed.' });
 } else {
  const rows = view.regression.explanations;
  const reopened = rows.filter((x) => x.reopened).length;
  lines.push(rows.length === 0
   ? { key: 'regression', icon: 'info', tone: 'unk', text: 'No regression has been evaluated: no occurrence has arrived after a resolution. That is not a statement that none can happen.' }
   : { key: 'regression', icon: reopened > 0 ? 'warn' : 'check', tone: reopened > 0 ? 'high' : 'ok', text: `${rows.length} stored regression evaluation${rows.length === 1 ? '' : 's'}; ${reopened === 0 ? 'none reopened the issue' : `${reopened} reopened the issue`}.` });
 }
 if (g.fixed_descendants.length > 0) lines.push({ key: 'descendants', icon: 'tag', tone: 'info', text: 'Releases that contain the fix by ancestry:', releases: g.fixed_descendants });
 return lines;
}

export interface ConsequenceLine { key: string; icon: IconName; tone?: 'ok' | 'crit'; text: string }
export type IssueActionChoice = 'resolve' | 'ignore' | 'unignore' | 'reopen';

/** What one action does to this issue and, as important, what it does not do to the other entities: incidents, rules and releases keep their own lifecycles. */
export function consequences(kind: IssueActionChoice, incidents: readonly IncidentView[] | null, fixedIn: readonly Id[]): ConsequenceLine[] {
 const own: ConsequenceLine = kind === 'resolve'
  ? { key: 'own', icon: 'check', tone: 'ok', text: 'The issue becomes Resolved. If the same error arrives in a fix release or a release descended from it, the issue comes back as Regressed; with no fix release named, an occurrence after the resolution time reopens it.' }
  : kind === 'ignore'
   ? { key: 'own', icon: 'snooze', text: 'The issue becomes Ignored. Only its workflow state changes.' }
   : kind === 'unignore'
    ? { key: 'own', icon: 'bug', text: 'The issue becomes Open again.' }
    : { key: 'own', icon: 'bug', text: 'The issue becomes Open again, as a person decided; the earlier resolution is not a claim that the error is gone.' };
 const lines: ConsequenceLine[] = [own];
 if (incidents === null) lines.push({ key: 'incidents', icon: 'bell', text: 'Which incidents link to this issue could not be read. Whatever they are, each keeps its own state and is resolved by a person on its own page.' });
 else if (incidents.length === 0) lines.push({ key: 'incidents', icon: 'bell', text: 'No incident in the queue links to this issue. An incident, if one exists, keeps its own state.' });
 else lines.push({ key: 'incidents', icon: 'bell', text: `Incident${incidents.length === 1 ? '' : 's'} ${incidents.map((i) => `${shortId(i.incident_id)} (${incidentWords(i).text})`).join(', ')} keep${incidents.length === 1 ? 's' : ''} ${incidents.length === 1 ? 'its' : 'their'} own state. ${incidents.length === 1 ? 'It is' : 'Each is'} resolved by a person on its own page.` });
 lines.push({ key: 'rules', icon: 'rule', text: 'Alert rules and their conditions keep their own state.' });
 lines.push({ key: 'release', icon: 'tag', text: kind === 'resolve' && fixedIn.length > 0 ? `The release${fixedIn.length === 1 ? '' : 's'} you name ${fixedIn.length === 1 ? 'is' : 'are'} recorded as the fix; nothing else about ${fixedIn.length === 1 ? 'it' : 'them'} changes.` : 'Releases are unaffected.' });
 lines.push({ key: 'conflict', icon: 'info', text: 'If someone else changes this issue first, nothing is applied and you see their change.' });
 return lines;
}

export type Built = { ok: true; value: ActionRequest } | { ok: false; error: string };
const ID = /^[0-9a-f]{32}$/;

/** The request that gives the issue an owner (or, with an empty owner, takes it away): against the revision on screen, with no actor, origin or timestamp. The owner must be a member of the organization; the server decides, and a refusal is shown as one. */
export function buildAssignAction(org: Id, project: Id, view: IssueEvidenceView, owner: string, commandId: Id): Built {
 if (!view.grouping) return { ok: false, error: 'The issue revision is not known, so no owner can be assigned.' };
 const who = owner.trim();
 if (who !== '' && !ID.test(who)) return { ok: false, error: 'An owner is a member account ID: 32 lowercase hexadecimal characters.' };
 return { ok: true, value: { org, command_id: commandId, expected_version: view.grouping.revision, project_id: project, target_id: view.issue, entity_kind: 'issue', kind: 'assign', payload: who === '' ? {} : { owner: who } } };
}

/** The answer of the assign route that means "this server does not serve it": the plain-text 404/405 of an unbuilt route, a bare 501 and a typed not_available. A real not found keeps its own code, and a 501 that carries a detail
 * (`needs_contracted_installation`) is this installation refusing this very request: it is shown as the refusal it is, not as "not available yet". */
export function assignUnavailable(outcome: IssueOutcome): boolean {
 if (outcome.kind === 'not_available') return true;
 return outcome.kind === 'refused' && (outcome.status === 405 || (outcome.status === 404 && outcome.code === 'unavailable') || (outcome.status === 0 && outcome.code === 'unavailable') || (outcome.status === 501 && outcome.detail === ''));
}

export const ASSIGN_UNAVAILABLE_TEXT = 'Assigning an owner to an error issue is not available yet on this installation. Nothing was changed.';
