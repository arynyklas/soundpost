// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The release screens apart from React. A deploy time is the recorded marker of a release in an environment and nothing else: a release with no
// marker is `deploy time unknown`, and the build time is never shown as a deploy. A count the server cannot state is `not available`, never 0.
import type { DeployRecord, DeployView, ListRequest, ReleaseListItem } from '../api/console';
import type { Id, IncidentView, ReleaseView } from '../api/types';
import { formatNs, scopeKey, type ViewContext } from '../app/context';
import { incidentWords } from '../issues/pageModel';
import type { IconName } from '../ui/Icon';
import { shortId, type LineageItem } from '../ui/primitives';

export interface ReleaseQuery { regressionsOnly: boolean; search: string }
export const DEFAULT_RELEASE_QUERY: ReleaseQuery = { regressionsOnly: false, search: '' };
export const RELEASE_PAGE_LIMIT = 50;

export function releaseListRequest(context: ViewContext, q: ReleaseQuery): ListRequest {
 const search = q.search.trim();
 return { org: context.org, projects: context.projects, limit: RELEASE_PAGE_LIMIT, ...(search !== '' ? { query: search } : {}) };
}
/** The server narrows the list to the selected environment and, on request, to releases with a regression. */
export function releaseFilter(context: ViewContext, q: ReleaseQuery): { environment?: Id; has_regressions?: boolean } {
 return { ...(context.environment !== '' ? { environment: context.environment } : {}), ...(q.regressionsOnly ? { has_regressions: true } : {}) };
}
export function releaseListKey(context: ViewContext, q: ReleaseQuery): string { return `${scopeKey(context)}|${context.generation}|${JSON.stringify(q)}`; }
export const releaseItemKey = (item: ReleaseListItem): string => `${item.project_id}:${item.release_id}`;

function timeOf(ns: string, timezone: string): string {
 try { return formatNs(ns, timezone); } catch { return `${ns} ns since the Unix epoch`; }
}

export interface DeployLine { key: string; text: string }
/** The deploy markers of one listed release, one line per environment; with none, `deploy time unknown`. */
export function deployLines(item: Pick<ReleaseListItem, 'deploys' | 'deployState'>, timezone: string): DeployLine[] {
 if (item.deployState !== 'known' || item.deploys.length === 0) return [{ key: 'unknown', text: 'deploy time unknown' }];
 return [...item.deploys].sort((a: DeployView, b: DeployView) => (BigInt(b.deployedAt) > BigInt(a.deployedAt) ? 1 : -1)).map((d) => ({ key: d.environment, text: `environment ${shortId(d.environment)}: ${timeOf(d.deployedAt, timezone)}` }));
}

/** The deploy markers of one release from the deploys route: first and last deploy per environment, and how many times it was recorded. */
export function deployRecordLines(records: readonly DeployRecord[], timezone: string): DeployLine[] {
 if (records.length === 0) return [{ key: 'unknown', text: 'Deploy time unknown: no deploy of this release was recorded. The build time is not a deploy time.' }];
 return records.map((r) => ({
  key: r.environment,
  text: `Environment ${shortId(r.environment)}: first deployed ${timeOf(r.first_deployed_at, timezone)}${r.count !== '1' ? `, last ${timeOf(r.last_deployed_at, timezone)} (${r.count} deploys)` : ''}`,
 }));
}

export interface CountCell { text: string; known: boolean }
/** A count of issues. `null` is not available; a count the server marks incomplete is shown with that said, never as a plain number. */
export function countCell(value: string | null, incomplete: boolean): CountCell {
 if (value === null) return { text: 'not available', known: false };
 let n = value;
 try { n = new Intl.NumberFormat('en-US').format(BigInt(value)); } catch { /* the raw counter is shown */ }
 return incomplete ? { text: `${n} (incomplete)`, known: true } : { text: n, known: true };
}

/** The build time, labelled as such. It is never the deploy time. */
export function builtText(ns: string | null, timezone: string): string { return ns === null ? 'build time not available' : `built ${timeOf(ns, timezone)}`; }

/** How many releases are on screen and whether more follow. */
export function shownText(shown: number, more: boolean): string {
 return more ? `Showing ${shown} release${shown === 1 ? '' : 's'}. More follow; Load more reads the next page.` : `Showing ${shown} release${shown === 1 ? '' : 's'}. No more follow.`;
}

/** The incidents of the queue that name this release among their links. */
export function incidentsOfRelease(entries: readonly IncidentView[], release: Id): IncidentView[] {
 return entries.filter((i) => i.links.some((l) => l.kind === 'release' && l.id === release));
}

export interface ReleaseLineageInput {
 release: Id;
 /** `null` when the queue could not be read, which is not "no incident". */
 incidents: readonly IncidentView[] | null;
 /** Issues whose stored regression evaluations ran in this release, when the view states them. */
 issues: readonly Id[] | null;
 links: { incident: (project: Id, id: Id) => string; issue: (id: Id) => string; service: (id: Id) => string; rules: string };
}
/** Rule → Incident → Issue → Release → Service around this release. What the server does not state is shown as not available, never dropped. */
export function releaseLineage(input: ReleaseLineageInput): LineageItem[] {
 const none = (kind: string, icon: IconName, name: string): LineageItem => ({ kind, name, icon, unavailable: true });
 const read = input.incidents !== null;
 const linked = input.incidents === null ? [] : incidentsOfRelease(input.incidents, input.release);
 const first = linked[0];
 const more = linked.length > 1 ? ` · +${linked.length - 1} more` : '';
 const states: Record<string, { text: string; tone: 'crit' | 'ok' | 'unk' }> = { firing: { text: 'firing', tone: 'crit' }, recovered: { text: 'recovered', tone: 'ok' }, unknown: { text: 'unknown', tone: 'unk' } };
 const cond = first ? (states[first.condition.state] ?? states.unknown!) : undefined;
 const rule: LineageItem = first && cond ? { kind: 'Rule', name: shortId(first.condition.id), icon: 'rule', href: input.links.rules, state: `${cond.text}${more}`, tone: cond.tone } : none('Rule', 'rule', read ? 'none linked' : 'not available');
 const incident: LineageItem = first ? { kind: 'Incident', name: shortId(first.incident_id), icon: 'bell', href: input.links.incident(first.project_id, first.incident_id), state: `${incidentWords(first).text}${more}`, tone: incidentWords(first).tone } : none('Incident', 'bell', read ? 'none linked' : 'not available');
 const issueId = input.issues?.[0];
 const issue: LineageItem = issueId ? { kind: 'Issue', name: shortId(issueId), icon: 'bug', href: input.links.issue(issueId), state: input.issues!.length > 1 ? `+${input.issues!.length - 1} more` : 'evaluated here' } : none('Issue', 'bug', input.issues === null ? 'not available' : 'none evaluated');
 const release: LineageItem = { kind: 'Release', name: shortId(input.release), icon: 'tag', current: true };
 const service = linked.flatMap((i) => i.links).find((l) => l.kind === 'service');
 const svc: LineageItem = service ? { kind: 'Service', name: shortId(service.id), icon: 'box', href: input.links.service(service.id) } : none('Service', 'box', read ? 'none linked' : 'not available');
 return [rule, incident, issue, release, svc];
}

/** The distinct issues of the stored regression evaluations of a release view, in the order they were stored. */
export function regressionIssues(view: ReleaseView | undefined): Id[] | null {
 if (view === undefined || view.sections.find((s) => s.name === 'regression')?.state === 'not_available') return null;
 return [...new Set(view.regressions.map((r) => r.issue))];
}
