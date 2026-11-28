// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import type { IssueListItem } from '../api/console';
import type { IncidentView, IssueEvidenceView } from '../api/types';
import type { IssueOutcome } from './actionModel';
import { assignUnavailable, buildAssignAction, consequences, incidentWords, issueLineage, linkedIncidents, ownerOfIssue, regressionStory } from './pageModel';

const A = 'a'.repeat(32), P = '1'.repeat(32), I = '3'.repeat(32), R = '4'.repeat(32), S = '6'.repeat(32), C = '7'.repeat(32), N = '8'.repeat(32), M = '9'.repeat(32);
const incident = (over: Record<string, unknown> = {}): IncidentView => ({
 incident_id: N, org: A, project_id: P, version: '2', status: 'open', condition: { id: C, state: 'firing', freshness: 'fresh', observed_at: '1' }, severity: 'major',
 links: [{ kind: 'issue', id: I }, { kind: 'service', id: S }], ...over,
}) as unknown as IncidentView;
const view = (over: Partial<IssueEvidenceView> = {}): IssueEvidenceView => ({
 org: A, project: P, issue: I, state: 'ready', occurrences: [], late_history: [], sections: [],
 grouping: { grouping_version: 1, fingerprint: 'f'.repeat(8), workflow: 'resolved', revision: '7', resolution_time_ns: '1730000000000000000', resolution_frontier: [R], observed_releases: [R], fixed_descendants: [], migration_links: [] }, ...over,
});
const links = { incident: (p: string, i: string) => `#incident:${p}:${i}`, release: (r: string) => `#release:${r}`, service: (s: string) => `#service:${s}`, rules: '#rules' };

describe('the lineage of an issue', () => {
 test('is always rule, incident, issue, release, service, in that order', () => {
  const items = issueLineage({ project: P, issue: I, workflow: 'open', incidents: [incident()], releases: [R], links });
  expect(items.map((i) => i.kind)).toEqual(['Rule', 'Incident', 'Issue', 'Release', 'Service']);
  expect(items[2]?.current).toBe(true);
 });
 test('names the incident linked to this issue with its state in words, and its service', () => {
  const items = issueLineage({ project: P, issue: I, workflow: 'open', incidents: [incident(), incident({ incident_id: M })], releases: [R], links });
  expect(items[1]).toMatchObject({ name: '88888888…', state: 'not acknowledged · +1 more', tone: 'crit', href: `#incident:${P}:${N}` });
  expect(items[0]).toMatchObject({ state: 'firing · +1 more' });
  expect(items[4]).toMatchObject({ kind: 'Service', href: `#service:${S}` });
  expect(items[3]).toMatchObject({ kind: 'Release', href: `#release:${R}` });
 });
 test('an incident that links another issue is not this issue\'s', () => {
  const items = issueLineage({ project: P, issue: I, workflow: 'open', incidents: [incident({ links: [{ kind: 'issue', id: R }] })], releases: [], links });
  expect(items[1]).toMatchObject({ unavailable: true, name: 'none linked' });
  expect(items[3]).toMatchObject({ unavailable: true, name: 'none named' });
 });
 test('a queue that could not be read is not available, which is not the same as none linked', () => {
  const items = issueLineage({ project: P, issue: I, workflow: undefined, incidents: null, releases: [], links });
  expect(items[0]).toMatchObject({ unavailable: true, name: 'not available' });
  expect(items[1]).toMatchObject({ unavailable: true, name: 'not available' });
  expect(items[4]).toMatchObject({ unavailable: true, name: 'not available' });
 });
 test('an incident is resolved, acknowledged or not acknowledged', () => {
  expect(incidentWords({ status: 'resolved', ack: undefined }).text).toBe('resolved');
  expect(incidentWords({ status: 'open', ack: { actor: A, at: '1', impact_revision: '1', version: '1', current: true } }).text).toBe('acknowledged');
  expect(incidentWords({ status: 'open', ack: undefined }).text).toBe('not acknowledged');
  expect(linkedIncidents([incident(), incident({ links: [] })], I)).toHaveLength(1);
 });
});

describe('the workflow and regression story', () => {
 test('a resolved issue says when, in which fix release, and that nothing has been evaluated yet', () => {
  const lines = regressionStory(view({ regression: { explanations: [] } }), 'UTC');
  expect(lines.map((l) => l.key)).toEqual(['workflow', 'resolved', 'frontier', 'regression']);
  expect(lines[0]?.text).toBe('Resolved at revision 7.');
  expect(lines[2]?.releases).toEqual([R]);
  expect(lines[3]?.text).toContain('No regression has been evaluated');
 });
 test('without a fix release only the resolution time decides, and it says so', () => {
  const g = view().grouping!;
  const lines = regressionStory(view({ grouping: { ...g, resolution_frontier: [] }, regression: { explanations: [] } }), 'UTC');
  expect(lines.find((l) => l.key === 'frontier')?.text).toContain('only the resolution time decides');
 });
 test('missing stored explanations claim no regression; stored ones are counted, and reopenings named', () => {
  expect(regressionStory(view(), 'UTC').find((l) => l.key === 'regression')?.text).toContain('no regression is claimed');
  const e = { occurrence: A, event_time_ns: '1', resolution_time_ns: '1', eligible: true, ancestry_known: true, reason: 'r', frontier: [], threshold: 1, window_ns: '0', qualifying: 1 };
  const lines = regressionStory(view({ regression: { explanations: [{ ...e, reopened: true }, { ...e, reopened: false }] } }), 'UTC');
  expect(lines.find((l) => l.key === 'regression')?.text).toBe('2 stored regression evaluations; 1 reopened the issue.');
 });
 test('an issue with no stored grouping states nothing about its workflow', () => {
  expect(regressionStory(view({ grouping: undefined, state: 'not_available' }), 'UTC')[0]?.text).toContain('not stated');
 });
});

describe('what an action does to the other entities', () => {
 test('every action keeps rules and releases independent and names the lost race', () => {
  for (const kind of ['resolve', 'ignore', 'unignore', 'reopen'] as const) {
   const text = consequences(kind, [], []).map((c) => c.text).join(' ');
   expect(text).toContain('Alert rules and their conditions keep their own state.');
   expect(text).toContain('nothing is applied and you see their change');
  }
 });
 test('a resolve names the incidents that stay as they are, and the release it records as the fix', () => {
  const text = consequences('resolve', [incident()], [R]).map((c) => c.text).join(' ');
  expect(text).toContain('Incident 88888888… (not acknowledged) keeps its own state.');
  expect(text).toContain('is resolved by a person on its own page');
  expect(text).toContain('is recorded as the fix');
  expect(text).toContain('Regressed');
 });
 test('an unreadable queue does not claim there is no incident', () => {
  expect(consequences('ignore', null, []).map((c) => c.text).join(' ')).toContain('could not be read');
 });
});

describe('assigning an owner', () => {
 test('is a conflict-safe issue action against the revision on screen, with the owner only', () => {
  const built = buildAssignAction(A, P, view(), M, 'c'.repeat(32));
  expect(built).toEqual({ ok: true, value: { org: A, command_id: 'c'.repeat(32), expected_version: '7', project_id: P, target_id: I, entity_kind: 'issue', kind: 'assign', payload: { owner: M } } });
 });
 test('an empty owner removes the owner; a malformed one is refused before anything is sent', () => {
  expect(buildAssignAction(A, P, view(), '', 'c'.repeat(32))).toMatchObject({ ok: true, value: { payload: {} } });
  expect(buildAssignAction(A, P, view(), 'not-an-id', 'c'.repeat(32)).ok).toBe(false);
  expect(buildAssignAction(A, P, view({ grouping: undefined }), M, 'c'.repeat(32)).ok).toBe(false);
 });
 test('only the answers of an unbuilt route are "not available yet"; a real not found and a refusal with its own detail are not', () => {
  const refused = (status: number, code: string, detail = ''): IssueOutcome => ({ kind: 'refused', status, detail, code, requestId: '' });
  expect(assignUnavailable({ kind: 'not_available', reason: 'x' })).toBe(true);
  expect(assignUnavailable(refused(501, 'unsupported'))).toBe(true);
  expect(assignUnavailable(refused(501, 'unsupported', 'needs_contracted_installation'))).toBe(false);
  expect(assignUnavailable(refused(400, 'invalid', 'issue_owner_unknown'))).toBe(false);
  expect(assignUnavailable(refused(405, 'unavailable'))).toBe(true);
  expect(assignUnavailable(refused(404, 'unavailable'))).toBe(true);
  expect(assignUnavailable(refused(404, 'not_found'))).toBe(false);
  expect(assignUnavailable(refused(400, 'invalid'))).toBe(false);
  expect(assignUnavailable({ kind: 'idle' })).toBe(false);
 });
 test('the owner is the stored one, else the one the list states', () => {
  const g = view().grouping!;
  expect(ownerOfIssue(view({ grouping: { ...g, owner: M } as typeof g }), undefined)).toBe(M);
  expect(ownerOfIssue(view(), { owner: N } as IssueListItem)).toBe(N);
  expect(ownerOfIssue(view(), undefined)).toBeUndefined();
 });
});
