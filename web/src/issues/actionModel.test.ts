// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The issue action state machine: every transition of the panel as a plain function, so a regression in what a submit sends or in
// what a server answer is shown as no longer needs a browser to be caught.
import { describe, expect, test } from 'bun:test';
import { ApiFault, OutcomeUnknown, VersionConflict, type ActionRequest, type ActionResponse, type IssueEvidenceView } from '../api/types';
import { buildIssueAction } from '../evidence/model';
import { conflictWords, settleIssueAction, submitIssueAction, type IssueOutcome, type SubmitInput } from './actionModel';

const A = 'a'.repeat(32), P = '1'.repeat(32), I = '3'.repeat(32), C = 'c'.repeat(32), R1 = '5'.repeat(32), R2 = '6'.repeat(32);
const view = (over: Partial<IssueEvidenceView> = {}): IssueEvidenceView => ({
 org: A, project: P, issue: I, state: 'ready', occurrences: [], late_history: [], sections: [],
 grouping: { grouping_version: 1, fingerprint: 'f'.repeat(8), workflow: 'open', revision: '7', resolution_frontier: [], observed_releases: [], fixed_descendants: [], migration_links: [] }, ...over,
});
const input = (over: Partial<SubmitInput> = {}): SubmitInput => ({ org: A, project: P, view: view(), kind: 'resolve', reason: 'fixed upstream', fixedIn: '', outcome: { kind: 'idle' }, busy: false, commandId: C, ...over });
const sent = (over: Partial<SubmitInput> = {}): ActionRequest => {
 const next = submitIssueAction(input(over));
 if (next.request === null) throw new Error(`nothing sent: ${JSON.stringify(next.outcome)}`);
 return next.request;
};
const committed = (over: Partial<ActionResponse> = {}): ActionResponse => ({ state: 'committed', entity_kind: 'issue', kind: 'resolve', target_id: I, revision: '8', issue: { id: I, workflow: 'resolved', revision: '8', grouping_version: 1 }, ...over });
const request = (): ActionRequest => sent();

describe('a submit sends one request for the revision on screen, or says why not', () => {
 test('a valid submit becomes pending and sends exactly the request, acting on the displayed revision with no actor, origin or time', () => {
  const next = submitIssueAction(input());
  expect(next.outcome).toEqual({ kind: 'pending' });
  expect(next.request).toEqual({ org: A, command_id: C, expected_version: '7', project_id: P, target_id: I, entity_kind: 'issue', kind: 'resolve', payload: { reason: 'fixed upstream' } });
  expect(Object.keys(next.request ?? {}).sort()).toEqual(['command_id', 'entity_kind', 'expected_version', 'kind', 'org', 'payload', 'project_id', 'target_id']);
 });
 test('the reason is required and trimmed: a blank one is refused locally and nothing is sent', () => {
  for (const reason of ['', '   ', '\n\t ']) {
   const next = submitIssueAction(input({ reason }));
   expect(next.request).toBeNull();
   expect(next.outcome).toEqual({ kind: 'invalid', text: 'Give a reason: it is recorded with the action in the audit trail.' });
  }
  expect(sent({ reason: '  padded  ' }).payload).toEqual({ reason: 'padded' });
 });
 test('every kind is sent as itself, and only a resolve may name fix releases', () => {
  for (const kind of ['resolve', 'ignore', 'unignore', 'reopen'] as const) expect(sent({ kind }).kind).toBe(kind);
  expect(sent({ kind: 'resolve', fixedIn: `${R1}, ${R2}` }).payload).toEqual({ reason: 'fixed upstream', fixed_frontier: [R1, R2] });
  for (const kind of ['ignore', 'unignore', 'reopen'] as const) {
   // Text left in the field of an earlier choice never rides along with another action.
   expect(sent({ kind, fixedIn: R1 }).payload).toEqual({ reason: 'fixed upstream' });
  }
 });
 test('fix releases are validated: not IDs, and more than 16, are refused with nothing sent', () => {
  const bad = submitIssueAction(input({ fixedIn: 'not-an-id' }));
  expect(bad.request).toBeNull();
  expect(bad.outcome.kind).toBe('invalid');
  const many = Array.from({ length: 17 }, (_, i) => i.toString(16).padStart(32, '0')).join(',');
  const over = submitIssueAction(input({ fixedIn: many }));
  expect(over.request).toBeNull();
  expect(over.outcome.kind === 'invalid' && over.outcome.text.startsWith('Name at most')).toBe(true);
 });
 test('a reason over 512 bytes or with control characters is refused', () => {
  expect(submitIssueAction(input({ reason: 'x'.repeat(513) })).request).toBeNull();
  expect(submitIssueAction(input({ reason: 'x'.repeat(512) })).request).not.toBeNull();
  expect(submitIssueAction(input({ reason: 'a\u0007b' })).request).toBeNull();
 });
 test('an issue whose revision is not known cannot be acted on', () => {
  const next = submitIssueAction(input({ view: view({ grouping: undefined }) }));
  expect(next.request).toBeNull();
  expect(next.outcome).toEqual({ kind: 'invalid', text: 'The issue revision is not known, so no action can be prepared.' });
 });
 test('while a request is pending, or the page is re-reading the issue, a submit does nothing at all', () => {
  const pending: IssueOutcome = { kind: 'pending' };
  const a = submitIssueAction(input({ outcome: pending }));
  expect(a.request).toBeNull();
  expect(a.outcome).toBe(pending);
  const idle: IssueOutcome = { kind: 'idle' };
  const b = submitIssueAction(input({ busy: true, outcome: idle }));
  expect(b.request).toBeNull();
  expect(b.outcome).toBe(idle);
  // A refused or conflicted earlier attempt does not block the next one.
  for (const outcome of [{ kind: 'invalid', text: 'x' }, { kind: 'conflict', detail: 'issue_version_conflict', expected: '7', current: '8' }, { kind: 'not_available', reason: 'r' }] as IssueOutcome[]) {
   expect(submitIssueAction(input({ outcome })).request).not.toBeNull();
  }
 });
});

describe('what a server answer makes of the outcome, the form and the page', () => {
 test('committed shows the server\'s workflow and revision, clears the form and re-reads the stored issue', () => {
  const s = settleIssueAction(request(), { kind: 'answer', response: committed() });
  expect(s).toEqual({ outcome: { kind: 'committed', action: 'resolve', issue: { id: I, workflow: 'resolved', revision: '8', grouping_version: 1 } }, clearForm: true, reload: true });
 });
 test('the committed action is the one that was sent, not the one on the radio when the answer arrived', () => {
  const s = settleIssueAction(sent({ kind: 'ignore' }), { kind: 'answer', response: committed({ kind: 'ignore' }) });
  expect(s.outcome.kind === 'committed' && s.outcome.action).toBe('ignore');
 });
 test('a committed answer without its issue is not a success: it is not_available and changes nothing', () => {
  const s = settleIssueAction(request(), { kind: 'answer', response: committed({ issue: undefined }) });
  expect(s).toEqual({ outcome: { kind: 'not_available', reason: 'not_available' }, clearForm: false, reload: false });
 });
 test('not_available keeps the server\'s reason, keeps the person\'s text and does not reload', () => {
  const s = settleIssueAction(request(), { kind: 'answer', response: { state: 'not_available', reason: 'issue_actions_not_wired', entity_kind: 'issue', kind: 'resolve', target_id: I } });
  expect(s).toEqual({ outcome: { kind: 'not_available', reason: 'issue_actions_not_wired' }, clearForm: false, reload: false });
  const bare = settleIssueAction(request(), { kind: 'answer', response: { state: 'not_available', entity_kind: 'issue', kind: 'resolve', target_id: I } });
  expect(bare.outcome).toEqual({ kind: 'not_available', reason: 'not_available' });
 });
});

describe('what each failure makes of the outcome', () => {
 const fail = (error: unknown) => settleIssueAction(request(), { kind: 'failure', error });
 test('a moved revision and a transition the workflow refuses are told apart, both reload, neither clears the text', () => {
  const moved = fail(new VersionConflict('9', 'd'.repeat(32), 'issue_version_conflict'));
  expect(moved).toEqual({ outcome: { kind: 'conflict', detail: 'issue_version_conflict', expected: '7', current: '9' }, clearForm: false, reload: true });
  const state = fail(new VersionConflict('7', 'd'.repeat(32), 'issue_state_conflict'));
  expect(state).toEqual({ outcome: { kind: 'conflict', detail: 'issue_state_conflict', expected: '7', current: '7' }, clearForm: false, reload: true });
 });
 test('the expected revision of a conflict is the one that was sent, even after the page moved on', () => {
  const s = settleIssueAction(sent({ view: view({ grouping: { grouping_version: 1, fingerprint: 'f', workflow: 'open', revision: '3', resolution_frontier: [], observed_releases: [], fixed_descendants: [], migration_links: [] } }) }), { kind: 'failure', error: new VersionConflict('5', '', 'issue_version_conflict') });
  expect(s.outcome).toMatchObject({ expected: '3', current: '5' });
 });
 test('an unknown outcome keeps the very request for an identical resend, and does not reload or clear', () => {
  const r = request();
  const s = settleIssueAction(r, { kind: 'failure', error: new OutcomeUnknown() });
  expect(s).toEqual({ outcome: { kind: 'unknown', request: r }, clearForm: false, reload: false });
  expect(s.outcome.kind === 'unknown' && s.outcome.request).toBe(r);
 });
 test('a refusal keeps the server\'s status, code, detail and request ID, and neither reloads nor clears', () => {
  const s = fail(new ApiFault(404, 'not_found', 'e'.repeat(32), 'gone'));
  expect(s).toEqual({ outcome: { kind: 'refused', status: 404, detail: 'gone', code: 'not_found', requestId: 'e'.repeat(32) }, clearForm: false, reload: false });
 });
 test('anything that is not a typed failure is a plain unavailable refusal, never a success', () => {
  for (const error of [new TypeError('network down'), 'boom', null]) {
   expect(fail(error)).toEqual({ outcome: { kind: 'refused', status: 0, detail: '', code: 'unavailable', requestId: '' }, clearForm: false, reload: false });
  }
 });
});

describe('the full sequences the page goes through', () => {
 test('ignore -> a reopen that the workflow refuses -> stop ignoring -> resolve with a fix release, each acting on the revision the server last committed', () => {
  let revision = 7;
  let workflow = 'open';
  const step = (kind: 'ignore' | 'unignore' | 'reopen' | 'resolve', server: (r: ActionRequest) => ActionResponse | Error, fixedIn = '') => {
   const v = view({ grouping: { grouping_version: 1, fingerprint: 'f', workflow, revision: String(revision), resolution_frontier: [], observed_releases: [], fixed_descendants: [], migration_links: [] } });
   const next = submitIssueAction(input({ view: v, kind, fixedIn }));
   if (next.request === null) throw new Error('not sent');
   expect(next.request.expected_version).toBe(String(revision));
   const answer = server(next.request);
   const settled = settleIssueAction(next.request, answer instanceof Error ? { kind: 'failure', error: answer } : { kind: 'answer', response: answer });
   if (settled.outcome.kind === 'committed') { revision = Number(settled.outcome.issue.revision); workflow = settled.outcome.issue.workflow; }
   return settled;
  };
  const ok = (kind: 'ignore' | 'unignore' | 'resolve', to: string) => (r: ActionRequest): ActionResponse => ({ state: 'committed', entity_kind: 'issue', kind, target_id: r.target_id, revision: String(Number(r.expected_version) + 1), issue: { id: r.target_id, workflow: to, revision: String(Number(r.expected_version) + 1), grouping_version: 1 } });
  expect(step('ignore', ok('ignore', 'ignored')).outcome.kind).toBe('committed');
  expect([revision, workflow]).toEqual([8, 'ignored']);
  const refused = step('reopen', () => new VersionConflict(String(revision), '', 'issue_state_conflict'));
  expect(refused.outcome).toMatchObject({ kind: 'conflict', detail: 'issue_state_conflict', expected: '8', current: '8' });
  expect([revision, workflow]).toEqual([8, 'ignored']);
  expect(step('unignore', ok('unignore', 'open')).outcome.kind).toBe('committed');
  const resolved = step('resolve', (r) => { expect(r.payload).toEqual({ reason: 'fixed upstream', fixed_frontier: [R1] }); return ok('resolve', 'resolved')(r); }, R1);
  expect(resolved.outcome).toMatchObject({ kind: 'committed', action: 'resolve' });
  expect([revision, workflow]).toEqual([10, 'resolved']);
 });
});

describe('the request builder, on its own, refuses what the panel never sends', () => {
 test('fix releases on anything but a resolve are refused by the builder itself, not only dropped by the panel', () => {
  const refused = buildIssueAction(A, P, view(), 'ignore', 'because', C, R1);
  expect(refused).toEqual({ ok: false, error: 'Only a resolve names the releases that contain the fix.' });
  expect(buildIssueAction(A, P, view(), 'resolve', 'because', C, R1).ok).toBe(true);
 });
});

describe('the conflict sentences never merge the two facts', () => {
 test('a moved revision names both revisions and says the page reloads', () => {
  const t = conflictWords('issue_version_conflict', '3', '5');
  expect(t).toContain('revision 5');
  expect(t).toContain('revision 3');
  expect(t).toContain('reloading');
 });
 test('a refused transition says the revision is the one acted on and the workflow does not allow it', () => {
  const t = conflictWords('issue_state_conflict', '3', '3');
  expect(t).toContain('does not allow this action');
  expect(t).not.toContain('reloading');
 });
});
