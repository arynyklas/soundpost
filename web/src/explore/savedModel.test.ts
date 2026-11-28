// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The saved-view flow as plain functions: what a save sends (and refuses), what opening a view does to the form, and what each server
// answer makes of the page.
import { describe, expect, test } from 'bun:test';
import { ApiFault, OutcomeUnknown, type SavedView, type ViewContext } from '../api/types';
import { defaultForm, type QueryForm } from './form';
import { featureSetId, profileById } from './profiles';
import { MAX_NAME_BYTES, MAX_SAVED_EXPRESSION_BYTES, buildDeleteRequest, buildSaveRequest, commandForAttempt, exportDocument, heldAfter, openView, refusalWords, settleSaved } from './savedModel';
import { REGISTRY } from './testRegistry.test';

const A = 'a'.repeat(32), P = '1'.repeat(32), Q = '2'.repeat(32), X = '9'.repeat(32), C = 'c'.repeat(32), V = '4'.repeat(32), U = '5'.repeat(32);
const ctx: ViewContext = { org: A, projects: [P, Q], environment: '', start: '1730000000000000000', end: '1730000060000000000', timezone: 'UTC', generation: 1 };
const form = (over: Partial<QueryForm> = {}): QueryForm => ({ ...defaultForm(ctx, 'promql', REGISTRY), expression: 'up{job="api"}', ...over });
const profile = (id: string) => { const p = profileById(REGISTRY, id); if (p === undefined) throw new Error('profile'); return p; };
const input = (over: Partial<Parameters<typeof buildSaveRequest>[3]> = {}) => ({ name: 'API up', project: P, commandId: C, ...over });
const problems = (f: QueryForm, i = input()): string[] => { const b = buildSaveRequest(ctx, f, REGISTRY, i); return b.ok ? [] : b.problems; };
const view = (over: Partial<SavedView> = {}): SavedView => ({
 id: V, org: A, project: P, name: 'API up', language: 'promql', profile: 'promql-prometheus-3.1.0', feature_set: featureSetId(profile('promql-prometheus-3.1.0'), []) ?? '', expression: 'up{job="api"}',
 projects: [P], mode: 'instant', allow_partial: false, owner: U, created_ns: '1730000000000000000', updated_ns: '1730000000000000001', revision: '3', ...over,
});

describe('a save sends exactly what the form says, owned by the chosen project, or says why not', () => {
 test('a PromQL instant query: name trimmed, text exact, the registered feature set, every selected project, no actor or time', () => {
  const b = buildSaveRequest(ctx, form({ expression: '  sum by (job) (\n  up\n)  ' }), REGISTRY, input({ name: '  API up  ' }));
  if (!b.ok) throw new Error(b.problems.join());
  expect(b.request).toEqual({
   org: A, project: P, operation: 'save', command_id: C, name: 'API up', language: 'promql', profile: 'promql-prometheus-3.1.0', feature_set: featureSetId(profile('promql-prometheus-3.1.0'), []),
   expression: '  sum by (job) (\n  up\n)  ', projects: [P, Q], mode: 'instant', allow_partial: false,
  });
  expect(Object.keys(b.request).some((k) => /actor|owner|origin|time|created|updated/.test(k))).toBe(false);
 });
 test('a selected feature changes the feature set; the profile is the selected one', () => {
  const p = profile('promql-prometheus-3.13.5');
  const b = buildSaveRequest(ctx, form({ profileId: p.id, features: ['type-and-unit-labels'] }), REGISTRY, input());
  if (!b.ok) throw new Error(b.problems.join());
  expect([b.request.profile, b.request.feature_set]).toEqual([p.id, featureSetId(p, ['type-and-unit-labels'])]);
 });
 test('a range query carries its step; an instant query never does', () => {
  const r = buildSaveRequest(ctx, form({ mode: 'range', stepSeconds: '30' }), REGISTRY, input());
  expect(r.ok && r.request.step_seconds).toBe('30');
  const i = buildSaveRequest(ctx, form({ mode: 'instant', stepSeconds: '30' }), REGISTRY, input());
  expect(i.ok && 'step_seconds' in i.request).toBe(false);
 });
 test('LogQL carries its order and optional page size; PromQL never carries either', () => {
  const l = buildSaveRequest(ctx, { ...defaultForm(ctx, 'logql', REGISTRY), expression: '{app="web"}', logLimit: '50', logOrder: 'forward' }, REGISTRY, input());
  if (!l.ok) throw new Error(l.problems.join());
  expect([l.request.language, l.request.profile, l.request.log_limit, l.request.log_order]).toEqual(['logql', 'logql-loki-3.5.2', '50', 'forward']);
  const none = buildSaveRequest(ctx, { ...defaultForm(ctx, 'logql', REGISTRY), expression: '{app="web"}', logLimit: '' }, REGISTRY, input());
  expect(none.ok && 'log_limit' in none.request).toBe(false);
  const p = buildSaveRequest(ctx, form({ logLimit: '50', logOrder: 'forward' }), REGISTRY, input());
  expect(p.ok && ('log_limit' in p.request || 'log_order' in p.request)).toBe(false);
 });
 test('partial results are saved only when the form opted in', () => {
  expect((buildSaveRequest(ctx, form({ allowPartial: true }), REGISTRY, input()) as { request: { allow_partial: boolean } }).request.allow_partial).toBe(true);
  expect((buildSaveRequest(ctx, form(), REGISTRY, input()) as { request: { allow_partial: boolean } }).request.allow_partial).toBe(false);
 });
 test('an update names the view and the revision that was read; a create names neither', () => {
  const u = buildSaveRequest(ctx, form(), REGISTRY, input({ update: { id: V, revision: '3' } }));
  expect(u.ok && [u.request.id, u.request.expected_revision]).toEqual([V, '3']);
  const c = buildSaveRequest(ctx, form(), REGISTRY, input());
  expect(c.ok && ('id' in c.request || 'expected_revision' in c.request)).toBe(false);
 });
 test('the name is required, bounded and free of control characters', () => {
  expect(problems(form(), input({ name: '   ' }))).toContain('Give the view a name.');
  expect(problems(form(), input({ name: 'x'.repeat(MAX_NAME_BYTES + 1) }))).toContain(`The name may be at most ${MAX_NAME_BYTES} bytes and must not contain control characters.`);
  expect(problems(form(), input({ name: 'x'.repeat(MAX_NAME_BYTES) }))).toEqual([]);
  expect(problems(form(), input({ name: 'a\u0007b' })).length).toBe(1);
  // Bytes, not characters: 61 two-byte characters are over the bound.
  expect(problems(form(), input({ name: 'é'.repeat(61) })).length).toBe(1);
 });
 test('the query is bounded and must be a valid selection: the same checks as running it', () => {
  expect(problems(form({ expression: 'x'.repeat(MAX_SAVED_EXPRESSION_BYTES + 1) })).length).toBeGreaterThan(0);
  expect(problems(form({ expression: '  ' }))).toContain('Enter a query expression.');
  expect(problems(form({ features: ['promql-binop-fill-modifiers'] }))).toContain('This profile registers no feature set with exactly these features.');
  expect(problems(form({ projects: [] }), input())).toContain('Select at least one project.');
 });
 test('the owning project must be one of the selected projects', () => {
  expect(problems(form({ projects: [P] }), input({ project: Q }))).toContain('The owning project must be one of the selected projects.');
  expect(problems(form({ projects: [P] }), input({ project: X }))).toContain('The owning project must be one of the selected projects.');
 });
 test('a query over a restricted source is never saved', () => {
  expect(problems({ ...defaultForm(ctx, 'logql', REGISTRY), expression: '{app="web"}', source: '5'.repeat(32), projects: [P] })).toContain('A query over a restricted source is not saved.');
 });
 test('a range step and a log page size must be whole numbers', () => {
  expect(problems(form({ mode: 'range', stepSeconds: '0' }))).toContain('The step must be a whole number of seconds, at least 1.');
  expect(problems({ ...defaultForm(ctx, 'logql', REGISTRY), expression: '{a="b"}', logLimit: 'x' })).toContain('The log page size must be a whole number of at least 1.');
 });
 test('a delete names the view, its owning project and the revision that was read', () => {
  expect(buildDeleteRequest(ctx, view({ project: Q, revision: '7' }), C)).toEqual({ org: A, project: Q, operation: 'delete', command_id: C, id: V, expected_revision: '7' });
 });
});

describe('opening a saved view fills the form with exactly what was saved, or refuses with the reason', () => {
 test('every saved choice reaches the form, and the restricted source is cleared', () => {
  const p = profile('promql-prometheus-3.13.5');
  const set = featureSetId(p, ['type-and-unit-labels']) ?? '';
  const r = openView(ctx, view({ profile: p.id, feature_set: set, mode: 'range', step_seconds: '60', allow_partial: true, projects: [Q, P] }), REGISTRY);
  if (!r.ok) throw new Error(r.reason);
  expect(r.patch).toEqual({ language: 'promql', profileId: p.id, features: ['type-and-unit-labels'], expression: 'up{job="api"}', mode: 'range', stepSeconds: '60', projects: [P, Q], allowPartial: true, logLimit: '', logOrder: 'backward', source: '' });
 });
 test('a view over fewer projects than the scope opens over exactly those projects, in scope order', () => {
  const r = openView(ctx, view({ projects: [Q] }), REGISTRY);
  if (!r.ok) throw new Error(r.reason);
  expect(r.patch.projects).toEqual([Q]);
 });
 test('a LogQL view restores its page size and order', () => {
  const l = openView(ctx, view({ language: 'logql', profile: 'logql-loki-3.5.2', feature_set: featureSetId(profile('logql-loki-3.5.2'), []) ?? '', log_limit: '50', log_order: 'forward', mode: 'range' }), REGISTRY);
  if (!l.ok) throw new Error(l.reason);
  expect([l.patch.language, l.patch.logLimit, l.patch.logOrder]).toEqual(['logql', '50', 'forward']);
 });
 test('a profile the server no longer registers is a refusal; nothing is switched to another profile', () => {
  const r = openView(ctx, view({ profile: 'promql-prometheus-9.9.9' }), REGISTRY);
  expect(r.ok).toBe(false);
  expect(!r.ok && r.reason).toContain('promql-prometheus-9.9.9');
  expect(!r.ok && r.reason).toContain('not switched to another profile');
 });
 test('a feature set the profile no longer registers, and a profile of the other language, are refusals', () => {
  const gone = openView(ctx, view({ feature_set: 'promql-prometheus-3.1.0/semantic-sha256-gone' }), REGISTRY);
  expect(!gone.ok && gone.reason).toContain('not switched to another feature set');
  const other = openView(ctx, view({ language: 'logql' }), REGISTRY);
  expect(!other.ok && other.reason).toContain('other language');
 });
 test('a view over a project outside the selected scope is refused, never narrowed', () => {
  const r = openView(ctx, view({ projects: [P, X] }), REGISTRY);
  expect(r.ok).toBe(false);
  expect(!r.ok && r.reason).toContain(X);
  expect(!r.ok && r.reason).toContain('not narrowed');
 });
});

describe('what each server answer makes of the page', () => {
 test('a committed save shows the view, re-reads the list and clears the name; a committed delete re-reads and keeps the name', () => {
  const saved = settleSaved({ kind: 'saved', view: view(), updated: false });
  expect(saved).toEqual({ outcome: { kind: 'saved', view: view(), updated: false }, reload: true, clearName: true });
  const deleted = settleSaved({ kind: 'deleted', id: V, name: 'API up' });
  expect(deleted).toEqual({ outcome: { kind: 'deleted', id: V, name: 'API up' }, reload: true, clearName: false });
 });
 test('a 409 is a lost race for a save and for a delete; the list is re-read, the name kept', () => {
  for (const what of ['save', 'delete'] as const) {
   expect(settleSaved({ kind: 'failure', what, error: new ApiFault(409, 'conflict', '', '') })).toEqual({ outcome: { kind: 'conflict', what }, reload: true, clearName: false });
  }
 });
 test('a transport failure is an unknown outcome, never a success and never a failure', () => {
  expect(settleSaved({ kind: 'failure', what: 'save', error: new OutcomeUnknown() })).toEqual({ outcome: { kind: 'unknown', what: 'save' }, reload: true, clearName: false });
 });
 test('every other refusal keeps the status, code and request ID and changes nothing', () => {
  expect(settleSaved({ kind: 'failure', what: 'save', error: new ApiFault(404, 'not_found', 'd'.repeat(32), '') })).toEqual({ outcome: { kind: 'refused', status: 404, code: 'not_found', requestId: 'd'.repeat(32) }, reload: false, clearName: false });
  expect(settleSaved({ kind: 'failure', what: 'delete', error: new TypeError('x') })).toEqual({ outcome: { kind: 'refused', status: 0, code: 'unavailable', requestId: '' }, reload: false, clearName: false });
 });
 test('a missing project, a missing view and a missing grant are said the same way', () => {
  expect(refusalWords(404)).toContain('not found or is not available');
  expect(refusalWords(429)).toContain('most saved views');
  expect(refusalWords(401)).toContain('session');
  expect(refusalWords(413)).toContain('too large');
  expect(refusalWords(500)).toContain('Nothing was changed');
 });
});

describe('the export is the views exactly as the server holds them', () => {
 test('a versioned document of the org, the project and the unaltered views', () => {
  const v = view();
  const doc = JSON.parse(exportDocument(A, P, [v])) as Record<string, unknown>;
  expect(doc).toEqual({ format: 'soundpost.saved-views', version: 1, org: A, project: P, views: [v] });
  expect(JSON.parse(exportDocument(A, P, []))).toMatchObject({ views: [] });
 });
});

describe('an attempt whose outcome is unknown is repeated under the same command ID (05.05 review)', () => {
 const C2 = 'd'.repeat(32), C3 = 'e'.repeat(32);
 const save = (over: Partial<QueryForm> = {}) => { const b = buildSaveRequest(ctx, form(over), REGISTRY, input()); if (!b.ok) throw new Error('save'); return b.request; };
 const del = () => buildDeleteRequest(ctx, view(), C);
 const unknown = (what: 'save' | 'delete') => settleSaved({ kind: 'failure', what, error: new OutcomeUnknown() });
 test('the retry of a save that ended unknown carries the first attempt\'s command ID, so the server can answer it from the first commit', () => {
  const first = commandForAttempt(null, save(), () => C2);
  expect(first.request.command_id).toBe(C2);
  const held = heldAfter(unknown('save'), first);
  expect(held).not.toBeNull();
  const retry = commandForAttempt(held, save(), () => C3);
  expect(retry.request.command_id).toBe(C2);
  expect(retry.request).toEqual(first.request);
 });
 test('a retry of a delete that ended unknown carries the same command ID', () => {
  const first = commandForAttempt(null, del(), () => C2);
  const held = heldAfter(unknown('delete'), first);
  expect(commandForAttempt(held, del(), () => C3).request.command_id).toBe(C2);
 });
 test('a different request after an unknown outcome is a different command with a fresh ID', () => {
  const first = commandForAttempt(null, save(), () => C2);
  const held = heldAfter(unknown('save'), first);
  expect(commandForAttempt(held, save({ expression: 'up{job="other"}' }), () => C3).request.command_id).toBe(C3);
  expect(commandForAttempt(held, del(), () => C3).request.command_id).toBe(C3);
 });
 test('every outcome the server decided releases the command ID: the next attempt is a new command', () => {
  const first = commandForAttempt(null, save(), () => C2);
  const decided = [
   settleSaved({ kind: 'saved', view: view(), updated: false }),
   settleSaved({ kind: 'deleted', id: V, name: 'x' }),
   settleSaved({ kind: 'failure', what: 'save', error: new ApiFault(409, 'conflict', '', '') }),
   settleSaved({ kind: 'failure', what: 'save', error: new ApiFault(404, 'not_found', '', '') }),
  ];
  for (const s of decided) expect(heldAfter(s, first)).toBeNull();
 });
});
