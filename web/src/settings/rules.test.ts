// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, test } from 'bun:test';
import { ApiFault, OutcomeUnknown } from '../api/types';
import { buildRuleSpec, declareReplay, emptyRuleDraft, listRules, parseLabelLines, parseRuleList, parseRuleView, retireRule, ruleDraftOf, saveRule, utcToNs, validRuleReason, type RuleProfile, type RuleView } from './rules';

const A = 'a'.repeat(32), P = '1'.repeat(32), Q = '2'.repeat(32), R = '3'.repeat(32), C = 'c'.repeat(32);
const profiles: RuleProfile[] = [{ id: 'logql-loki-3.5.2', feature_sets: ['l1'] }, { id: 'promql-prometheus-3.13.5', feature_sets: ['p1', 'p2'] }];
const view = (over: Record<string, unknown> = {}, spec: Record<string, unknown> = {}): Record<string, unknown> => ({
 rule_id: R, revision: '2', version: '2', retired: false, created_ns: '100', updated_ns: '200',
 rule: { kind: 'alert', profile: 'promql-prometheus-3.13.5', feature_set: 'p1', expression: 'up == 0', interval_seconds: 60, for_seconds: 0, recovery_hold_seconds: 0, missing_data: 'unknown', severity: 'critical', ...spec }, ...over,
});
const list = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ org: A, project_id: P, can_author: true, recording_available: false, profiles, rules: [view()], ...over });

describe('what the server answers is accepted only for the project asked about', () => {
 test('a catalogue is read as it is', () => {
  const l = parseRuleList(list(), { org: A, project: P });
  expect(l.can_author).toBe(true);
  expect(l.rules).toHaveLength(1);
  expect(l.rules[0]).toMatchObject({ rule_id: R, revision: '2', version: '2', retired: false });
  expect(l.profiles.map((p) => p.id)).toEqual(['logql-loki-3.5.2', 'promql-prometheus-3.13.5']);
 });
 test("another project's or organization's catalogue is refused", () => {
  expect(() => parseRuleList(list({ project_id: Q }), { org: A, project: P })).toThrow(ApiFault);
  expect(() => parseRuleList(list({ org: Q }), { org: A, project: P })).toThrow(ApiFault);
 });
 test('a malformed rule refuses the whole answer', () => {
  for (const bad of [view({ revision: 2 }), view({ rule_id: 'x' }), view({ retired: 'no' }), view({}, { kind: 'delete' }), view({}, { interval_seconds: -1 }), view({}, { interval_seconds: 1.5 }), view({}, { labels: 'env=prod' })]) {
   expect(() => parseRuleList(list({ rules: [bad] }), { org: A, project: P })).toThrow(ApiFault);
  }
  expect(() => parseRuleList(list({ can_author: 'yes' }), { org: A, project: P })).toThrow(ApiFault);
 });
 test('a field the page does not show is dropped', () => {
  const v = parseRuleView(view({ secret: 'LEAK' }, { owner: 'LEAK' }));
  expect(JSON.stringify(v)).not.toContain('LEAK');
 });
});

describe('a draft becomes the closed wire definition, or one sentence says what to fix', () => {
 const draft = { ...emptyRuleDraft(profiles), expression: ' up == 0 ' };
 test('the default draft is the metric language with its first feature set', () => {
  expect(emptyRuleDraft(profiles)).toMatchObject({ kind: 'alert', profile: 'promql-prometheus-3.13.5', featureSet: 'p1', intervalSeconds: '60' });
  expect(emptyRuleDraft([])).toMatchObject({ profile: '', featureSet: '' });
 });
 test('an alert rule', () => {
  expect(buildRuleSpec({ ...draft, forSeconds: '120', holdSeconds: '60', severity: 'critical', missingData: 'error' }, profiles)).toEqual({
   ok: true, value: { kind: 'alert', profile: 'promql-prometheus-3.13.5', feature_set: 'p1', expression: 'up == 0', interval_seconds: 60, for_seconds: 120, recovery_hold_seconds: 60, missing_data: 'error', severity: 'critical' },
  });
 });
 test('a recording rule carries its metric name and sorted labels, and no alert field', () => {
  const built = buildRuleSpec({ ...draft, kind: 'recording', recordName: 'job:up:sum', labels: 'env = prod\n\nclass=web' }, profiles);
  expect(built).toEqual({ ok: true, value: { kind: 'recording', profile: 'promql-prometheus-3.13.5', feature_set: 'p1', expression: 'up == 0', interval_seconds: 60, record_name: 'job:up:sum', labels: [{ name: 'class', value: 'web' }, { name: 'env', value: 'prod' }] } });
  expect(JSON.stringify(built)).not.toContain('severity');
 });
 test('what is plainly wrong is refused before anything is sent', () => {
  const refused = (d: Partial<typeof draft>): boolean => !buildRuleSpec({ ...draft, ...d }, profiles).ok;
  expect(refused({ profile: 'promql-prometheus-9.9.9' })).toBe(true);
  expect(refused({ featureSet: 'l1' })).toBe(true); // a feature set of another profile
  expect(refused({ expression: '   ' })).toBe(true);
  expect(refused({ expression: 'x'.repeat(65537) })).toBe(true);
  for (const interval of ['0', '86401', '1.5', '-5', '', 'abc', '60 s']) expect(refused({ intervalSeconds: interval })).toBe(true);
  expect(refused({ forSeconds: '2592001' })).toBe(true);
  expect(refused({ holdSeconds: '-1' })).toBe(true);
  expect(refused({ severity: 'catastrophic' })).toBe(true);
  expect(refused({ missingData: 'ignore' })).toBe(true);
  expect(refused({ kind: 'recording', recordName: '' })).toBe(true);
  expect(refused({ kind: 'recording', recordName: '9lives' })).toBe(true);
  expect(refused({ kind: 'recording', recordName: 'ok', labels: 'env' })).toBe(true);
  expect(refused({ kind: 'recording', recordName: 'ok', labels: 'env=a\nenv=b' })).toBe(true);
  expect(refused({ kind: 'recording', recordName: 'ok', labels: '__name__=x' })).toBe(true);
 });
 test('a rule round-trips through its draft', () => {
  const v = parseRuleView(view({}, { for_seconds: 30, severity: 'warning' }));
  const built = buildRuleSpec(ruleDraftOf(v), profiles);
  expect(built.ok && built.value).toMatchObject({ kind: 'alert', expression: 'up == 0', for_seconds: 30, severity: 'warning', interval_seconds: 60 });
  const recording: RuleView = { ...v, rule: { kind: 'recording', profile: 'promql-prometheus-3.13.5', feature_set: 'p1', expression: 'sum(up)', interval_seconds: 60, record_name: 'job:up:sum', labels: [{ name: 'env', value: 'prod' }] } };
  expect(parseLabelLines(ruleDraftOf(recording).labels)).toEqual({ ok: true, value: [{ name: 'env', value: 'prod' }] });
 });
});

describe('the reason and the replay window', () => {
 test('a reason of 1 to 512 bytes without control characters', () => {
  expect(validRuleReason('stop the page')).toBe(true);
  for (const reason of ['', 'x'.repeat(513), 'a\u0000b', 'é'.repeat(257)]) expect(validRuleReason(reason)).toBe(false);
 });
 test('a UTC time is converted to exact nanoseconds, anything else is refused', () => {
  expect(utcToNs('1970-01-01T00:01Z')).toBe('60000000000');
  expect(utcToNs('2026-11-15T10:00:00Z')).toBe('1794736800000000000');
  for (const bad of ['', 'yesterday', '2026-11-15 10:00Z', '2026-11-15T10:00', '2026-13-45T10:00Z', '1969-12-31T23:59Z']) expect(utcToNs(bad)).toBeNull();
 });
});

const original = globalThis.fetch;
afterEach(() => { globalThis.fetch = original; });
const answer = (body: unknown, status = 200): Response => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const spec = { kind: 'alert' as const, profile: 'promql-prometheus-3.13.5', feature_set: 'p1', expression: 'up == 0', interval_seconds: 60, severity: 'critical' };
const save = { org: A, project: P, command: C, rule: R, expected_revision: '1', reason: 'tighten', spec };

describe('the requests', () => {
 test('a list names only the project', async () => {
  let body: unknown;
  globalThis.fetch = ((_: RequestInfo | URL, init?: RequestInit) => { body = JSON.parse(String(init?.body)); return Promise.resolve(answer(list())); }) as typeof fetch;
  expect((await listRules(A, P, new AbortController().signal)).rules).toHaveLength(1);
  expect(body).toEqual({ org: A, project_id: P, operation: 'list' });
 });
 test('a save carries the command, the revision it read, the reason and the rule; only a committed answer is a save', async () => {
  let body: unknown;
  globalThis.fetch = ((_: RequestInfo | URL, init?: RequestInit) => { body = JSON.parse(String(init?.body)); return Promise.resolve(answer({ state: 'committed', rule: view({ revision: '2' }) })); }) as typeof fetch;
  expect((await saveRule(save, new AbortController().signal)).revision).toBe('2');
  expect(body).toEqual({ org: A, project_id: P, operation: 'save', command_id: C, rule_id: R, expected_revision: '1', reason: 'tighten', rule: spec });
  globalThis.fetch = (() => Promise.resolve(answer({ state: 'pending', rule: view() }))) as typeof fetch;
  await expect(saveRule(save, new AbortController().signal)).rejects.toBeInstanceOf(ApiFault);
 });
 test('a committed answer for another rule is refused', async () => {
  globalThis.fetch = (() => Promise.resolve(answer({ state: 'committed', rule: view({ rule_id: Q }) }))) as typeof fetch;
  await expect(saveRule(save, new AbortController().signal)).rejects.toBeInstanceOf(ApiFault);
  await expect(retireRule({ org: A, project: P, command: C, rule: R, expected_revision: '2', reason: 'stop' }, new AbortController().signal)).rejects.toBeInstanceOf(ApiFault);
 });
 test('a retirement names the revision it read', async () => {
  let body: unknown;
  globalThis.fetch = ((_: RequestInfo | URL, init?: RequestInit) => { body = JSON.parse(String(init?.body)); return Promise.resolve(answer({ state: 'committed', rule: view({ retired: true, revision: '3' }) })); }) as typeof fetch;
  expect((await retireRule({ org: A, project: P, command: C, rule: R, expected_revision: '2', reason: 'stop' }, new AbortController().signal)).retired).toBe(true);
  expect(body).toEqual({ org: A, project_id: P, operation: 'retire', command_id: C, rule_id: R, expected_revision: '2', reason: 'stop' });
 });
 test('a replay declaration carries the window as exact nanoseconds and no command ID', async () => {
  let body: unknown;
  globalThis.fetch = ((_: RequestInfo | URL, init?: RequestInit) => { body = JSON.parse(String(init?.body)); return Promise.resolve(answer({ state: 'committed', rule_id: R, from_ns: '1', to_ns: '2' })); }) as typeof fetch;
  await declareReplay({ org: A, project: P, rule: R, reason: 'outage', from_ns: '1794736800000000000', to_ns: '1794740400000000000' }, new AbortController().signal);
  expect(body).toEqual({ org: A, project_id: P, operation: 'replay', rule_id: R, reason: 'outage', replay: { from_ns: '1794736800000000000', to_ns: '1794740400000000000' } });
 });
 test('a 409 and a 404 are faults with their status; a transport failure is an unknown outcome, an abort is not', async () => {
  for (const status of [409, 404, 400]) {
   globalThis.fetch = (() => Promise.resolve(answer({ code: 'conflict', detail: 'rule_definition_conflict', request_id: 'f'.repeat(32) }, status))) as typeof fetch;
   await expect(saveRule(save, new AbortController().signal)).rejects.toMatchObject({ status });
  }
  globalThis.fetch = (() => Promise.reject(new TypeError('network down'))) as typeof fetch;
  await expect(saveRule(save, new AbortController().signal)).rejects.toBeInstanceOf(OutcomeUnknown);
  globalThis.fetch = (() => Promise.reject(new DOMException('aborted', 'AbortError'))) as typeof fetch;
  await expect(saveRule(save, new AbortController().signal)).rejects.not.toBeInstanceOf(OutcomeUnknown);
 });
});
