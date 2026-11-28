// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, test } from 'bun:test';
import { getPolicies, parsePolicyView, writePolicy } from '../api/client';
import { ApiFault, OutcomeUnknown, type NotificationPolicyView, type PolicyView } from '../api/types';
import { basisPointsText, buildDestination, buildNotification, buildRetention, describeWriteFailure, durationWords, notificationChanged, notificationDraft, percentToBasisPoints, secondsText, secondsToNs, validEndpoint, validReason } from './policy';

const A = 'a'.repeat(32), B = 'b'.repeat(32), P = '1'.repeat(32), Q = '2'.repeat(32), D = '3'.repeat(32);
const notification = (over: Partial<NotificationPolicyView> = {}): NotificationPolicyView => ({ source: 'default', revision: '1', min_operations: 20, min_failures: 5, rate_basis_points: 500, regression_min: 5, critical_codes: [], first_reminder_ns: '900000000000', reminder_every_ns: '3600000000000', max_suppression_ns: '604800000000000', default_zone: '', ...over });
const view = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ org: A, project_id: P, revision: '12', manage_destinations: false, notification: notification(), destinations: [], retention: [], ...over });

describe('durations and rates are exact', () => {
 test('seconds round-trip without floating point', () => {
  expect(secondsText('900000000000')).toBe('900');
  expect(secondsText('1500000000')).toBe('1.5');
  expect(secondsText('1')).toBe('0.000000001');
  expect(secondsToNs('900')).toBe('900000000000');
  expect(secondsToNs('1.5')).toBe('1500000000');
  expect(secondsToNs('0.000000001')).toBe('1');
 });
 test('anything that is not a plain non-negative decimal is refused', () => {
  for (const bad of ['', '-1', '1e3', '1.0000000001', ' ', 'abc', '1,5', '99999999999']) expect(secondsToNs(bad)).toBeNull();
 });
 test('words state a duration in whole units, else in seconds', () => {
  expect(durationWords('900000000000')).toBe('15 minutes');
  expect(durationWords('604800000000000')).toBe('7 days');
  expect(durationWords('5400000000000')).toBe('1 hour 30 minutes');
  expect(durationWords('1500000000')).toBe('1.5 seconds');
 });
 test('rates are basis points with at most two places', () => {
  expect(basisPointsText(500)).toBe('5');
  expect(basisPointsText(725)).toBe('7.25');
  expect(basisPointsText(705)).toBe('7.05');
  expect(percentToBasisPoints('7.25')).toBe(725);
  expect(percentToBasisPoints('100')).toBe(10000);
  for (const bad of ['0', '100.01', '101', '-1', '1.234', '', 'x']) expect(percentToBasisPoints(bad)).toBeNull();
 });
});

describe('the notification policy form', () => {
 const base = notificationDraft(notification());
 test('the default policy round-trips unchanged', () => {
  const built = buildNotification(base);
  expect(built.ok && built.value).toEqual({ min_operations: 20, min_failures: 5, rate_basis_points: 500, regression_min: 5, critical_codes: [], first_reminder_ns: '900000000000', reminder_every_ns: '3600000000000', max_suppression_ns: '604800000000000', default_zone: '' });
  expect(notificationChanged(base, notification())).toBe(false);
 });
 test('an edit is a change, codes are sorted and de-duplicated', () => {
  const draft = { ...base, minFailures: '9', criticalCodes: 'payment_failed, auth_down  auth_down', defaultZone: 'Asia/Almaty' };
  const built = buildNotification(draft);
  expect(built.ok && built.value.critical_codes).toEqual(['auth_down', 'payment_failed']);
  expect(built.ok && built.value.min_failures).toBe(9);
  expect(notificationChanged(draft, notification())).toBe(true);
 });
 test('every invalid field is refused with its own message', () => {
  const fields: [Partial<typeof base>, RegExp][] = [
   [{ minOperations: '0' }, /Minimum operations/], [{ minFailures: '' }, /Minimum failures/], [{ ratePercent: '0' }, /Failure rate/], [{ ratePercent: '100.5' }, /Failure rate/], [{ regressionMin: '-1' }, /Regression minimum/],
   [{ criticalCodes: 'has space!' }, /Critical codes/], [{ firstReminderSeconds: '0' }, /First reminder/], [{ reminderEverySeconds: 'x' }, /Reminder interval/],
   [{ maxSuppressionSeconds: '7776001' }, /Longest snooze/], [{ maxSuppressionSeconds: '0' }, /Longest snooze/], [{ defaultZone: 'Mars/Olympus' }, /time zone/],
  ];
  for (const [over, message] of fields) {
   const built = buildNotification({ ...base, ...over });
   expect(built.ok).toBe(false);
   expect(!built.ok && built.error).toMatch(message);
  }
 });
 test('exactly 90 days is the longest window', () => { expect(buildNotification({ ...base, maxSuppressionSeconds: '7776000' }).ok).toBe(true); });
 test('more than 32 critical codes are refused', () => { expect(buildNotification({ ...base, criticalCodes: Array.from({ length: 33 }, (_, i) => `c${i}`).join(',') }).ok).toBe(false); });
});

describe('retention and destination forms', () => {
 test('retention is a listed signal for 1 to 3650 whole days', () => {
  expect(buildRetention('logs', '30')).toEqual({ ok: true, value: { signal: 'logs', days: 30 } });
  for (const [s, d] of [['logs', '0'], ['logs', '3651'], ['logs', '1.5'], ['logs', ''], ['secrets', '5']] as const) expect(buildRetention(s, d).ok).toBe(false);
 });
 test('an endpoint is https without credentials, query or fragment', () => {
  expect(validEndpoint('https://hooks.example.test/notify')).toBe(true);
  for (const bad of ['http://hooks.example.test/', 'https://u:p@hooks.example.test/', 'https://hooks.example.test/x?token=1', 'https://hooks.example.test/#a', 'https://hooks.example.test/?', 'nope']) expect(validEndpoint(bad)).toBe(false);
 });
 test('destinations: webhook needs an endpoint, email an address; the secret is sent only when typed', () => {
  expect(buildDestination({ id: D, type: 'webhook', endpoint: 'https://h.example.test/x', address: '', enabled: true, secret: '' })).toEqual({ ok: true, value: { id: D, type: 'webhook', enabled: true, endpoint: 'https://h.example.test/x' } });
  expect(buildDestination({ id: D, type: 'webhook', endpoint: 'https://h.example.test/x', address: '', enabled: false, secret: 's3cret' })).toEqual({ ok: true, value: { id: D, type: 'webhook', enabled: false, endpoint: 'https://h.example.test/x', secret: 's3cret' } });
  expect(buildDestination({ id: D, type: 'smtp', endpoint: '', address: 'ops@example.test', enabled: true, secret: '' })).toEqual({ ok: true, value: { id: D, type: 'smtp', enabled: true, address: 'ops@example.test' } });
  for (const bad of [{ type: 'webhook', endpoint: 'https://h.example.test/x?t=1' }, { type: 'webhook', endpoint: '' }, { type: 'smtp', address: 'nobody' }, { type: 'carrier-pigeon' }]) expect(buildDestination({ id: D, type: 'webhook', endpoint: '', address: '', enabled: true, secret: '', ...bad }).ok).toBe(false);
 });
 test('a reason is 1 to 512 bytes without control characters', () => {
  expect(validReason('rotate the token')).toBe(true);
  for (const bad of ['', 'a'.repeat(513), 'line\nbreak', 'é'.repeat(257)]) expect(validReason(bad)).toBe(false);
 });
});

describe('a refused or unconfirmed write is described, never softened', () => {
 test('each status says what it means and that nothing changed', () => {
  expect(describeWriteFailure(new ApiFault(409, 'conflict', '', 'conflict')).kind).toBe('conflict');
  expect(describeWriteFailure(new ApiFault(409, 'conflict', '', 'conflict')).text).toContain('nothing was changed');
  expect(describeWriteFailure(new ApiFault(403, 'forbidden', '', '')).text).toContain('last five minutes');
  expect(describeWriteFailure(new ApiFault(404, 'not_found', '', '')).kind).toBe('not_found');
  expect(describeWriteFailure(new ApiFault(400, 'invalid', '', 'notification_policy_invalid')).text).toContain('notification policy invalid');
  expect(describeWriteFailure(new ApiFault(400, 'invalid', '', 'invalid')).text).not.toContain('(invalid)');
  expect(describeWriteFailure(new ApiFault(401, 'unauthenticated', '', '')).kind).toBe('signed_out');
  expect(describeWriteFailure(new ApiFault(503, 'unavailable', '', '')).kind).toBe('failed');
 });
 test('an unknown outcome is not "nothing changed"', () => {
  const f = describeWriteFailure(new OutcomeUnknown());
  expect(f.kind).toBe('unknown_outcome');
  expect(f.text).toContain('may or may not have been applied');
  expect(f.text).not.toContain('Nothing was changed');
 });
});

describe('the policy view is accepted only for the scope it was requested for', () => {
 const want = { org: A, project: P };
 test('matching', () => { expect(parsePolicyView(view(), want).notification.min_operations).toBe(20); });
 test('another organization or project is refused', () => {
  expect(() => parsePolicyView(view(), { org: B, project: P })).toThrow(ApiFault);
  expect(() => parsePolicyView(view(), { org: A, project: Q })).toThrow(ApiFault);
 });
 test('a revision that is not a decimal string is refused', () => { expect(() => parsePolicyView(view({ revision: 12 }), want)).toThrow(ApiFault); });
 test('a destination keeps only the fields a page shows: a secret that should not have been sent is dropped', () => {
  const v = parsePolicyView(view({ destinations: [{ id: D, type: 'webhook', endpoint_host: 'h.example.test', enabled: true, has_secret: true, secret: 'LEAK', endpoint: 'https://h.example.test/TOKEN' }] }), want);
  expect(JSON.stringify(v)).not.toContain('LEAK');
  expect(JSON.stringify(v)).not.toContain('TOKEN');
  expect(v.destinations[0]).toEqual({ id: D, type: 'webhook', endpoint_host: 'h.example.test', enabled: true, has_secret: true });
 });
 test('a malformed destination, retention or notification is refused', () => {
  expect(() => parsePolicyView(view({ destinations: [{ id: 'x', type: 'webhook', enabled: true, has_secret: true }] }), want)).toThrow(ApiFault);
  expect(() => parsePolicyView(view({ retention: [{ signal: 'logs', days: -1 }] }), want)).toThrow(ApiFault);
  expect(() => parsePolicyView(view({ notification: notification({ source: 'other' as 'default' }) }), want)).toThrow(ApiFault);
 });
});

const original = globalThis.fetch;
afterEach(() => { globalThis.fetch = original; });
const answer = (body: unknown, status = 200): Response => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const request = { org: A, project_id: P, command_id: 'c'.repeat(32), expected_revision: '12', reason: 'tighten', change: { kind: 'retention' as const, retention: { signal: 'logs', days: 30 } } };

describe('the policy client', () => {
 test('a read posts only the selectors and operation', async () => {
  let body: unknown;
  globalThis.fetch = ((_: RequestInfo | URL, init?: RequestInit) => { body = JSON.parse(String(init?.body)); return Promise.resolve(answer(view())); }) as typeof fetch;
  await getPolicies(A, P, new AbortController().signal);
  expect(body).toEqual({ org: A, project_id: P, operation: 'read' });
 });
 test('a write posts the command, expected revision, reason and change', async () => {
  let body: unknown;
  globalThis.fetch = ((_: RequestInfo | URL, init?: RequestInit) => { body = JSON.parse(String(init?.body)); return Promise.resolve(answer({ state: 'committed', revision: '13', policy: view({ revision: '13' }) })); }) as typeof fetch;
  const out = await writePolicy(request, new AbortController().signal);
  expect(out.revision).toBe('13');
  expect(body).toEqual({ org: A, project_id: P, operation: 'write', command_id: 'c'.repeat(32), expected_revision: '12', reason: 'tighten', change: request.change });
 });
 test('only a committed answer is a save: another state is refused', async () => {
  globalThis.fetch = (() => Promise.resolve(answer({ state: 'not_available', revision: '13', policy: view() }))) as typeof fetch;
  await expect(writePolicy(request, new AbortController().signal)).rejects.toBeInstanceOf(ApiFault);
 });
 test('a committed answer for another project is refused', async () => {
  globalThis.fetch = (() => Promise.resolve(answer({ state: 'committed', revision: '13', policy: view({ project_id: Q }) }))) as typeof fetch;
  await expect(writePolicy(request, new AbortController().signal)).rejects.toBeInstanceOf(ApiFault);
 });
 test('a 409 and a 403 are faults with their status; nothing is returned as saved', async () => {
  for (const status of [409, 403, 404, 400]) {
   globalThis.fetch = (() => Promise.resolve(answer({ code: 'conflict', detail: 'conflict', request_id: 'f'.repeat(32) }, status))) as typeof fetch;
   await expect(writePolicy(request, new AbortController().signal)).rejects.toMatchObject({ status });
  }
 });
 test('a transport failure is an unknown outcome, an abort is not', async () => {
  globalThis.fetch = (() => Promise.reject(new TypeError('network down'))) as typeof fetch;
  await expect(writePolicy(request, new AbortController().signal)).rejects.toBeInstanceOf(OutcomeUnknown);
  globalThis.fetch = (() => Promise.reject(new DOMException('aborted', 'AbortError'))) as typeof fetch;
  await expect(writePolicy(request, new AbortController().signal)).rejects.not.toBeInstanceOf(OutcomeUnknown);
 });
});
