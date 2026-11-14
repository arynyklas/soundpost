// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import type { IncidentView } from '../api/types';
import { availableActions, buildRequest, deliveryEntryText, deliveryHeadline, digestText, emptyDraft, faultText, msUntilExpiry, newCommandId, rateText, responseWords, splitTimeline, unreadText, urgencyText } from './model';

const A = 'a'.repeat(32), P = '1'.repeat(32), I = '2'.repeat(32), C = '3'.repeat(32), E = '4'.repeat(32), U = '5'.repeat(32);
const view = (over: Partial<IncidentView> = {}): IncidentView => ({
 incident_id: I, org: A, project_id: P, version: '7', status: 'open', condition: { id: C, state: 'firing', freshness: 'fresh', observed_at: '1700000000000000000' }, episode_id: E, severity: 'major', impact_revision: '1', source_firing: true,
 notification: { reminders_paused: false, worse_impact_eligible: true, urgency: { state: 'empty', reason: 'no_notification_policy_state' }, delivery: { state: 'empty', reason: 'no_delivery_created', attention: 'none' }, digest: { state: 'empty', reason: 'no_notification_policy_state', sent: 0 }, unread_change: { state: 'empty', reason: 'no_notification_policy_state', changed: false, queue_revision: '0', seen_revision: '0' } }, links: [], observed_impacts: 1, last_activity: '1700000000000000000', ...over,
});
const id = 'c'.repeat(32);
const now = 1_700_000_000_123;

describe('requests carry only what the user chose', () => {
 test('revision, scope and target come from the incident being viewed; no actor, origin or timestamp field exists', () => {
  const built = buildRequest(view(), { ...emptyDraft('ack'), reason: ' on it ' }, id, now);
  if (!built.ok) throw new Error(built.error);
  expect(built.request).toEqual({ org: A, command_id: id, expected_version: '7', project_id: P, target_id: I, entity_kind: 'incident', kind: 'ack', payload: { reason: 'on it' } });
  expect(JSON.stringify(built.request)).not.toMatch(/actor|origin|principal|at"/);
 });
 test('resolve needs a reason, and a reason may not smuggle control characters', () => {
  expect(buildRequest(view(), emptyDraft('resolve'), id, now).ok).toBe(false);
  expect(buildRequest(view(), { ...emptyDraft('resolve'), reason: '   ' }, id, now).ok).toBe(false);
  expect(buildRequest(view(), { ...emptyDraft('ack'), reason: 'a\u0007b' }, id, now).ok).toBe(false);
  expect(buildRequest(view(), { ...emptyDraft('ack'), reason: 'é'.repeat(257) }, id, now).ok).toBe(false);
  expect(buildRequest(view(), { ...emptyDraft('resolve'), reason: 'rolled back' }, id, now).ok).toBe(true);
 });
 test('assign: a valid ID, or empty to unassign only when an owner exists', () => {
  const owner = buildRequest(view(), { ...emptyDraft('assign'), owner: U }, id, now);
  expect(owner.ok && owner.request.payload.owner).toBe(U);
  expect(buildRequest(view(), { ...emptyDraft('assign'), owner: 'not-an-id' }, id, now).ok).toBe(false);
  expect(buildRequest(view(), emptyDraft('assign'), id, now).ok).toBe(false);
  const removal = buildRequest(view({ owner: U }), emptyDraft('assign'), id, now);
  expect(removal.ok && 'owner' in removal.request.payload).toBe(false);
 });
 test('snooze and maintenance end exactly the chosen number of minutes after now, in exact nanoseconds', () => {
  const built = buildRequest(view(), { ...emptyDraft('snooze'), reason: 'flapping', minutes: 60 }, id, now);
  expect(built.ok && built.request.payload.until).toBe(String((BigInt(now) + 3_600_000n) * 1_000_000n));
  expect(buildRequest(view(), { ...emptyDraft('maintenance'), reason: 'x', minutes: 7 }, id, now).ok).toBe(false);
 });
 test('recovery cannot be reported from stale or unknown data', () => {
  for (const freshness of ['stale', 'unknown'] as const) expect(buildRequest(view(), { ...emptyDraft('impact'), state: 'recovered', freshness }, id, now).ok).toBe(false);
  const worse = buildRequest(view(), { ...emptyDraft('impact'), severity: 'critical' }, id, now);
  expect(worse.ok && worse.request.payload.impact).toEqual({ condition: C, episode: E, severity: 'critical', state: 'firing', freshness: 'fresh' });
 });
 test('link needs a well formed ID', () => {
  expect(buildRequest(view(), { ...emptyDraft('link'), linkId: 'x' }, id, now).ok).toBe(false);
  const ok = buildRequest(view(), { ...emptyDraft('link'), linkKind: 'release', linkId: U }, id, now);
  expect(ok.ok && ok.request.payload.link).toEqual({ kind: 'release', id: U });
 });
 test('command IDs are random 128-bit hex and never repeat', () => {
  const ids = new Set(Array.from({ length: 50 }, newCommandId));
  expect(ids.size).toBe(50);
  for (const v of ids) expect(v).toMatch(/^[0-9a-f]{32}$/);
 });
});

describe('what the workspace offers and says', () => {
 test('a resolved incident accepts nothing; windows can only be ended while active', () => {
  expect(availableActions(view({ status: 'resolved' }))).toEqual([]);
  expect(availableActions(view())).toEqual(['assign', 'ack', 'resolve', 'link', 'impact', 'snooze', 'maintenance']);
  const active = { actor: U, reason: 'r', from: '1', until: '9', version: '2', active: true };
  expect(availableActions(view({ snooze: active, maintenance: active }))).toEqual(['assign', 'ack', 'resolve', 'link', 'impact', 'unsnooze', 'maintenance_end']);
  expect(availableActions(view({ ack: { actor: U, at: '1', impact_revision: '1', version: '2', current: true } }))).not.toContain('ack');
  expect(availableActions(view({ ack: { actor: U, at: '1', impact_revision: '1', version: '2', current: false } }))).toContain('ack');
 });
 test('a missing denominator is rate unknown with the observed count and freshness, never a percentage', () => {
  const text = rateText(view({ observed_impacts: 3 }), (ns) => `T${ns}`);
  expect(text).toContain('Rate unknown');
  expect(text).toContain('3 impact observations');
  expect(text).toContain('fresh data');
  expect(text).toContain('T1700000000000000000');
  expect(text).not.toMatch(/\d\s*%/);
  expect(rateText(view({ observed_impacts: 1, condition: { id: C, state: 'unknown', freshness: 'stale', observed_at: '5' } }), (ns) => ns)).toContain('1 impact observation;');
 });
 test('ack is worded as current or as covering an earlier impact only', () => {
  expect(responseWords(view({ ack: { actor: U, at: '1', impact_revision: '1', version: '2', current: true } }))).toContain('Acknowledged for the current impact');
  expect(responseWords(view({ ack: { actor: U, at: '1', impact_revision: '1', version: '2', current: false } })).join(' ')).toContain('worsened');
  expect(responseWords(view({ status: 'resolved' }))[0]).toBe('Resolved by a person');
 });
 test('the timeline splits the source observations from the person actions', () => {
  const e = (type: string, n: number) => ({ version: String(n), at: '1', type, origin: 'human' as const, actor: U });
  const split = splitTimeline([e('open', 1), e('assign', 2), e('impact', 3), e('ack', 4)]);
  expect(split.condition.map((x) => x.type)).toEqual(['open', 'impact']);
  expect(split.response.map((x) => x.type)).toEqual(['assign', 'ack']);
 });
 test('expiry is the earliest active window and never negative', () => {
  expect(msUntilExpiry(view(), now)).toBeNull();
  const w = (until: number, active: boolean) => ({ actor: U, reason: 'r', from: '1', until: String(BigInt(until) * 1_000_000n), version: '2', active });
  expect(msUntilExpiry(view({ snooze: w(now + 5000, true), maintenance: w(now + 1000, true) }), now)).toBe(1000);
  expect(msUntilExpiry(view({ snooze: w(now - 5000, true) }), now)).toBe(0);
  expect(msUntilExpiry(view({ snooze: w(now + 5000, false) }), now)).toBeNull();
 });
 test('fault text: denied and missing are one message, unknown details are never echoed', () => {
  expect(faultText('x', 403)).toBe(faultText('y', 404));
  expect(faultText('<img src=x onerror=alert(1)>', 400)).not.toContain('<');
  expect(faultText('incident_resolved', 409)).toContain('resolved');
  expect(faultText('', 401)).toContain('session');
 });
});

describe('notification words never soften a failed or uncertain delivery', () => {
 const fmt = (ns: string): string => `t${ns}`;
 const entry = { id: C, kind: 'worse_impact', route: 'immediate', phase: 'pending', status: 'uncertain' as const, attempts: 2, last_outcome: 'unknown', last_code: 'timeout', last_at: '9', eligible_at: '5', uncertain: true, possible_duplicate: true };
 test('uncertain says the provider may have accepted it, and duplicates are named', () => {
  const text = deliveryEntryText(entry, fmt);
  expect(text).toContain('worse impact (immediate): uncertain: the provider may have accepted a message the product could not confirm');
  expect(text).toContain('2 attempts; last attempt unknown (timeout) at t9');
  expect(text).toContain('more than once');
  expect(text).not.toMatch(/accepted by the provider/);
 });
 test('the headline follows the most urgent attention and a failure is never called accepted', () => {
  expect(deliveryHeadline({ state: 'ready', attention: 'failed' })).toBe('Delivery failed');
  expect(deliveryHeadline({ state: 'ready', attention: 'uncertain' })).toContain('may have accepted');
  expect(deliveryHeadline({ state: 'ready', attention: 'pending' })).toBe('Delivery pending');
  expect(deliveryHeadline({ state: 'not_available', reason: 'notification_outbox_not_wired' })).toContain('not wired');
 });
 test('urgency, digest and unread come from the policy; no policy means no invented tier', () => {
  expect(urgencyText({ state: 'ready', tier: 'urgent', mode: 'active' })).toBe('Urgency: urgent, notifies immediately');
  expect(urgencyText({ state: 'ready', tier: 'queue', mode: 'shadow' })).toContain('shadow mode: nothing leaves the product');
  expect(urgencyText({ state: 'empty', reason: 'no_notification_policy_state' })).toContain('No notification policy has evaluated');
  expect(digestText({ state: 'ready', pending: true, next_at: '7', sent: 1 }, fmt)).toBe('Digest: not covered by a digest yet, but already visible here; next digest t7; 1 digest accepted');
  expect(digestText({ state: 'ready', next_at: '0', sent: 0 }, fmt)).toContain('next digest not scheduled');
  expect(unreadText({ state: 'ready', changed: true, queue_revision: '4', seen_revision: '1' })).toContain('changed since the last digest covered it');
  expect(unreadText({ state: 'ready', changed: false, queue_revision: '4', seen_revision: '4' })).toBe('Unread change: none since the last digest');
 });
});
