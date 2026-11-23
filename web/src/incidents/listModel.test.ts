// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import type { IncidentView } from '../api/types';
import { agoWords, chipCounts, hasOutdatedAck, incidentTitle, isUnacknowledged, matchesChip, matchesSearch, nextStep, summarize } from './listModel';

const A = 'a'.repeat(32), P = '1'.repeat(32), C = '3'.repeat(32), E = '4'.repeat(32), U = '5'.repeat(32);
const idN = (n: number): string => n.toString(16).padStart(32, '0');
const view = (over: Partial<IncidentView> = {}): IncidentView => ({
 incident_id: idN(1), org: A, project_id: P, version: '3', status: 'open', condition: { id: C, state: 'firing', freshness: 'fresh', observed_at: '1700000000000000000' }, episode_id: E, severity: 'major', impact_revision: '1', source_firing: true,
 notification: { reminders_paused: false, worse_impact_eligible: true, urgency: { state: 'empty', reason: 'no_notification_policy_state' }, delivery: { state: 'empty', reason: 'no_delivery_created', attention: 'none' }, digest: { state: 'empty', reason: 'no_notification_policy_state', sent: 0 }, unread_change: { state: 'empty', reason: 'no_notification_policy_state', changed: false, queue_revision: '0', seen_revision: '0' } },
 links: [], observed_impacts: 1, last_activity: '1700000000000000000', ...over,
});
const withDelivery = (attention: 'failed' | 'uncertain' | 'accepted'): Partial<IncidentView> => ({
 ack: { actor: U, at: '1', impact_revision: '1', version: '2', current: true },
 notification: { ...view().notification, delivery: { state: 'ready', attention, counts: {}, entries: [] } },
});
const acked = { ack: { actor: U, at: '1', impact_revision: '1', version: '2', current: true } } satisfies Partial<IncidentView>;

describe('the title is the server title or the console fallback', () => {
 test('a title that was never set (or only spaces) falls back to the short ID', () => {
  expect(incidentTitle(view())).toBe(`Incident ${idN(1).slice(0, 8)}…`);
  expect(incidentTitle(view({ title: '   ' }))).toBe(`Incident ${idN(1).slice(0, 8)}…`);
  expect(incidentTitle(view({ title: 'Checkout p95 latency' }))).toBe('Checkout p95 latency');
 });
});

describe('next step', () => {
 test('an unacknowledged open incident needs an acknowledgement; a current ack, a snooze or maintenance covers it', () => {
  expect(nextStep(view())?.id).toBe('acknowledge');
  expect(nextStep(view(acked))).toBeNull();
  expect(nextStep(view({ snooze: { actor: U, reason: 'r', from: '1', until: '9', version: '2', active: true } }))).toBeNull();
  expect(nextStep(view({ maintenance: { actor: U, reason: 'r', from: '1', until: '9', version: '2', active: true } }))).toBeNull();
 });
 test('an acknowledgement that predates a worse impact no longer covers it', () => {
  const stale = view({ ack: { actor: U, at: '1', impact_revision: '1', version: '2', current: false }, impact_revision: '2' });
  expect(isUnacknowledged(stale)).toBe(true);
  expect(hasOutdatedAck(stale)).toBe(true);
  expect(nextStep(stale)?.id).toBe('acknowledge');
 });
 test('a failed or uncertain delivery is the next step once acknowledged; an accepted one is not', () => {
  expect(nextStep(view(withDelivery('failed')))?.label).toBe('Check delivery');
  expect(nextStep(view(withDelivery('uncertain')))?.id).toBe('delivery');
  expect(nextStep(view(withDelivery('accepted')))).toBeNull();
 });
 test('a recovered source with fresh data is closed by resolving; stale data is unknown, not recovered', () => {
  const recovered = { ...acked, condition: { id: C, state: 'recovered' as const, freshness: 'fresh' as const, observed_at: '1' }, source_firing: false };
  expect(nextStep(view(recovered))?.id).toBe('resolve');
  expect(nextStep(view({ ...recovered, condition: { ...recovered.condition, freshness: 'stale' } }))).toBeNull();
 });
 test('a resolved incident has no next step', () => { expect(nextStep(view({ status: 'resolved' }))).toBeNull(); });
});

describe('the figures are counted from the loaded entries', () => {
 const entries = [
  view({ incident_id: idN(1), severity: 'critical' }),
  view({ incident_id: idN(2), ...withDelivery('failed'), owner: U }),
  view({ incident_id: idN(3), ...withDelivery('uncertain') }),
  view({ incident_id: idN(4), ...acked }),
  view({ incident_id: idN(5), status: 'resolved', ...withDelivery('failed') }),
 ];
 test('summary', () => {
  const s = summarize(entries);
  expect(s).toMatchObject({ open: 4, needsAction: 3, unacknowledged: 1, outdatedAck: 0, loaded: 5 });
  expect(s.delivery).toEqual({ failed: 1, uncertain: 1, unstated: 2 });
 });
 test('a resolved incident with a failed delivery is not an open delivery problem', () => {
  expect(matchesChip(entries[4]!, 'delivery', undefined)).toBe(false);
  expect(matchesChip(entries[4]!, 'resolved', undefined)).toBe(true);
 });
 test('every chip count equals the number of rows the chip shows', () => {
  const counts = chipCounts(entries, U);
  expect(counts).toEqual({ all: 5, open: 4, needs: 3, critical: 1, mine: 1, unassigned: 3, delivery: 2, resolved: 1 });
  for (const chip of Object.keys(counts) as (keyof typeof counts)[]) expect(entries.filter((v) => matchesChip(v, chip, U)).length).toBe(counts[chip]);
 });
 test('"assigned to me" is empty when the account is unknown, never everything', () => { expect(chipCounts(entries, undefined).mine).toBe(0); });
});

describe('search and age', () => {
 const v = view({ title: 'Checkout p95 latency', owner: U });
 test('every word must match something the row shows', () => {
  const labels = { project: 'storefront-web', owner: 'Ravi Patel' };
  expect(matchesSearch(v, 'checkout ravi', labels)).toBe(true);
  expect(matchesSearch(v, 'STOREFRONT', labels)).toBe(true);
  expect(matchesSearch(v, 'checkout payments', labels)).toBe(false);
  expect(matchesSearch(v, '   ', labels)).toBe(true);
  expect(matchesSearch(v, v.incident_id.slice(0, 6), labels)).toBe(true);
 });
 test('ago words', () => {
  const now = 1_700_000_000_000 + 58 * 60_000;
  expect(agoWords('1700000000000000000', now)).toBe('58 min ago');
  expect(agoWords('1700000000000000000', now + 3_600_000)).toBe('1 h 58 min ago');
  expect(agoWords('1700000000000000000', 1_700_000_000_000 + 3 * 86_400_000)).toBe('3 d ago');
  expect(agoWords('1700000000000000000', 1_699_999_000_000)).toBe('just now');
 });
});
