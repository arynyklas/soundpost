// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import type { IncidentView, TimelineEntry } from '../api/types';
import { buildTimeline, filterTimeline, laneCounts, openedAt } from './timelineModel';

const A = 'a'.repeat(32), P = '1'.repeat(32), I = '2'.repeat(32), C = '3'.repeat(32), E = '4'.repeat(32), U = '5'.repeat(32), V = '6'.repeat(32), X = '7'.repeat(32);
const NS = (min: number): string => String(BigInt(1_700_000_000_000 + min * 60_000) * 1_000_000n);
const fmt = (ns: string): string => `t${ns.slice(0, 6)}`;
const entry = (version: number, at: number, over: Partial<TimelineEntry>): TimelineEntry => ({ version: String(version), at: NS(at), type: 'ack', origin: 'human', actor: U, ...over });
const view = (timeline: TimelineEntry[], over: Partial<IncidentView> = {}): IncidentView => ({
 incident_id: I, org: A, project_id: P, version: String(timeline.length), status: 'open', condition: { id: C, state: 'firing', freshness: 'fresh', observed_at: NS(0) }, episode_id: E, severity: 'major', impact_revision: '1', source_firing: true,
 notification: { reminders_paused: false, worse_impact_eligible: true, urgency: { state: 'empty' }, delivery: { state: 'empty', reason: 'no_delivery_created', attention: 'none' }, digest: { state: 'empty', sent: 0 }, unread_change: { state: 'empty', changed: false, queue_revision: '0', seen_revision: '0' } },
 links: [], observed_impacts: 1, last_activity: NS(0), timeline, ...over,
});
const OPEN = entry(1, 0, { type: 'open', origin: 'system', actor: V, impact: { condition: C, episode: E, severity: 'major', state: 'firing', freshness: 'fresh' } });

describe('lanes come from what each entry is', () => {
 const t = view([
  OPEN,
  entry(2, 1, { type: 'assign', owner: X }),
  entry(3, 2, { type: 'link', link: { kind: 'issue', id: X } }),
  entry(4, 3, { type: 'link', link: { kind: 'release', id: X } }),
  entry(5, 4, { type: 'link', link: { kind: 'service', id: X } }),
  entry(6, 5, { type: 'note', note: 'Rolled back\ncanary' }),
  entry(7, 6, { type: 'impact', origin: 'system', actor: V, impact: { condition: C, episode: E, severity: 'critical', state: 'firing', freshness: 'fresh' } }),
 ]);
 const items = buildTimeline(t, fmt);
 test('source observations are the Alert lane and carry no person', () => {
  const alerts = items.filter((i) => i.lane === 'alert');
  expect(alerts.map((i) => i.type)).toEqual(['impact', 'open']);
  expect(alerts.every((i) => i.actor === undefined && i.system)).toBe(true);
  expect(alerts[0]?.text).toContain('severity critical, source firing, fresh data');
 });
 test('a linked issue is an error, a linked release a deploy, any other link and every action a person', () => {
  const lane = (type: string, id?: string): string | undefined => items.find((i) => i.type === type && (id === undefined || i.text.includes(id.slice(0, 8))))?.lane;
  expect(items.find((i) => i.text.startsWith('linked issue'))?.lane).toBe('error');
  expect(items.find((i) => i.text.startsWith('linked release'))?.lane).toBe('deploy');
  expect(items.find((i) => i.text.startsWith('linked service'))?.lane).toBe('person');
  expect(lane('assign')).toBe('person');
  expect(lane('note')).toBe('person');
 });
 test('a note keeps its text verbatim, as a quote, and is tagged Note', () => {
  const n = items.find((i) => i.type === 'note');
  expect(n?.quote).toBe('Rolled back\ncanary');
  expect(n?.tag).toBe('Note');
  expect(n?.text).toBe('added a note');
 });
 test('newest first, and every entry is there', () => {
  expect(items.map((i) => i.version)).toEqual(['7', '6', '5', '4', '3', '2', '1']);
 });
 test('counts equal what each filter shows; Everything is all of them', () => {
  const counts = laneCounts(items);
  expect(counts).toEqual({ all: 7, person: 3, alert: 2, error: 1, deploy: 1, notification: 0 });
  for (const lane of ['person', 'alert', 'error', 'deploy', 'notification'] as const) expect(filterTimeline(items, lane).length).toBe(counts[lane]);
  expect(filterTimeline(items, 'all').length).toBe(7);
 });
 test('the incident opened at its first entry', () => { expect(openedAt(t)).toBe(NS(0)); });
});

describe('words of each action', () => {
 const word = (e: TimelineEntry): string => buildTimeline(view([OPEN, e]), fmt).find((i) => i.version === e.version)!.text;
 test('assign, unassign, ack, resolve', () => {
  expect(word(entry(2, 1, { type: 'assign', owner: X }))).toBe('assigned');
  expect(buildTimeline(view([OPEN, entry(2, 1, { type: 'assign', owner: X })]), fmt)[0]?.owner).toBe(X);
  expect(word(entry(2, 1, { type: 'assign' }))).toBe('removed the owner');
  expect(word(entry(2, 1, { type: 'ack' }))).toBe('acknowledged');
  expect(word(entry(2, 1, { type: 'resolve', reason: 'fixed' }))).toBe('resolved the incident');
 });
 test('a reason is quoted, a snooze names its end', () => {
  const s = buildTimeline(view([OPEN, entry(2, 1, { type: 'snooze', until: NS(60), reason: 'flapping' })]), fmt)[0];
  expect(s?.quote).toBe('flapping');
  expect(s?.text).toContain('until t');
 });
 test('a title entry names the title; a GitLab link entry names the GitLab issue', () => {
  expect(word(entry(2, 1, { type: 'title', title: 'Checkout down' }))).toBe('set the title to “Checkout down”');
  const link = { ...entry(2, 1, { type: 'external_end' }), external_link: { url: 'https://git.example.test/shop/web/-/issues/7', gitlab_project: 'shop/web', iid: 7 } } as TimelineEntry;
  expect(word(link)).toBe('linked GitLab issue shop/web#7');
  expect(word(entry(3, 2, { type: 'something_new' }))).toBe('recorded an action');
 });
});

describe('deliveries are part of the timeline as the Notifications lane', () => {
 const delivery = { id: X, kind: 'open', route: 'immediate', phase: 'pending', status: 'failed' as const, attempts: 1, last_outcome: 'terminal', last_code: 'egress_blocked', last_at: NS(3), eligible_at: NS(1) };
 test('a failed delivery stays failed, at its last attempt time', () => {
  const items = buildTimeline(view([OPEN, entry(2, 5, { type: 'ack' })], { notification: { ...view([]).notification, delivery: { state: 'ready', attention: 'failed', counts: { failed: 1 }, entries: [delivery] } } }), fmt);
  const d = items.find((i) => i.lane === 'notification');
  expect(d?.at).toBe(NS(3));
  expect(d?.text).toContain('open (immediate): failed');
  expect(d?.tone).toBe('high');
  expect(items.map((i) => i.type)).toEqual(['ack', 'delivery', 'open']);
 });
 test('a delivery state that is not available adds nothing and invents nothing', () => {
  expect(buildTimeline(view([OPEN]), fmt).filter((i) => i.lane === 'notification')).toEqual([]);
 });
});
