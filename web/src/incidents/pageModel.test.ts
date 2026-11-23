// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import type { IncidentView } from '../api/types';
import type { ViewContext } from '../app/context';
import { evidenceLinks, evidenceWindow, lineageItems, notServed, resolveConsequences, responseState } from './pageModel';

const A = 'a'.repeat(32), P = '1'.repeat(32), I = '2'.repeat(32), C = '3'.repeat(32), E = '4'.repeat(32), U = '5'.repeat(32), ISS = '6'.repeat(32), REL = '7'.repeat(32), SVC = '8'.repeat(32);
const NS = (ms: number): string => String(BigInt(ms) * 1_000_000n);
const T0 = 1_700_000_000_000;
const view = (over: Partial<IncidentView> = {}): IncidentView => ({
 incident_id: I, org: A, project_id: P, version: '2', status: 'open', condition: { id: C, state: 'firing', freshness: 'fresh', observed_at: NS(T0) }, episode_id: E, severity: 'major', impact_revision: '1', source_firing: true,
 notification: { reminders_paused: false, worse_impact_eligible: true, urgency: { state: 'empty' }, delivery: { state: 'empty', attention: 'none' }, digest: { state: 'empty', sent: 0 }, unread_change: { state: 'empty', changed: false, queue_revision: '0', seen_revision: '0' } },
 links: [], observed_impacts: 1, last_activity: NS(T0 + 60_000), timeline: [{ version: '1', at: NS(T0), type: 'open', origin: 'system', actor: U }, { version: '2', at: NS(T0 + 60_000), type: 'ack', origin: 'human', actor: U }], ...over,
});
const context: ViewContext = { org: A, projects: [P, 'f'.repeat(32)], environment: '', start: NS(T0 - 3_600_000), end: NS(T0 + 3_600_000), timezone: 'UTC', generation: 1 };
const href = (section: string, o?: { service?: string; target?: { project: string; id: string } | null }): string => `#${section}${o?.service ? `/s:${o.service}` : ''}${o?.target ? `/t:${o.target.id}` : ''}`;
const full = view({ links: [{ kind: 'issue', id: ISS }, { kind: 'release', id: REL }, { kind: 'service', id: SVC }] });

describe('lineage: Rule → Incident → Issue → Release → Service', () => {
 test('the order is fixed and every kind is present', () => {
  expect(lineageItems(full, href).map((i) => i.kind)).toEqual(['Rule', 'Incident', 'Issue', 'Release', 'Service']);
 });
 test('a link the incident does not carry is shown as not linked, not dropped', () => {
  const items = lineageItems(view(), href);
  expect(items.map((i) => i.kind)).toEqual(['Rule', 'Incident', 'Issue', 'Release', 'Service']);
  for (const k of ['Issue', 'Release', 'Service']) {
   const item = items.find((i) => i.kind === k)!;
   expect(item.unavailable).toBe(true);
   expect(item.name).toBe('none linked');
   expect(item.href).toBeUndefined();
  }
 });
 test('linked records open their own screens; the incident is the current chip', () => {
  const items = lineageItems(full, href);
  expect(items.find((i) => i.kind === 'Issue')?.href).toBe(`#issues/t:${ISS}`);
  expect(items.find((i) => i.kind === 'Release')?.href).toBe(`#releases/t:${REL}`);
  expect(items.find((i) => i.kind === 'Service')?.href).toBe(`#services/s:${SVC}`);
  expect(items.find((i) => i.kind === 'Incident')?.current).toBe(true);
  expect(items.find((i) => i.kind === 'Rule')?.state).toBe('firing');
 });
 test('an unknown source state is said as such', () => {
  expect(lineageItems(view({ condition: { id: C, state: 'unknown', freshness: 'stale', observed_at: '1' }, source_firing: false }), href)[0]?.state).toBe('state unknown');
 });
});

describe('response state in words', () => {
 const ack = { actor: U, at: '1', impact_revision: '1', version: '2', current: true };
 test('each state has its own words', () => {
  expect(responseState(view()).label).toBe('not acknowledged');
  expect(responseState(view({ ack }), 'Ravi').label).toBe('acknowledged by Ravi');
  expect(responseState(view({ ack: { ...ack, current: false } })).label).toBe('acknowledged an earlier impact only');
  expect(responseState(view({ snooze: { actor: U, reason: 'r', from: '1', until: '9', version: '2', active: true } })).label).toBe('reminders snoozed');
  expect(responseState(view({ maintenance: { actor: U, reason: 'r', from: '1', until: '9', version: '2', active: true } })).label).toBe('in maintenance');
  expect(responseState(view({ status: 'resolved' })).label).toBe('resolved, source still firing');
  expect(responseState(view({ status: 'resolved', source_firing: false })).label).toBe('resolved');
 });
});

describe('evidence window and links', () => {
 test('an open incident looks from 15 minutes before it opened until now', () => {
  const w = evidenceWindow(view(), T0 + 600_000);
  expect(w.open).toBe(true);
  expect(BigInt(w.start)).toBe(BigInt(NS(T0 - 15 * 60_000)));
  expect(BigInt(w.end)).toBe(BigInt(NS(T0 + 600_000)) + 1n);
 });
 test('a resolved incident looks until it was resolved, never past it', () => {
  const w = evidenceWindow(view({ status: 'resolved', resolved_at: NS(T0 + 120_000), last_activity: NS(T0 + 120_000) }), T0 + 9_999_999);
  expect(w.open).toBe(false);
  expect(BigInt(w.end)).toBe(BigInt(NS(T0 + 120_000)) + 1n);
 });
 test('the window never ends before it starts', () => {
  const w = evidenceWindow(view({ last_activity: '1', timeline: undefined }), 0);
  expect(BigInt(w.end) > BigInt(w.start)).toBe(true);
 });
 test('links carry the incident window and only the incident project; linked records get their own links; no counts are invented', () => {
  const { links, window } = evidenceLinks(full, context, T0 + 600_000);
  expect(links.map((l) => l.key)).toEqual(['traces', 'logs', 'metrics', `issue:${ISS}`, `release:${REL}`, `service:${SVC}`]);
  const traces = new URLSearchParams(links[0]!.href.slice(1));
  expect(traces.get('view')).toBe('traces');
  expect(traces.get('projects')).toBe(P);
  expect(traces.get('start')).toBe(window.start);
  expect(traces.get('end')).toBe(window.end);
  expect(traces.get('span')).toBeNull();
  expect(new URLSearchParams(links.find((l) => l.key === `issue:${ISS}`)!.href.slice(1)).get('target')).toBe(`${P}:${ISS}`);
  expect(new URLSearchParams(links.find((l) => l.key === `service:${SVC}`)!.href.slice(1)).get('service')).toBe(SVC);
  expect(links.every((l) => !/\d{2,} /.test(l.label))).toBe(true);
 });
});

describe('what resolving does to the other entities', () => {
 test('a firing source keeps firing and the linked issue keeps its own state; a worse impact opens a new incident', () => {
  const words = resolveConsequences(full).map((c) => c.text).join('\n');
  expect(words).toContain('Resolved, source still firing');
  expect(words).toContain('keeps its own state');
  expect(words).toContain('never reopened');
  expect(words).toContain('Closes your team’s response');
 });
 test('a recovered source and no linked issue say that nothing else is affected', () => {
  const words = resolveConsequences(view({ source_firing: false, condition: { id: C, state: 'recovered', freshness: 'fresh', observed_at: '1' } })).map((c) => c.text).join('\n');
  expect(words).toContain('source has recovered');
  expect(words).toContain('No error issue is linked');
  expect(words).not.toContain('keeps its own state');
 });
 test('several linked issues are all said to keep their own state', () => {
  expect(resolveConsequences(view({ links: [{ kind: 'issue', id: ISS }, { kind: 'issue', id: REL }] })).map((c) => c.text).join('\n')).toContain('keep their own state');
 });
});

describe('a server that does not know an action', () => {
 test('only the unknown-kind refusal, a plain 405 and a bare 501 mean not served', () => {
  expect(notServed(400, 'action_kind_unknown')).toBe(true);
  expect(notServed(501, '')).toBe(true);
  expect(notServed(405, '')).toBe(true);
  expect(notServed(404, '')).toBe(false);
  expect(notServed(400, 'incident_note_invalid')).toBe(false);
  expect(notServed(403, '')).toBe(false);
 });
 test('every answer of this installation to a title, a note or an owner has its own detail and is a refusal of that request, never "not served"', () => {
  expect(notServed(501, 'needs_contracted_installation')).toBe(false);
  expect(notServed(400, 'invalid')).toBe(false);
  expect(notServed(400, '')).toBe(false);
  expect(notServed(400, 'incident_reason_invalid')).toBe(false);
  expect(notServed(400, 'issue_owner_unknown')).toBe(false);
  expect(notServed(429, 'incident_timeline_full')).toBe(false);
 });
});
