// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import type { IncidentView } from '../api/types';
import { buildRequest, emptyDraft, faultText } from './model';

const A = 'a'.repeat(32), P = '1'.repeat(32), I = '2'.repeat(32), C = '3'.repeat(32), E = '4'.repeat(32);
const view = (over: Partial<IncidentView> = {}): IncidentView => ({
 incident_id: I, org: A, project_id: P, version: '7', status: 'open', condition: { id: C, state: 'firing', freshness: 'fresh', observed_at: '1' }, episode_id: E, severity: 'major', impact_revision: '1', source_firing: true,
 notification: { reminders_paused: false, worse_impact_eligible: true, urgency: { state: 'empty' }, delivery: { state: 'empty', attention: 'none' }, digest: { state: 'empty', sent: 0 }, unread_change: { state: 'empty', changed: false, queue_revision: '0', seen_revision: '0' } },
 links: [], observed_impacts: 1, last_activity: '1', ...over,
});
const id = 'c'.repeat(32);
const note = (text: string, v: IncidentView = view()) => buildRequest(v, { ...emptyDraft('note'), note: text }, id, 0);
const title = (text: string) => buildRequest(view(), { ...emptyDraft('title'), title: text }, id, 0);

describe('notes (console API section 2)', () => {
 test('a note is an incident action on the revision on screen and carries only the note', () => {
  expect(note('  Rolled back canary  ')).toEqual({ ok: true, request: { org: A, command_id: id, expected_version: '7', project_id: P, target_id: I, entity_kind: 'incident', kind: 'note', payload: { note: 'Rolled back canary' } } });
 });
 test('a note is also accepted on a resolved incident', () => { expect(note('post-incident review', view({ status: 'resolved' })).ok).toBe(true); });
 test('empty, over 2000 bytes (not characters) and control characters other than a line break are refused before anything is sent', () => {
  expect(note('   ').ok).toBe(false);
  expect(note('a'.repeat(2000)).ok).toBe(true);
  expect(note('a'.repeat(2001)).ok).toBe(false);
  expect(note('é'.repeat(1001)).ok).toBe(false);
  expect(note('é'.repeat(1000)).ok).toBe(true);
  expect(note('line one\nline two').ok).toBe(true);
  expect(note('tab\there').ok).toBe(false);
  expect(note('nul\u0000').ok).toBe(false);
  expect(note('cr\rhere').ok).toBe(false);
 });
});

describe('titles (console API section 1)', () => {
 test('a title carries only the title, trimmed', () => {
  expect(title('  Checkout p95 above 1.5 s ')).toMatchObject({ ok: true, request: { kind: 'title', payload: { title: 'Checkout p95 above 1.5 s' } } });
 });
 test('1 to 160 bytes without control characters', () => {
  expect(title('').ok).toBe(false);
  expect(title('x'.repeat(160)).ok).toBe(true);
  expect(title('x'.repeat(161)).ok).toBe(false);
  expect(title('a\nb').ok).toBe(false);
 });
});

describe('words for the new refusals', () => {
 test('notes full, invalid note and invalid title are explained', () => {
  expect(faultText('incident_notes_full', 429)).toContain('room for acknowledging and resolving');
  expect(faultText('incident_notes_full', 400)).toContain('room for acknowledging and resolving');
  expect(faultText('incident_note_invalid', 400)).toContain('1 to 2000 bytes');
  expect(faultText('incident_title_invalid', 400)).toContain('1 to 160 bytes');
 });
});
