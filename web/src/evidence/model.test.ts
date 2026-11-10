// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import type { AncestryOrder, IssueEvidenceView } from '../api/types';
import { buildIssueAction, frameReasonWords, occurrenceAncestryWords, orderWords, parseCompareIds, parseFrameLines, positionText, sourceWords } from './model';

const A = 'a'.repeat(32), P = '1'.repeat(32), I = '2'.repeat(32), C = '3'.repeat(32), F = 'e'.repeat(64);
const issue = (over: Partial<IssueEvidenceView> = {}): IssueEvidenceView => ({
 org: A, project: P, issue: I, state: 'incomplete', occurrences: [], late_history: [], sections: [],
 grouping: { grouping_version: 3, fingerprint: F, workflow: 'resolved', revision: '4', resolution_frontier: [], observed_releases: [], fixed_descendants: [], migration_links: [] }, ...over,
});

describe('frame input', () => {
 test('one frame per line, exact artifact IDs only', () => {
  const ok = parseFrameLines(`${A} 10 7 boom\n\n${A} 3 - \n`);
  expect(ok.ok && ok.value).toEqual([
   { module_id: '', function: 'boom', artifact_id: A, line: 10, column: 7, in_app: true, async: false },
   { module_id: '', function: '', artifact_id: A, line: 3, column: null, in_app: true, async: false },
  ]);
 });
 test('a path, URL, label or short hash is never accepted as an identity (no runtime fetch target exists)', () => {
  for (const bad of ['dist/app.js 1 1 f', 'https://example.test/app.js.map 1 1 f', 'v1.2.3 1 1 f', `${A.slice(1)} 1 1 f`, `${A.toUpperCase()} 1 1 f`]) expect(parseFrameLines(bad).ok).toBe(false);
 });
 test('shape, count and text bounds', () => {
  expect(parseFrameLines('').ok).toBe(false);
  expect(parseFrameLines(`${A} x 1 f`).ok).toBe(false);
  expect(parseFrameLines(`${A} 1 f`).ok).toBe(false);
  expect(parseFrameLines(`${A} 1 1 ${'f'.repeat(513)}`).ok).toBe(false);
  expect(parseFrameLines(Array.from({ length: 65 }, () => `${A} 1 1 f`).join('\n')).ok).toBe(false);
  expect(parseFrameLines(Array.from({ length: 64 }, () => `${A} 1 1 f`).join('\n')).ok).toBe(true);
 });
 test('markup in a function name is kept as the literal text it is', () => {
  const r = parseFrameLines(`${A} 1 1 <img src=x onerror=alert(1)>`);
  expect(r.ok && r.value[0]?.function).toBe('<img src=x onerror=alert(1)>');
 });
});

describe('release comparison input', () => {
 test('distinct 32-hex IDs, at most 16', () => {
  expect(parseCompareIds('').ok).toBe(true);
  expect(parseCompareIds(`${A}, ${P}  ${I}`)).toEqual({ ok: true, value: [A, P, I] });
  expect(parseCompareIds(`${A},${A}`).ok).toBe(false);
  expect(parseCompareIds('v1.0').ok).toBe(false);
  expect(parseCompareIds(Array.from({ length: 17 }, (_, i) => i.toString(16).padStart(32, '0')).join(',')).ok).toBe(false);
 });
});

describe('words', () => {
 test('every ancestry order has its own sentence and unknown claims no order', () => {
  const orders: AncestryOrder[] = ['same', 'ancestor', 'descendant', 'concurrent', 'unknown'];
  expect(new Set(orders.map(orderWords)).size).toBe(5);
  expect(orderWords('unknown')).toMatch(/unknown/i);
  expect(orderWords('unknown')).toMatch(/no order is claimed/);
  expect(orderWords('unknown')).not.toMatch(/ancestor of it|descendant of it|concurrent/);
 });
 test('unknown ancestry never reads as a regression or as known', () => {
  const words = occurrenceAncestryWords({ occurrence_id: A, record_id: P, grouping_version: 1, fingerprint: F, event_time_ns: '1', arrival_time_ns: '2', ancestry: 'unknown', freshness: 'fresh', late: false });
  expect(words).toMatch(/Ancestry unknown/);
  expect(words).toMatch(/no regression is claimed/);
 });
 test('each non-mapped reason is specific; an unrecognised one is not read as success', () => {
  expect(frameReasonWords('identity_mismatch')).not.toBe(frameReasonWords('artifact_unavailable'));
  expect(frameReasonWords('resolved')).toMatch(/Mapped through/);
  expect(frameReasonWords('martian')).toMatch(/^Not mapped/);
 });
 test('source state is spelled out', () => {
  expect(sourceWords({ state: 'withheld', reason: 'source_grant_required' })).toMatch(/separate sources grant/);
  expect(sourceWords({ state: 'withheld', reason: 'sources_not_requested' })).toMatch(/never fetched by default/);
  expect(sourceWords({ state: 'absent', reason: 'no_source_content' })).toMatch(/no source content/);
  expect(sourceWords({ state: 'absent', reason: 'frame_not_mapped' })).toMatch(/not mapped/);
  expect(sourceWords({ state: 'absent', reason: 'frame_not_mapped' })).not.toMatch(/withheld/i);
  expect(sourceWords({ state: 'present', context: 'x' })).toMatch(/shown below/);
 });
 test('position text', () => {
  expect(positionText('src/app.ts', 4, 8, 'handle')).toBe('src/app.ts:4:8 in handle');
  expect(positionText('a', 4, null, '')).toBe('a:4');
 });
});

describe('issue action request', () => {
 test('revision, scope and target come from the issue on screen; no actor, origin or timestamp field exists', () => {
  const built = buildIssueAction(A, P, issue(), 'resolve', ' fixed in 1.4 ', C);
  expect(built.ok && built.value).toEqual({ org: A, command_id: C, expected_version: '4', project_id: P, target_id: I, entity_kind: 'issue', kind: 'resolve', payload: { reason: 'fixed in 1.4' } });
  expect(JSON.stringify(built)).not.toMatch(/actor|origin|principal|"at"/);
 });
 test('only the four issue actions; no incident action and no grouping migration is offered here', () => {
  for (const kind of ['ack', 'assign', 'snooze', 'grouping_migration'] as const) expect(buildIssueAction(A, P, issue(), kind, '', C).ok).toBe(false);
  for (const kind of ['resolve', 'ignore', 'unignore', 'reopen'] as const) expect(buildIssueAction(A, P, issue(), kind, '', C).ok).toBe(true);
 });
 test('no action can be prepared without a known revision; reasons are bounded plain text', () => {
  const noGrouping: IssueEvidenceView = { ...issue(), state: 'not_available' };
  delete noGrouping.grouping;
  expect(buildIssueAction(A, P, noGrouping, 'resolve', '', C).ok).toBe(false);
  expect(buildIssueAction(A, P, issue(), 'resolve', 'a\u0007b', C).ok).toBe(false);
  expect(buildIssueAction(A, P, issue(), 'resolve', 'é'.repeat(257), C).ok).toBe(false);
 });
});
