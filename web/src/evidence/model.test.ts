// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import type { AncestryOrder, ExceptionChain, IssueEvidenceView, RegressionExplanation } from '../api/types';
import { EVIDENCE_REASON, buildIssueAction, chainEdgeWords, chainReasonWords, frameReasonWords, handledFatalWords, mechanismWords, occurrenceAncestryWords, orderWords, parseCompareIds, parseFrameLines, positionText, regressionAncestryWords, regressionDecisionWords, regressionOutcomeWords, regressionPolicyWords, sourceWords } from './model';

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
  for (const kind of ['ack', 'assign', 'snooze', 'grouping_migration'] as const) expect(buildIssueAction(A, P, issue(), kind, 'why', C).ok).toBe(false);
  for (const kind of ['resolve', 'ignore', 'unignore', 'reopen'] as const) expect(buildIssueAction(A, P, issue(), kind, 'why', C).ok).toBe(true);
 });
 test('a reason is required: the server refuses an issue action without one', () => {
  for (const reason of ['', '   ', '\n']) {
   const built = buildIssueAction(A, P, issue(), 'ignore', reason, C);
   expect(built.ok).toBe(false);
   expect(!built.ok && built.error).toMatch(/reason/i);
  }
 });
 test('no action can be prepared without a known revision; reasons are bounded plain text', () => {
  const noGrouping: IssueEvidenceView = { ...issue(), state: 'not_available' };
  delete noGrouping.grouping;
  expect(buildIssueAction(A, P, noGrouping, 'resolve', 'why', C).ok).toBe(false);
  expect(buildIssueAction(A, P, issue(), 'resolve', 'a\u0007b', C).ok).toBe(false);
  expect(buildIssueAction(A, P, issue(), 'resolve', 'é'.repeat(257), C).ok).toBe(false);
  expect(buildIssueAction(A, P, issue(), 'resolve', 'é'.repeat(256), C).ok).toBe(true);
 });
 test('only a resolve names the releases that contain the fix, as distinct release IDs', () => {
  const built = buildIssueAction(A, P, issue(), 'resolve', 'fixed', C, `${P}, ${I}`);
  expect(built.ok && built.value.payload).toEqual({ reason: 'fixed', fixed_frontier: [P, I] });
  expect(buildIssueAction(A, P, issue(), 'ignore', 'why', C, P).ok).toBe(false);
  expect(buildIssueAction(A, P, issue(), 'resolve', 'fixed', C, 'v1.4').ok).toBe(false);
  expect(buildIssueAction(A, P, issue(), 'resolve', 'fixed', C, `${P},${P}`).ok).toBe(false);
  const tooMany = buildIssueAction(A, P, issue(), 'resolve', 'fixed', C, Array.from({ length: 17 }, (_, i) => i.toString(16).padStart(32, '0')).join(','));
  expect(!tooMany.ok && tooMany.error).toMatch(/at most 16/);
  const none = buildIssueAction(A, P, issue(), 'resolve', 'fixed', C, '  ');
  expect(none.ok && 'fixed_frontier' in none.value.payload).toBe(false);
 });
});

describe('stored occurrence words', () => {
 const chain: ExceptionChain = {
  nodes: [{ id: 0, exception_class: 'TopError', frames: [], context_suppressed: false }, { id: 1, exception_class: 'RootCause', frames: [], context_suppressed: true }],
  edges: [{ from: 0, to: 1, kind: 'cause' }, { from: 0, to: 1, kind: 'group', ordinal: 2 }],
  reasons: ['node_limit'],
 };
 test('every stored mechanism has its own sentence and an unknown one claims nothing', () => {
  const known = ['manual', 'uncaught_exception', 'unhandled_rejection', 'thread_exception', 'asyncio_exception'];
  expect(new Set(known.map(mechanismWords)).size).toBe(5);
  expect(mechanismWords('martian')).toMatch(/does not recognise/);
 });
 test('handled and fatal are two separate facts, never merged', () => {
  expect(new Set([handledFatalWords(true, true), handledFatalWords(true, false), handledFatalWords(false, true), handledFatalWords(false, false)]).size).toBe(4);
  expect(handledFatalWords(false, true)).toBe('Not handled, fatal.');
  expect(handledFatalWords(true, false)).toBe('Handled, not fatal.');
 });
 test('an edge names the stored kind and both classes in the stored direction; a group edge counts members from one', () => {
  expect(chainEdgeWords(chain, chain.edges[0]!)).toBe('TopError (node 0) to RootCause (node 1): cause');
  expect(chainEdgeWords(chain, chain.edges[1]!)).toBe('TopError (node 0) to RootCause (node 1): group member 3');
 });
 test('every reason the wire allows has words, and an unknown one is not explained away', () => {
  for (const r of ['cycle', 'node_limit', 'frame_limit', 'group_limit', 'unknown_throw', 'project_root_unconfigured', 'frame_not_project_safe', 'foreign_or_custom_error_class', 'safe_original_stack_unavailable', 'stack_formatter_hooked', 'stack_not_plain', 'stack_unparsed', 'native_brand_unavailable', 'cause_accessor', 'group_accessor', 'safe_group_boundary_unavailable', 'unsafe_group_container']) expect(chainReasonWords(r)).not.toMatch(/does not recognise/);
  expect(chainReasonWords('martian')).toMatch(/does not recognise/);
 });
 test('the occurrence reasons are specific: not stored, partial and missing telemetry grant differ', () => {
  const reasons = ['occurrence_not_stored', 'occurrence_read_partial', 'occurrence_needs_telemetry_read', 'occurrence_payload_view_not_built'].map((r) => EVIDENCE_REASON[r]);
  expect(reasons.every((r) => typeof r === 'string')).toBe(true);
  expect(new Set(reasons).size).toBe(4);
  expect(EVIDENCE_REASON['occurrence_needs_telemetry_read']).toMatch(/telemetry\.read/);
 });
});

describe('regression words', () => {
 const x = (over: Partial<RegressionExplanation> = {}): RegressionExplanation => ({ occurrence: A, evidence_release: P, event_time_ns: '9', resolution_time_ns: '1', eligible: true, ancestry_known: true, reason: 'stored', frontier: [], threshold: 2, window_ns: '0', qualifying: 1, reopened: false, ...over });
 test('eligible and not eligible are different sentences, and neither is a reopen', () => {
  expect(regressionDecisionWords(x({ eligible: true }))).toMatch(/^Eligible/);
  expect(regressionDecisionWords(x({ eligible: false }))).toMatch(/^Not eligible/);
  expect(regressionOutcomeWords(x({ reopened: true }))).toBe('Reopened the issue.');
  expect(regressionOutcomeWords(x({ eligible: true, reopened: false }))).toBe('Did not reopen the issue.');
 });
 test('unknown ancestry says it was decided by the explicit boundary and is never worded as release ancestry', () => {
  expect(regressionAncestryWords(x({ ancestry_known: false }))).toMatch(/Ancestry unknown.*resolution time boundary, not by release ancestry/);
  expect(regressionAncestryWords(x({ ancestry_known: true }))).toBe('Release ancestry known.');
  expect(regressionAncestryWords(x({ ancestry_known: true }))).not.toMatch(/unknown/i);
 });
 test('the policy states how many qualified of how many needed, within the window or with none', () => {
  expect(regressionPolicyWords(x({ qualifying: 1, threshold: 2, window_ns: '0' }))).toBe('1 qualifying of 2 needed, with no time window.');
  expect(regressionPolicyWords(x({ qualifying: 2, threshold: 2, window_ns: '50' }))).toBe('2 qualifying of 2 needed, within 50 ns of event time.');
 });
 test('no evaluation and no reader are two different reasons', () => {
  expect(EVIDENCE_REASON['no_regression_evaluated']).not.toBe(EVIDENCE_REASON['regression_explanation_view_not_built']);
  expect(EVIDENCE_REASON['no_regression_evaluated']).toMatch(/not a statement that none can happen/);
 });
});
