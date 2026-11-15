// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Server-rendered markup of the stored occurrence. Exception classes, codes, frame names and chain reasons come from the application and are untrusted: they must reach the page only as escaped text, and the links come only from identities the record itself names.
import { describe, expect, test } from 'bun:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { ErrorOccurrenceView, RegressionExplanation, ReleaseRegression, ViewContext } from '../api/types';
import { conflictWords } from './actionModel';
import { OccurrenceFacts } from './OccurrenceDetail';
import { RegressionTable } from './RegressionTable';

const CANARY = '<img src=x onerror="window.__pwn=1"> & <script>window.__pwn=2</script>';
const P = '1'.repeat(32), B = 'b'.repeat(32), R = '4'.repeat(32), T = '5'.repeat(32), A = 'a'.repeat(32);
const context: ViewContext = { org: A, projects: [P], environment: '', start: '1', end: '2000000000000', timezone: 'UTC', generation: 1 };
const frame = { module_id: 'app', function: CANARY, artifact_id: A, line: 3, column: 4, in_app: true, async: false };
const view = (detail: Record<string, unknown> = {}): ErrorOccurrenceView => ({
 org: A, project: P, issue: R, occurrence: B, state: 'ready', sections: [{ name: 'occurrence_detail', state: 'ready' }],
 detail: { exception_class: CANARY, mechanism: 'unhandled_rejection', handled: false, fatal: true, code: CANARY, build_id: B, frames: [], ...detail } as ErrorOccurrenceView['detail'],
});
const render = (v: ErrorOccurrenceView): string => renderToStaticMarkup(React.createElement(OccurrenceFacts, { context, project: P, view: v }));

describe('stored occurrence markup', () => {
 test('an XSS canary in the class, the code, the chain classes and the chain reasons is escaped everywhere', () => {
  const html = render(view({
   exception_graph: { nodes: [{ id: 0, exception_class: CANARY, frames: [], context_suppressed: false }, { id: 1, exception_class: CANARY, frames: [], context_suppressed: true }], edges: [{ from: 0, to: 1, kind: 'cause' }], reasons: [CANARY] },
  }));
  expect(html).not.toMatch(/<img/i);
  expect(html).not.toMatch(/<script/i);
  expect(html).not.toMatch(/<[a-z][^>"']*\sonerror\s*=/i);
  expect(html).toContain('&lt;img src=x onerror=');
 });
 test('class, mechanism, handled, fatal and code are shown as stored, each with its own test ID', () => {
  const html = render(view({ handled: true, fatal: false, code: 'E_STORED', exception_class: 'StoredFailure' }));
  expect(html).toContain('data-testid="occ-class"');
  expect(html).toMatch(/data-testid="occ-class"><code>StoredFailure<\/code>/);
  expect(html).toMatch(/data-testid="occ-handled-fatal" data-handled="yes" data-fatal="no">Handled, not fatal\./);
  expect(html).toMatch(/data-testid="occ-code"><code>E_STORED<\/code>/);
  expect(html).toMatch(/data-testid="occ-mechanism"><code>unhandled_rejection<\/code>\. A promise rejection nothing handled\./);
  expect(render(view({ code: null }))).toContain('No code was recorded.');
 });
 test('release and trace links exist only for identities the record names, inside the selected project', () => {
  const none = render(view());
  expect(none).not.toContain('occ-release-link');
  expect(none).not.toContain('occ-trace-link');
  expect(none).toContain('The record names no release.');
  expect(none).toContain('The record names no trace.');
  const html = render(view({ release_id: R, trace_id: T, span_id: '0102030405060708' }));
  expect(html).toContain(`href="#org=${A}&amp;projects=${P}&amp;start=1&amp;end=2000000000000&amp;tz=UTC&amp;view=releases&amp;target=${P}%3A${R}"`);
  expect(html).toContain(`href="#org=${A}&amp;projects=${P}&amp;start=1&amp;end=2000000000000&amp;tz=UTC&amp;view=traces&amp;target=${P}%3A${T}"`);
  expect(html).toContain('0102030405060708');
 });
 test('a chain says what was suppressed and why it may be incomplete; no chain says so too', () => {
  const html = render(view({ exception_graph: { nodes: [{ id: 0, exception_class: 'Top', frames: [], context_suppressed: true }], edges: [], reasons: ['cycle'] } }));
  expect(html).toContain('suppressed the context');
  expect(html).toContain('data-reason="cycle"');
  expect(html).toContain('No edge joins these errors.');
  expect(render(view())).toContain('The record stores no exception chain');
 });
 test('a record with no frames says there is nothing to map, and a stored frame is looked up and not typed', () => {
  expect(render(view())).toContain('This record stores no frames');
  const html = render(view({ frames: [frame] }));
  expect(html).not.toContain('stored-frames-none');
  expect(html).toContain('data-testid="stored-frames"');
 });
 test('an occurrence that is not ready shows nothing of a record', () => {
  const v: ErrorOccurrenceView = { org: A, project: P, issue: R, occurrence: B, state: 'not_available', reason: 'occurrence_not_stored', sections: [{ name: 'occurrence_detail', state: 'not_available', reason: 'occurrence_not_stored' }] };
  expect(render(v)).toBe('');
 });
});

describe('issue action conflicts', () => {
 test('a moved revision names both revisions and the reload; a forbidden transition names neither as moved', () => {
  const moved = conflictWords('issue_version_conflict', '3', '5');
  expect(moved).toMatch(/revision 5/);
  expect(moved).toMatch(/revision 3/);
  expect(moved).toMatch(/Nothing was changed/);
  const state = conflictWords('issue_state_conflict', '3', '3');
  expect(state).toMatch(/does not allow this action/);
  expect(state).not.toMatch(/now at revision/);
  expect(state).toMatch(/Nothing was changed/);
 });
});

describe('regression table markup', () => {
 const row = (over: Partial<RegressionExplanation> = {}): RegressionExplanation => ({ occurrence: B, evidence_release: T, event_time_ns: '900000000000', resolution_time_ns: '1', eligible: true, ancestry_known: true, reason: 'release is the fix frontier or a descendant of it', frontier: [R], threshold: 1, window_ns: '0', qualifying: 1, reopened: true, ...over });
 const table = (rows: (RegressionExplanation | ReleaseRegression)[], byRelease = false): string => renderToStaticMarkup(React.createElement(RegressionTable, { context, project: P, rows, caption: 'Stored', byRelease }));
 test('the stored reason is text: an XSS canary reaches the page only escaped', () => {
  const html = table([row({ reason: CANARY })]);
  expect(html).not.toMatch(/<img/i);
  expect(html).not.toMatch(/<script/i);
  expect(html).not.toMatch(/<[a-z][^>"']*\sonerror\s*=/i);
  expect(html).toContain('&lt;img src=x onerror=');
 });
 test('each row states the stored verdict, ancestry, reason, frontier, policy and outcome, and links the release and the frontier', () => {
  const html = table([row(), row({ eligible: false, ancestry_known: false, reopened: false, evidence_release: undefined, frontier: [], reason: 'ancestry unknown: event after the explicit resolution boundary' })]);
  expect(html).toContain('data-eligible="yes" data-ancestry="known" data-reopened="yes"');
  expect(html).toContain('data-eligible="no" data-ancestry="unknown" data-reopened="no"');
  expect(html).toContain('Reopened the issue.');
  expect(html).toContain('Did not reopen the issue.');
  expect(html).toContain('Ancestry unknown: decided by the explicit resolution time boundary');
  expect(html).toContain('The occurrence names no release.');
  expect(html).toContain('No fix frontier was recorded.');
  expect(html).toContain(`view=releases&amp;target=${P}%3A${T}`);
  expect(html).toContain(`view=releases&amp;target=${P}%3A${R}`);
  expect(html).toContain('1 qualifying of 1 needed, with no time window.');
 });
 test('a release lists the issue of each evaluation and does not repeat the release column; an issue does the opposite', () => {
  const byRelease = table([{ ...row(), issue: A }], true);
  expect(byRelease).toContain('<th scope="col">Issue</th>');
  expect(byRelease).not.toContain('Release it ran in');
  expect(byRelease).toContain(`view=issues&amp;target=${P}%3A${A}`);
  const byIssue = table([row()]);
  expect(byIssue).toContain('Release it ran in');
  expect(byIssue).not.toContain('<th scope="col">Issue</th>');
 });
});
