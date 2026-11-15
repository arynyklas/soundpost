// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Server-rendered markup of the issue body and of the stored occurrence's frames: what is on the page for a given selection. The
// transitions that lead there are in model.test.ts and actionModel.test.ts; the real browser flow is in the e2e specs.
import { describe, expect, test } from 'bun:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { ErrorOccurrenceView, IssueEvidenceView, OccurrenceEvidence, SafeFrame, ViewContext } from '../api/types';
import { MAX_FRAMES } from '../evidence/model';
import { IssueActions } from './IssueActions';
import { IssueBody } from './IssuePage';
import { OccurrenceFacts } from './OccurrenceDetail';

const A = 'a'.repeat(32), P = '1'.repeat(32), I = '3'.repeat(32), B = 'b'.repeat(32);
const O1 = '5'.repeat(32), O2 = '6'.repeat(32), O3 = '7'.repeat(32);
const context: ViewContext = { org: A, projects: [P], environment: '', start: '1', end: '2000000000000', timezone: 'UTC', generation: 1 };
const occ = (id: string, over: Partial<OccurrenceEvidence> = {}): OccurrenceEvidence => ({ occurrence_id: id, record_id: id, grouping_version: 1, fingerprint: 'f'.repeat(8), event_time_ns: '1730000000000000000', arrival_time_ns: '1730000000000000001', ancestry: 'known', freshness: 'fresh', late: false, ...over });
const view = (over: Partial<IssueEvidenceView> = {}): IssueEvidenceView => ({
 org: A, project: P, issue: I, state: 'ready', occurrences: [occ(O1), occ(O2)], late_history: [occ(O3, { late: true })], sections: [],
 grouping: { grouping_version: 1, fingerprint: 'f'.repeat(8), workflow: 'open', revision: '7', resolution_frontier: [], observed_releases: [], fixed_descendants: [], migration_links: [] }, ...over,
});
const body = (v: IssueEvidenceView, selected: string | null, reloading = false): string => renderToStaticMarkup(React.createElement(IssueBody, { context, project: P, id: I, view: v, selected, onSelect: () => undefined, reloading, onReload: () => undefined }));
const frame = (n: number): SafeFrame => ({ module_id: 'app', function: `f${n}`, artifact_id: A, line: n, column: n, in_app: true, async: false });
const occurrenceView = (frames: SafeFrame[]): ErrorOccurrenceView => ({ org: A, project: P, issue: I, occurrence: O1, state: 'ready', sections: [], detail: { exception_class: 'Error', mechanism: 'onerror', handled: false, fatal: true, code: null, build_id: B, frames } });
const facts = (frames: SafeFrame[]): string => renderToStaticMarkup(React.createElement(OccurrenceFacts, { context, project: P, view: occurrenceView(frames) }));

describe('the issue body shows the stored detail of exactly the occurrence that is selected', () => {
 test('with nothing selected no stored detail section is on the page, and every row offers it without claiming it is open', () => {
  const html = body(view(), null);
  expect(html).not.toContain('data-section="occurrence-detail"');
  for (const id of [O1, O2, O3]) expect(html).toContain(`aria-label="Show stored detail of occurrence ${id}"`);
  expect(html).not.toContain('aria-pressed="true"');
 });
 test('a selected current occurrence opens its detail section, marks only its own row, and no other occurrence\'s', () => {
  const html = body(view(), O2);
  expect(html.match(/data-section="occurrence-detail"/g)).toHaveLength(1);
  expect(html).toContain(`data-section="occurrence-detail" data-occurrence="${O2}"`);
  expect(html.match(/aria-pressed="true"/g)).toHaveLength(1);
  expect(html).toMatch(new RegExp(`<tr[^>]*data-occurrence="${O2}"[^>]*aria-selected="true"`));
  expect(html).toMatch(new RegExp(`<tr[^>]*data-occurrence="${O1}"[^>]*aria-selected="false"`));
 });
 test('a selected late occurrence opens its detail too, and stays listed in the late history table', () => {
  const html = body(view(), O3);
  expect(html).toContain(`data-section="occurrence-detail" data-occurrence="${O3}"`);
  expect(html).toMatch(new RegExp(`<tr[^>]*data-occurrence="${O3}" data-late="yes"`));
 });
 test('a selection the view no longer lists opens nothing', () => {
  const html = body(view({ occurrences: [occ(O2)] }), O1);
  expect(html).not.toContain('data-section="occurrence-detail"');
  expect(html).not.toContain('aria-pressed="true"');
 });
 test('the page says when there is no occurrence evidence and no late evidence, rather than rendering empty tables', () => {
  const html = body(view({ occurrences: [], late_history: [] }), null);
  expect(html).toContain('No occurrence evidence is stored for this issue.');
  expect(html).toContain('No late evidence is recorded.');
  expect(html).not.toContain('<table');
 });
});

describe('the issue body carries the action panel for the revision the server stated', () => {
 test('the panel shows the revision it acts on, and Reload is disabled while the page re-reads', () => {
  expect(body(view(), null)).toContain('data-testid="issue-expected-version">7<');
  expect(body(view({ grouping: undefined }), null)).toContain('data-testid="issue-expected-version">unknown<');
  expect(body(view(), null)).not.toMatch(/<button[^>]*disabled=""[^>]*>Reload issue/);
  expect(body(view(), null, true)).toMatch(/<button[^>]*disabled=""[^>]*>Reload issue/);
 });
 test('the page being re-read reaches the action panel: it is busy exactly when the body is reloading', () => {
  expect(body(view(), null)).toContain('aria-busy="false"');
  expect(body(view(), null, true)).toContain('aria-busy="true"');
 });
 test('while the page re-reads, the whole action form is disabled: nothing can be submitted against a revision about to change', () => {
  const idle = renderToStaticMarkup(React.createElement(IssueActions, { org: A, project: P, view: view(), busy: false, onChanged: () => undefined }));
  const busy = renderToStaticMarkup(React.createElement(IssueActions, { org: A, project: P, view: view(), busy: true, onChanged: () => undefined }));
  expect(idle).not.toContain('disabled');
  expect(busy).toContain('aria-busy="true"');
  expect(busy).toMatch(/<fieldset disabled="">/);
  expect(busy).toMatch(/<textarea[^>]*disabled=""/);
  expect(busy).toMatch(/<button[^>]*disabled=""[^>]*>Submit: Resolve/);
 });
 test('resolve is the first choice and carries the fix-release field; the reason is required', () => {
  const html = renderToStaticMarkup(React.createElement(IssueActions, { org: A, project: P, view: view(), busy: false, onChanged: () => undefined }));
  expect(html).toContain('<input type="radio" name="issue-action" checked="" value="resolve"/>');
  expect(html.match(/checked=""/g)).toHaveLength(1);
  expect(html).toContain('name="fixed-in"');
  expect(html).toMatch(/<textarea[^>]*name="reason"[^>]*required=""/);
  for (const label of ['Resolve', 'Ignore', 'Stop ignoring', 'Reopen']) expect(html).toContain(label);
  expect(html).toContain('data-outcome="idle"');
 });
});

describe('the stored frames of a selected occurrence', () => {
 test('a record with no frames says there is nothing to map and starts no lookup panel', () => {
  const html = facts([]);
  expect(html).toContain('data-testid="stored-frames-none"');
  expect(html).not.toContain('data-testid="stored-frames"');
 });
 test('a record with frames shows the lookup panel, loading until the server answers, with nothing resolved on its own', () => {
  const html = facts([frame(1), frame(2)]);
  expect(html).toContain('data-testid="stored-frames"');
  expect(html).not.toContain('stored-frames-none');
  expect(html).toContain('data-state="loading"');
  expect(html).not.toContain('more stored frames');
 });
 test('frames beyond one lookup are counted, not silently dropped', () => {
  const html = facts(Array.from({ length: MAX_FRAMES + 3 }, (_, i) => frame(i)));
  expect(html).toContain('3 more stored frames are not resolved here.');
  expect(facts(Array.from({ length: MAX_FRAMES }, (_, i) => frame(i)))).not.toContain('more stored frames');
 });
});
