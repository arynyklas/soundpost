// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Server-rendered markup of the issue body and of the stored occurrence's frames: what is on the page for a given selection. The
// transitions that lead there are in model.test.ts and actionModel.test.ts; the real browser flow is in the e2e specs.
import { describe, expect, test } from 'bun:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { ErrorOccurrenceView, IssueEvidenceView, OccurrenceEvidence, SafeFrame, ViewContext } from '../api/types';
import { MAX_FRAMES } from '../evidence/model';
import { NO_NAMES } from '../shell/ShellContext';
import type { IssueActionChoice } from './pageModel';
import { IssueActionForm, IssueActions, actionsFor } from './IssueActions';
import { IssueBody, IssueHero, ReloadIssueButton } from './IssuePage';
import { OccurrenceFacts } from './OccurrenceDetail';

const A = 'a'.repeat(32), P = '1'.repeat(32), I = '3'.repeat(32), B = 'b'.repeat(32);
const O1 = '5'.repeat(32), O2 = '6'.repeat(32), O3 = '7'.repeat(32);
const context: ViewContext = { org: A, projects: [P], environment: '', start: '1', end: '2000000000000', timezone: 'UTC', generation: 1 };
const occ = (id: string, over: Partial<OccurrenceEvidence> = {}): OccurrenceEvidence => ({ occurrence_id: id, record_id: id, grouping_version: 1, fingerprint: 'f'.repeat(8), event_time_ns: '1730000000000000000', arrival_time_ns: '1730000000000000001', ancestry: 'known', freshness: 'fresh', late: false, ...over });
const view = (over: Partial<IssueEvidenceView> = {}): IssueEvidenceView => ({
 org: A, project: P, issue: I, state: 'ready', occurrences: [occ(O1), occ(O2)], late_history: [occ(O3, { late: true })], sections: [],
 grouping: { grouping_version: 1, fingerprint: 'f'.repeat(8), workflow: 'open', revision: '7', resolution_frontier: [], observed_releases: [], fixed_descendants: [], migration_links: [] }, ...over,
});
const body = (v: IssueEvidenceView, selected: string | null): string => renderToStaticMarkup(React.createElement(IssueBody, { context, project: P, id: I, view: v, selected, onSelect: () => undefined, href: (section) => `#${section}` }));
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

describe('the issue hero states the revision the server stated, and the actions follow the workflow', () => {
 const hero = (v: IssueEvidenceView | undefined): string => renderToStaticMarkup(React.createElement(IssueHero, { id: I, context, view: v, summary: { kind: 'loading' }, lineage: [], actions: null }));
 test('the revision is the one h1 page figure; with no stored grouping no revision is claimed', () => {
  expect(hero(view())).toContain('data-testid="issue-expected-version">7<');
  expect(hero(view({ grouping: undefined }))).not.toContain('issue-expected-version');
  expect(hero(view())).toMatch(/<h1 tabindex="-1" data-issue="3{32}">Error issue<\/h1>/);
  expect(hero(undefined).match(/<h1/g)).toHaveLength(1);
 });
 test('an open issue offers resolve and ignore, an ignored one stop ignoring, a resolved one reopen; an unknown state offers none', () => {
  expect(actionsFor('open')).toEqual(['resolve', 'ignore']);
  expect(actionsFor('ignored')).toEqual(['unignore']);
  expect(actionsFor('resolved')).toEqual(['reopen']);
  expect(actionsFor(undefined)).toEqual([]);
  const html = renderToStaticMarkup(React.createElement(IssueActions, { org: A, project: P, view: view(), busy: false, names: NO_NAMES, owner: undefined, incidents: [], onChanged: () => undefined }));
  expect(html).toContain('Resolve error issue');
  expect(html).toContain('>Ignore<');
  expect(html).toContain('Reassign');
  expect(html).not.toContain('<dialog');
 });
});

describe('the reload issue button', () => {
 const button = (reloading: boolean): string => renderToStaticMarkup(React.createElement(ReloadIssueButton, { reloading, onReload: () => undefined }));
 test('is disabled exactly while the page re-reads', () => {
  expect(button(true)).toContain('disabled=""');
  expect(button(false)).not.toContain('disabled');
  expect(button(true)).toContain('Reload issue');
 });
});

describe('the action form', () => {
 const form = (busy: boolean, initialKind: IssueActionChoice = 'resolve'): string => renderToStaticMarkup(React.createElement(IssueActionForm, { org: A, project: P, view: view(), busy, initialKind, incidents: [], onChanged: () => undefined, onCommitted: () => undefined, onPending: () => undefined, onCancel: () => undefined }));
 test('while the page re-reads, the whole action form is disabled: nothing can be submitted against a revision about to change', () => {
  const idle = form(false);
  const busy = form(true);
  expect(idle).not.toContain('disabled');
  expect(busy).toContain('aria-busy="true"');
  expect(busy).toMatch(/<fieldset disabled="">/);
  expect(busy).toMatch(/<textarea[^>]*disabled=""/);
  expect(busy).toMatch(/<button[^>]*disabled=""[^>]*>Submit: Resolve/);
 });
 test('the choice the person opened is the checked one and carries the fix-release field only for a resolve; the reason is required', () => {
  const html = form(false);
  expect(html).toContain('<input type="radio" name="issue-action" checked="" value="resolve"/>');
  expect(html.match(/checked=""/g)).toHaveLength(1);
  expect(html).toContain('name="fixed-in"');
  expect(html).toMatch(/<textarea[^>]*name="reason"[^>]*required=""/);
  for (const label of ['Resolve', 'Ignore', 'Stop ignoring', 'Reopen']) expect(html).toContain(label);
  expect(html).toContain('data-outcome="idle"');
  const reopen = form(false, 'reopen');
  expect(reopen).toContain('checked="" value="reopen"');
  expect(reopen).not.toContain('name="fixed-in"');
 });
 test('it says in words what the action does to the other entities, which keep their own lifecycles', () => {
  const html = form(false);
  expect(html).toContain('data-testid="issue-action-consequences"');
  expect(html).toContain('Alert rules and their conditions keep their own state.');
  expect(html).toContain('Releases are unaffected.');
  expect(html).toContain('nothing is applied and you see their change');
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
