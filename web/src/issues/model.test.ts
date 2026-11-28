// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The occurrence selection and the stored-frames lookup of the issue page, as plain functions.
import { describe, expect, test } from 'bun:test';
import type { ErrorOccurrenceDetail, IssueEvidenceView, OccurrenceEvidence, SafeFrame, ViewContext } from '../api/types';
import { MAX_FRAMES } from '../evidence/model';
import { chosenOccurrence, issueReadKey, occurrenceReadKey, selectedFor, storedFramesPlan } from './model';

const A = 'a'.repeat(32), P = '1'.repeat(32), Q = '2'.repeat(32), I = '3'.repeat(32), J = '4'.repeat(32), B = 'b'.repeat(32);
const O1 = '5'.repeat(32), O2 = '6'.repeat(32), O3 = '7'.repeat(32);
const ctx = (over: Partial<ViewContext> = {}): ViewContext => ({ org: A, projects: [P], environment: '', start: '1', end: '2000000000000', timezone: 'UTC', generation: 1, ...over });
const occ = (id: string, over: Partial<OccurrenceEvidence> = {}): OccurrenceEvidence => ({ occurrence_id: id, record_id: id, grouping_version: 1, fingerprint: 'f', event_time_ns: '1', arrival_time_ns: '2', ancestry: 'known', freshness: 'fresh', late: false, ...over });
const issue = (over: Partial<IssueEvidenceView> = {}): IssueEvidenceView => ({ org: A, project: P, issue: I, state: 'ready', occurrences: [occ(O1), occ(O2)], late_history: [occ(O3, { late: true })], sections: [], ...over });
const frame = (n: number): SafeFrame => ({ module_id: 'app', function: `f${n}`, artifact_id: A, line: n, column: n, in_app: true, async: false });
const detail = (frames: SafeFrame[], over: Partial<ErrorOccurrenceDetail> = {}): ErrorOccurrenceDetail => ({ exception_class: 'Error', mechanism: 'onerror', handled: false, fatal: true, code: null, build_id: B, frames, ...over });

describe('an occurrence is chosen under one read and shown only for that read', () => {
 const held = { key: issueReadKey(ctx(), P, I), id: O1 };
 test('the selection is returned for its own key and for no other', () => {
  expect(selectedFor(held, issueReadKey(ctx(), P, I))).toBe(O1);
  expect(selectedFor(null, issueReadKey(ctx(), P, I))).toBeNull();
 });
 test('another issue, another project, another organization, another window or another generation drops it', () => {
  for (const other of [issueReadKey(ctx(), P, J), issueReadKey(ctx(), Q, I), issueReadKey(ctx({ org: B }), P, I), issueReadKey(ctx({ end: '3' }), P, I), issueReadKey(ctx({ generation: 2 }), P, I), issueReadKey(ctx({ environment: 'prod' }), P, I)]) {
   expect(selectedFor(held, other)).toBeNull();
  }
 });
 test('the read keys of the issue and of one of its occurrences differ by the occurrence and by everything else', () => {
  const base = occurrenceReadKey(ctx(), P, I, O1);
  expect(base).not.toBe(occurrenceReadKey(ctx(), P, I, O2));
  expect(base).not.toBe(occurrenceReadKey(ctx(), P, J, O1));
  expect(base).not.toBe(occurrenceReadKey(ctx(), Q, I, O1));
  expect(base).not.toBe(occurrenceReadKey(ctx({ generation: 2 }), P, I, O1));
  expect(base).not.toBe(issueReadKey(ctx(), P, I));
 });
});

describe('the chosen occurrence is looked up in the issue as the server now states it', () => {
 test('a current occurrence and a late one are both found, as the very rows of the view', () => {
  const v = issue();
  expect(chosenOccurrence(v, O2)).toBe(v.occurrences[1]);
  expect(chosenOccurrence(v, O3)).toBe(v.late_history[0]);
  expect(chosenOccurrence(v, O3)?.late).toBe(true);
 });
 test('nothing is chosen without a selection or without a view, and an occurrence the view does not list shows nothing', () => {
  expect(chosenOccurrence(issue(), null)).toBeUndefined();
  expect(chosenOccurrence(undefined, O1)).toBeUndefined();
  expect(chosenOccurrence(issue(), 'f'.repeat(32))).toBeUndefined();
  // After a reload that no longer lists it, the stored record behind it is not shown.
  expect(chosenOccurrence(issue({ occurrences: [occ(O2)] }), O1)).toBeUndefined();
 });
 test('an occurrence listed in both places is the current one', () => {
  const v = issue({ occurrences: [occ(O1, { freshness: 'fresh' })], late_history: [occ(O1, { late: true })] });
  expect(chosenOccurrence(v, O1)?.late).toBe(false);
 });
});

describe('the stored frames are looked up exactly as stored, once, for the record\'s own build', () => {
 test('no stored frame means no lookup at all', () => {
  expect(storedFramesPlan(ctx(), P, detail([]))).toBeNull();
 });
 test('the request is the record\'s own frames, its build, the page\'s org and project, and never asks for source text', () => {
  const frames = [frame(1), frame(2), frame(3)];
  const plan = storedFramesPlan(ctx(), P, detail(frames));
  expect(plan?.request).toEqual({ org: A, project: P, build: B, frames, include_sources: false });
  expect(plan?.unsent).toBe(0);
 });
 test('at most one lookup\'s worth is sent, the first frames in stored order, and the rest are counted', () => {
  const frames = Array.from({ length: MAX_FRAMES + 6 }, (_, i) => frame(i));
  const plan = storedFramesPlan(ctx(), P, detail(frames));
  expect(plan?.request.frames).toEqual(frames.slice(0, MAX_FRAMES));
  expect(plan?.unsent).toBe(6);
  const exact = storedFramesPlan(ctx(), P, detail(frames.slice(0, MAX_FRAMES)));
  expect(exact?.unsent).toBe(0);
 });
 test('the read key follows the build, the frames, the scope and the generation, so another record is never shown the old answer', () => {
  const base = storedFramesPlan(ctx(), P, detail([frame(1)]))?.key;
  expect(base).toBeDefined();
  expect(storedFramesPlan(ctx(), P, detail([frame(1)]))?.key).toBe(base);
  for (const other of [
   storedFramesPlan(ctx(), P, detail([frame(2)])),
   storedFramesPlan(ctx(), P, detail([frame(1)], { build_id: J })),
   storedFramesPlan(ctx(), Q, detail([frame(1)])),
   storedFramesPlan(ctx({ org: B }), P, detail([frame(1)])),
   storedFramesPlan(ctx({ generation: 2 }), P, detail([frame(1)])),
  ]) expect(other?.key).not.toBe(base);
 });
});
