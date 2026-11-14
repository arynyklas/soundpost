// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { ApiFault, type FramesRequest, type ViewState } from './types';
import { parseFrames, parseIssueEvidence, parseReleaseEvidence } from './client';

const A = 'a'.repeat(32), P = '1'.repeat(32), B = 'b'.repeat(32), R = '4'.repeat(32), R2 = '5'.repeat(32), H = 'd'.repeat(64);
const sent = { module_id: '', function: 'boom', artifact_id: A, line: 10, column: 7, in_app: true, async: false };
const req = (over: Partial<FramesRequest> = {}): FramesRequest => ({ org: A, project: P, build: B, frames: [sent], include_sources: false, ...over });
const reply = (over: Record<string, unknown> = {}, frame: Record<string, unknown> = {}): Record<string, unknown> => ({
 org: A, project: P, build: B, state: 'incomplete', reason: 'frames_unmapped', sections: [{ name: 'symbolication', state: 'incomplete' }],
 frames: [{ original: { ...sent }, reason: 'identity_mismatch', source: { state: 'withheld', reason: 'sources_not_requested' }, ...frame }], ...over,
});
const refused = (fn: () => unknown): void => { expect(fn).toThrow(ApiFault); };

describe('frames response is accepted only for the request that was sent', () => {
 test('the matching answer is accepted', () => { expect(parseFrames(reply(), req()).frames).toHaveLength(1); });
 test('another org, project or build is a fault, never rendered', () => {
  for (const other of [{ org: B }, { project: B }, { build: A }]) refused(() => parseFrames(reply(other), req()));
 });
 test('a shorter, longer or reordered frame list is a fault', () => {
  refused(() => parseFrames(reply({ frames: [] }), req()));
  const two = req({ frames: [sent, { ...sent, line: 11 }] });
  refused(() => parseFrames(reply(), two));
  const swapped = reply({ frames: [{ original: { ...sent, line: 11 }, reason: 'unmapped', source: { state: 'withheld' } }, { original: { ...sent }, reason: 'unmapped', source: { state: 'withheld' } }] });
  refused(() => parseFrames(swapped, two));
 });
 test('a frame whose original differs from what was sent is a fault', () => {
  refused(() => parseFrames(reply({}, { original: { ...sent, function: 'other' } }), req()));
  refused(() => parseFrames(reply({}, { original: { ...sent, artifact_id: B } }), req()));
 });
 test('mapped means a position and a map hash together', () => {
  refused(() => parseFrames(reply({}, { reason: 'resolved' }), req()));
  refused(() => parseFrames(reply({}, { resolved: { source: 'a.ts', line: 1, column: 1 }, map_sha256: H }), req()));
  refused(() => parseFrames(reply({}, { reason: 'resolved', resolved: { source: 'a.ts', line: 1, column: 1 } }), req()));
  expect(parseFrames(reply({}, { reason: 'resolved', resolved: { source: 'a.ts', line: 1, column: 1 }, map_sha256: H }), req()).frames[0]?.resolved?.source).toBe('a.ts');
 });
 test('source text exists only when the source is present and only when it was requested', () => {
  refused(() => parseFrames(reply({}, { source: { state: 'withheld', context: 'SECRET' } }), req()));
  refused(() => parseFrames(reply({}, { source: { state: 'present' } }), req({ include_sources: true })));
  refused(() => parseFrames(reply({}, { source: { state: 'present', context: 'SECRET' } }), req({ include_sources: false })));
  expect(parseFrames(reply({}, { source: { state: 'present', context: 'x' } }), req({ include_sources: true })).frames[0]?.source.context).toBe('x');
 });
 test('junk reasons and states are faults', () => {
  refused(() => parseFrames(reply({}, { reason: 'Mapped <b>' }), req()));
  refused(() => parseFrames(reply({ state: 'fine' }), req()));
  refused(() => parseFrames(reply({}, { source: { state: 'maybe' } }), req()));
 });
});

const release = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
 org: A, project: P, state: 'ready', parents: [{ id: R2, known: true }], children: [], comparisons: [{ release: R2, order: 'descendant' }], sections: [{ name: 'ancestry', state: 'ready' }],
 release: { id: R, build_id: B, label: 'v2', revision: '1', build_time_ns: '5', debug_artifacts: [{ artifact_id: A, debug_id: 'd', sha256: H }], label_history: [{ revision: '1', label: 'v2' }] }, ...over,
});
describe('release evidence', () => {
 const want = { org: A, project: P, release: R, compare: [R2] };
 test('accepted only for the requested release, in the requested comparison order', () => {
  expect(parseReleaseEvidence(release(), want).release?.id).toBe(R);
  refused(() => parseReleaseEvidence(release({ org: B }), want));
  refused(() => parseReleaseEvidence(release(), { ...want, release: R2 }));
  refused(() => parseReleaseEvidence(release({ comparisons: [] }), want));
  refused(() => parseReleaseEvidence(release({ comparisons: [{ release: R, order: 'descendant' }] }), want));
 });
 test('an order outside the closed vocabulary (for example a lexical or time verdict) is a fault', () => {
  for (const order of ['newer', 'older', 'before', 'after', '']) refused(() => parseReleaseEvidence(release({ comparisons: [{ release: R2, order }] }), want));
 });
 test('a not_available view carries no release and no comparison', () => {
  expect(parseReleaseEvidence(release({ state: 'not_available', reason: 'release_records_need_org_admin', release: undefined, comparisons: [] }), want).state).toBe('not_available' as ViewState);
  refused(() => parseReleaseEvidence(release({ state: 'not_available' }), want));
 });
});

const occ = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ occurrence_id: A, record_id: B, grouping_version: 3, fingerprint: H, event_time_ns: '1', arrival_time_ns: '2', ancestry: 'unknown', freshness: 'fresh', late: false, ...over });
const issueView = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
 org: A, project: P, issue: R, state: 'incomplete', occurrences: [occ()], late_history: [occ({ late: true })], sections: [{ name: 'grouping', state: 'ready' }],
 grouping: { grouping_version: 3, fingerprint: H, workflow: 'resolved', revision: '4', resolution_frontier: [], observed_releases: [], fixed_descendants: [], migration_links: [] }, ...over,
});
describe('issue evidence', () => {
 const want = { org: A, project: P, issue: R };
 test('accepted for the requested issue only', () => {
  expect(parseIssueEvidence(issueView(), want).grouping?.grouping_version).toBe(3);
  refused(() => parseIssueEvidence(issueView({ issue: A }), want));
  refused(() => parseIssueEvidence(issueView({ project: B }), want));
 });
 test('late history entries must be marked late and occurrences must not be', () => {
  refused(() => parseIssueEvidence(issueView({ late_history: [occ({ late: false })] }), want));
  refused(() => parseIssueEvidence(issueView({ occurrences: [occ({ late: true })] }), want));
 });
 test('known ancestry names a release; anything else is unknown', () => {
  refused(() => parseIssueEvidence(issueView({ occurrences: [occ({ ancestry: 'known' })] }), want));
  refused(() => parseIssueEvidence(issueView({ occurrences: [occ({ ancestry: 'probably' })] }), want));
  expect(parseIssueEvidence(issueView({ occurrences: [occ({ ancestry: 'known', release_id: R2 })] }), want).occurrences).toHaveLength(1);
 });
 test('grouping is required unless the view is not_available, which carries none', () => {
  refused(() => parseIssueEvidence(issueView({ grouping: undefined }), want));
  expect(parseIssueEvidence(issueView({ state: 'not_available', reason: 'issue_evidence_view_not_built', grouping: undefined, occurrences: [], late_history: [] }), want).state).toBe('not_available' as ViewState);
  refused(() => parseIssueEvidence(issueView({ state: 'not_available' }), want));
 });
 test('hash and version are typed', () => {
  refused(() => parseIssueEvidence(issueView({ grouping: { ...(issueView().grouping as object), fingerprint: 'abc' } }), want));
  refused(() => parseIssueEvidence(issueView({ occurrences: [occ({ fingerprint: 'zz' })] }), want));
 });
});
