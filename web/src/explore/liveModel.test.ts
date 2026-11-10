// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import type { LiveEvent } from '../api/types';
import { DEFAULT_LIVE_LIMITS, applyLiveEvent, beginAttachment, endAttachment, initialLive, type LiveContext, type LiveView } from './liveModel';

const P = '1'.repeat(32), Q = '2'.repeat(32), S = '8'.repeat(32), S2 = '7'.repeat(32), G = '9'.repeat(32), R = '3'.repeat(32);
const ctx = (over: Partial<LiveContext> = {}): LiveContext => ({ now: 1000, projects: [P], limits: DEFAULT_LIVE_LIMITS, ...over });
const open = (id = S): LiveEvent => ({ type: 'open', stream_id: id, watermarks: [{ group: G, index: '5' }] });
const record = (seq: string, line = `line ${seq}`, over: Partial<LiveEvent> = {}): LiveEvent => ({
 type: 'record', stream_id: S, sequence: seq, project: P, labels: [{ name: 'app', value: 'web' }], cursors: [{ group: G, index: seq }],
 entry: { index: '0', time: '1730000000000000001', id: R, multiplicity: '1', line, stream_labels: [{ name: 'app', value: 'web' }], structured_metadata: [{ name: 'trace', value: 'x' }] }, ...over,
});
const gap = (from: string, to: string, reason = 'replay_evicted', over: Partial<LiveEvent> = {}): LiveEvent => ({ type: 'gap', stream_id: S, sequence: to, gap: { reason, from_sequence: from, to_sequence: to, after: [{ group: G, index: '1' }], through: [{ group: G, index: '9' }] }, ...over });
const fold = (events: LiveEvent[], view: LiveView = beginAttachment(initialLive(), false), c: LiveContext = ctx()): LiveView => events.reduce((v, e) => applyLiveEvent(v, e, c), view);
const lines = (v: LiveView): string[] => v.items.flatMap((i) => (i.kind === 'row' ? [i.line] : []));

describe('a live view is built only from the events the server sent, in order', () => {
 test('open starts the stream, records append in order and the last handled sequence is tracked exactly', () => {
  const v = fold([open(), record('1'), record('2'), record('3')]);
  expect([v.phase, v.streamId, v.lastSequence, lines(v), v.received, v.evicted]).toEqual(['live', S, '3', ['line 1', 'line 2', 'line 3'], 3, 0]);
  expect(v.items[0]).toMatchObject({ kind: 'row', sequence: '1', project: P, time: '1730000000000000001', id: R, line: 'line 1', labels: [{ name: 'app', value: 'web' }], streamLabels: [{ name: 'app', value: 'web' }], metadata: [{ name: 'trace', value: 'x' }] });
  expect(v.bytes).toBeGreaterThan(0);
 });
 test('sequences beyond 2^53 stay exact', () => {
  const v = fold([open(), record('9007199254740993')], { ...beginAttachment(initialLive(), false), lastSequence: '9007199254740992' });
  expect([v.lastSequence, v.gaps, v.duplicates]).toEqual(['9007199254740993', 0, 0]);
 });
 test('a heartbeat proves liveness and freshness only: no row, no sequence, the time of receipt is kept', () => {
  const v = fold([open(), record('1'), { type: 'heartbeat', stream_id: S, watermarks: [{ group: G, index: '8' }] }], undefined, ctx({ now: 4242 }));
  expect([v.heartbeats, v.lastHeartbeatAt, v.lastSequence, v.items.length, v.watermarks]).toEqual([1, 4242, '1', 1, [{ group: G, index: '8' }]]);
 });
});

describe('gaps are explicit, with exact bounds, and never become rows', () => {
 test('a gap event is an item with its reason, sequence bounds and cursors, and advances the position', () => {
  const v = fold([open(), record('1'), gap('2', '7'), record('8')]);
  expect(v.items.map((i) => i.kind)).toEqual(['row', 'gap', 'row']);
  expect(v.items[1]).toMatchObject({ kind: 'gap', announced: true, reason: 'replay_evicted', from: '2', to: '7', sequence: '7', after: [{ group: G, index: '1' }], through: [{ group: G, index: '9' }] });
  expect([v.lastSequence, v.gaps]).toEqual(['8', 1]);
 });
 test('a record that skips sequences without a gap event is shown as an unannounced gap, not hidden', () => {
  const v = fold([open(), record('1'), record('5')]);
  expect(v.items[1]).toMatchObject({ kind: 'gap', announced: false, reason: 'unannounced_sequence_jump', from: '2', to: '4', sequence: null });
  expect([v.lastSequence, v.gaps, v.received]).toEqual(['5', 1, 2]);
 });
 test('a gap that starts after the next expected sequence also shows the unannounced loss before it', () => {
  const v = fold([open(), record('1'), gap('4', '6')]);
  expect(v.items.map((i) => (i.kind === 'gap' ? [i.announced, i.from, i.to] : 'row'))).toEqual(['row', [false, '2', '3'], [true, '4', '6']]);
  expect(v.gaps).toBe(2);
 });
 test('an event at or before the position already handled is counted and ignored, never shown twice', () => {
  const v = fold([open(), record('1'), record('2'), record('2', 'again'), record('1', 'older'), gap('1', '2')]);
  expect([lines(v), v.duplicates, v.lastSequence, v.gaps]).toEqual([['line 1', 'line 2'], 3, '2', 0]);
 });
 test('resuming onto a new stream after the retained one expired shows the stream was replaced and the gap at its exact place', () => {
  let v = fold([open(), record('1'), record('2')]);
  v = beginAttachment(v, true);
  expect([v.phase, v.streamId, v.lastSequence, lines(v)]).toEqual(['connecting', S, '2', ['line 1', 'line 2']]);
  v = fold([open(S2), gap('3', '3', 'replay_expired', { stream_id: S2 }), record('4', 'fresh', { stream_id: S2 })], v);
  expect([v.replaced, v.streamId, v.lastSequence]).toEqual([true, S2, '4']);
  expect(v.items.map((i) => (i.kind === 'gap' ? i.reason : i.line))).toEqual(['line 1', 'line 2', 'replay_expired', 'fresh']);
  expect(v.items[2]).toMatchObject({ announced: true, from: '3', to: '3' });
 });
 test('resuming the same stream is not a replacement', () => {
  let v = fold([open(), record('1')]);
  v = fold([open(), record('2')], beginAttachment(v, true));
  expect([v.replaced, lines(v)]).toEqual([false, ['line 1', 'line 2']]);
 });
});

describe('revocation ends the view and clears what was buffered, immediately', () => {
 test('a revoke clears every row and gap, ends the view and names the reason', () => {
  const v = fold([open(), record('1'), gap('2', '3'), record('4'), { type: 'revoke', stream_id: S, reason: 'scope_revoked', failure: { code: 'not_found', safe_message: 'not_found' } }]);
  expect([v.phase, v.items, v.bytes, v.watermarks]).toEqual(['ended', [], 0, []]);
  expect(v.end).toEqual({ kind: 'revoked', reason: 'scope_revoked', code: 'not_found' });
 });
 test('no event after a revoke can put a row back', () => {
  const v = fold([open(), record('1'), { type: 'revoke', stream_id: S, reason: 'deleted' }, record('2', 'after revoke'), gap('3', '4'), open(), { type: 'heartbeat', stream_id: S }]);
  expect([v.items, v.received, v.end?.kind, v.phase]).toEqual([[], 1, 'revoked', 'ended']);
 });
 test('a typed error ends the view but keeps what was legitimately delivered, and a slow consumer says so', () => {
  const v = fold([open(), record('1'), { type: 'error', stream_id: S, reason: 'slow_consumer', failure: { code: 'quota', safe_message: 'quota' } }, record('2')]);
  expect([v.phase, lines(v), v.end]).toEqual(['ended', ['line 1'], { kind: 'error', reason: 'slow_consumer', code: 'quota' }]);
 });
 test('a client side end never overrides a server revoke, and an interrupted stream is resumable, not revoked', () => {
  const revoked = fold([open(), { type: 'revoke', stream_id: S, reason: 'scope_revoked' }]);
  expect(endAttachment(revoked, { kind: 'stopped', reason: 'stopped_by_you', code: '' }).end?.kind).toBe('revoked');
  const live = fold([open(), record('1')]);
  const cut = endAttachment(live, { kind: 'interrupted', reason: 'connection_lost', code: '' });
  expect([cut.phase, cut.end?.kind, lines(cut), cut.lastSequence]).toEqual(['ended', 'interrupted', ['line 1'], '1']);
 });
 test('a refusal of this reader clears the rows still held; any other failure keeps them for an explicit resume', () => {
  const live = fold([open(), record('1')]);
  const refused = endAttachment(beginAttachment(live, true), { kind: 'refused', reason: 'not_found', code: 'not_found' });
  expect([refused.items, refused.phase, refused.end?.kind]).toEqual([[], 'ended', 'refused']);
  const quota = endAttachment(beginAttachment(live, true), { kind: 'interrupted', reason: 'quota', code: 'quota' });
  expect([lines(quota), quota.lastSequence]).toEqual([['line 1'], '1']);
 });
 test('a record of a project that was not requested, or of another stream, is a violation that ends the view and clears it', () => {
  const foreign = fold([open(), record('1'), record('2', 'foreign', { project: Q })]);
  expect([foreign.phase, foreign.items, foreign.end?.kind, foreign.end?.reason]).toEqual(['ended', [], 'error', 'foreign_project']);
  const other = fold([open(), record('1'), record('2', 'x', { stream_id: S2 })]);
  expect([other.phase, other.end?.reason]).toEqual(['ended', 'stream_mismatch']);
 });
});

describe('the view is bounded in memory and says what it dropped', () => {
 test('only the newest items stay; the count of dropped ones is exact and visible', () => {
  const v = fold([open(), ...['1', '2', '3', '4', '5'].map((s) => record(s))], undefined, ctx({ limits: { maxItems: 3, maxBytes: 1 << 20 } }));
  expect([lines(v), v.evicted, v.received, v.lastSequence]).toEqual([['line 3', 'line 4', 'line 5'], 2, 5, '5']);
 });
 test('the byte bound also evicts, but the newest item is never dropped', () => {
  const long = 'x'.repeat(400);
  const v = fold([open(), record('1', long), record('2', long), record('3', long)], undefined, ctx({ limits: { maxItems: 100, maxBytes: 1000 } }));
  expect(v.items.length).toBeLessThan(3);
  expect(v.items.at(-1)).toMatchObject({ kind: 'row', sequence: '3' });
  expect(v.bytes).toBeLessThanOrEqual(1000 + long.length);
  expect(v.evicted).toBe(3 - v.items.length);
  const huge = fold([open(), record('1', 'y'.repeat(5000))], undefined, ctx({ limits: { maxItems: 100, maxBytes: 1000 } }));
  expect(huge.items).toHaveLength(1);
 });
 test('gaps count toward the bound but the total gap count never decreases', () => {
  const v = fold([open(), gap('1', '1'), gap('2', '2'), gap('3', '3'), record('4')], undefined, ctx({ limits: { maxItems: 2, maxBytes: 1 << 20 } }));
  expect([v.items.length, v.gaps, v.evicted]).toEqual([2, 3, 2]);
 });
});

describe('attachments', () => {
 test('a fresh attachment forgets the previous view; a resumed one keeps position and rows', () => {
  const old = fold([open(), record('1'), record('2')]);
  const fresh = beginAttachment(old, false);
  expect([fresh.phase, fresh.items, fresh.lastSequence, fresh.streamId, fresh.received]).toEqual(['connecting', [], '0', '', 0]);
  const resumed = beginAttachment(old, true);
  expect([resumed.phase, resumed.items.length, resumed.lastSequence, resumed.streamId, resumed.end]).toEqual(['connecting', 2, '2', S, null]);
 });
});
