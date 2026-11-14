// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { ApiFault } from '../api/types';
import { emptySummary, gapReason, gapSentence, lineSplitter, lossText, parseReplayLine, summarize, toItem, type ReplayLine } from './model';
import { ItemQueue } from './queue';

const want = { org: 'a'.repeat(32), project: 'b'.repeat(32), replay: 'c'.repeat(32) };
const chunk = { replay_id: want.replay, sequence: '2', nodes: [], events: [] };
const line = (o: Record<string, unknown>): string => JSON.stringify(o);
const refused = (text: string): boolean => { try { parseReplayLine(text, want); return false; } catch (e) { return e instanceof ApiFault && e.code === 'invalid_response'; } };

describe('replay line parser', () => {
 test('accepts every closed line type for exactly the requested replay', () => {
  expect(parseReplayLine(line({ type: 'open', ...want }), want)).toEqual({ type: 'open', ...want });
  expect(parseReplayLine(line({ type: 'delta', sequence: '2', policy_revision: '7', loss: '3', chunk }), want)).toMatchObject({ type: 'delta', sequence: '2', policy: '7', loss: '3' });
  expect(parseReplayLine(line({ type: 'checkpoint', sequence: '1', policy_revision: 7, loss: '0', chunk }), want)).toMatchObject({ type: 'checkpoint', policy: '7' });
  expect(parseReplayLine(line({ type: 'gap', sequence: '4', through: '5', reason: 'missing_chunk' }), want)).toEqual({ type: 'gap', sequence: '4', through: '5', reason: 'missing_chunk' });
  expect(parseReplayLine(line({ type: 'revoke', reason: 'deleted' }), want)).toEqual({ type: 'revoke', reason: 'deleted' });
  expect(parseReplayLine(line({ type: 'truncated', next_sequence: '9' }), want)).toEqual({ type: 'truncated', next: '9' });
  expect(parseReplayLine(line({ type: 'end' }), want)).toEqual({ type: 'end' });
 });
 test('refuses another org, project or replay, unknown types and malformed numbers', () => {
  for (const other of ['org', 'project', 'replay']) expect(refused(line({ type: 'open', ...want, [other]: 'd'.repeat(32) }))).toBe(true);
  expect(refused(line({ type: 'exec' }))).toBe(true);
  expect(refused(line({ type: 'delta', sequence: 2, policy_revision: '7', loss: '0', chunk }))).toBe(true); // JSON number sequence
  expect(refused(line({ type: 'delta', sequence: '2', policy_revision: '7', loss: '-1', chunk }))).toBe(true);
  expect(refused(line({ type: 'delta', sequence: '2', policy_revision: '7', loss: '0', chunk: 'text' }))).toBe(true);
  expect(refused(line({ type: 'gap', sequence: '6', through: '5', reason: 'missing_chunk' }))).toBe(true);
  expect(refused(line({ type: 'gap', sequence: '0', through: '5', reason: 'missing_chunk' }))).toBe(true);
  expect(refused(line({ type: 'revoke', reason: 'because' }))).toBe(true);
  expect(refused(line({ type: 'error', code: 'Not Safe <b>' }))).toBe(true);
  expect(refused('not json')).toBe(true);
  expect(refused('"just a string"')).toBe(true);
 });
 test('splits a text stream into lines without losing a line cut across reads', () => {
  const split = lineSplitter();
  expect([...split('{"a":1}\n{"b"'), ...split(':2}\n\n{"c":3}\n')]).toEqual(['{"a":1}', '{"b":2}', '{"c":3}']);
  expect(() => lineSplitter()('x'.repeat(2_200_000))).toThrow();
 });
});

describe('viewer items', () => {
 test('a chunk line becomes its own JSON bytes; gaps and terminal lines map to closed items; page-level lines map to none', () => {
  const l = parseReplayLine(line({ type: 'delta', sequence: '2', policy_revision: '7', loss: '0', chunk }), want);
  const item = toItem(l);
  expect(item?.kind).toBe('chunk');
  if (item?.kind === 'chunk') expect(JSON.parse(new TextDecoder().decode(item.bytes))).toEqual(chunk);
  expect(toItem({ type: 'gap', sequence: '4', through: '5', reason: 'missing_chunk' })).toEqual({ kind: 'gap', reason: 'missing_chunk', from: '4', through: '5' });
  expect(toItem({ type: 'revoke', reason: 'authority_revoked' })).toEqual({ kind: 'revoke', reason: 'authority_revoked' });
  expect(toItem({ type: 'error', code: 'unavailable' })).toEqual({ kind: 'error' });
  for (const type of ['end', 'open'] as const) expect(toItem(type === 'end' ? { type } : { type, ...want })).toBeNull();
  expect(toItem({ type: 'truncated', next: '9' })).toBeNull();
 });
 test('a reason the viewer does not know is mapped, never passed through or dropped', () => {
  expect(gapReason('index_mismatch')).toBe('conflicting_chunk');
  expect(gapReason('anything else <script>')).toBe('invalid_chunk');
  expect(gapReason('missing_chunk')).toBe('missing_chunk');
 });
});

describe('summary', () => {
 const fold = (lines: ReplayLine[]) => lines.reduce(summarize, emptySummary());
 const c = (type: 'checkpoint' | 'delta', sequence: string, loss = '0', policy = '1'): ReplayLine => ({ type, sequence, policy, loss, chunk });
 test('a gap stays open until a checkpoint resumes it, and a delta never resumes it', () => {
  const open = fold([c('checkpoint', '1'), c('delta', '2'), { type: 'gap', sequence: '3', through: '4', reason: 'missing_chunk' }, c('delta', '5')]);
  expect(open.gaps).toEqual([{ from: '3', through: '4', reason: 'missing_chunk', resumedAt: null }]);
  expect(gapSentence(open.gaps[0]!)).toContain('stays paused there');
  const resumed = summarize(open, c('checkpoint', '6'));
  expect(resumed.gaps[0]!.resumedAt).toBe('6');
  expect(gapSentence(resumed.gaps[0]!)).toContain('resumes only at checkpoint 6');
  expect(resumed.checkpoints).toBe(2);
 });
 test('recording loss is summed exactly, not as a JS number, and unreported loss is unknown rather than none', () => {
  expect(lossText(emptySummary())).toContain('unknown');
  expect(lossText(fold([c('checkpoint', '1')]))).toContain('none reported');
  const big = fold([c('checkpoint', '1', '9007199254740993'), c('delta', '2', '9007199254740993')]);
  expect(big.loss).toBe(18014398509481986n);
  expect(lossText(big)).toContain('18014398509481986 events');
 });
 test('policy revisions are listed once each in the order seen and terminal lines set the end state', () => {
  const s = fold([c('checkpoint', '1', '0', '1'), c('delta', '2', '0', '1'), c('checkpoint', '3', '0', '2')]);
  expect(s.policies).toEqual(['1', '2']);
  expect(fold([{ type: 'revoke', reason: 'deleted' }]).terminal).toBe('deleted');
  expect(fold([{ type: 'revoke', reason: 'authority_revoked' }]).terminal).toBe('revoked');
  expect(fold([{ type: 'truncated', next: '9' }])).toMatchObject({ terminal: 'truncated', next: '9' });
  expect(fold([{ type: 'unsupported', sequence: '3', reason: 'recorder_version' }]).unsupported).toBe(1);
 });
});

describe('item queue', () => {
 test('delivers in order, and clear drops everything not yet pulled and ends the stream', async () => {
  const q = new ItemQueue();
  q.push({ kind: 'unsupported' }); q.push({ kind: 'error' });
  const it = q[Symbol.asyncIterator]();
  expect((await it.next()).value).toEqual({ kind: 'unsupported' });
  q.clear();
  expect((await it.next()).done).toBe(true);
  q.push({ kind: 'unsupported' }); // nothing is delivered after a clear
  expect((await it.next()).done).toBe(true);
  expect(q.pending).toBe(0);
 });
 test('a waiting reader is released by close, and queued items still drain after close', async () => {
  const q = new ItemQueue();
  const it = q[Symbol.asyncIterator]();
  const waiting = it.next();
  q.push({ kind: 'unsupported' });
  expect((await waiting).value).toEqual({ kind: 'unsupported' });
  q.push({ kind: 'error' });
  q.close();
  expect((await it.next()).value).toEqual({ kind: 'error' });
  expect((await it.next()).done).toBe(true);
  const q2 = new ItemQueue();
  const w2 = q2[Symbol.asyncIterator]().next();
  q2.close();
  expect((await w2).done).toBe(true);
 });
});
