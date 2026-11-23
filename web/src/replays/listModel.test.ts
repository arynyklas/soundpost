// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { chunksText, lengthText, recordingView } from './listModel';

const NS = 1_000_000_000n;
describe('replay list words', () => {
 test('the recording is a word; an unknown recording is not complete and an unknown gap count is not no gaps', () => {
  expect(recordingView({ recording: 'complete', gaps: '0' })).toEqual({ word: 'Complete', tone: 'ok', detail: 'no gap reported' });
  expect(recordingView({ recording: 'complete', gaps: null }).detail).toBe('no gap reported');
  expect(recordingView({ recording: 'gap', gaps: '2' })).toEqual({ word: 'Has a gap', tone: 'high', detail: '2 gaps' });
  expect(recordingView({ recording: 'partial', gaps: null }).detail).toBe('gaps not counted');
  expect(recordingView({ recording: 'unknown', gaps: null })).toEqual({ word: 'Not stated', tone: 'unk', detail: 'the server did not state how complete it is' });
 });
 test('the length is exact seconds or minutes, and not stated when an end is unknown (never 0 s)', () => {
  expect(lengthText('0', String(252n * NS))).toBe('4 min 12 s');
  expect(lengthText('0', String(NS + 500_000_000n))).toBe('1.5 s');
  expect(lengthText(null, '5')).toBe('not stated');
  expect(lengthText('5', '4')).toBe('not stated');
 });
 test('chunks are counted or not stated', () => {
  expect(chunksText('1')).toBe('1 chunk');
  expect(chunksText('12')).toBe('12 chunks');
  expect(chunksText(null)).toBe('not stated');
 });
});
