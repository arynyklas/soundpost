// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { coverageView, reasonWords, unitWord, windowText } from './listModel';

describe('profile list words', () => {
 test('every profile keeps its own unit and an unknown unit is not stated, never a unit', () => {
  expect(unitWord('samples')).toBe('samples');
  expect(unitWord('nanoseconds')).toBe('nanoseconds');expect(unitWord('events')).toBe('events');
  expect(unitWord('unknown')).toBe('unit not stated');
 });
 test('unknown coverage with a reason is an unsupported runtime in words, and without one it is not stated; neither is complete', () => {
  expect(coverageView({ coverage: 'unknown', unsupportedReason: 'unsupported_in_browser' })).toEqual({ word: 'Unsupported', tone: 'unk', detail: 'unsupported in browser' });
  expect(coverageView({ coverage: 'unknown' }).word).toBe('Not stated');
  expect(coverageView({ coverage: 'partial' }).detail).toContain('not estimated');
  expect(coverageView({ coverage: 'complete' }).word).toBe('Complete');
  expect(reasonWords('a_b_c')).toBe('a b c');
 });
 test('a window the server did not state is not stated; one end alone is said as such', () => {
  const fmt = (ns: string): string => `t${ns}`;
  expect(windowText(null, null, fmt)).toBe('not stated');
  expect(windowText('1', '2', fmt)).toBe('t1 to t2');
  expect(windowText('1', '1', fmt)).toBe('t1');
  expect(windowText('1', null, fmt)).toBe('from t1');
  expect(windowText(null, '2', fmt)).toBe('until t2');
 });
});
