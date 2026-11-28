// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { bucketWidth, logHistogram, widthWords } from './logModel';

const NS = 1_000_000_000n, T0 = 1730000000n * NS;
const at = (s: number): string => String(T0 + BigInt(s) * NS);
const e = (s: number, m = '1') => ({ time: at(s), multiplicity: m });
const window = { start: at(0), end: at(600) }; // ten minutes: ten buckets of one minute

describe('log histogram', () => {
 test('the bucket width is the smallest round width that keeps at most sixty buckets', () => {
  expect(bucketWidth(600_000)).toBe(10_000);
  expect(bucketWidth(3_600_000)).toBe(60_000);
  expect(bucketWidth(24 * 3_600_000)).toBe(30 * 60_000);
  expect(widthWords(60_000)).toBe('1 minute');
  expect(widthWords(30_000)).toBe('30 seconds');
 });
 test('a complete answer counts lines per bucket, honours multiplicity and shows a real zero as zero', () => {
  const h = logHistogram({ entries: [e(1), e(2), e(130, '3')], window, complete: true, limitReached: false, order: 'backward' });
  expect(h?.counted).toBe(5);
  const counts = h?.buckets.map((b) => b.values?.[0]) ?? [];
  expect(counts).toHaveLength(60);
  expect(counts.map((c, i) => (i === 0 ? c === 2 : i === 13 ? c === 3 : c === 0)).every(Boolean)).toBe(true);
  expect(h?.buckets.every((b) => b.values !== null)).toBe(true);
 });
 test('an answer that is not complete never shows an empty bucket as zero', () => {
  const h = logHistogram({ entries: [e(1)], window, complete: false, limitReached: false, order: 'backward' });
  expect(h?.buckets.filter((b) => b.values === null).length).toBe((h?.buckets.length ?? 0) - 1);
  expect(h?.note).toContain('not shown as zero');
 });
 test('a page limit leaves the part the page did not reach without samples (newest first: before the oldest line returned)', () => {
  const h = logHistogram({ entries: [e(590), e(595)], window, complete: true, limitReached: true, order: 'backward' });
  const reached = h?.buckets.filter((b) => b.values !== null) ?? [];
  expect(reached.length).toBeGreaterThan(0);
  expect(reached.every((b) => b.start >= Number(T0 / 1_000_000n) + 580_000)).toBe(true);
  expect(h?.buckets[0]?.values).toBeNull();
  expect(h?.note).toContain('page limit');
 });
 test('an empty or inverted window has no histogram', () => {
  expect(logHistogram({ entries: [], window: { start: at(5), end: at(5) }, complete: true, limitReached: false, order: 'backward' })).toBeNull();
 });
});
