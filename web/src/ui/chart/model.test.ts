// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { detectGaps, inGap, intersectGaps, mergeGaps, nearestIndex, niceMax, niceMin, runs, sampleStep, timeTicks, yTicks, type Sample } from './model';

const at = (t: number, v: number | null, special?: string): Sample => (special === undefined ? { t, v } : { t, v, special });

describe('axes', () => {
 test('the maximum is a round number at or above the data and never zero', () => {
  expect([niceMax(0), niceMax(0.7), niceMax(1.84), niceMax(2.4), niceMax(2.6), niceMax(7), niceMax(11)]).toEqual([1, 1, 2, 2.5, 5, 10, 20]);
 });
 test('the minimum is zero, or a round number below the lowest value', () => {
  expect([niceMin(5), niceMin(0), niceMin(-0.3), niceMin(-42)]).toEqual([0, 0, -0.5, -50]);
 });
 test('labels run from the top to the bottom of the axis', () => { expect(yTicks(0, 9, 4)).toEqual([9, 6, 3, 0]); expect(yTicks(-50, 100, 4)).toEqual([100, 50, 0, -50]); });
 test('time ticks are round and bounded', () => {
  const ticks = timeTicks(0, 3_600_000, 5);
  expect(ticks.length).toBeLessThanOrEqual(5);
  expect(ticks.every((t) => t % 900_000 === 0 || t % 1_800_000 === 0)).toBe(true);
 });
});

describe('gaps are no samples, never zero', () => {
 const minute = (n: number): number => n * 60_000;
 const full = Array.from({ length: 60 }, (_, i) => at(minute(i), 1));
 test('a series with every sample has no gap', () => { expect(detectGaps(full, 0, minute(59))).toEqual([]); });
 test('a hole between samples wider than 2.5 intervals is a gap from the last sample before to the first after', () => {
  const holed = full.filter((s) => s.t < minute(20) || s.t > minute(30));
  expect(detectGaps(holed, 0, minute(59))).toEqual([{ from: minute(19), to: minute(31) }]);
 });
 test('no sample before the first or after the last one is a gap to the window edge', () => {
  const late = full.filter((s) => s.t >= minute(10));
  expect(detectGaps(late, 0, minute(59))).toEqual([{ from: 0, to: minute(10) }]);
  expect(detectGaps(full.filter((s) => s.t <= minute(40)), 0, minute(59))).toEqual([{ from: minute(40), to: minute(59) }]);
 });
 test('a series with no value at all is one gap over the window', () => { expect(detectGaps([at(1, null)], 0, 10)[0]).toEqual({ from: 0, to: 10, text: 'no samples' }); expect(detectGaps([], 0, 10)).toHaveLength(1); });
 test('a present value that cannot be plotted (NaN, Inf, stale marker) is not a gap and breaks the line', () => {
  const s = full.map((p) => (p.t === minute(30) ? at(p.t, null, 'NaN') : p));
  expect(detectGaps(s, 0, minute(59))).toEqual([]);
  expect(sampleStep(s)).toBe(minute(1));
  const parts = runs(s, []);
  expect(parts).toHaveLength(2);
  expect(parts[0]!.at(-1)!.t).toBe(minute(29));
  expect(parts[1]![0]!.t).toBe(minute(31));
 });
 test('runs break at null values and inside gaps', () => {
  expect(runs([at(1, 1), at(2, null), at(3, 3), at(4, 4)], [{ from: 3.5, to: 5 }]).map((r) => r.map((p) => p.t))).toEqual([[1], [3]]);
 });
 test('gap lists merge and intersect', () => {
  expect(mergeGaps([{ from: 5, to: 8 }, { from: 1, to: 6 }, { from: 10, to: 11 }])).toEqual([{ from: 1, to: 8 }, { from: 10, to: 11 }]);
  expect(intersectGaps([{ from: 0, to: 10 }], [{ from: 5, to: 20 }])).toEqual([{ from: 5, to: 10 }]);
  expect(inGap([{ from: 5, to: 8 }], 6)).toBeDefined();
  expect(inGap([{ from: 5, to: 8 }], 5)).toBeUndefined();
 });
 test('the nearest sample is found by time', () => { expect(nearestIndex([at(0, 1), at(10, 2), at(20, 3)], 12)).toBe(1); expect(nearestIndex([], 1)).toBe(-1); });
});
