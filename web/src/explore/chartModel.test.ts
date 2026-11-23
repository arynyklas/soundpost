// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import type { EvaluationWire, Sample } from '../api/types';
import { chartSamples, chartWindow, downsample, formatNumber, markCounts, markSentence, seriesStats } from './chartModel';
import { planSeries } from './model';

const NS = 1_000_000_000n, T0 = 1730000000n * NS;
const at = (s: number): string => String(T0 + BigInt(s) * NS);
const bitsOf = (x: number): string => { const dv = new DataView(new ArrayBuffer(8)); dv.setFloat64(0, x); return dv.getBigUint64(0).toString(16).padStart(16, '0'); };
const s = (sec: number, bits: string): Sample => ({ time: at(sec), float: bits });
const range: EvaluationWire = { instant: false, time: '0', start: at(0), end: at(70), step: String(10n * NS) };

describe('chart samples', () => {
 test('a missing evaluation step is an absent sample in the middle of the gap, never a value', () => {
  const out = chartSamples([s(0, bitsOf(10)), s(10, bitsOf(11)), s(20, bitsOf(12)), s(60, bitsOf(20)), s(70, bitsOf(20))], range);
  const absent = out.filter((x) => x.v === null);
  expect(absent).toHaveLength(1);
  expect(absent[0]?.special).toBeUndefined();
  expect(absent[0]?.t).toBe(Number(T0 / 1_000_000n) + 40_000);
  expect(out.filter((x) => x.v !== null).map((x) => x.v)).toEqual([10, 11, 12, 20, 20]);
  expect(out.map((x) => x.t)).toEqual([...out.map((x) => x.t)].sort((a, b) => a - b));
 });
 test('NaN, infinities, the stale marker and a histogram are named present values, not gaps and not numbers', () => {
  const out = chartSamples([s(0, bitsOf(1)), s(10, '7ff8000000000001'), s(20, '7ff0000000000000'), s(30, 'fff0000000000000'), s(40, '7ff0000000000002'), { time: at(50), histogram: { float: { flavor: 'counter', schema: 0, zero_threshold: bitsOf(0), sum: bitsOf(1), count: bitsOf(1), zero_count: bitsOf(0), positive_spans: [], negative_spans: [], positive_buckets: [], negative_buckets: [], reset_hint: 'unknown' } } }, s(60, bitsOf(2)), s(70, bitsOf(3))], range);
  expect(out.filter((x) => x.special !== undefined).map((x) => x.special)).toEqual(['NaN', '+Inf', '-Inf', 'stale marker', 'native histogram']);
  expect(out.filter((x) => x.v === null && x.special === undefined)).toHaveLength(0);
  expect(out.every((x) => x.v === null || Number.isFinite(x.v))).toBe(true);
 });
 test('an instant evaluation has no chart window', () => {
  expect(chartWindow({ instant: true, time: at(5), start: '0', end: '0', step: '0' })).toBeNull();
  expect(chartWindow(null)).toBeNull();
  expect(chartWindow(range)).toEqual({ start: Number(T0 / 1_000_000n), end: Number(T0 / 1_000_000n) + 70_000 });
 });
});

describe('figures', () => {
 test('statistics are of the plottable values only and a series with none has none (not zeros)', () => {
  const plan = planSeries([s(0, bitsOf(2)), s(10, '7ff8000000000001'), s(20, bitsOf(4)), s(30, bitsOf(9))], range);
  expect(seriesStats(plan)).toEqual({ count: 3, min: 2, max: 9, avg: 5, last: 9 });
  expect(seriesStats(planSeries([s(0, '7ff8000000000001')], range))).toBeNull();
 });
 test('numbers keep four significant digits and the sign of zero', () => {
  expect(formatNumber(1.83456)).toBe('1.835');
  expect(formatNumber(48)).toBe('48');
  expect(formatNumber(-0)).toBe('-0');
  expect(formatNumber(-2.5)).toBe('-2.5');
  expect(formatNumber(12345678)).toBe('12,350,000');
  expect(formatNumber(1e-9)).toBe('1.000e-9');
 });
 test('the unplotted values are counted and spelled in a sentence', () => {
  const plan = planSeries([s(0, bitsOf(1)), s(10, '7ff8000000000001'), s(20, '7ff8000000000001'), s(30, '7ff0000000000002')], range);
  const c = markCounts([plan]);
  expect(c).toEqual({ nan: 2, inf: 0, stale: 1, histogram: 0 });
  expect(markSentence(c)).toBe('Not plotted, and the line breaks there: 2 NaN (a value, not a gap), 1 stale marker (the absence of a sample).');
  expect(markSentence({ nan: 0, inf: 0, stale: 0, histogram: 0 })).toBe('');
 });
});

describe('thinning a dense series for drawing', () => {
 test('a series within the bound is untouched', () => {
  const small = Array.from({ length: 10 }, (_, i) => ({ t: i, v: i }));
  const out = downsample(small, 100);
  expect(out.thinned).toBe(false);
  expect(out.samples).toEqual(small);
 });
 test('a dense series keeps its peak and trough, stays in time order and never drops an absent or named sample', () => {
  const dense = Array.from({ length: 20_000 }, (_, i) => ({ t: i, v: i === 7001 ? 1000 : i === 12_000 ? -50 : i % 10 })) as { t: number; v: number | null; special?: string }[];
  dense[5000] = { t: 5000, v: null };
  dense[9000] = { t: 9000, v: null, special: 'NaN' };
  const out = downsample(dense, 1500);
  expect(out.thinned).toBe(true);
  expect(out.samples.length).toBeLessThan(3000);
  expect(out.samples.some((s) => s.v === 1000)).toBe(true);
  expect(out.samples.some((s) => s.v === -50)).toBe(true);
  expect(out.samples.some((s) => s.t === 5000 && s.v === null && s.special === undefined)).toBe(true);
  expect(out.samples.some((s) => s.t === 9000 && s.special === 'NaN')).toBe(true);
  expect(out.samples.map((s) => s.t)).toEqual([...out.samples.map((s) => s.t)].sort((a, b) => a - b));
 });
});
