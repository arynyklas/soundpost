// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import type { EvaluationWire, LogStream, ProjectResult, QueryResult, QueryValue, Sample } from '../api/types';
import { elapsedText, entriesInOrder, floatView, histogramView, isEmptyValue, labelsText, nsToIso, planSeries, projectState, resultState, sampleText, splitByRuneRange } from './model';

const bitsOf = (x: number): string => {
 const dv = new DataView(new ArrayBuffer(8));
 dv.setFloat64(0, x);
 return dv.getBigUint64(0).toString(16).padStart(16, '0');
};
const NS = 1_000_000_000n;
const T0 = 1730000000n * NS;
const at = (seconds: number): string => String(T0 + BigInt(seconds) * NS);
const num = (seconds: number, x: number): Sample => ({ time: at(seconds), float: bitsOf(x) });
const raw = (seconds: number, bits: string): Sample => ({ time: at(seconds), float: bits });
const range: EvaluationWire = { instant: false, time: '0', start: at(0), end: at(70), step: String(10n * NS) };

describe('a float is shown as exactly what it is', () => {
 test('numbers keep their exact text, signed zero is distinguishable from zero', () => {
  expect(floatView(bitsOf(1))).toMatchObject({ kind: 'finite', text: '1', value: 1 });
  expect(floatView(bitsOf(42.5)).text).toBe('42.5');
  expect(floatView('0000000000000000')).toMatchObject({ kind: 'finite', text: '0' });
  expect(floatView('8000000000000000')).toMatchObject({ kind: 'finite', text: '-0' });
  expect(floatView('0000000000000001').text).toBe('5e-324');
  expect(floatView(bitsOf(0.1 + 0.2)).text).toBe('0.30000000000000004');
 });
 test('infinities are named with their sign', () => {
  expect(floatView('7ff0000000000000')).toMatchObject({ kind: 'pos_inf', text: '+Inf', value: null });
  expect(floatView('fff0000000000000')).toMatchObject({ kind: 'neg_inf', text: '-Inf', value: null });
 });
 test('every ordinary NaN is NaN whatever its payload and sign, and keeps its bits', () => {
  for (const bits of ['7ff8000000000000', '7ff8000000000001', 'fff8000000000000', '7ff0000000000001', '7fffffffffffffff', 'fff0000000000002']) {
   const v = floatView(bits);
   expect([v.kind, v.text, v.bits, v.value]).toEqual(['nan', 'NaN', bits, null]);
  }
 });
 test('only the exact stale marker bits are a stale marker, and it is never NaN or a number', () => {
  const v = floatView('7ff0000000000002');
  expect([v.kind, v.text, v.value]).toEqual(['stale', 'stale marker', null]);
  expect(floatView('7ff0000000000002').text).not.toBe(floatView('7ff8000000000001').text);
 });
});

describe('a series plan: missing samples are gaps, never zeros', () => {
 test('every step present is one unbroken run with no gap', () => {
  const plan = planSeries([0, 10, 20, 30, 40, 50, 60, 70].map((s) => num(s, s + 1)), range);
  expect([plan.segments.length, plan.segments[0]?.length, plan.gaps, plan.marks, plan.points]).toEqual([1, 8, [], [], 8]);
 });
 test('steps absent in the middle (a stale marker ends a series) are one gap that names its exact bounds and size', () => {
  const plan = planSeries([num(0, 1), num(10, 2), num(20, 3), num(60, 7), num(70, 8)], range);
  expect(plan.segments.map((s) => s.length)).toEqual([3, 2]);
  expect(plan.gaps).toEqual([{ after: at(20), before: at(60), missing: 3 }]);
  expect(plan.points).toBe(5);
  expect(plan.segments.flat().some((p) => p.value === 0)).toBe(false);
 });
 test('a series that starts late or ends early has leading and trailing gaps', () => {
  const plan = planSeries([num(30, 1), num(40, 2), num(50, 3)], range);
  expect(plan.gaps).toEqual([{ after: null, before: at(30), missing: 3 }, { after: at(50), before: null, missing: 2 }]);
 });
 test('an instant evaluation, or none, has no gaps to infer', () => {
  const samples = [num(0, 1), num(60, 2)];
  expect(planSeries(samples, { ...range, instant: true, step: '0' }).gaps).toEqual([]);
  expect(planSeries(samples, null).gaps).toEqual([]);
 });
 test('an ordinary NaN is a value: it is marked, it breaks the line, and it is not a gap', () => {
  const plan = planSeries([num(0, 1), num(10, 2), raw(20, '7ff8000000000001'), num(30, 4)], range);
  expect(plan.marks).toEqual([{ time: at(20), kind: 'nan', bits: '7ff8000000000001' }]);
  expect(plan.segments.map((s) => s.length)).toEqual([2, 1]);
  expect(plan.gaps.filter((g) => g.after !== null && g.before !== null)).toEqual([]);
 });
 test('infinities, a stale marker bit pattern and a histogram are marks, never plotted points', () => {
  const histogram: Sample = { time: at(40), histogram: { float: { flavor: 'gauge', schema: 0, zero_threshold: bitsOf(0), sum: bitsOf(1), count: bitsOf(1), zero_count: bitsOf(0), positive_spans: [], negative_spans: [], positive_buckets: [], negative_buckets: [], reset_hint: 'unknown' } } };
  const plan = planSeries([num(0, 1), raw(10, '7ff0000000000000'), raw(20, 'fff0000000000000'), raw(30, '7ff0000000000002'), histogram, num(50, 6)], range);
  expect(plan.marks.map((m) => [m.kind, m.time])).toEqual([['pos_inf', at(10)], ['neg_inf', at(20)], ['stale', at(30)], ['histogram', at(40)]]);
  expect(plan.segments.flat().map((p) => p.time)).toEqual([at(0), at(50)]);
 });
 test('nanosecond gap arithmetic is exact beyond 2^53', () => {
  const ev: EvaluationWire = { instant: false, time: '0', start: '1730000000000000001', end: '1730000000000000005', step: '1' };
  const s = (time: string): Sample => ({ time, float: bitsOf(1) });
  const plan = planSeries([s('1730000000000000001'), s('1730000000000000003'), s('1730000000000000005')], ev);
  expect(plan.gaps).toEqual([{ after: '1730000000000000001', before: '1730000000000000003', missing: 1 }, { after: '1730000000000000003', before: '1730000000000000005', missing: 1 }]);
  expect(plan.segments).toHaveLength(3);
 });
});

const stats = { scans_started: '1', pages_read: '1', rows_read: '1', bytes_read: '1', series_returned: '1', samples_returned: '1', logs_returned: '0', peak_memory_bytes: '1', elapsed_ns: '1', cached: false, limit_reached: false };
const P = '1'.repeat(32), Q = '2'.repeat(32), G = '9'.repeat(32);
const vec = (n: number): QueryValue => ({ type: 'vector', vector: Array.from({ length: n }, () => ({ labels: [], sample: num(0, 1) })) });
const pr = (over: Partial<ProjectResult> = {}): ProjectResult => ({ project_id: P, value: vec(1), diagnostics: [], watermarks: [{ group: G, index: '1' }], completeness: 'complete', stats, ...over });

describe('every project panel has its own honest state', () => {
 test('complete with rows is ready, complete with none is empty, a scalar or string is never empty', () => {
  expect(projectState(pr()).kind).toBe('ready');
  expect(projectState(pr({ value: vec(0) })).kind).toBe('empty');
  expect(projectState(pr({ value: { type: 'scalar', scalar: num(0, 0) } })).kind).toBe('ready');
  expect(projectState(pr({ value: { type: 'string', string: '' } })).kind).toBe('ready');
  expect(isEmptyValue({ type: 'matrix', matrix: [] })).toBe(true);
  expect(isEmptyValue({ type: 'streams', streams: [{ labels: [], entries: [] }] })).toBe(true);
 });
 test('partial is incomplete even with zero rows: a gap is never an empty or green zero result', () => {
  expect(projectState(pr({ completeness: 'partial', value: vec(0) })).kind).toBe('incomplete');
  expect(projectState(pr({ completeness: 'partial' })).kind).toBe('incomplete');
  const s = projectState(pr({ completeness: 'stale', value: vec(0) }));
  expect(s.kind).toBe('stale');
 });
 test('a failed project is incomplete and says why', () => {
  const s = projectState(pr({ value: null, completeness: 'partial', failure: { code: 'quota', safe_message: 'quota' } }));
  expect(s).toMatchObject({ kind: 'incomplete', reason: 'project_failed' });
 });
 test('the whole result is only as good as its worst project', () => {
  const r = (...projects: ProjectResult[]): QueryResult => ({ projects });
  expect(resultState(r(pr(), pr({ project_id: Q }))).kind).toBe('ready');
  expect(resultState(r(pr({ value: vec(0) }), pr({ project_id: Q, value: vec(0) }))).kind).toBe('empty');
  expect(resultState(r(pr(), pr({ project_id: Q, value: vec(0) }))).kind).toBe('ready');
  expect(resultState(r(pr(), pr({ project_id: Q, completeness: 'partial' }))).kind).toBe('incomplete');
  expect(resultState(r(pr(), pr({ project_id: Q, completeness: 'stale' }))).kind).toBe('stale');
  expect(resultState(r(pr({ completeness: 'stale' }), pr({ project_id: Q, completeness: 'partial' }))).kind).toBe('incomplete');
  expect(resultState(r(pr(), pr({ project_id: Q, value: null, completeness: 'partial', failure: { code: 'x', safe_message: 'y' } }))).kind).toBe('incomplete');
 });
});

describe('log entries keep the language order and exact nanoseconds', () => {
 const entry = (index: string, time: string, line: string): LogStream['entries'][number] => ({ index, time, id: `${'a'.repeat(31)}${index.slice(-1)}`, multiplicity: '1', line, stream_labels: [], structured_metadata: [] });
 test('entries of several streams are interleaved by their global index, ties never merge', () => {
  const streams: LogStream[] = [
   { labels: [{ name: 'app', value: 'web' }], entries: [entry('0', '1730000000000000003', 'a'), entry('3', '1730000000000000001', 'd')] },
   { labels: [{ name: 'app', value: 'api' }], entries: [entry('1', '1730000000000000003', 'b'), entry('2', '1730000000000000002', 'c')] },
  ];
  const out = entriesInOrder(streams);
  expect(out.map((e) => e.entry.line)).toEqual(['a', 'b', 'c', 'd']);
  expect(out.map((e) => e.streamLabels[0]?.value)).toEqual(['web', 'api', 'api', 'web']);
  expect(out[0]?.entry.time).toBe(out[1]?.entry.time);
 });
 test('indexes beyond 2^53 still order exactly', () => {
  const streams: LogStream[] = [{ labels: [], entries: [entry('9007199254740993', '1', 'later'), entry('9007199254740992', '1', 'earlier')] }];
  expect(entriesInOrder(streams).map((e) => e.entry.line)).toEqual(['earlier', 'later']);
 });
});

describe('source ranges and label text', () => {
 test('the highlighted part is cut by rune, so astral characters count once', () => {
  expect(splitByRuneRange('sum(rate(x[5m]))', 4, 8)).toEqual({ before: 'sum(', hit: 'rate', after: '(x[5m]))' });
  expect(splitByRuneRange('a😀b', 1, 2)).toEqual({ before: 'a', hit: '😀', after: 'b' });
  expect(splitByRuneRange('abc', 0, 3)).toEqual({ before: '', hit: 'abc', after: '' });
 });
 test('an out of range or reversed range highlights nothing rather than guessing', () => {
  expect(splitByRuneRange('abc', 2, 9)).toBeNull();
  expect(splitByRuneRange('abc', 3, 2)).toBeNull();
  expect(splitByRuneRange('abc', -1, 2)).toBeNull();
 });
 test('label values are escaped so control characters and quotes stay visible', () => {
  expect(labelsText([])).toBe('{}');
  expect(labelsText([{ name: 'a', value: 'b' }, { name: 'c', value: 'x"y\nz' }])).toBe('{a="b", c="x\\"y\\nz"}');
  expect(labelsText([{ name: 'k', value: '<img src=x onerror=alert(1)>' }])).toBe('{k="<img src=x onerror=alert(1)>"}');
 });
 test('nanoseconds are shown exactly, not rounded to milliseconds', () => {
  expect(nsToIso('1730000000000000001')).toBe('2024-10-27T03:33:20.000000001Z');
  expect(nsToIso('1730000000000000002')).not.toBe(nsToIso('1730000000000000001'));
  expect(nsToIso('0')).toBe('1970-01-01T00:00:00.000000000Z');
  expect(nsToIso('-5')).toBe('-5');
 });
 test('elapsed time keeps its unit', () => {
  expect(elapsedText('1500000')).toBe('1.5 ms');
  expect(elapsedText('2500000000')).toBe('2.5 s');
  expect(elapsedText('999')).toBe('999 ns');
  expect(elapsedText('1500')).toBe('1.5 µs');
 });
});

describe('native histograms are shown bucket by bucket from their spans', () => {
 const base = { flavor: 'gauge', schema: 3, zero_threshold: bitsOf(0.001), sum: bitsOf(10.5), reset_hint: 'no' };
 test('integer buckets are delta encoded: absolute counts and bucket indexes come from the spans', () => {
  const v = histogramView({ integer: { ...base, count: '7', zero_count: '1', positive_spans: [{ offset: -1, length: 2 }, { offset: 1, length: 1 }], negative_spans: [{ offset: 4, length: 1 }], positive_buckets: ['2', '1', '-1'], negative_buckets: ['3'] } });
  expect(v.variant).toBe('integer');
  expect(v.positive).toEqual([{ index: -1, count: '2' }, { index: 0, count: '3' }, { index: 2, count: '2' }]);
  expect(v.negative).toEqual([{ index: 4, count: '3' }]);
  expect([v.count, v.zeroCount, v.schema, v.flavor, v.resetHint, v.sum.text, v.zeroThreshold.text]).toEqual(['7', '1', 3, 'gauge', 'no', '10.5', '0.001']);
 });
 test('counts beyond 2^53 stay exact', () => {
  const v = histogramView({ integer: { ...base, count: '18014398509481985', zero_count: '0', positive_spans: [{ offset: 0, length: 2 }], negative_spans: [], positive_buckets: ['9007199254740993', '1'], negative_buckets: [] } });
  expect(v.positive.map((b) => b.count)).toEqual(['9007199254740993', '9007199254740994']);
 });
 test('stated absolute counts win over the delta walk', () => {
  const v = histogramView({ integer: { ...base, count: '5', zero_count: '0', positive_spans: [{ offset: 0, length: 2 }], negative_spans: [], positive_buckets: ['2', '1'], negative_buckets: [], positive_counts: ['2', '3'] } });
  expect(v.positive.map((b) => b.count)).toEqual(['2', '3']);
 });
 test('float histogram buckets keep their float values and a NaN count is NaN', () => {
  const v = histogramView({ float: { ...base, count: bitsOf(3), zero_count: bitsOf(0), positive_spans: [{ offset: 0, length: 2 }], negative_spans: [], positive_buckets: [bitsOf(1.5), '7ff8000000000001'], negative_buckets: [], custom_bounds: [bitsOf(1), '7ff0000000000000'] } });
  expect(v.variant).toBe('float');
  expect(v.positive).toEqual([{ index: 0, count: '1.5' }, { index: 1, count: 'NaN' }]);
  expect(v.customBounds.map((b) => b.text)).toEqual(['1', '+Inf']);
 });
 test('a sample shows its kind: number, NaN, stale marker or histogram', () => {
  expect(sampleText({ time: '1', float: bitsOf(2) })).toEqual({ text: '2', kind: 'finite' });
  expect(sampleText({ time: '1', float: '7ff8000000000001' })).toEqual({ text: 'NaN', kind: 'nan' });
  expect(sampleText({ time: '1', float: '7ff0000000000002' })).toEqual({ text: 'stale marker', kind: 'stale' });
  expect(sampleText({ time: '1', histogram: { float: { ...base, count: bitsOf(1), zero_count: bitsOf(0), positive_spans: [], negative_spans: [], positive_buckets: [], negative_buckets: [] } } }).kind).toBe('histogram');
 });
});
