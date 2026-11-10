// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The result model: how an exact C06 value is turned into what a person may be shown. Nanoseconds, counts and float bits
// stay strings or BigInt here; a JavaScript number is only ever used for drawing coordinates and for a finite float whose
// bits are shown next to it. Missing data is a gap, never a zero.
import type { EvaluationWire, FloatBits, Label, LoadState, LogEntry, LogStream, NativeHistogram, ProjectResult, QueryResult, QueryValue, Sample } from '../api/types';

export type FloatKind = 'finite' | 'nan' | 'stale' | 'pos_inf' | 'neg_inf';
export interface FloatView { kind: FloatKind; text: string; bits: FloatBits; value: number | null }
/** The exact bits of the storage stale marker, a NaN with one specific payload. */
export const STALE_BITS: FloatBits = '7ff0000000000002';

const scratch = new DataView(new ArrayBuffer(8));
const MANTISSA = (1n << 52n) - 1n;

/** Reads 16 hex digits of IEEE-754 binary64. NaN, infinities and the stale marker are named, never shown as a number; -0 is
 * not 0; an ordinary NaN (any payload or sign) is NaN and only the exact stale bit pattern is the stale marker. */
export function floatView(bits: FloatBits): FloatView {
 if (!/^[0-9a-f]{16}$/.test(bits)) throw new TypeError('invalid float bits');
 const b = BigInt(`0x${bits}`);
 if (((b >> 52n) & 0x7ffn) === 0x7ffn) {
  if ((b & MANTISSA) === 0n) return b >> 63n === 1n ? { kind: 'neg_inf', text: '-Inf', bits, value: null } : { kind: 'pos_inf', text: '+Inf', bits, value: null };
  return bits === STALE_BITS ? { kind: 'stale', text: 'stale marker', bits, value: null } : { kind: 'nan', text: 'NaN', bits, value: null };
 }
 scratch.setBigUint64(0, b);
 const value = scratch.getFloat64(0);
 return { kind: 'finite', text: Object.is(value, -0) ? '-0' : String(value), bits, value };
}

/** What a sample is, in words: its text and whether it is a number, NaN, the stale marker or a native histogram. */
export function sampleText(s: Sample): { text: string; kind: FloatKind | 'histogram' } {
 if (s.histogram !== undefined) return { text: 'native histogram', kind: 'histogram' };
 const v = floatView(s.float ?? '0000000000000000');
 return { text: v.text, kind: v.kind };
}

export type MarkKind = 'nan' | 'pos_inf' | 'neg_inf' | 'stale' | 'histogram';
export interface PlotPoint { time: string; value: number; bits: FloatBits }
export interface PlotMark { time: string; kind: MarkKind; bits?: FloatBits }
/** A run of evaluation steps with no sample. `after`/`before` are the neighbouring sample times (null at the range edge) and
 * `missing` is how many evaluation steps lie in the gap. */
export interface Gap { after: string | null; before: string | null; missing: number | null }
export interface SeriesPlan { segments: PlotPoint[][]; marks: PlotMark[]; gaps: Gap[]; points: number }

/** Splits a series into plottable runs, value marks and gaps. A line is never drawn across a gap, a NaN or an infinity, an
 * ordinary NaN is a mark and not a gap, and an absent step is never filled in. Gap arithmetic is BigInt nanoseconds. */
export function planSeries(samples: Sample[], evaluation: EvaluationWire | null): SeriesPlan {
 const step = evaluation !== null && !evaluation.instant && BigInt(evaluation.step) > 0n ? BigInt(evaluation.step) : null;
 const segments: PlotPoint[][] = [];
 const marks: PlotMark[] = [];
 const gaps: Gap[] = [];
 let current: PlotPoint[] = [];
 const flush = (): void => { if (current.length > 0) segments.push(current); current = []; };
 let last: Sample | null = null;
 for (const s of samples) {
  if (step !== null && evaluation !== null) {
   const t = BigInt(s.time);
   if (last === null) {
    const start = BigInt(evaluation.start);
    if (t > start) gaps.push({ after: null, before: s.time, missing: Number((t - start + step - 1n) / step) });
   } else {
    const dt = t - BigInt(last.time);
    if (dt > step) { flush(); gaps.push({ after: last.time, before: s.time, missing: Number((dt - 1n) / step) }); }
   }
  }
  last = s;
  if (s.histogram !== undefined) { flush(); marks.push({ time: s.time, kind: 'histogram' }); continue; }
  const v = floatView(s.float ?? '0000000000000000');
  if (v.kind === 'finite' && v.value !== null) current.push({ time: s.time, value: v.value, bits: v.bits });
  else { flush(); marks.push({ time: s.time, kind: v.kind as MarkKind, bits: v.bits }); }
 }
 flush();
 if (step !== null && evaluation !== null && last !== null) {
  const missing = (BigInt(evaluation.end) - BigInt(last.time)) / step;
  if (missing >= 1n) gaps.push({ after: last.time, before: null, missing: Number(missing) });
 }
 return { segments, marks, gaps, points: samples.length };
}

/** A complete answer with nothing in it. A scalar and a string always have a value. */
export function isEmptyValue(v: QueryValue): boolean {
 switch (v.type) {
  case 'vector': return v.vector.length === 0;
  case 'matrix': return v.matrix.length === 0;
  case 'streams': return v.streams.every((s) => s.entries.length === 0);
  default: return false;
 }
}

/** One project's state. Partial is never empty and never ready, a failed project is incomplete, and stale data is stale. */
export function projectState(pr: ProjectResult): LoadState<ProjectResult> {
 if (pr.failure !== undefined) return { kind: 'incomplete', data: pr, reason: 'project_failed' };
 if (pr.completeness === 'partial') return { kind: 'incomplete', data: pr, reason: 'shards_missing' };
 if (pr.completeness === 'stale') return { kind: 'stale', data: pr, reason: 'freshness_stale' };
 if (pr.value !== null && isEmptyValue(pr.value)) return { kind: 'empty', data: pr };
 return { kind: 'ready', data: pr };
}

/** The whole answer is only as good as its worst project: any partial or failed project makes it incomplete, then any stale
 * one makes it stale, and it is empty only when every project is complete and empty. */
export function resultState(r: QueryResult): LoadState<QueryResult> {
 const states = r.projects.map(projectState);
 const failed = r.projects.some((p) => p.failure !== undefined);
 if (states.some((s) => s.kind === 'incomplete')) return { kind: 'incomplete', data: r, reason: failed ? 'project_failed' : 'shards_missing' };
 if (states.some((s) => s.kind === 'stale')) return { kind: 'stale', data: r, reason: 'freshness_stale' };
 if (states.length > 0 && states.every((s) => s.kind === 'empty')) return { kind: 'empty', data: r };
 return { kind: 'ready', data: r };
}

export interface OrderedEntry { entry: LogEntry; streamLabels: Label[] }
/** Every entry of every stream in the language-defined order of the project result (its global index, compared exactly). */
export function entriesInOrder(streams: LogStream[]): OrderedEntry[] {
 const keyed: { key: bigint; row: OrderedEntry }[] = [];
 for (const stream of streams) for (const entry of stream.entries) keyed.push({ key: BigInt(entry.index), row: { entry, streamLabels: stream.labels } });
 keyed.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
 return keyed.map((k) => k.row);
}

/** Cuts text at a half-open range of Unicode runes (an astral character counts once). A range outside the text is null: nothing is guessed. */
export function splitByRuneRange(text: string, startRune: number, endRune: number): { before: string; hit: string; after: string } | null {
 if (!Number.isInteger(startRune) || !Number.isInteger(endRune) || startRune < 0 || startRune > endRune) return null;
 const runes = Array.from(text);
 if (endRune > runes.length) return null;
 return { before: runes.slice(0, startRune).join(''), hit: runes.slice(startRune, endRune).join(''), after: runes.slice(endRune).join('') };
}

/** `{name="value", ...}` with each value JSON-escaped so quotes and control characters stay visible. Plain text, never markup. */
export function labelsText(labels: Label[]): string {
 return `{${labels.map((l) => `${l.name}=${JSON.stringify(l.value)}`).join(', ')}}`;
}

/** An exact UTC instant with all nine fractional digits. A value that is not a representable non-negative instant is returned as is. */
export function nsToIso(ns: string): string {
 if (!/^(0|[1-9][0-9]*)$/.test(ns)) return ns;
 const n = BigInt(ns);
 const ms = n / 1_000_000n;
 if (ms > 8_640_000_000_000_000n) return ns;
 const fraction = String(n % 1_000_000_000n).padStart(9, '0');
 return new Date(Number(ms)).toISOString().replace(/\.\d{3}Z$/, `.${fraction}Z`);
}

/** A duration given in nanoseconds, with its unit. */
export function elapsedText(ns: string): string {
 const n = BigInt(ns);
 const unit = (div: bigint, label: string): string => {
  const whole = n / div;
  const tenth = (n % div) * 10n / div;
  return `${whole}${tenth === 0n ? '' : `.${tenth}`} ${label}`;
 };
 if (n >= 1_000_000_000n) return unit(1_000_000_000n, 's');
 if (n >= 1_000_000n) return unit(1_000_000n, 'ms');
 if (n >= 1_000n) return unit(1_000n, 'µs');
 return `${n} ns`;
}

export interface BucketView { index: number; count: string }
export interface HistogramView {
 variant: 'integer' | 'float';
 schema: number;
 flavor: string;
 resetHint: string;
 sum: FloatView;
 count: string;
 zeroCount: string;
 zeroThreshold: FloatView;
 positive: BucketView[];
 negative: BucketView[];
 customBounds: FloatView[];
}

function bucketViews(spans: { offset: number; length: number }[], counts: string[]): BucketView[] {
 const out: BucketView[] = [];
 let index = 0;
 let at = 0;
 for (const span of spans) {
  index += span.offset;
  for (let i = 0; i < span.length; i++) out.push({ index: index++, count: counts[at++] ?? '' });
 }
 return out;
}

/** Expands a native histogram's spans into buckets. Integer buckets are delta encoded and are accumulated exactly (BigInt),
 * unless the server states absolute counts; float buckets keep their float text. */
export function histogramView(h: NativeHistogram): HistogramView {
 if (h.float !== undefined) {
  const f = h.float;
  return {
   variant: 'float', schema: f.schema, flavor: f.flavor, resetHint: f.reset_hint, sum: floatView(f.sum), count: floatView(f.count).text, zeroCount: floatView(f.zero_count).text, zeroThreshold: floatView(f.zero_threshold),
   positive: bucketViews(f.positive_spans, f.positive_buckets.map((b) => floatView(b).text)), negative: bucketViews(f.negative_spans, f.negative_buckets.map((b) => floatView(b).text)), customBounds: (f.custom_bounds ?? []).map(floatView),
  };
 }
 const i = h.integer;
 if (i === undefined) throw new TypeError('histogram has no variant');
 const absolute = (deltas: string[], stated: string[] | undefined): string[] => {
  if (stated !== undefined) return stated;
  let sum = 0n;
  return deltas.map((d) => String((sum += BigInt(d))));
 };
 return {
  variant: 'integer', schema: i.schema, flavor: i.flavor, resetHint: i.reset_hint, sum: floatView(i.sum), count: i.count, zeroCount: i.zero_count, zeroThreshold: floatView(i.zero_threshold),
  positive: bucketViews(i.positive_spans, absolute(i.positive_buckets, i.positive_counts)), negative: bucketViews(i.negative_spans, absolute(i.negative_buckets, i.negative_counts)), customBounds: (i.custom_bounds ?? []).map(floatView),
 };
}
