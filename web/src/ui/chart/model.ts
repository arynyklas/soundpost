// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Pure chart geometry: scales, ticks, gap detection and hover lookup. No DOM, so it is unit-tested with bun.

/** One sample. `v` null with no `special` is "no value at this time" (a gap). `special` names a PRESENT value that cannot be plotted (NaN, +Inf, -Inf, a stale marker, a native histogram): the line breaks there, it is not a gap and never zero. */
export interface Sample { t: number; v: number | null; special?: string }
export interface Gap { from: number; to: number; text?: string }

/** A "nice" axis maximum at or above `value` (1, 2, 2.5, 5 times a power of ten). Never zero. */
export function niceMax(value: number): number {
 if (!Number.isFinite(value) || value <= 0) return 1;
 const exp = Math.floor(Math.log10(value));
 const base = 10 ** exp;
 const f = value / base;
 const step = f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10;
 return step * base;
}

/** Axis labels from the top (max) to the bottom (min). */
export function yTicks(min: number, max: number, count = 4): number[] {
 const out: number[] = [];
 for (let i = 0; i < count; i++) out.push(max - ((max - min) * i) / (count - 1));
 return out;
}

/** The bottom of the value axis: zero, or the next round number below the lowest value when values are negative. */
export function niceMin(lowest: number): number { return lowest < 0 ? -niceMax(-lowest) : 0; }

/** A sample that is present (it has a value or names a value that cannot be plotted). */
export const isPresent = (s: Sample): boolean => s.v !== null || s.special !== undefined;

const MINUTE = 60_000, HOUR = 60 * MINUTE, DAY = 24 * HOUR;
const STEPS = [1000, 5000, 10_000, 15_000, 30_000, MINUTE, 2 * MINUTE, 5 * MINUTE, 10 * MINUTE, 15 * MINUTE, 30 * MINUTE, HOUR, 2 * HOUR, 3 * HOUR, 6 * HOUR, 12 * HOUR, DAY, 2 * DAY, 7 * DAY];

/** The format of a clock label for a span: seconds only for short spans, the date for spans of two days and more. */
export function clockFormatter(spanMs: number, timeZone: string): (ms: number) => string {
 const withSeconds = spanMs <= 10 * MINUTE;
 const withDate = spanMs > 2 * DAY;
 const time = new Intl.DateTimeFormat('en-GB', { timeZone, hour: '2-digit', minute: '2-digit', ...(withSeconds ? { second: '2-digit' } : {}), hour12: false });
 const date = new Intl.DateTimeFormat('en-GB', { timeZone, day: '2-digit', month: 'short' });
 return (ms) => (withDate ? `${date.format(new Date(ms))} ${time.format(new Date(ms))}` : time.format(new Date(ms)));
}

/** Evenly spaced round-clock ticks inside [start,end]. `maxTicks` bounds the count so labels never collide. */
export function timeTicks(start: number, end: number, maxTicks: number): number[] {
 const span = end - start;
 if (!(span > 0) || maxTicks < 2) return [start, end];
 const step = STEPS.find((s) => span / s <= maxTicks - 1) ?? STEPS[STEPS.length - 1]!;
 // Align to UTC multiples; fine for sub-day steps in whole-hour zones, and the labels are formatted in the console's zone anyway.
 const first = Math.ceil(start / step) * step;
 const out: number[] = [];
 for (let t = first; t <= end; t += step) out.push(t);
 return out.length >= 2 ? out : [start, end];
}

function median(values: number[]): number {
 if (values.length === 0) return 0;
 const s = [...values].sort((a, b) => a - b);
 const m = Math.floor(s.length / 2);
 return s.length % 2 ? s[m]! : (s[m - 1]! + s[m]!) / 2;
}

/** The sample interval: the median spacing of the samples that carry a value. */
export function sampleStep(samples: readonly Sample[]): number {
 const ts = samples.filter(isPresent).map((s) => s.t);
 const d: number[] = [];
 for (let i = 1; i < ts.length; i++) d.push(ts[i]! - ts[i - 1]!);
 return median(d);
}

/** Where a series has no samples: null values, and spans between samples (or before the first and after the last) wider than 2.5 sample intervals. Never zero. */
export function detectGaps(samples: readonly Sample[], start: number, end: number, factor = 2.5): Gap[] {
 const gaps: Gap[] = [];
 const have = samples.filter(isPresent);
 if (have.length === 0) return [{ from: start, to: end, text: 'no samples' }];
 const step = sampleStep(samples) || (end - start) / 60;
 const limit = step * factor;
 const first = have[0]!;
 if (first.t - start > limit) gaps.push({ from: start, to: first.t });
 for (let i = 1; i < have.length; i++) {
  const a = have[i - 1]!, b = have[i]!;
  if (b.t - a.t > limit) gaps.push({ from: a.t, to: b.t });
 }
 const last = have[have.length - 1]!;
 if (end - last.t > limit) gaps.push({ from: last.t, to: end });
 return gaps;
}

/** Merge overlapping or touching gap spans, keeping the first text. */
export function mergeGaps(all: readonly Gap[]): Gap[] {
 const sorted = [...all].sort((a, b) => a.from - b.from);
 const out: Gap[] = [];
 for (const g of sorted) {
  const last = out[out.length - 1];
  if (last && g.from <= last.to) { last.to = Math.max(last.to, g.to); if (last.text === undefined && g.text !== undefined) last.text = g.text; } else out.push({ ...g });
 }
 return out;
}

export function inGap(gaps: readonly Gap[], t: number): Gap | undefined { return gaps.find((g) => t > g.from && t < g.to); }

/** Index of the sample nearest to `t` (samples sorted by time), or -1 when none. */
export function nearestIndex(samples: readonly Sample[], t: number): number {
 let best = -1, bestD = Infinity;
 for (let i = 0; i < samples.length; i++) {
  const d = Math.abs(samples[i]!.t - t);
  if (d < bestD) { best = i; bestD = d; } else if (samples[i]!.t > t) break;
 }
 return best;
}

/** Split a series into drawable runs: a run ends at a null value, or where a gap begins. */
export function runs(samples: readonly Sample[], gaps: readonly Gap[]): Sample[][] {
 const out: Sample[][] = [];
 let cur: Sample[] = [];
 for (const s of samples) {
  if (s.v === null || inGap(gaps, s.t)) { if (cur.length) out.push(cur); cur = []; continue; }
  cur.push(s);
 }
 if (cur.length) out.push(cur);
 return out;
}

export function linePath(points: readonly { x: number; y: number }[]): string {
 return points.map((p, i) => `${i ? 'L' : 'M'}${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ');
}

/** Estimated text width in CSS px for the tooltip when no canvas is available (tests, server rendering). */
export function estimateTextWidth(text: string, px = 12.5): number { return Math.ceil(text.length * px * 0.56); }

/** The spans where both lists have a gap (a band drawn for several series is only where none of them has samples). */
export function intersectGaps(a: readonly Gap[], b: readonly Gap[]): Gap[] {
 const out: Gap[] = [];
 for (const x of a) for (const y of b) { const from = Math.max(x.from, y.from), to = Math.min(x.to, y.to); if (to > from) out.push({ from, to, ...(x.text ?? y.text ? { text: x.text ?? y.text } : {}) } as Gap); }
 return out;
}
