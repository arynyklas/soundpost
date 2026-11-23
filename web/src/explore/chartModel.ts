// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Pure mapping from an exact C06 range series to what the shared chart draws, and the figures shown next to it. Nothing is invented:
// a missing evaluation step stays a missing sample (never zero), and NaN, infinities, the stale marker and native histograms are named
// present values that break the line. Nanoseconds stay strings or BigInt; a JavaScript number is only used for the chart's epoch ms.
import type { EvaluationWire, Sample as WireSample } from '../api/types';
import type { Sample as ChartSample } from '../ui/chart/model';
import { planSeries, type MarkKind, type SeriesPlan } from './model';

/** At most this many series share one chart (the chart has six distinct series tones); the rest are listed and said not to be drawn. */
export const MAX_DRAWN = 6;
export const NS_PER_MS = 1_000_000n;

export const nsToMs = (ns: string): number => Number(BigInt(ns) / NS_PER_MS);

const MARK_WORDS: Record<MarkKind, string> = { nan: 'NaN', pos_inf: '+Inf', neg_inf: '-Inf', stale: 'stale marker', histogram: 'native histogram' };
export const markWord = (kind: MarkKind): string => MARK_WORDS[kind];

/** A number for an axis, a tooltip or a statistics cell: four significant digits, never exponent noise for ordinary values. */
export function formatNumber(v: number): string {
 if (!Number.isFinite(v)) return String(v);
 if (v === 0) return Object.is(v, -0) ? '-0' : '0';
 const abs = Math.abs(v);
 if (abs >= 1e15 || abs < 1e-6) return v.toExponential(3);
 return new Intl.NumberFormat('en-US', { maximumSignificantDigits: 4 }).format(v);
}

/** The evaluation window in epoch ms, or null for an instant evaluation (nothing is charted over time then). */
export function chartWindow(evaluation: EvaluationWire | null): { start: number; end: number } | null {
 if (evaluation === null || evaluation.instant) return null;
 const start = nsToMs(evaluation.start), end = nsToMs(evaluation.end);
 return end > start ? { start, end } : null;
}

/**
 * The samples of one series as the chart takes them. A plottable sample is a value; NaN, an infinity, the stale marker and a native
 * histogram are present values that cannot be plotted (`special`, the line breaks); every run of absent evaluation steps gets one
 * absent sample in its middle so the line is cut there and the tooltip says "no samples", never a value.
 */
export function chartSamples(samples: readonly WireSample[], evaluation: EvaluationWire | null): ChartSample[] {
 const plan = planSeries([...samples], evaluation);
 const out: ChartSample[] = [];
 for (const seg of plan.segments) for (const p of seg) out.push({ t: nsToMs(p.time), v: Number(p.value) });
 for (const m of plan.marks) out.push({ t: nsToMs(m.time), v: null, special: markWord(m.kind) });
 const win = chartWindow(evaluation);
 for (const g of plan.gaps) {
  const from = g.after !== null ? nsToMs(g.after) : win?.start;
  const to = g.before !== null ? nsToMs(g.before) : win?.end;
  if (from !== undefined && to !== undefined && to > from) out.push({ t: (from + to) / 2, v: null });
 }
 return out.sort((a, b) => a.t - b.t);
}

export interface SeriesStats { count: number; min: number; max: number; avg: number; last: number }
/** Minimum, maximum, mean and last of the plottable values of a series, or null when it has none (never zeros). The mean is of the samples that exist; absent steps are not in it. */
export function seriesStats(plan: SeriesPlan): SeriesStats | null {
 let count = 0, min = Infinity, max = -Infinity, sum = 0, last = 0, lastAt = -1n;
 for (const seg of plan.segments) {
  for (const p of seg) {
   count++; sum += p.value; if (p.value < min) min = p.value; if (p.value > max) max = p.value;
   const t = BigInt(p.time);
   if (t >= lastAt) { lastAt = t; last = p.value; }
  }
 }
 return count === 0 ? null : { count, min, max, avg: sum / count, last };
}

export interface MarkCounts { nan: number; inf: number; stale: number; histogram: number }
export function markCounts(plans: readonly SeriesPlan[]): MarkCounts {
 const c: MarkCounts = { nan: 0, inf: 0, stale: 0, histogram: 0 };
 for (const plan of plans) for (const m of plan.marks) { if (m.kind === 'nan') c.nan++; else if (m.kind === 'stale') c.stale++; else if (m.kind === 'histogram') c.histogram++; else c.inf++; }
 return c;
}

/** The words under a chart for the values it does not plot; empty when there are none. */
export function markSentence(c: MarkCounts): string {
 const parts: string[] = [];
 if (c.nan > 0) parts.push(`${c.nan} NaN (a value, not a gap)`);
 if (c.inf > 0) parts.push(`${c.inf} infinite`);
 if (c.stale > 0) parts.push(`${c.stale} stale ${c.stale === 1 ? 'marker' : 'markers'} (the absence of a sample)`);
 if (c.histogram > 0) parts.push(`${c.histogram} native ${c.histogram === 1 ? 'histogram' : 'histograms'}`);
 return parts.length === 0 ? '' : `Not plotted, and the line breaks there: ${parts.join(', ')}.`;
}

/** The most points one series puts on the chart; a drawing needs a few per pixel, and the shared chart takes its extent from every point it is given. */
export const MAX_CHART_POINTS = 1500;

/**
 * Thins a dense series for drawing: each run of plottable samples is cut into groups and only the lowest and the highest value of a group stay (in time order), so peaks and
 * troughs survive. Absent samples and named values (NaN and the rest) are never dropped. The figures and the data table use every sample; only the drawing is thinned.
 */
export function downsample(samples: readonly ChartSample[], max = MAX_CHART_POINTS): { samples: ChartSample[]; thinned: boolean } {
 if (samples.length <= max) return { samples: [...samples], thinned: false };
 const group = Math.ceil(samples.length / (max / 2));
 const out: ChartSample[] = [];
 let bucket: ChartSample[] = [];
 const flush = (): void => {
  if (bucket.length === 0) return;
  let lo = bucket[0]!, hi = bucket[0]!;
  for (const s of bucket) { if ((s.v ?? 0) < (lo.v ?? 0)) lo = s; if ((s.v ?? 0) > (hi.v ?? 0)) hi = s; }
  out.push(...(lo === hi ? [lo] : lo.t <= hi.t ? [lo, hi] : [hi, lo]));
  bucket = [];
 };
 for (const s of samples) {
  if (s.v === null) { flush(); out.push(s); continue; }
  bucket.push(s);
  if (bucket.length >= group) flush();
 }
 flush();
 return { samples: out, thinned: true };
}
