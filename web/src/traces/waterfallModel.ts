// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The span waterfall of one trace: every span the account may read, in parent-child order, placed on one time axis. Positions come from the
// recorded wall-clock start of each span and the observed duration bounds, never from an invented end: a span with no measured duration has
// a position and no length. Nothing here says which work caused which; the critical path analysis does that, and this only marks its result.
import type { PathResult, SpanId, SpanReport } from '../api/types';
import { durationText } from './model';

/** The server's stated clamp for an unknown clock bound (2^62 ns); a maximum at or above it is no upper bound. */
const UNBOUNDED_NS = 1n << 62n;
export const MAX_WATERFALL_ROWS = 1000;

export interface WaterfallRow {
 key: string;
 span: SpanReport;
 depth: number;
 /** On a critical path of the analysis. */
 onPath: boolean;
 /** One of several candidates for the critical branch. */
 ambiguous: boolean;
 /** Percent of the axis, 0..100, two decimals. */
 left: number;
 /** Length of the shortest observed duration, percent of the axis; 0 when the duration is not measured. */
 width: number;
 /** Where the longest possible duration ends, percent of the axis from `left`; equal to `width` for an exact duration. */
 widthMax: number;
 measured: boolean;
 /** Why this row sits where it does when it is not under a parent (an orphan, a duplicate ID, a span in a cycle). */
 detached: string | null;
}
export interface Waterfall { rows: WaterfallRow[]; total: number; shown: number; spanNs: bigint; ticks: { at: number; text: string }[] }

const pct = (n: bigint, total: bigint): number => Math.round(Number((n * 10000n) / total)) / 100;
const startOf = (s: SpanReport): bigint => BigInt(s.start_wall_ns);
const byStart = (a: SpanReport, b: SpanReport): number => { const d = startOf(a) - startOf(b); return d < 0n ? -1 : d > 0n ? 1 : a.span_id < b.span_id ? -1 : a.span_id > b.span_id ? 1 : 0; };

/** Orders the spans depth first under their parents (children by start time), places each on the shared axis and marks the ones on a critical path. */
export function waterfall(path: PathResult, limit = MAX_WATERFALL_ROWS): Waterfall {
 const spans = path.spans;
 const copies = new Map<SpanId, number>();
 for (const s of spans) copies.set(s.span_id, (copies.get(s.span_id) ?? 0) + 1);
 const real = new Map<SpanId, SpanReport>();
 for (const s of spans) if (copies.get(s.span_id) === 1 && !s.flags.includes('in_cycle')) real.set(s.span_id, s);
 const children = new Map<SpanId, SpanReport[]>();
 const roots: { span: SpanReport; detached: string | null }[] = [];
 const rest: { span: SpanReport; detached: string }[] = [];
 for (const s of spans) {
  if (!real.has(s.span_id)) { rest.push({ span: s, detached: s.flags.includes('in_cycle') ? 'in a parent cycle: no order is invented for it' : 'its span ID is recorded more than once' }); continue; }
  const p = s.parent_id;
  if (p === null) roots.push({ span: s, detached: null });
  else if (real.has(p) && p !== s.span_id) { const list = children.get(p) ?? []; list.push(s); children.set(p, list); }
  else roots.push({ span: s, detached: copies.get(p) !== undefined && !real.has(p) ? 'its parent is ambiguous or in a cycle' : 'its parent is not in the data this account can read' });
 }
 roots.sort((a, b) => byStart(a.span, b.span));
 const onPath = new Map<SpanId, boolean>();
 for (const t of path.trees) for (const g of t.segments) onPath.set(g.span_id, g.ambiguous);

 const order: { span: SpanReport; depth: number; detached: string | null }[] = [];
 const stack: { span: SpanReport; depth: number; detached: string | null }[] = [];
 for (let i = roots.length - 1; i >= 0; i--) stack.push({ ...roots[i]!, depth: 0 });
 const seen = new Set<SpanId>();
 while (stack.length > 0) {
  const cur = stack.pop()!;
  if (seen.has(cur.span.span_id)) continue;
  seen.add(cur.span.span_id);
  order.push(cur);
  const kids = [...(children.get(cur.span.span_id) ?? [])].sort(byStart);
  for (let i = kids.length - 1; i >= 0; i--) stack.push({ span: kids[i]!, depth: cur.depth + 1, detached: null });
 }
 for (const r of rest) order.push({ span: r.span, depth: 0, detached: r.detached });

 let t0 = order.length === 0 ? 0n : startOf(order[0]!.span);
 for (const o of order) { const s = startOf(o.span); if (s < t0) t0 = s; }
 let end = t0 + 1n;
 const longest = (s: SpanReport): bigint => (!s.duration.known ? 0n : BigInt(s.duration.max_ns) >= UNBOUNDED_NS ? BigInt(s.duration.min_ns) : BigInt(s.duration.max_ns));
 for (const o of order) { const e = startOf(o.span) + longest(o.span); if (e > end) end = e; }
 const total = end - t0;
 const rows: WaterfallRow[] = order.slice(0, limit).map((o, i) => {
  const s = o.span;
  const left = pct(startOf(s) - t0, total);
  const measured = s.duration.known;
  const width = measured ? pct(BigInt(s.duration.min_ns), total) : 0;
  const widthMax = measured ? pct(longest(s), total) : 0;
  return { key: `${i}:${s.span_id}`, span: s, depth: o.depth, onPath: onPath.has(s.span_id), ambiguous: onPath.get(s.span_id) === true, left, width: Math.min(width, 100 - left), widthMax: Math.min(widthMax, 100 - left), measured, detached: o.detached };
 });
 const ticks = [0, 25, 50, 75, 100].map((at) => ({ at, text: at === 0 ? '0' : durationText((total * BigInt(at)) / 100n) }));
 return { rows, total: order.length, shown: rows.length, spanNs: total, ticks };
}
