// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Wire-shaped trace fixtures for the unit tests. The shapes follow internal/traces/critical_path.go and internal/httpapi/traces.go exactly.
import type { DurationBounds, PathResult, PathSegment, SpanReport, TraceView, TreePath } from '../api/types';

export const ORG = 'a'.repeat(32), PROJECT = 'b'.repeat(32), TRACE = 'c'.repeat(32);
export const sid = (n: number): string => n.toString(16).padStart(16, '0');
export const MS = 1_000_000n;
export const bounds = (min: bigint, max: bigint = min, basis = 'same_domain_monotonic'): DurationBounds => ({ known: true, min_ns: String(min), max_ns: String(max), basis });
export const unknownBounds = (): DurationBounds => ({ known: false, min_ns: '0', max_ns: '0' });
const T0 = 1_700_000_000_000_000_000n;

export function span(id: number, parent: number | null, startMs: number, endMs: number | null, over: Partial<SpanReport> = {}): SpanReport {
 return {
  span_id: sid(id), parent_id: parent === null ? null : sid(parent), span_kind: 'internal', operation: `op.${id}`, status: 'ok', start_wall_ns: String(T0 + BigInt(startMs) * MS),
  end_wall_ns: endMs === null ? null : String(T0 + BigInt(endMs) * MS), duration: endMs === null ? unknownBounds() : bounds(BigInt(endMs - startMs) * MS), flags: [], sample_probability: 1, sample_decision: 'keep', links: [], ...over,
 };
}
export const segment = (id: number, depth: number, selfMs: number, over: Partial<PathSegment> = {}): PathSegment => ({ span_id: sid(id), depth, self: bounds(BigInt(selfMs) * MS), ambiguous: false, parallel_siblings_off_path: 0, async_children_off_path: 0, ...over });
export const tree = (root: number, duration: DurationBounds, segments: PathSegment[], orphan = false): TreePath => ({ root_span_id: sid(root), orphan, duration, segments });

/** A clean 100 ms root with concurrent 70 ms and 40 ms branches: the path is root then the 70 ms branch. */
export function cleanPath(over: Partial<PathResult> = {}): PathResult {
 return {
  trace_id: TRACE, span_count: 3, spans: [span(1, null, 0, 100), span(2, 1, 0, 70), span(3, 1, 0, 40)],
  trees: [tree(1, bounds(100n * MS), [segment(1, 0, 30, { parallel_siblings_off_path: 1 }), segment(2, 1, 70)])],
  observed: bounds(100n * MS), edges: [], clock_issues: [], unlike_clock_domains: false, max_uncertainty_ns: '0',
  sampling: { kept: 3, dropped: 0, min_probability: 1, sampled: false, invalid_probability: 0 }, complete: true, reasons: [], ...over,
 };
}
export function viewOf(path: PathResult | undefined, over: Partial<TraceView> = {}): TraceView {
 return { org: ORG, project: PROJECT, trace: TRACE, state: path ? 'ready' : 'empty', partial: false, ...(path ? { path } : {}), sections: [{ name: 'spans', state: path ? 'ready' : 'empty' }], ...over };
}
