// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { ApiFault, type PathResult, type TraceView } from '../api/types';
import { MS, ORG, PROJECT, TRACE, bounds, cleanPath, segment, sid, span, tree, unknownBounds, viewOf } from './fixture';
import { basisWords, boundsText, detailsOf, durationText, exploreWindow, flagWords, limits, observedWords, offPath, parseTraceView, rows } from './model';

const want = { org: ORG, project: PROJECT, trace: TRACE };
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
const refuses = (raw: unknown): void => {
 let fault: unknown;
 try { parseTraceView(raw, want); } catch (e) { fault = e; }
 expect(fault).toBeInstanceOf(ApiFault);
 expect((fault as ApiFault).code).toBe('invalid_response');
};

describe('parseTraceView accepts only what it asked for', () => {
 test('a well-formed view round-trips and duplicate span IDs (one report per copy) are accepted', () => {
  const v = viewOf(cleanPath());
  expect(parseTraceView(clone(v), want).path?.span_count).toBe(3);
  const dup = cleanPath({ span_count: 4, spans: [...cleanPath().spans, span(2, 1, 0, 90, { flags: ['duplicate_id'] })] });
  expect(parseTraceView(clone(viewOf(dup)), want).path?.spans.length).toBe(4);
 });
 test('another org, project or trace is a fault, never rendered', () => {
  for (const key of ['org', 'project', 'trace'] as const) refuses({ ...clone(viewOf(cleanPath())), [key]: 'f'.repeat(32) });
  const other = viewOf(cleanPath({ trace_id: 'd'.repeat(32) }));
  refuses(clone(other));
 });
 test('a nanosecond JSON number, a negative bound, min above max and a malformed id are faults', () => {
  const bad = (mutate: (v: TraceView) => void): void => { const v = clone(viewOf(cleanPath())); mutate(v); refuses(v); };
  bad((v) => { (v.path!.spans[0] as unknown as Record<string, unknown>).start_wall_ns = 1700000000000000000; });
  bad((v) => { v.path!.observed = { known: true, min_ns: '-1', max_ns: '5' }; });
  bad((v) => { v.path!.observed = { known: true, min_ns: '9', max_ns: '5' }; });
  bad((v) => { v.path!.spans[0]!.span_id = 'XYZ'; });
  bad((v) => { v.path!.observed.basis = 'guess'; });
  bad((v) => { v.path!.spans[0]!.flags = ['mystery']; });
  bad((v) => { v.path!.edges = [{ kind: 'mystery' }]; });
  bad((v) => { v.path!.spans[1]!.links = [{ trace_id: 'nope', span_id: sid(1), same_trace: true, resolved: true }]; });
 });
 test('every part must agree: span count, segments, edges and clock issues name spans of this trace', () => {
  const bad = (mutate: (p: PathResult) => void): void => { const v = clone(viewOf(cleanPath())); mutate(v.path!); refuses(v); };
  bad((p) => { p.span_count = 99; });
  bad((p) => { p.trees[0]!.segments.push(segment(77, 2, 1)); });
  bad((p) => { p.trees[0]!.root_span_id = sid(77); });
  bad((p) => { p.edges = [{ kind: 'missing_parent', span_id: sid(77) }]; });
  bad((p) => { p.clock_issues = [{ span_id: sid(2), parent_id: sid(77), kind: 'starts_before_parent', certain: false, cross_domain: true, uncertainty_ns: '1' }]; });
  bad((p) => { p.trees[0]!.segments[0]!.depth = -1; });
 });
 test('ready needs a path; empty and not_available must not carry one', () => {
  refuses({ ...clone(viewOf(undefined)), state: 'ready' });
  refuses({ ...clone(viewOf(cleanPath())), state: 'empty' });
  refuses({ ...clone(viewOf(cleanPath())), state: 'not_available' });
  expect(parseTraceView(clone(viewOf(undefined, { state: 'not_available', reason: 'span_source_not_wired' })), want).state).toBe('not_available');
  expect(parseTraceView(clone(viewOf(undefined, { state: 'incomplete', partial: true, reason: 'spans_partial' })), want).path).toBeUndefined();
 });
});

describe('durations are exact and never a lone total when bounds differ', () => {
 test('units and BigInt exactness beyond 2^53', () => {
  expect(durationText(0n)).toBe('0 ns');
  expect(durationText(999n)).toBe('999 ns');
  expect(durationText(1_500n)).toBe('1.5 µs');
  expect(durationText(100n * MS)).toBe('100 ms');
  expect(durationText(1_234_567_890n)).toBe('1.234 s');
  expect(durationText(9_007_199_254_740_993n)).toBe('9007199.254 s');
 });
 test('boundsText says exactly, between, or not measured', () => {
  expect(boundsText(bounds(100n * MS))).toBe('exactly 100 ms');
  expect(boundsText(bounds(93n * MS, 107n * MS, 'wall_clock_with_uncertainty'))).toBe('between 93 ms and 107 ms');
  expect(boundsText(unknownBounds())).toBe('not measured');
 });
 test('observed duration: differing bounds state no single total, equal bounds do not claim a range, unknown is not zero', () => {
  const differ = observedWords(cleanPath({ observed: bounds(100n * MS, 130n * MS, 'wall_clock_with_uncertainty') }));
  expect(differ).toContain('between 100 ms and 130 ms');
  expect(differ).toContain('no single total is shown');
  expect(differ).not.toContain('exactly');
  const same = observedWords(cleanPath());
  expect(same).toContain('exactly 100 ms');
  expect(same).not.toContain('no single total');
  const unknown = observedWords(cleanPath({ observed: unknownBounds() }));
  expect(unknown).toContain('not measured');
  expect(unknown).not.toMatch(/\b0 ns\b/);
 });
 test('the derivation of a bound is stated: monotonic of one domain, or wall clocks widened by uncertainty', () => {
  expect(basisWords(bounds(1n))).toContain('monotonic readings of one clock domain');
  expect(basisWords(bounds(1n, 2n, 'wall_clock_with_uncertainty'))).toContain('never subtracted');
  expect(basisWords(unknownBounds())).toContain('No duration could be derived');
 });
});

describe('every limit is a sentence', () => {
 const path = (over: Partial<PathResult>): PathResult => cleanPath({ complete: false, ...over });
 const sentence = (p: PathResult, code: string, partial = false): string => limits(p, partial).find((l) => l.code === code)?.text ?? '';
 test('a clean trace says what the absence of a report does and does not prove', () => {
  const l = limits(cleanPath(), false);
  expect(l.map((x) => x.code)).toEqual(['none_reported']);
  expect(l[0]!.text).toContain('not proof of completeness');
 });
 test('missing and ambiguous edges name their counts and the consequence', () => {
  const p = path({ reasons: ['missing_parent', 'cycle', 'duplicate_span_id', 'multiple_roots', 'parent_ambiguous'], edges: [{ kind: 'missing_parent', span_id: sid(3), other_span_ids: [sid(9)] }, { kind: 'missing_parent', span_id: sid(4) }, { kind: 'cycle', count: 2 }, { kind: 'duplicate_span_id', span_id: sid(2), count: 2 }, { kind: 'multiple_roots', count: 3 }, { kind: 'parent_ambiguous', span_id: sid(5) }] });
  expect(sentence(p, 'missing_parent')).toContain('2 spans name a parent');
  expect(sentence(p, 'missing_parent')).toContain('never added to the duration of the root');
  expect(sentence(p, 'cycle')).toContain('2 spans in a cycle');
  expect(sentence(p, 'cycle')).toContain('excluded from every path');
  expect(sentence(p, 'duplicate_span_id')).toContain('Every copy is excluded');
  expect(sentence(p, 'multiple_roots')).toContain('3 spans have no parent');
  expect(sentence(p, 'parent_ambiguous')).toContain('1 span names a parent');
 });
 test('clock skew is uncertainty and never reorders; a certain violation is inconsistent data', () => {
  const p = path({ reasons: ['clock_uncertain', 'clock_violation'], unlike_clock_domains: true, max_uncertainty_ns: String(10n * MS) });
  expect(sentence(p, 'clock_uncertain')).toContain('never reorders cause and effect');
  expect(sentence(p, 'clock_violation')).toContain('same clock domain');
  expect(sentence(p, 'unlike_clock_domains')).toContain('10 ms');
  expect(sentence(p, 'unlike_clock_domains')).toContain('never subtracted');
 });
 test('sampling, partial reads, boundaries, cancellation, open and reversed spans are all stated', () => {
  const p = path({
   reasons: ['head_sampled', 'sample_probability_invalid', 'span_open', 'end_before_start', 'span_incomplete', 'link_unresolved', 'link_foreign_trace', 'critical_branch_ambiguous', 'sequential_order_uncertain', 'no_root'],
   sampling: { kept: 2, dropped: 1, min_probability: 0.25, sampled: true, invalid_probability: 1 },
   spans: [span(1, null, 0, 100), span(2, 1, 0, null, { flags: ['open'] }), span(3, 1, 50, 20, { flags: ['end_before_start'] }), span(4, 1, 0, 5, { flags: ['dependency_boundary', 'cancelled'], span_kind: 'client', dependency_alias: 'payments' })],
   edges: [{ kind: 'link_unresolved', span_id: sid(1) }, { kind: 'link_foreign_trace', span_id: sid(1) }, { kind: 'critical_branch_ambiguous', span_id: sid(1), count: 2 }],
  });
  expect(sentence(p, 'head_sampled')).toContain('lowest probability 0.25');
  expect(sentence(p, 'head_sampled')).toContain('only part of the work');
  expect(sentence(p, 'sample_probability_invalid')).toContain('is unknown');
  expect(sentence(p, 'span_open')).toContain('no end time is invented');
  expect(sentence(p, 'end_before_start')).toContain('not repaired');
  expect(sentence(p, 'link_unresolved')).toContain('never extends the duration');
  expect(sentence(p, 'link_foreign_trace')).toContain('nothing from that trace is read');
  expect(sentence(p, 'critical_branch_ambiguous')).toContain('1 place');
  expect(sentence(p, 'sequential_order_uncertain')).toContain('not a claim that they were parallel');
  expect(sentence(p, 'no_root')).toContain('true start of the request is unknown');
  expect(sentence(p, 'dependency_boundary')).toContain('not proof of no work');
  expect(sentence(p, 'cancelled')).toContain('until cancellation');
  expect(sentence(p, 'spans_partial', true)).toContain('partial');
  expect(sentence(p, 'spans_partial', false)).toBe('');
 });
 test('a reason this page does not know is stated as unknown, never dropped', () => {
  expect(sentence(path({ reasons: ['brand_new_reason'] }), 'brand_new_reason')).toContain('does not recognise');
 });
});

describe('rows and details', () => {
 test('rows follow path order; off-path spans are counted separately and flags become words', () => {
  const p = cleanPath();
  const r = rows(p);
  expect(r.map((x) => x.span.span_id)).toEqual([sid(1), sid(2)]);
  expect(r[0]!.selfText).toBe('exactly 30 ms');
  expect(r[0]!.notes.join(' ')).toContain('1 sibling ran in parallel or could not be ordered, off the path');
  expect(offPath(p).map((s) => s.span_id)).toEqual([sid(3)]);
  const amb = cleanPath({ trees: [tree(1, bounds(100n * MS), [segment(1, 0, 30), segment(2, 1, 70, { ambiguous: true, async_children_off_path: 2 })])] });
  expect(rows(amb)[1]!.notes.join(' ')).toContain('clock uncertainty prevents ranking');
  expect(rows(amb)[1]!.notes.join(' ')).toContain('2 asynchronous children not counted');
  expect(flagWords('dependency_boundary')).toContain('internals not captured');
  expect(flagWords('open')).toBe('no recorded end');
 });
 test('selected span details are label/text pairs; an unknown selection is null', () => {
  const p = cleanPath({ spans: [span(1, null, 0, 100), span(2, 1, 0, 70, { operation: '<img src=x onerror=1>', links: [{ trace_id: TRACE, span_id: sid(9), same_trace: true, resolved: false }] }), span(3, 1, 0, 40)], clock_issues: [{ span_id: sid(2), parent_id: sid(1), kind: 'starts_before_parent', certain: false, cross_domain: true, uncertainty_ns: String(10n * MS) }] });
  const d = detailsOf(p, sid(2))!;
  const get = (label: string): string => d.find((x) => x.label === label)?.value ?? '';
  expect(get('Operation')).toBe('<img src=x onerror=1>');
  expect(get('Observed duration')).toBe('exactly 70 ms');
  expect(get('Parent')).toBe(sid(1));
  expect(get('Link')).toContain('target not readable here');
  expect(get('Link')).toContain('not part of the duration');
  expect(get('Clock')).toContain('may be clock skew within 10 ms');
  expect(detailsOf(p, sid(1))!.find((x) => x.label === 'Parent')!.value).toBe('none recorded');
  expect(detailsOf(p, sid(42))).toBeNull();
  expect(detailsOf(p, null)).toBeNull();
 });
 test('a certain clock violation is not blamed on skew, an uncertain one is', () => {
  const issue = (certain: boolean) => ({ span_id: sid(2), parent_id: sid(1), kind: 'ends_after_parent' as const, certain, cross_domain: false, uncertainty_ns: '0' });
  const value = (certain: boolean): string => detailsOf(cleanPath({ clock_issues: [issue(certain)] }), sid(2))!.find((d) => d.label === 'Clock')!.value;
  expect(value(true)).toContain('cannot be explained by clock uncertainty');
  expect(value(true)).not.toContain('may be clock skew');
  expect(value(false)).toContain('may be clock skew within 0 ns');
  expect(value(false)).not.toContain('cannot be explained');
 });
 test('the Explore window is exact BigInt nanoseconds, one second either side, and never underflows', () => {
  const s = span(1, null, 0, 100);
  const w = exploreWindow(s);
  expect(BigInt(s.start_wall_ns) - BigInt(w.start)).toBe(1_000_000_000n);
  expect(BigInt(w.end) - BigInt(s.end_wall_ns!)).toBe(1_000_000_001n);
  expect(exploreWindow({ ...s, start_wall_ns: '5', end_wall_ns: '9' }).start).toBe('0');
  const open = exploreWindow(span(1, null, 0, null));
  expect(BigInt(open.end) - BigInt(s.start_wall_ns)).toBe(1_000_000_001n);
 });
});
