// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Pure view mapping for the trace page. Every limit of the analysis is turned into a sentence here, so no state of a trace
// is carried by colour or position alone. Nanoseconds are decimal strings on the wire and BigInt here, never `number`.
import { ApiFault, type DurationBounds, type Id, type PathResult, type PathSegment, type SpanId, type SpanReport, type TraceView, type ViewState } from '../api/types';

const ID32 = /^[0-9a-f]{32}$/;
const ID16 = /^[0-9a-f]{16}$/;
const NS = /^-?(0|[1-9][0-9]{0,18})$/;
const CODE = /^[a-z_]{1,48}$/;
const STATES: readonly ViewState[] = ['ready', 'empty', 'incomplete', 'stale', 'not_available'];
const BASES = ['same_domain_monotonic', 'wall_clock_with_uncertainty'];
const FLAGS = ['open', 'end_before_start', 'cross_domain_duration', 'dependency_boundary', 'cancelled', 'incomplete', 'async', 'duplicate_id', 'in_cycle', 'orphan'];
const EDGE_KINDS = ['missing_parent', 'parent_ambiguous', 'parent_in_cycle', 'cycle', 'duplicate_span_id', 'multiple_roots', 'no_root', 'sequential_order_uncertain', 'critical_branch_ambiguous', 'link_unresolved', 'link_foreign_trace'];
/** Bounds on what a page renders; the server caps the trace at the same order of magnitude. */
export const MAX_RENDER_SPANS = 100_000;
const MAX_TEXT = 256;

const bad = (): never => { throw new ApiFault(200, 'invalid_response', '', 'response does not match the request'); };
const isRec = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const dec = (v: unknown): v is string => typeof v === 'string' && NS.test(v);
const text = (v: unknown): v is string => typeof v === 'string' && v.length <= MAX_TEXT;
const spanId = (v: unknown): v is string => typeof v === 'string' && ID16.test(v);
const list = (v: unknown, max = MAX_RENDER_SPANS): v is unknown[] => Array.isArray(v) && v.length <= max;

function boundsOk(b: unknown): b is DurationBounds {
 if (!isRec(b) || typeof b.known !== 'boolean' || !dec(b.min_ns) || !dec(b.max_ns)) return false;
 if (b.basis !== undefined && !BASES.includes(b.basis as string)) return false;
 return !b.known || (BigInt(b.min_ns) >= 0n && BigInt(b.min_ns) <= BigInt(b.max_ns));
}

/** Accepts a trace view only for exactly the requested organization, project and trace, and a path whose parts agree with each other (every segment, edge and clock issue names a span of this trace). A response that does not is a fault and is never rendered. */
export function parseTraceView(raw: unknown, want: { org: Id; project: Id; trace: Id }): TraceView {
 if (!isRec(raw) || raw.org !== want.org || raw.project !== want.project || raw.trace !== want.trace || !STATES.includes(raw.state as ViewState) || typeof raw.partial !== 'boolean') return bad();
 if (!list(raw.sections, 32) || !raw.sections.every((s) => isRec(s) && typeof s.name === 'string' && STATES.includes(s.state as ViewState))) return bad();
 const hasPath = raw.path !== undefined;
 // ready always carries a path; empty and not_available never do; a partial or stale read may or may not have spans to analyze.
 if ((raw.state === 'ready' && !hasPath) || ((raw.state === 'empty' || raw.state === 'not_available') && hasPath)) return bad();
 if (raw.reason !== undefined && (typeof raw.reason !== 'string' || !CODE.test(raw.reason))) return bad();
 if (hasPath) parsePath(raw.path, want.trace);
 return raw as unknown as TraceView;
}

function parsePath(raw: unknown, trace: Id): void {
 if (!isRec(raw) || raw.trace_id !== trace || !ID32.test(trace) || !list(raw.spans) || raw.span_count !== (raw.spans as unknown[]).length) return bad();
 if (!list(raw.trees) || !list(raw.edges) || !list(raw.clock_issues) || !list(raw.reasons, 64) || !boundsOk(raw.observed) || typeof raw.complete !== 'boolean' || typeof raw.unlike_clock_domains !== 'boolean' || !dec(raw.max_uncertainty_ns)) return bad();
 const ids = new Set<string>();
 for (const s of raw.spans as unknown[]) {
  if (!isRec(s) || !spanId(s.span_id) || (s.parent_id !== null && !spanId(s.parent_id)) || !text(s.span_kind) || !text(s.operation) || !text(s.status) || (s.dependency_alias !== undefined && !text(s.dependency_alias))) return bad();
  if (!dec(s.start_wall_ns) || (s.end_wall_ns !== null && !dec(s.end_wall_ns)) || !boundsOk(s.duration) || !list(s.flags, 16) || !(s.flags as unknown[]).every((f) => FLAGS.includes(f as string)) || typeof s.sample_probability !== 'number' || !text(s.sample_decision) || !list(s.links, 256)) return bad();
  for (const k of ['job_id', 'replay_id', 'profile_id']) if (s[k] !== undefined && (typeof s[k] !== 'string' || !ID32.test(s[k] as string))) return bad();
  for (const l of s.links as unknown[]) if (!isRec(l) || typeof l.trace_id !== 'string' || !ID32.test(l.trace_id) || !spanId(l.span_id) || typeof l.same_trace !== 'boolean' || typeof l.resolved !== 'boolean') return bad();
  ids.add(s.span_id);
 }
 // A duplicate span ID is reported once per copy by the server; copies are never on a path, so they stay only in the off-path list.
 for (const t of raw.trees as unknown[]) {
  if (!isRec(t) || !spanId(t.root_span_id) || !ids.has(t.root_span_id) || typeof t.orphan !== 'boolean' || !boundsOk(t.duration) || !list(t.segments)) return bad();
  for (const g of t.segments as unknown[]) if (!isRec(g) || !spanId(g.span_id) || !ids.has(g.span_id) || typeof g.depth !== 'number' || !Number.isInteger(g.depth) || g.depth < 0 || !boundsOk(g.self) || typeof g.ambiguous !== 'boolean' || typeof g.parallel_siblings_off_path !== 'number' || typeof g.async_children_off_path !== 'number') return bad();
 }
 for (const e of raw.edges as unknown[]) if (!isRec(e) || !EDGE_KINDS.includes(e.kind as string) || (e.span_id !== undefined && !ids.has(e.span_id as string)) || (e.other_span_ids !== undefined && (!list(e.other_span_ids, 64) || !(e.other_span_ids as unknown[]).every(spanId))) || (e.count !== undefined && typeof e.count !== 'number')) return bad();
 for (const c of raw.clock_issues as unknown[]) if (!isRec(c) || !ids.has(c.span_id as string) || !ids.has(c.parent_id as string) || (c.kind !== 'starts_before_parent' && c.kind !== 'ends_after_parent') || typeof c.certain !== 'boolean' || typeof c.cross_domain !== 'boolean' || !dec(c.uncertainty_ns)) return bad();
 if (!(raw.reasons as unknown[]).every((r) => typeof r === 'string' && CODE.test(r))) return bad();
 const s = raw.sampling;
 if (!isRec(s) || typeof s.kept !== 'number' || typeof s.dropped !== 'number' || typeof s.min_probability !== 'number' || typeof s.sampled !== 'boolean' || typeof s.invalid_probability !== 'number') return bad();
}

// ---- durations ---------------------------------------------------------------------------------------------------
function scaled(n: bigint, div: bigint, unit: string): string {
 const whole = n / div;
 const frac = ((n % div) * 1000n) / div;
 const digits = frac === 0n ? '' : `.${frac.toString().padStart(3, '0').replace(/0+$/, '')}`;
 return `${whole}${digits} ${unit}`;
}
/** A nanosecond count in the largest unit that keeps it readable, exact to three decimals. */
export function durationText(ns: bigint): string {
 const sign = ns < 0n ? '-' : '';
 const n = ns < 0n ? -ns : ns;
 if (n < 1_000n) return `${sign}${n} ns`;
 if (n < 1_000_000n) return `${sign}${scaled(n, 1_000n, 'µs')}`;
 if (n < 1_000_000_000n) return `${sign}${scaled(n, 1_000_000n, 'ms')}`;
 return `${sign}${scaled(n, 1_000_000_000n, 's')}`;
}
/** An interval in words. Never a single figure unless the two bounds are equal. */
export function boundsText(b: DurationBounds): string {
 if (!b.known) return 'not measured';
 const lo = BigInt(b.min_ns), hi = BigInt(b.max_ns);
 return lo === hi ? `exactly ${durationText(lo)}` : `between ${durationText(lo)} and ${durationText(hi)}`;
}
export function basisWords(b: DurationBounds): string {
 if (!b.known) return 'No duration could be derived from the recorded times.';
 return b.basis === 'wall_clock_with_uncertainty'
  ? 'Derived from wall clocks of unlike clock domains, widened by their stated uncertainty; monotonic readings of unlike domains are never subtracted.'
  : 'Derived from monotonic readings of one clock domain.';
}
/** The observed duration of the whole trace. When the bounds differ no single total is stated. */
export function observedWords(path: PathResult): string {
 const b = path.observed;
 if (!b.known) return 'Observed duration of this trace: not measured. A root has no recorded end or its recorded end precedes its start, so no bound can be given.';
 if (BigInt(b.min_ns) === BigInt(b.max_ns)) return `Observed duration of this trace: ${boundsText(b)}.`;
 return `Observed duration of this trace: ${boundsText(b)}. The bounds differ, so no single total is shown.`;
}

// ---- limits in words ---------------------------------------------------------------------------------------------
export interface Limit { code: string; text: string }
const edgeCount = (path: PathResult, kind: string): number => path.edges.filter((e) => e.kind === kind).reduce((n, e) => n + (e.count ?? 1), 0);
const flagCount = (path: PathResult, flag: string): number => path.spans.filter((s) => s.flags.includes(flag)).length;
const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;

/** Every limit of the analysis as a sentence: what is missing, what is ambiguous, what the clocks cannot say and what sampling hides. */
export function limits(path: PathResult, partial: boolean): Limit[] {
 const out: Limit[] = [];
 const add = (code: string, t: string): void => { out.push({ code, text: t }); };
 if (partial) add('spans_partial', 'The read of this trace was partial: some data did not answer, so spans may be missing. Missing spans are not proof that no work happened.');
 for (const reason of path.reasons) {
  switch (reason) {
   case 'missing_parent': add(reason, `${plural(edgeCount(path, 'missing_parent'), 'span names', 'spans name')} a parent that is not in the data this account can read (lost, outside the window, or not visible to this account). They are shown as separate orphan trees and are never added to the duration of the root.`); break;
   case 'parent_ambiguous': add(reason, `${plural(edgeCount(path, 'parent_ambiguous'), 'span names', 'spans name')} a parent whose span ID occurs more than once, so its real parent cannot be decided. It is shown as an orphan tree.`); break;
   case 'cycle': add(reason, `The recorded parent links form a cycle (${plural(edgeCount(path, 'cycle'), 'span', 'spans')} in a cycle). That data is corrupt or incomplete; spans in a cycle are excluded from every path and no order is invented for them.`); break;
   case 'duplicate_span_id': add(reason, `${plural(edgeCount(path, 'duplicate_span_id'), 'span ID is', 'span IDs are')} recorded more than once. Every copy is excluded from the causal path because it cannot be told which one is real.`); break;
   case 'multiple_roots': add(reason, `${edgeCount(path, 'multiple_roots')} spans have no parent. A trace should have one root, so the trees are analyzed separately and the trace duration is shown only as bounds.`); break;
   case 'no_root': add(reason, 'No span without a parent was read: the root is missing, so every tree here begins at an orphan and the true start of the request is unknown.'); break;
   case 'span_open': add(reason, `${plural(flagCount(path, 'open'), 'span has', 'spans have')} no recorded end. Their duration is not measured; no end time is invented.`); break;
   case 'end_before_start': add(reason, `${plural(flagCount(path, 'end_before_start'), 'span records', 'spans record')} an end earlier than its start. It is reported as recorded and not repaired; no duration is given for it.`); break;
   case 'clock_violation': add(reason, 'Some child spans start before or end after their parent on the same clock domain, which no clock uncertainty can explain. The recorded data is inconsistent; the parent link still decides cause and effect.'); break;
   case 'clock_uncertain': add(reason, 'Some child spans appear to start before or end after their parent. Across hosts this can be clock skew within the stated uncertainty, so it is reported as uncertainty; wall-clock time never reorders cause and effect.'); break;
   case 'critical_branch_ambiguous': add(reason, `Clock uncertainty prevents deciding which of several branches finished last in ${plural(path.edges.filter((e) => e.kind === 'critical_branch_ambiguous').length, 'place', 'places')}. All candidates are marked ambiguous instead of one being chosen.`); break;
   case 'sequential_order_uncertain': add(reason, 'Clock uncertainty prevents deciding whether some sibling spans ran one after another or at the same time. Those spans are shown as parallel work off the path, which is not a claim that they were parallel.'); break;
   case 'link_unresolved': add(reason, `${plural(edgeCount(path, 'link_unresolved'), 'link points', 'links point')} at a span that is not in this trace's readable data. A link is an asynchronous reference and never extends the duration of a request.`); break;
   case 'link_foreign_trace': add(reason, `${plural(edgeCount(path, 'link_foreign_trace'), 'link points', 'links point')} at a span of another trace. It is shown as a reference only; nothing from that trace is read or counted here.`); break;
   case 'head_sampled': add(reason, `Head sampling applies (lowest probability ${path.sampling.min_probability}; ${plural(path.sampling.dropped, 'span has', 'spans have')} a drop decision). Spans that were not sampled are absent, so this trace may be only part of the work.`); break;
   case 'sample_probability_invalid': add(reason, `${plural(path.sampling.invalid_probability, 'span carries', 'spans carry')} a sampling probability that is not a valid probability, so what fraction of work was sampled is unknown.`); break;
   case 'span_incomplete': add(reason, `${plural(flagCount(path, 'incomplete'), 'span is', 'spans are')} marked incomplete by its producer.`); break;
   default: add(reason, `The analysis reported a limit this page does not recognise (${reason}); treat the trace as incomplete.`);
  }
 }
 if (path.unlike_clock_domains) add('unlike_clock_domains', `Spans were recorded on unlike clock domains (largest stated uncertainty ${durationText(BigInt(path.max_uncertainty_ns))}). Monotonic readings of different domains are never subtracted; across domains only wall clocks with that uncertainty are used.`);
 const boundary = flagCount(path, 'dependency_boundary');
 if (boundary > 0) add('dependency_boundary', `${plural(boundary, 'dependency call ends', 'dependency calls end')} at the dependency boundary: the dependency's internals were not captured, so none are shown. That is a visibility limit, not proof of no work inside it.`);
 const cancelled = flagCount(path, 'cancelled');
 if (cancelled > 0) add('cancelled', `${plural(cancelled, 'span was', 'spans were')} cancelled; its duration is observed only until cancellation.`);
 if (out.length === 0) add('none_reported', 'No missing edge, clock conflict, sampling or loss was reported for the spans that were read. Spans this account cannot read are never shown, so absence of a report is not proof of completeness.');
 return out;
}

// ---- rows ---------------------------------------------------------------------------------------------------------
const FLAG_WORDS: Record<string, string> = {
 open: 'no recorded end', end_before_start: 'end recorded before start', cross_domain_duration: 'start and end on unlike clock domains', dependency_boundary: 'dependency boundary: internals not captured',
 cancelled: 'cancelled', incomplete: 'marked incomplete', async: 'asynchronous child: not part of the synchronous path', duplicate_id: 'span ID recorded more than once', in_cycle: 'in a parent cycle', orphan: 'parent missing or ambiguous',
};
export function flagWords(flag: string): string { return FLAG_WORDS[flag] ?? flag; }

export interface Row { key: string; tree: number; segment: PathSegment; span: SpanReport; selfText: string; durationText: string; notes: string[] }
const spanIndex = (path: PathResult): Map<SpanId, SpanReport> => new Map(path.spans.map((s) => [s.span_id, s]));

/** One row per path segment of every tree, in path order. A span that is on no path is not a row: it is counted as off-path work. */
export function rows(path: PathResult): Row[] {
 const byId = spanIndex(path);
 const out: Row[] = [];
 path.trees.forEach((t, tree) => {
  t.segments.forEach((segment, i) => {
   const span = byId.get(segment.span_id);
   if (!span) return;
   const notes = [...span.flags.map(flagWords)];
   if (segment.ambiguous) notes.push('one of several candidates for the critical branch; clock uncertainty prevents ranking them');
   if (segment.parallel_siblings_off_path > 0) notes.push(`${plural(segment.parallel_siblings_off_path, 'sibling ran', 'siblings ran')} in parallel or could not be ordered, off the path`);
   if (segment.async_children_off_path > 0) notes.push(`${plural(segment.async_children_off_path, 'asynchronous child', 'asynchronous children')} not counted in this span's duration`);
   out.push({ key: `${tree}:${i}:${segment.span_id}`, tree, segment, span, selfText: boundsText(segment.self), durationText: boundsText(span.duration), notes });
  });
 });
 return out;
}

/** Off-path spans: present in the data, on no critical path. */
export function offPath(path: PathResult): SpanReport[] {
 const on = new Set(path.trees.flatMap((t) => t.segments.map((s) => s.span_id)));
 return path.spans.filter((s) => !on.has(s.span_id));
}

export interface Detail { label: string; value: string }
/** The details of one span as label/text pairs; every value is rendered as a text node. */
export function detailsOf(path: PathResult, id: SpanId | null): Detail[] | null {
 const s = id === null ? undefined : spanIndex(path).get(id);
 if (!s) return null;
 const d: Detail[] = [
  { label: 'Operation', value: s.operation }, { label: 'Kind', value: s.span_kind }, { label: 'Status', value: s.status },
  { label: 'Span ID', value: s.span_id }, { label: 'Parent', value: s.parent_id ?? 'none recorded' },
  { label: 'Observed duration', value: boundsText(s.duration) }, { label: 'How it was derived', value: basisWords(s.duration) },
  { label: 'Sampling', value: `decision ${s.sample_decision}, probability ${s.sample_probability}` },
 ];
 if (s.dependency_alias) d.push({ label: 'Dependency', value: s.dependency_alias });
 if (s.flags.length) d.push({ label: 'Limits of this span', value: s.flags.map(flagWords).join('; ') });
 for (const l of s.links) d.push({ label: 'Link', value: `${l.span_id} in ${l.same_trace ? 'this trace' : `trace ${l.trace_id}`}: ${l.resolved ? 'target span is in this trace' : 'target not readable here'} (asynchronous reference, not part of the duration)` });
 const clock = path.clock_issues.filter((c) => c.span_id === s.span_id);
 for (const c of clock) d.push({ label: 'Clock', value: `${c.kind === 'starts_before_parent' ? 'starts before its parent' : 'ends after its parent'}: ${c.certain ? 'cannot be explained by clock uncertainty' : `may be clock skew within ${durationText(BigInt(c.uncertainty_ns))}`}${c.cross_domain ? ' (unlike clock domains)' : ''}` });
 return d;
}

/** The half-open nanosecond window around a span for the Explore view: [start - 1s, end + 1s), or one second after the start of an open span. */
export function exploreWindow(s: SpanReport): { start: string; end: string } {
 const second = 1_000_000_000n;
 const start = BigInt(s.start_wall_ns);
 const end = s.end_wall_ns !== null && BigInt(s.end_wall_ns) >= start ? BigInt(s.end_wall_ns) : start;
 const lo = start > second ? start - second : 0n;
 return { start: String(lo), end: String(end + second + 1n) };
}
