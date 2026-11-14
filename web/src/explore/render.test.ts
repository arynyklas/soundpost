// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Server-rendered markup of the result components. Telemetry text (log lines, label values, strings, language messages) is
// untrusted: it must reach the page only as escaped text, never as an element or an attribute.
import { describe, expect, test } from 'bun:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { QueryFault, type EvaluationWire, type LogEntry, type ProjectResult, type QueryValue, type Sample } from '../api/types';
import { DiagnosticList, FaultView } from './ExplorePage';
import { LiveItems } from './LiveLogView';
import { LogResult } from './LogResult';
import { MetricResult } from './MetricResult';
import { SavedViews } from './SavedViews';
import type { LiveItem } from './liveModel';

const P = '1'.repeat(32), G = '9'.repeat(32), R = '3'.repeat(32);
const CANARY = '<img src=x onerror="window.__pwn=1"> & <script>window.__pwn=2</script>';
const stats = { scans_started: '1', pages_read: '1', rows_read: '1', bytes_read: '1', series_returned: '1', samples_returned: '1', logs_returned: '0', peak_memory_bytes: '1', elapsed_ns: '1', cached: false, limit_reached: false };
const project = (value: QueryValue): ProjectResult => ({ project_id: P, value, diagnostics: [], watermarks: [{ group: G, index: '1' }], completeness: 'complete', stats });
const render = (el: React.ReactElement): string => renderToStaticMarkup(el);
const bitsOf = (x: number): string => { const dv = new DataView(new ArrayBuffer(8)); dv.setFloat64(0, x); return dv.getBigUint64(0).toString(16).padStart(16, '0'); };
const NS = 1_000_000_000n, T0 = 1730000000n * NS;
const at = (s: number): string => String(T0 + BigInt(s) * NS);
const sample = (s: number, bits: string): Sample => ({ time: at(s), float: bits });
const noElementsFromText = (html: string): void => {
 expect(html).not.toMatch(/<img/i);
 expect(html).not.toMatch(/<script/i);
 expect(html).not.toMatch(/<[^>]*\sonerror\s*=/i);
 expect(html).toContain('&lt;img src=x onerror=');
};

describe('log text is only ever text', () => {
 const entry = (index: string, time: string, line: string, over: Partial<LogEntry> = {}): LogEntry => ({ index, time, id: `${'a'.repeat(31)}${index}`, multiplicity: '1', line, stream_labels: [{ name: 'app', value: 'web' }], structured_metadata: [], ...over });
 const logs = (entries: LogEntry[], labels = [{ name: 'app', value: 'web' }]): ProjectResult => project({ type: 'streams', streams: [{ labels, entries }] });
 test('an XSS canary in the line, a stream label and structured metadata is escaped everywhere', () => {
  const html = render(React.createElement(LogResult, { result: logs([entry('0', '1730000000000000001', CANARY, { stream_labels: [{ name: 'canary', value: CANARY }], structured_metadata: [{ name: 'meta', value: CANARY }] })], [{ name: 'canary', value: CANARY }]) }));
  noElementsFromText(html);
  expect((html.match(/&lt;img src=x onerror=/g) ?? []).length).toBeGreaterThanOrEqual(3);
 });
 test('lines one nanosecond apart and two at the same nanosecond are four rows, each with its exact time and position', () => {
  const html = render(React.createElement(LogResult, { result: logs([entry('0', '1730000000000000001', 'a'), entry('1', '1730000000000000002', 'b'), entry('2', '1730000000000000003', 'c'), entry('3', '1730000000000000003', 'd')]) }));
  expect((html.match(/data-entry/g) ?? []).length).toBe(4);
  expect(html).toContain('data-time="1730000000000000001"');
  expect(html).toContain('data-time="1730000000000000002"');
  expect((html.match(/data-time="1730000000000000003"/g) ?? []).length).toBe(2);
  expect(html.indexOf('>c<')).toBeLessThan(html.indexOf('>d<'));
 });
 test('stream labels and structured metadata are separate columns and an empty metadata set says none', () => {
  const html = render(React.createElement(LogResult, { result: logs([entry('0', '1', 'x'), entry('1', '2', 'y', { structured_metadata: [{ name: 'trace', value: 't' }] })]) }));
  expect(html).toContain('data-cell="stream-labels"');
  expect(html).toContain('data-cell="structured-metadata"');
  expect(html).toContain('<small>none</small>');
  expect(html).toContain('{trace=&quot;t&quot;}');
 });
 test('no match is stated as empty, not blank', () => {
  expect(render(React.createElement(LogResult, { result: logs([]) }))).toContain('No log entry matched. Nothing is missing.');
 });
});

describe('metric text is only ever text, and every value says what it is', () => {
 test('canary label values and string results are escaped', () => {
  const vec = project({ type: 'vector', vector: [{ labels: [{ name: 'job', value: CANARY }], sample: sample(0, bitsOf(1)) }] });
  noElementsFromText(render(React.createElement(MetricResult, { result: vec })));
  noElementsFromText(render(React.createElement(MetricResult, { result: project({ type: 'string', string: CANARY }) })));
 });
 test('NaN, infinities, signed zero and the stale marker are named; a plain number is not decorated', () => {
  const rows = [['7ff8000000000001', 'NaN'], ['7ff0000000000000', '+Inf'], ['fff0000000000000', '-Inf'], ['8000000000000000', '-0'], ['7ff0000000000002', 'stale marker'], [bitsOf(42), '42']] as const;
  const html = render(React.createElement(MetricResult, { result: project({ type: 'vector', vector: rows.map(([bits], i) => ({ labels: [{ name: 'n', value: String(i) }], sample: sample(0, bits) })) }) }));
  for (const [bits, text] of rows) expect(html).toContain(`data-bits="${bits}"`);
  expect(html).toContain('data-kind="nan"');
  expect(html).toContain('data-kind="pos_inf"');
  expect(html).toContain('data-kind="neg_inf"');
  expect(html).toContain('data-kind="stale"');
  expect(html).toContain('>-0<');
  expect(html).toContain('>42<');
  expect(html).toContain('not a number: a real value, not a missing one');
  expect(html).toContain('a stale marker: the absence of a sample, not a value');
  expect(rows.map(([, t]) => t).every((t) => html.includes(t))).toBe(true);
 });
 test('a range with absent steps is two lines and a named gap, and no zero is invented', () => {
  const range: EvaluationWire = { instant: false, time: '0', start: at(0), end: at(70), step: String(10n * NS) };
  const matrix = project({ type: 'matrix', matrix: [{ labels: [{ name: '__name__', value: 'explore_stale' }], samples: [sample(0, bitsOf(10)), sample(10, bitsOf(11)), sample(20, bitsOf(12)), sample(60, bitsOf(20)), sample(70, bitsOf(20))] }] });
  const html = render(React.createElement(MetricResult, { result: matrix, evaluation: range }));
  expect(html).toContain('data-segments="2"');
  expect(html).toContain('data-gap-count="1"');
  expect(html).toContain(`data-after="${at(20)}" data-before="${at(60)}"`);
  expect(html).toContain('no sample for 3 evaluation steps');
  expect(html).toContain('A missing sample is absent, not zero.');
  expect(html).not.toMatch(/>0</);
 });
 test('a native histogram is shown with its buckets, not as a number', () => {
  const histogram: Sample = { time: at(0), histogram: { float: { flavor: 'counter', schema: 0, zero_threshold: bitsOf(0), sum: bitsOf(5.5), count: bitsOf(4), zero_count: bitsOf(1), positive_spans: [{ offset: 0, length: 2 }], negative_spans: [], positive_buckets: [bitsOf(2), bitsOf(1)], negative_buckets: [], reset_hint: 'unknown' } } };
  const html = render(React.createElement(MetricResult, { result: project({ type: 'vector', vector: [{ labels: [], sample: histogram }] }) }));
  expect(html).toContain('data-kind="histogram"');
  expect(html).toContain('Native histogram (float variant): count 4, sum 5.5, schema 0');
  expect(html).toContain('<td><code>1</code></td><td><code>1</code></td>');
 });
});

describe('failures and diagnostics are shown as text with their stated range', () => {
 test('a language error with hostile text in the message and in the query is escaped and marks only the stated characters', () => {
  const expr = `sum(${CANARY}`;
  const fault = new QueryFault(400, 'language', R, '', { languageCode: 'syntax.unexpected-token', category: 'syntax', range: { start_byte: 4, end_byte: 10, start_rune: 4, end_rune: 10 }, detail: CANARY });
  const html = render(React.createElement(FaultView, { state: { kind: 'error', fault }, expression: expr }));
  noElementsFromText(html);
  expect(html).toContain('data-code="language"');
  expect(html).toContain('<mark data-testid="expression-mark">&lt;img s</mark>rc=x');
  expect(html).toContain('characters 4 to 10');
 });
 test('a budget fault says the query was refused, never shortened, and shows no range', () => {
  const html = render(React.createElement(FaultView, { state: { kind: 'error', fault: new QueryFault(429, 'quota', R, 'quota') }, expression: 'up' }));
  expect(html).toContain('data-code="quota"');
  expect(html).toContain('refused rather than shortened');
  expect(html).not.toContain('<mark');
 });
 test('a denied or missing scope is the one Not found', () => {
  const html = render(React.createElement(FaultView, { state: { kind: 'unauthorized', status: 404, requestId: R }, expression: 'up' }));
  expect(html).toContain('Not found');
 });
 test('diagnostics keep their severity word and highlight the cited characters as text', () => {
  const html = render(React.createElement(DiagnosticList, { expression: 'sum(explore_mixed)', diagnostics: [{ severity: 'warning', code: 'MixedFloatsHistogramsWarning', source_range: { start_byte: 0, end_byte: 18, start_rune: 0, end_rune: 18 }, safe_message: 'encountered a mix of histograms and floats' }] }));
  expect(html).toContain('<strong>Warning:</strong>');
  expect(html).toContain('<mark>sum(explore_mixed)</mark>');
  expect(html).toContain('MixedFloatsHistogramsWarning');
 });
});

describe('live rows and gaps', () => {
 const row = (sequence: string, line: string): LiveItem => ({ kind: 'row', sequence, project: P, time: '1730000000000000001', id: R, multiplicity: '1', line, labels: [{ name: 'c', value: CANARY }], streamLabels: [{ name: 's', value: CANARY }], metadata: [{ name: 'm', value: CANARY }] });
 test('a canary row is escaped in the line and every label set', () => {
  noElementsFromText(render(React.createElement(LiveItems, { items: [row('1', CANARY)] })));
 });
 test('a gap states its reason, exact sequence bounds and that nothing was delivered between them', () => {
  const gap: LiveItem = { kind: 'gap', sequence: '7', reason: 'replay_evicted', from: '4', to: '7', after: [{ group: G, index: '1' }], through: [{ group: G, index: '9' }], announced: true };
  const html = render(React.createElement(LiveItems, { items: [row('3', 'before'), gap, row('8', 'after')] }));
  expect(html).toContain('data-gap="true" data-announced="yes" data-reason="replay_evicted" data-from="4" data-to="7"');
  expect(html).toContain('were not delivered');
  expect(html.indexOf('before')).toBeLessThan(html.indexOf('data-gap'));
  expect(html.indexOf('data-gap')).toBeLessThan(html.indexOf('after'));
  const unannounced = render(React.createElement(LiveItems, { items: [{ ...gap, announced: false, reason: 'unannounced_sequence_jump', after: [], through: [] }] }));
  expect(unannounced).toContain('the server did not announce it');
 });
});

describe('saved views are an explicit not-available state', () => {
 test('typed unsupported, no list, nothing saved', () => {
  const html = render(React.createElement(SavedViews, { context: { org: 'a'.repeat(32), projects: [P], environment: '', start: '1', end: '2', timezone: 'UTC', generation: 0 } }));
  expect(html).toContain('data-state="unsupported"');
  expect(html).toContain('Not available');
  expect(html).toContain('Nothing is saved');
  expect(html).not.toContain('<ul');
 });
});
