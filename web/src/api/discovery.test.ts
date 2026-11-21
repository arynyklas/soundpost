// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, test } from 'bun:test';
import { bindSession, discover, exemplars, formatExpression, parseDiscovery, parseExemplars, parseFormat } from './client';
import { ApiFault, type DiscoveryRequest, type ExemplarRequest, type FormatRequest } from './types';

const A = 'a'.repeat(32), P = '1'.repeat(32), Q = '2'.repeat(32), T = '4'.repeat(32), REC = '5'.repeat(32), G = '9'.repeat(32);
const dreq = (over: Partial<DiscoveryRequest> = {}): DiscoveryRequest => ({ org: A, projects: [P], signal: 'metric', kind: 'metric_names', matchers: [], time: { start: '1', end: '2' }, limit: 2, ...over });
const ereq = (over: Partial<ExemplarRequest> = {}): ExemplarRequest => ({ org: A, projects: [P], profile: 'promql-prometheus-3.1.0', feature_set: 'f', expression: 'explore_requests', window: { start: '1', end: '2' }, limit: 2, ...over });
const fresh = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ completeness: 'complete', watermarks: [{ group: G, index: '5' }], cached: false, ...over });
const page = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ items: ['a', 'b'], more: false, freshness: fresh(), ...over });
const exemplar = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ project_id: P, labels: [{ name: 'job', value: 'api' }], sample: { time: '1730000000000000000', float: '7ff8000000000001' }, trace_id: T, record_id: REC, ...over });
const bad = (fn: () => unknown): void => { expect(fn).toThrow(ApiFault); };

describe('discovery pages are exact and bounded', () => {
 test('a page, the last page and a null item list', () => {
  expect(parseDiscovery(page({ more: true, next_cursor: 'c1' }), dreq()).next_cursor).toBe('c1');
  expect(parseDiscovery(page(), dreq()).more).toBe(false);
  expect(parseDiscovery(page({ items: null }), dreq()).items).toEqual([]);
 });
 test('a cursor exists exactly when more does', () => {
  bad(() => parseDiscovery(page({ more: true }), dreq()));
  bad(() => parseDiscovery(page({ more: false, next_cursor: 'c' }), dreq()));
  bad(() => parseDiscovery(page({ more: true, next_cursor: '' }), dreq()));
 });
 test('more items than the limit, a non-string item or an unknown freshness is a fault', () => {
  bad(() => parseDiscovery(page({ items: ['a', 'b', 'c'] }), dreq()));
  bad(() => parseDiscovery(page({ items: ['a', 5] }), dreq()));
  bad(() => parseDiscovery(page({ freshness: fresh({ completeness: 'fine' }) }), dreq()));
  bad(() => parseDiscovery(page({ freshness: fresh({ watermarks: [{ group: 'x', index: '1' }] }) }), dreq()));
  bad(() => parseDiscovery(page({ freshness: fresh({ cached: 'no' }) }), dreq()));
  bad(() => parseDiscovery(null, dreq()));
 });
 test('partial and stale freshness are kept, never turned into complete', () => {
  expect(parseDiscovery(page({ freshness: fresh({ completeness: 'partial' }) }), dreq()).freshness.completeness).toBe('partial');
  expect(parseDiscovery(page({ freshness: fresh({ completeness: 'stale' }) }), dreq()).freshness.completeness).toBe('stale');
 });
});

describe('exemplars belong to the requested projects and keep exact values', () => {
 test('an exemplar with its exact NaN bits and its trace', () => {
  const out = parseExemplars({ exemplars: [exemplar({ span_id: 'abcdef0123456789' })], more: false, freshness: fresh() }, ereq());
  expect(out.exemplars[0]).toMatchObject({ trace_id: T, sample: { float: '7ff8000000000001' }, span_id: 'abcdef0123456789' });
 });
 test('another project, a bad trace or span id, more than the limit and a stray cursor are faults', () => {
  const wrap = (e: unknown[], extra: Record<string, unknown> = {}): unknown => ({ exemplars: e, more: false, freshness: fresh(), ...extra });
  bad(() => parseExemplars(wrap([exemplar({ project_id: Q })]), ereq()));
  bad(() => parseExemplars(wrap([exemplar({ trace_id: 'x' })]), ereq()));
  bad(() => parseExemplars(wrap([exemplar({ span_id: 'ABCDEF0123456789' })]), ereq()));
  bad(() => parseExemplars(wrap([exemplar(), exemplar(), exemplar()]), ereq()));
  bad(() => parseExemplars(wrap([exemplar()], { next_cursor: 'c' }), ereq()));
  bad(() => parseExemplars(wrap([exemplar({ sample: { time: 1 } })]), ereq()));
 });
 test('no exemplars is an empty list, not a missing field', () => {
  expect(parseExemplars({ exemplars: null, more: false, freshness: fresh() }, ereq()).exemplars).toEqual([]);
 });
});

describe('format results', () => {
 test('formatted text and its diagnostics', () => {
  expect(parseFormat({ formatted: 'sum(up)', diagnostics: [] }).formatted).toBe('sum(up)');
  expect(parseFormat({ formatted: 'x', diagnostics: [{ severity: 'info', code: 'c', safe_message: 'm' }] }).diagnostics).toHaveLength(1);
  expect(parseFormat({ formatted: 'x', diagnostics: null }).diagnostics).toEqual([]);
 });
 test('anything else is a fault', () => {
  bad(() => parseFormat({ formatted: 5, diagnostics: [] }));
  bad(() => parseFormat({ formatted: 'x', diagnostics: [{ severity: 'nope', code: 'c', safe_message: 'm' }] }));
  bad(() => parseFormat(null));
 });
});

type Fetch = typeof fetch;
const original = globalThis.fetch;
afterEach(() => { globalThis.fetch = original; bindSession(''); });
function mock(handler: (url: string, init: RequestInit) => Response): { calls: { url: string; init: RequestInit }[] } {
 const calls: { url: string; init: RequestInit }[] = [];
 globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => { calls.push({ url: String(input), init: init ?? {} }); return handler(String(input), init ?? {}); }) as Fetch;
 return { calls };
}

describe('discover, exemplars and format are POSTs with the typed body and the CSRF header', () => {
 test('each route, body and header', async () => {
  bindSession('tok');
  const signal = new AbortController().signal;
  const m = mock((url) => new Response(JSON.stringify(url.endsWith('/discover') ? page() : url.endsWith('/exemplars') ? { exemplars: [], more: false, freshness: fresh() } : { formatted: 'x', diagnostics: [] }), { status: 200 }));
  await discover(dreq(), signal);
  await exemplars(ereq(), signal);
  const f: FormatRequest = { org: A, projects: [P], language: 'promql', profile: 'p', feature_set: 'f', expression: 'up' };
  await formatExpression(f, signal);
  expect(m.calls.map((c) => c.url)).toEqual(['/api/v1/discover', '/api/v1/exemplars', '/api/v1/query/format']);
  expect(JSON.parse(m.calls[0]!.init.body as string)).toEqual(dreq());
  expect(JSON.parse(m.calls[2]!.init.body as string)).toEqual(f);
  for (const c of m.calls) expect([c.init.method, c.init.credentials, c.init.signal, (c.init.headers as Record<string, string>)['X-CSRF-Token']]).toEqual(['POST', 'same-origin', signal, 'tok']);
 });
 test('a budget refusal is the typed quota fault', async () => {
  mock(() => new Response(JSON.stringify({ code: 'quota', detail: 'quota' }), { status: 429 }));
  await expect(discover(dreq(), new AbortController().signal)).rejects.toMatchObject({ status: 429, code: 'quota' });
  await expect(exemplars(ereq(), new AbortController().signal)).rejects.toMatchObject({ status: 429, code: 'quota' });
  await expect(formatExpression({ org: A, projects: [P], language: 'logql', profile: 'p', feature_set: 'f', expression: 'x' }, new AbortController().signal)).rejects.toMatchObject({ status: 429 });
 });
});
