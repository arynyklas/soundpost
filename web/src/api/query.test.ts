// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, test } from 'bun:test';
import { bindSession, createLiveTicket, openLive, parseLiveEvent, parseQueryResult, query, queryFaultOf, stateOfQueryFault } from './client';
import type { SseFrame } from './sse';
import { ApiFault, QueryFault, type LiveEvent, type QueryRequest } from './types';

const A = 'a'.repeat(32), P = '1'.repeat(32), Q = '2'.repeat(32), R = '3'.repeat(32), G = '9'.repeat(32), RID = 'c'.repeat(32);
const req = (over: Partial<QueryRequest> = {}): QueryRequest => ({
 org: A, language: 'promql', profile: 'promql-prometheus-3.1.0', expression: 'up', feature_set: 'promql-prometheus-3.1.0/semantic-sha256-x',
 evaluation: { instant: true, time: '1730000000000000000', start: '0', end: '0', step: '0' }, projects: [P], budget: { timeout_ns: '0', memory_bytes: '0', max_returned: '0' }, allow_partial: false, ...over,
});
const stats = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ scans_started: '1', pages_read: '1', rows_read: '3', bytes_read: '100', series_returned: '1', samples_returned: '3', logs_returned: '0', peak_memory_bytes: '4096', elapsed_ns: '1500000', cached: false, limit_reached: false, ...over });
const project = (id: string, value: unknown, over: Record<string, unknown> = {}): Record<string, unknown> => ({ project_id: id, value, diagnostics: [], watermarks: [{ group: G, index: '5' }], completeness: 'complete', stats: stats(), ...over });
const sample = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ time: '1730000000000000001', float: '3ff0000000000000', ...over });
const vector = (s: Record<string, unknown> = sample()): unknown => ({ type: 'vector', vector: [{ labels: [{ name: 'job', value: 'api' }], sample: s }] });
const entry = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ index: '0', time: '1730000000000000001', id: R, multiplicity: '1', line: 'hello', stream_labels: [{ name: 'app', value: 'web' }], structured_metadata: [], ...over });
const streams = (e: Record<string, unknown> = entry()): unknown => ({ type: 'streams', streams: [{ labels: [{ name: 'app', value: 'web' }], entries: [e] }] });
const floatHistogram = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ float: { flavor: 'gauge', schema: 0, zero_threshold: '0000000000000000', sum: '4014000000000000', count: '4010000000000000', zero_count: '0000000000000000', positive_spans: [{ offset: 0, length: 2 }], negative_spans: [], positive_buckets: ['3ff0000000000000', '4000000000000000'], negative_buckets: [], reset_hint: 'unknown', ...over } });
const bad = (raw: unknown, r: QueryRequest = req()): void => { expect(() => parseQueryResult(raw, r)).toThrow(ApiFault); };

describe('parseQueryResult: a result is accepted only for exactly the request that was sent', () => {
 test('a well formed vector, scalar, string, matrix and log result', () => {
  const out = parseQueryResult({ projects: [project(P, vector())] }, req());
  expect(out.projects[0]?.value).toMatchObject({ type: 'vector' });
  expect(parseQueryResult({ projects: [project(P, { type: 'scalar', scalar: sample() })] }, req()).projects).toHaveLength(1);
  expect(parseQueryResult({ projects: [project(P, { type: 'string', string: 'hello' })] }, req()).projects).toHaveLength(1);
  expect(parseQueryResult({ projects: [project(P, { type: 'matrix', matrix: [{ labels: [], samples: [sample(), sample({ time: '1730000010000000000' })] }] })] }, req()).projects).toHaveLength(1);
  expect(parseQueryResult({ projects: [project(P, streams())] }, req({ language: 'logql', profile: 'logql-loki-3.5.2' })).projects).toHaveLength(1);
 });
 test('nanosecond strings and exact float bits survive untouched, an ordinary NaN keeps its payload', () => {
  const out = parseQueryResult({ projects: [project(P, vector(sample({ float: '7ff8000000000001' })))] }, req());
  const v = out.projects[0]?.value;
  expect(v?.type === 'vector' && v.vector[0]?.sample).toEqual({ time: '1730000000000000001', float: '7ff8000000000001' });
  const logs = parseQueryResult({ projects: [project(P, streams(entry({ time: '1730000000000000002' })))] }, req({ language: 'logql', profile: 'logql-loki-3.5.2' }));
  const s = logs.projects[0]?.value;
  expect(s?.type === 'streams' && s.streams[0]?.entries[0]?.time).toBe('1730000000000000002');
  expect('1730000000000000001' !== '1730000000000000002').toBe(true);
 });
 test('a project that was not requested, a missing or a repeated one is refused, never merged', () => {
  bad({ projects: [project(Q, vector())] });
  bad({ projects: [] });
  bad({ projects: [project(P, vector()), project(P, vector())] }, req({ projects: [P, Q] }));
  bad({ projects: [project(P, vector())] }, req({ projects: [P, Q] }));
  bad({ projects: [project(P, vector()), project(Q, vector())] });
  expect(parseQueryResult({ projects: [project(P, vector()), project(Q, vector())] }, req({ projects: [Q, P] })).projects.map((p) => p.project_id)).toEqual([P, Q]);
 });
 test('every number on the wire must be a string: a JSON number could have lost nanoseconds', () => {
  bad({ projects: [project(P, vector(sample({ time: 1730000000000000001 })))] });
  bad({ projects: [project(P, streams(entry({ index: 0 })))] }, req({ language: 'logql' }));
  bad({ projects: [project(P, streams(entry({ multiplicity: 1 })))] }, req({ language: 'logql' }));
  bad({ projects: [project(P, vector(), { stats: stats({ elapsed_ns: 1500000 }) })] });
  bad({ projects: [project(P, vector(sample({ time: '01730000000000000000' })))] });
  bad({ projects: [project(P, vector(sample({ time: '1730000000000000000.5' })))] });
 });
 test('float bits are exactly 16 lowercase hex digits and exactly one of float and histogram is present', () => {
  for (const float of ['7FF8000000000001', '7ff800000000001', '7ff80000000000010', 'NaN', 1.5, '0x7ff8000000000001']) bad({ projects: [project(P, vector(sample({ float })))] });
  bad({ projects: [project(P, vector({ time: '1' }))] });
  bad({ projects: [project(P, vector(sample({ histogram: floatHistogram() })))] });
  expect(parseQueryResult({ projects: [project(P, vector({ time: '1', histogram: floatHistogram() }))] }, req()).projects).toHaveLength(1);
 });
 test('a native histogram must be internally consistent: its spans account for every bucket', () => {
  bad({ projects: [project(P, vector({ time: '1', histogram: floatHistogram({ positive_buckets: ['3ff0000000000000'] }) }))] });
  bad({ projects: [project(P, vector({ time: '1', histogram: floatHistogram({ sum: 'zz' }) }))] });
  bad({ projects: [project(P, vector({ time: '1', histogram: {} }))] });
  bad({ projects: [project(P, vector({ time: '1', histogram: { integer: {}, float: floatHistogram().float } }))] });
  const integer = { integer: { flavor: 'counter', schema: 0, zero_threshold: '0000000000000000', sum: '4014000000000000', count: '3', zero_count: '0', positive_spans: [{ offset: -1, length: 2 }], negative_spans: [], positive_buckets: ['1', '-1'], negative_buckets: [], reset_hint: 'no' } };
  expect(parseQueryResult({ projects: [project(P, vector({ time: '1', histogram: integer }))] }, req()).projects).toHaveLength(1);
  bad({ projects: [project(P, vector({ time: '1', histogram: { integer: { ...integer.integer, count: 3 } } }))] });
 });
 test('log streams exist only for LogQL, ids must be 32 hex digits', () => {
  bad({ projects: [project(P, streams())] });
  bad({ projects: [project(P, streams(entry({ id: 'xyz' })))] }, req({ language: 'logql' }));
  bad({ projects: [project(P, streams(entry({ line: 5 })))] }, req({ language: 'logql' }));
  bad({ projects: [project(P, streams(entry({ stream_labels: 'a=b' })))] }, req({ language: 'logql' }));
 });
 test('completeness, diagnostics, watermarks and the failure rule are closed', () => {
  bad({ projects: [project(P, vector(), { completeness: 'healthy' })] });
  bad({ projects: [project(P, vector(), { diagnostics: [{ severity: 'fatal', code: 'x', safe_message: 'y' }] })] });
  bad({ projects: [project(P, vector(), { diagnostics: [{ severity: 'warning', code: 'x', source_range: { start_byte: -1, end_byte: 2, start_rune: 0, end_rune: 2 }, safe_message: 'y' }] })] });
  bad({ projects: [project(P, vector(), { watermarks: [{ group: 'x', index: '5' }] })] });
  bad({ projects: [project(P, null)] }); // no value and no failure
  bad({ projects: [project(P, vector(), { failure: { code: 'quota', safe_message: 'quota' } })] }); // a failure carries no value
  bad({ projects: [project(P, null, { failure: { code: 'quota', safe_message: 'quota' }, completeness: 'complete' })] }); // a failed project is never complete
  const failed = parseQueryResult({ projects: [project(P, null, { failure: { code: 'quota', safe_message: 'quota' }, completeness: 'partial' })] }, req({ allow_partial: true }));
  expect(failed.projects[0]).toMatchObject({ value: null, completeness: 'partial', failure: { code: 'quota' } });
  const ok = parseQueryResult({ projects: [project(P, vector(), { diagnostics: [{ severity: 'warning', code: 'promql.mixed', source_range: { start_byte: 0, end_byte: 3, start_rune: 0, end_rune: 3 }, safe_message: 'mixed' }] })] }, req());
  expect(ok.projects[0]?.diagnostics[0]).toMatchObject({ severity: 'warning', source_range: { start_rune: 0, end_rune: 3 } });
 });
 test('anything that is not an object with a projects array is refused', () => { for (const raw of [null, [], 'x', 7, {}, { projects: 'x' }]) bad(raw); });
});

describe('queryFaultOf keeps the code, request id and approved text of a typed failure only', () => {
 const language = { code: 'language', language_code: 'promql.syntax', category: 'syntax', source_range: { start_byte: 4, end_byte: 6, start_rune: 4, end_rune: 6 }, detail: "unexpected ')'", request_id: RID };
 test('a language error keeps its category, code and source range', async () => {
  const f = await queryFaultOf(new Response(JSON.stringify(language), { status: 400, headers: { 'X-Request-ID': RID } }));
  expect(f).toBeInstanceOf(QueryFault);
  expect([f.status, f.code, f.requestId]).toEqual([400, 'language', RID]);
  expect(f.language).toEqual({ languageCode: 'promql.syntax', category: 'syntax', range: { start_byte: 4, end_byte: 6, start_rune: 4, end_rune: 6 }, detail: "unexpected ')'" });
 });
 test('an empty language code (the real server sends one for a PromQL syntax error) stays empty, not "unknown"', async () => {
  const f = await queryFaultOf(new Response(JSON.stringify({ ...language, language_code: '', source_range: { start_byte: 4, end_byte: 4, start_rune: 4, end_rune: 4 } }), { status: 400 }));
  expect([f.language?.languageCode, f.language?.category, f.language?.range]).toEqual(['', 'syntax', { start_byte: 4, end_byte: 4, start_rune: 4, end_rune: 4 }]);
 });
 test('a missing or invalid range is null; hostile codes are dropped', async () => {
  const f = await queryFaultOf(new Response(JSON.stringify({ ...language, source_range: null, language_code: '<img onerror=x>', category: 'a b' }), { status: 400 }));
  expect(f.language?.range).toBeNull();
  expect([f.language?.languageCode, f.language?.category]).toEqual(['unknown', 'unknown']);
  const g = await queryFaultOf(new Response(JSON.stringify({ ...language, source_range: { start_byte: 9, end_byte: 2, start_rune: 9, end_rune: 2 } }), { status: 400 }));
  expect(g.language?.range).toBeNull();
 });
 test('a typed fault keeps code and the approved detail; the request id comes from the header or a valid body id', async () => {
  const quota = await queryFaultOf(new Response(JSON.stringify({ code: 'quota', retryable: false, detail: 'quota', request_id: RID }), { status: 429 }));
  expect([quota.status, quota.code, quota.detail, quota.requestId, quota.language]).toEqual([429, 'quota', 'quota', RID, null]);
  const unsafe = await queryFaultOf(new Response(JSON.stringify({ code: 'not_found', detail: '<img src=x onerror=alert(1)>', request_id: '<b>' }), { status: 404, headers: { 'X-Request-ID': 'nope' } }));
  expect([unsafe.detail, unsafe.requestId]).toEqual(['', '']);
 });
 test('a body that is not a typed failure is generic and its text is never shown', async () => {
  const f = await queryFaultOf(new Response('<html>proxy error</html>', { status: 502 }));
  expect([f.code, f.detail, f.language]).toEqual(['unavailable', '', null]);
 });
 test('a language error that lacks the language fields is not trusted as one', async () => {
  const f = await queryFaultOf(new Response(JSON.stringify({ code: 'language', detail: 'x' }), { status: 400 }));
  expect(f.language).toBeNull();
 });
});

describe('stateOfQueryFault: a budget is a typed error, never a silent rate limit or a shortened answer', () => {
 const fault = (status: number, code: string): QueryFault => new QueryFault(status, code, RID, '');
 test('denied, missing and a foreign project are one state; a session end is another', () => {
  expect(stateOfQueryFault(fault(403, 'forbidden'))).toEqual(stateOfQueryFault(fault(404, 'not_found')));
  expect(stateOfQueryFault(fault(404, 'not_found')).kind).toBe('unauthorized');
  expect(stateOfQueryFault(fault(401, 'unauthenticated'))).toMatchObject({ kind: 'unauthorized', status: 401 });
 });
 test('quota, timeout, cancellation, stale data and language errors keep their own code', () => {
  for (const [status, code] of [[429, 'quota'], [504, 'timeout'], [499, 'cancelled'], [409, 'stale'], [400, 'language'], [400, 'invalid'], [413, 'too_large'], [503, 'unavailable']] as const) {
   const s = stateOfQueryFault(fault(status, code));
   expect(s.kind).toBe('error');
   expect(s.kind === 'error' && s.fault.code).toBe(code);
  }
 });
 test('unsupported is explicit and a network failure is an error', () => {
  expect(stateOfQueryFault(fault(501, 'unsupported')).kind).toBe('unsupported');
  expect(stateOfQueryFault(new TypeError('x')).kind).toBe('error');
 });
});

describe('parseLiveEvent: a frame is one typed event or a protocol fault', () => {
 const frame = (event: string, data: unknown, id: string | null = null): SseFrame => ({ id, event, data: JSON.stringify(data) });
 const record = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ type: 'record', stream_id: G, sequence: '3', project: P, entry: entry(), labels: [{ name: 'app', value: 'web' }], cursors: [{ group: G, index: '5' }], ...over });
 test('every event type of the closed union', () => {
  expect(parseLiveEvent(frame('open', { type: 'open', stream_id: G, watermarks: [{ group: G, index: '5' }] })).type).toBe('open');
  expect(parseLiveEvent(frame('record', record(), '3')).sequence).toBe('3');
  expect(parseLiveEvent(frame('gap', { type: 'gap', stream_id: G, sequence: '7', gap: { reason: 'replay_evicted', from_sequence: '4', to_sequence: '7', after: [{ group: G, index: '1' }], through: [{ group: G, index: '9' }] } }, '7')).gap).toMatchObject({ reason: 'replay_evicted', from_sequence: '4', to_sequence: '7' });
  expect(parseLiveEvent(frame('heartbeat', { type: 'heartbeat', stream_id: G })).type).toBe('heartbeat');
  expect(parseLiveEvent(frame('revoke', { type: 'revoke', stream_id: G, reason: 'scope_revoked', failure: { code: 'not_found', safe_message: 'not_found' } })).reason).toBe('scope_revoked');
  expect(parseLiveEvent(frame('error', { type: 'error', stream_id: G, reason: 'slow_consumer', failure: { code: 'quota', safe_message: 'quota' } })).type).toBe('error');
 });
 test('the SSE event name and id must agree with the typed payload', () => {
  expect(() => parseLiveEvent(frame('gap', record()))).toThrow(ApiFault);
  expect(() => parseLiveEvent(frame('record', record(), '4'))).toThrow(ApiFault);
  expect(() => parseLiveEvent(frame('record', record(), null))).toThrow(ApiFault);
 });
 test('unknown types, malformed payloads and JSON numbers for sequences are faults', () => {
  expect(() => parseLiveEvent({ id: null, event: 'record', data: '{' })).toThrow(ApiFault);
  expect(() => parseLiveEvent(frame('snapshot', { type: 'snapshot', stream_id: G }))).toThrow(ApiFault);
  expect(() => parseLiveEvent(frame('record', record({ sequence: 3 }), '3'))).toThrow(ApiFault);
  expect(() => parseLiveEvent(frame('record', record({ sequence: '0' }), '0'))).toThrow(ApiFault);
  expect(() => parseLiveEvent(frame('record', record({ entry: undefined }), '3'))).toThrow(ApiFault);
  expect(() => parseLiveEvent(frame('record', record({ project: 'x' }), '3'))).toThrow(ApiFault);
  expect(() => parseLiveEvent(frame('gap', { type: 'gap', stream_id: G, sequence: '7' }, '7'))).toThrow(ApiFault);
  expect(() => parseLiveEvent(frame('open', { type: 'open', stream_id: 'x' }))).toThrow(ApiFault);
  expect(() => parseLiveEvent(frame('revoke', { type: 'revoke', stream_id: G, reason: '<img src=x>' }))).toThrow(ApiFault);
 });
});

type Fetch = typeof fetch;
const original = globalThis.fetch;
afterEach(() => { globalThis.fetch = original; bindSession(''); });
function mockFetch(handler: (url: string, init: RequestInit) => Response | Promise<Response>): { calls: { url: string; init: RequestInit }[] } {
 const calls: { url: string; init: RequestInit }[] = [];
 globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => { calls.push({ url: String(input), init: init ?? {} }); return handler(String(input), init ?? {}); }) as Fetch;
 return { calls };
}
const sseResponse = (text: string, over: ResponseInit = {}): Response => new Response(new Blob([text]).stream(), { status: 200, headers: { 'Content-Type': 'text/event-stream' }, ...over });

describe('query, live tickets and the fetch-based live stream', () => {
 test('query POSTs the typed body with the CSRF header and no query text in the URL', async () => {
  bindSession('tok');
  const m = mockFetch(() => new Response(JSON.stringify({ projects: [project(P, vector())] }), { status: 200 }));
  const signal = new AbortController().signal;
  const out = await query(req({ expression: 'secret_metric' }), signal);
  expect(out.projects).toHaveLength(1);
  const call = m.calls[0]!;
  expect([call.url, call.init.method, call.init.credentials, call.init.cache, call.init.signal]).toEqual(['/api/v1/query', 'POST', 'same-origin', 'no-store', signal]);
  expect((call.init.headers as Record<string, string>)['X-CSRF-Token']).toBe('tok');
  expect(JSON.parse(call.init.body as string)).toEqual(req({ expression: 'secret_metric' }));
  expect(call.url).not.toContain('secret_metric');
 });
 test('a failing query throws the typed fault and never a result', async () => {
  mockFetch(() => new Response(JSON.stringify({ code: 'quota', retryable: false, detail: 'quota', request_id: RID }), { status: 429 }));
  await expect(query(req(), new AbortController().signal)).rejects.toMatchObject({ status: 429, code: 'quota' });
 });
 test('a result for a different request is a fault, not an answer', async () => {
  mockFetch(() => new Response(JSON.stringify({ projects: [project(Q, vector())] }), { status: 200 }));
  await expect(query(req(), new AbortController().signal)).rejects.toMatchObject({ code: 'invalid_response' });
 });
 test('createLiveTicket posts the stored request and validates the ticket', async () => {
  bindSession('tok');
  const body = { org: A, projects: [P], profile: 'logql-loki-3.5.2', feature_set: 'f', expression: '{app="web"}', budget: { timeout_ns: '0', memory_bytes: '0', max_returned: '0' } };
  const m = mockFetch(() => new Response(JSON.stringify({ ticket: R, expires_at: '1730000060000000000' }), { status: 200 }));
  expect(await createLiveTicket(body, new AbortController().signal)).toEqual({ ticket: R, expires_at: '1730000060000000000' });
  expect([m.calls[0]!.url, m.calls[0]!.init.method]).toEqual(['/api/v1/live-tickets', 'POST']);
  expect(JSON.parse(m.calls[0]!.init.body as string)).toEqual(body);
  mockFetch(() => new Response(JSON.stringify({ ticket: 'abc', expires_at: 5 }), { status: 200 }));
  await expect(createLiveTicket(body, new AbortController().signal)).rejects.toMatchObject({ code: 'invalid_response' });
  mockFetch(() => new Response(JSON.stringify({ code: 'not_found', detail: 'not_found' }), { status: 404 }));
  await expect(createLiveTicket(body, new AbortController().signal)).rejects.toMatchObject({ status: 404 });
 });
 test('openLive is a GET with the ticket as the only query parameter, the CSRF header and Last-Event-ID', async () => {
  bindSession('tok');
  const signal = new AbortController().signal;
  const m = mockFetch(() => sseResponse(': soundpost live\n\nevent: open\ndata: {"type":"open","stream_id":"' + G + '"}\n\n'));
  const events: LiveEvent[] = [];
  for await (const ev of await openLive(R, '41', signal)) events.push(ev);
  expect(events.map((e) => e.type)).toEqual(['open']);
  const call = m.calls[0]!;
  expect(call.url).toBe(`/api/v1/live?ticket=${R}`);
  expect([call.init.method, call.init.credentials, call.init.cache, call.init.signal, call.init.body]).toEqual(['GET', 'same-origin', 'no-store', signal, undefined]);
  const headers = call.init.headers as Record<string, string>;
  expect([headers['X-CSRF-Token'], headers['Last-Event-ID'], headers.Accept]).toEqual(['tok', '41', 'text/event-stream']);
  mockFetch(() => sseResponse(''));
  const fresh = mockFetch(() => sseResponse(''));
  await openLive(R, null, signal);
  expect('Last-Event-ID' in (fresh.calls[0]!.init.headers as Record<string, string>)).toBe(false);
 });
 test('a refusal, a wrong content type and a non-ticket id are faults, never a stream', async () => {
  mockFetch(() => new Response(JSON.stringify({ code: 'not_found', detail: 'not_found' }), { status: 404 }));
  await expect(openLive(R, null, new AbortController().signal)).rejects.toMatchObject({ status: 404, code: 'not_found' });
  mockFetch(() => new Response('<html></html>', { status: 200, headers: { 'Content-Type': 'text/html' } }));
  await expect(openLive(R, null, new AbortController().signal)).rejects.toBeInstanceOf(ApiFault);
  await expect(openLive('not-a-ticket', null, new AbortController().signal)).rejects.toBeInstanceOf(ApiFault);
  await expect(openLive(R, '01', new AbortController().signal)).rejects.toBeInstanceOf(ApiFault);
 });
 test('a protocol violation inside the stream surfaces as a fault when it is reached', async () => {
  mockFetch(() => sseResponse('event: record\ndata: {"type":"gap","stream_id":"' + G + '"}\n\n'));
  const iterator = (await openLive(R, null, new AbortController().signal))[Symbol.asyncIterator]();
  await expect(iterator.next()).rejects.toBeInstanceOf(ApiFault);
 });
});
