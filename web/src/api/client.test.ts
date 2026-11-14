// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { apiFault, parseView, stateOfFault, stateOfView } from './client';
import { ApiFault, LOAD_STATE_KINDS, type InvestigationRequest, type InvestigationView, type ViewState } from './types';

const A = 'a'.repeat(32), B = 'b'.repeat(32), P = '1'.repeat(32), Q = '2'.repeat(32);
const req = (over: Partial<InvestigationRequest> = {}): InvestigationRequest => ({ org: A, kind: 'service', projects: [P], window: { start: '10', end: '20' }, limit: 10, ...over });
const view = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ kind: 'service', org: A, window: { start: '10', end: '20' }, state: 'ready', projects: [{ project_id: P, sources: [] }], metric_names: [], more: false, sections: [], ...over });

describe('parseView accepts only the requested scope', () => {
 test('matching view', () => { expect(parseView(view(), req()).org).toBe(A); });
 test('another organization is refused, not rendered', () => { expect(() => parseView(view({ org: B }), req())).toThrow(ApiFault); });
 test('another project is refused', () => { expect(() => parseView(view({ projects: [{ project_id: Q, sources: [] }] }), req())).toThrow(ApiFault); });
 test('another kind is refused', () => { expect(() => parseView(view({ kind: 'queue' }), req())).toThrow(ApiFault); });
 test('another window is refused', () => { expect(() => parseView(view({ window: { start: '10', end: '99' } }), req())).toThrow(ApiFault); });
 test('a link to another target is refused', () => { expect(() => parseView(view({ link: { kind: 'trace', project_id: P, id: B, available: true } }), req({ kind: 'trace', target: A }))).toThrow(ApiFault); });
 test('unknown state is refused', () => { expect(() => parseView(view({ state: 'healthy' }), req())).toThrow(ApiFault); });
});

describe('state mapping never turns a gap into success', () => {
 const states: ViewState[] = ['ready', 'empty', 'incomplete', 'stale', 'not_available'];
 test.each(states)('view state %s', (state) => {
  const mapped = stateOfView(view({ state, reason: 'why' }) as unknown as InvestigationView);
  expect(mapped.kind).toBe(state === 'not_available' ? 'unsupported' : state);
  expect(LOAD_STATE_KINDS).toContain(mapped.kind);
  if (state === 'incomplete' || state === 'stale') expect('reason' in mapped && mapped.reason).toBe('why');
 });
 test('not available is never ready or empty', () => {
  const mapped = stateOfView(view({ state: 'not_available' }) as unknown as InvestigationView);
  expect(mapped.kind === 'ready' || mapped.kind === 'empty').toBe(false);
 });
 const fault = (status: number): ApiFault => new ApiFault(status, 'x', 'r'.repeat(32), '');
 test('denied and missing are one state with one shape', () => {
  const a = stateOfFault(fault(403)), b = stateOfFault(fault(404));
  expect(a).toEqual(b);
  expect(a.kind).toBe('unauthorized');
 });
 test('session end is distinguishable from not found', () => { expect(stateOfFault(fault(401))).toMatchObject({ kind: 'unauthorized', status: 401 }); });
 test('429, 501, 500 and a network failure', () => {
  expect(stateOfFault(fault(429)).kind).toBe('rate_limited');
  expect(stateOfFault(fault(501)).kind).toBe('unsupported');
  expect(stateOfFault(fault(500)).kind).toBe('error');
  expect(stateOfFault(new TypeError('x')).kind).toBe('error');
 });
});

describe('apiFault keeps code, request ID and approved detail only', () => {
 test('typed body', async () => {
  const f = await apiFault(new Response(JSON.stringify({ code: 'quota', detail: 'quota', request_id: 'ignored', retryable: true, extra: '<img onerror=x>' }), { status: 429, headers: { 'X-Request-ID': 'c'.repeat(32) } }));
  expect([f.status, f.code, f.requestId, f.detail]).toEqual([429, 'quota', 'c'.repeat(32), 'quota']);
 });
 test('unsafe detail and malformed id are dropped', async () => {
  const f = await apiFault(new Response(JSON.stringify({ code: 'not_found', detail: '<img src=x onerror=alert(1)>' }), { status: 404, headers: { 'X-Request-ID': '<b>' } }));
  expect([f.detail, f.requestId]).toEqual(['', '']);
 });
 test('non-JSON body is a generic fault', async () => {
  const f = await apiFault(new Response('<html>proxy</html>', { status: 502 }));
  expect([f.code, f.detail]).toEqual(['unavailable', '']);
 });
});
