// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, test } from 'bun:test';
import { deleteSavedView, listSavedViews, parseSavedView, parseSavedViewList, saveSavedView } from './client';
import { ApiFault, OutcomeUnknown, type SavedViewDeleteRequest, type SavedViewSaveRequest } from './types';

const A = 'a'.repeat(32), P = '1'.repeat(32), Q = '2'.repeat(32), V = '4'.repeat(32), W = '6'.repeat(32), U = '5'.repeat(32), C = 'c'.repeat(32);
const wire = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
 id: V, org: A, project: P, name: 'API up', language: 'promql', profile: 'promql-prometheus-3.1.0', feature_set: 'promql-prometheus-3.1.0/semantic-sha256-x', expression: 'up',
 projects: [P], mode: 'instant', allow_partial: false, owner: U, created_ns: '1730000000000000000', updated_ns: '1730000000000000001', revision: '3', ...over,
});
const save = (over: Partial<SavedViewSaveRequest> = {}): SavedViewSaveRequest => ({
 org: A, project: P, operation: 'save', command_id: C, name: 'API up', language: 'promql', profile: 'promql-prometheus-3.1.0', feature_set: 'promql-prometheus-3.1.0/semantic-sha256-x', expression: 'up', projects: [P], mode: 'instant', allow_partial: false, ...over,
});
const del = (): SavedViewDeleteRequest => ({ org: A, project: P, operation: 'delete', command_id: C, id: V, expected_revision: '3' });
const signal = (): AbortSignal => new AbortController().signal;

describe('a saved view is accepted only as a consistent statement for the project it was asked for', () => {
 test('a well-formed view parses, with its optional fields only when present', () => {
  const v = parseSavedView(wire(), A, P);
  expect(v).toMatchObject({ id: V, org: A, project: P, name: 'API up', mode: 'instant', revision: '3', owner: U });
  expect('step_seconds' in v || 'log_limit' in v || 'log_order' in v).toBe(false);
  const full = parseSavedView(wire({ mode: 'range', step_seconds: '15', language: 'logql', log_limit: '50', log_order: 'forward' }), A, P);
  expect([full.step_seconds, full.log_limit, full.log_order]).toEqual(['15', '50', 'forward']);
 });
 test('a view of another organization or project, or one that does not run over its own project, is refused', () => {
  for (const raw of [wire({ org: 'b'.repeat(32) }), wire({ project: Q }), wire({ projects: [Q] }), wire({ projects: [] }), wire({ projects: [P, P] })]) expect(() => parseSavedView(raw, A, P)).toThrow(ApiFault);
 });
 test('bounds and types: name, text, ids, decimals, mode and order', () => {
  const bad: Record<string, unknown>[] = [
   wire({ name: '' }), wire({ name: 'x'.repeat(121) }), wire({ expression: '' }), wire({ expression: 'x'.repeat(16385) }), wire({ id: 'nope' }), wire({ owner: 'nope' }),
   wire({ language: 'sql' }), wire({ mode: 'live' }), wire({ allow_partial: 'no' }), wire({ revision: 3 }), wire({ revision: '03' }), wire({ created_ns: 1.5 }), wire({ updated_ns: '-' }),
   wire({ step_seconds: 15 }), wire({ log_limit: 'x' }), wire({ log_order: 'sideways' }), wire({ projects: Array.from({ length: 17 }, (_, i) => i.toString(16).padStart(32, '0')) }),
  ];
  for (const raw of bad) expect(() => parseSavedView(raw, A, P)).toThrow(ApiFault);
  expect(() => parseSavedView(null, A, P)).toThrow(ApiFault);
  expect(() => parseSavedView([], A, P)).toThrow(ApiFault);
 });
 test('a list is ready with views or empty with none, never the other way, and never repeats a view', () => {
  expect(parseSavedViewList({ state: 'ready', views: [wire()] }, A, P)).toHaveLength(1);
  expect(parseSavedViewList({ state: 'empty', views: null }, A, P)).toEqual([]);
  expect(parseSavedViewList({ state: 'empty', views: [] }, A, P)).toEqual([]);
  expect(() => parseSavedViewList({ state: 'ready', views: [] }, A, P)).toThrow(ApiFault);
  expect(() => parseSavedViewList({ state: 'empty', views: [wire()] }, A, P)).toThrow(ApiFault);
  expect(() => parseSavedViewList({ state: 'ready', views: [wire(), wire()] }, A, P)).toThrow(ApiFault);
  expect(() => parseSavedViewList({ state: 'ready', views: [wire(), wire({ id: W, project: Q, projects: [Q] })] }, A, P)).toThrow(ApiFault);
  expect(() => parseSavedViewList({ state: 'committed', views: [] }, A, P)).toThrow(ApiFault);
 });
});

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });
function answer(status: number, body: unknown, calls: { url: string; init: RequestInit | undefined }[] = []): void {
 globalThis.fetch = (async (url: string, init?: RequestInit) => { calls.push({ url, init }); return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', 'X-Request-ID': 'd'.repeat(32) } }); }) as unknown as typeof fetch;
}

describe('the client sends one POST per action, with the query text only in the body', () => {
 test('list posts org, project and operation, and parses the project\'s views', async () => {
  const calls: { url: string; init: RequestInit | undefined }[] = [];
  answer(200, { state: 'ready', views: [wire()] }, calls);
  const views = await listSavedViews(A, P, signal());
  expect(views.map((v) => v.id)).toEqual([V]);
  expect(calls).toHaveLength(1);
  expect(calls[0]?.url).toBe('/api/v1/saved-views');
  expect(calls[0]?.init?.method).toBe('POST');
  expect(JSON.parse(String(calls[0]?.init?.body))).toEqual({ org: A, project: P, operation: 'list' });
 });
 test('save posts the whole request in the body, and a refusal is its typed fault', async () => {
  const calls: { url: string; init: RequestInit | undefined }[] = [];
  answer(200, { state: 'committed', view: wire() }, calls);
  const saved = await saveSavedView(save(), signal());
  expect(saved.id).toBe(V);
  expect(JSON.parse(String(calls[0]?.init?.body))).toEqual(save());
  expect(calls[0]?.url).not.toContain('up');
  answer(404, { code: 'not_found' });
  await expect(saveSavedView(save(), signal())).rejects.toMatchObject({ status: 404, code: 'not_found' });
  answer(409, { code: 'conflict' });
  await expect(saveSavedView(save({ id: V, expected_revision: '3' }), signal())).rejects.toMatchObject({ status: 409, code: 'conflict' });
 });
 test('a committed save must be the view that was sent: same name, text, profile and feature set, and for an update the same view at a newer revision', async () => {
  for (const raw of [wire({ name: 'other' }), wire({ expression: 'down' }), wire({ profile: 'promql-prometheus-3.13.5' }), wire({ feature_set: 'x' })]) {
   answer(200, { state: 'committed', view: raw });
   await expect(saveSavedView(save(), signal())).rejects.toMatchObject({ code: 'invalid_response' });
  }
  answer(200, { state: 'committed', view: wire({ id: W, revision: '4' }) });
  await expect(saveSavedView(save({ id: V, expected_revision: '3' }), signal())).rejects.toMatchObject({ code: 'invalid_response' });
  answer(200, { state: 'committed', view: wire({ revision: '3' }) });
  await expect(saveSavedView(save({ id: V, expected_revision: '3' }), signal())).rejects.toMatchObject({ code: 'invalid_response' });
  answer(200, { state: 'committed', view: wire({ revision: '4' }) });
  expect((await saveSavedView(save({ id: V, expected_revision: '3' }), signal())).revision).toBe('4');
  answer(200, { state: 'ready', view: wire() });
  await expect(saveSavedView(save(), signal())).rejects.toMatchObject({ code: 'invalid_response' });
 });
 test('delete is a deletion only when the server answers committed', async () => {
  const calls: { url: string; init: RequestInit | undefined }[] = [];
  answer(200, { state: 'committed' }, calls);
  await deleteSavedView(del(), signal());
  expect(JSON.parse(String(calls[0]?.init?.body))).toEqual(del());
  answer(200, { state: 'ready' });
  await expect(deleteSavedView(del(), signal())).rejects.toMatchObject({ code: 'invalid_response' });
  answer(409, { code: 'conflict' });
  await expect(deleteSavedView(del(), signal())).rejects.toMatchObject({ status: 409 });
 });
 test('a transport failure after the request left is an unknown outcome; an abort is an abort', async () => {
  globalThis.fetch = (async () => { throw new TypeError('network down'); }) as unknown as typeof fetch;
  await expect(saveSavedView(save(), signal())).rejects.toBeInstanceOf(OutcomeUnknown);
  await expect(deleteSavedView(del(), signal())).rejects.toBeInstanceOf(OutcomeUnknown);
  globalThis.fetch = (async () => { throw new DOMException('aborted', 'AbortError'); }) as unknown as typeof fetch;
  await expect(saveSavedView(save(), signal())).rejects.toMatchObject({ name: 'AbortError' });
 });
});
