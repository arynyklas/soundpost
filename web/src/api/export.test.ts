// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, test } from 'bun:test';
import { bindSession, createExport, downloadExport, exportStatus, parseExportGrant, parseExportOperation } from './client';
import { ApiFault } from './types';

const A = 'a'.repeat(32), P = '1'.repeat(32), X = '6'.repeat(32), Y = '7'.repeat(32);
const op = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ id: X, kind: 'export', phase: 'running', generation: '1', progress: '0', chunks: '0', ...over });
const bad = (fn: () => unknown): void => { expect(fn).toThrow(ApiFault); };

describe('an export operation is accepted only when it is a consistent statement', () => {
 test('running, complete and failed with their own required fields', () => {
  expect(parseExportOperation(op(), X).phase).toBe('running');
  expect(parseExportOperation(op({ phase: 'complete', generation: '2', progress: '4096', chunks: '1' }), X).chunks).toBe('1');
  expect(parseExportOperation(op({ phase: 'failed', generation: '2', safe_reason: 'revoked' }), X).safe_reason).toBe('revoked');
 });
 test('a complete export with no chunk, a failure without a reason and a reason on success are contradictions', () => {
  bad(() => parseExportOperation(op({ phase: 'complete', chunks: '0' }), X));
  bad(() => parseExportOperation(op({ phase: 'failed' }), X));
  bad(() => parseExportOperation(op({ phase: 'complete', chunks: '1', safe_reason: 'revoked' }), X));
  bad(() => parseExportOperation(op({ phase: 'running', safe_reason: 'timeout' }), X));
 });
 test('another operation, an unknown phase, a JSON number or an unsafe reason is refused', () => {
  bad(() => parseExportOperation(op({ id: Y }), X));
  bad(() => parseExportOperation(op({ phase: 'done' }), X));
  bad(() => parseExportOperation(op({ progress: 5 }), X));
  bad(() => parseExportOperation(op({ kind: 'delete' }), X));
  bad(() => parseExportOperation(op({ phase: 'failed', safe_reason: '<img src=x>' }), X));
  bad(() => parseExportOperation(null, X));
 });
 test('a grant carries the operation and a bounded ticket', () => {
  expect(parseExportGrant({ operation: op(), ticket: 'tkt' }).ticket).toBe('tkt');
  bad(() => parseExportGrant({ operation: op(), ticket: '' }));
  bad(() => parseExportGrant({ operation: op(), ticket: 'x'.repeat(5000) }));
  bad(() => parseExportGrant({ operation: op({ phase: 'complete', chunks: '1' }), ticket: 't' }));
  bad(() => parseExportGrant({ ticket: 't' }));
 });
});

type Fetch = typeof fetch;
const original = globalThis.fetch;
afterEach(() => { globalThis.fetch = original; bindSession(''); });
function mock(handler: (init: RequestInit) => Response): { calls: { url: string; init: RequestInit }[] } {
 const calls: { url: string; init: RequestInit }[] = [];
 globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => { calls.push({ url: String(input), init: init ?? {} }); return handler(init ?? {}); }) as Fetch;
 return { calls };
}
const signal = new AbortController().signal;

describe('create, status and download are three closed POSTs of the same route', () => {
 test('create sends exactly the closed fields with exact nanoseconds and accepts the 202 grant', async () => {
  bindSession('tok');
  const m = mock(() => new Response(JSON.stringify({ operation: op(), ticket: 'tkt' }), { status: 202 }));
  const grant = await createExport(A, P, 'log', { start: '1730000000000000001', end: '1730000060000000000' }, signal);
  expect(grant.operation.id).toBe(X);
  const call = m.calls[0]!;
  expect([call.url, call.init.method, call.init.credentials, call.init.signal, (call.init.headers as Record<string, string>)['X-CSRF-Token']]).toEqual(['/api/v1/exports', 'POST', 'same-origin', signal, 'tok']);
  expect(JSON.parse(call.init.body as string)).toEqual({ operation: 'create', org: A, project: P, signal: 'log', start_ns: '1730000000000000001', end_ns: '1730000060000000000' });
 });
 test('status names the operation and the answer must be that operation', async () => {
  const m = mock(() => new Response(JSON.stringify(op({ phase: 'complete', chunks: '2', generation: '2' })), { status: 200 }));
  expect((await exportStatus(A, P, X, signal)).phase).toBe('complete');
  expect(JSON.parse(m.calls[0]!.init.body as string)).toEqual({ operation: 'status', org: A, project: P, id: X });
  mock(() => new Response(JSON.stringify(op({ id: Y })), { status: 200 }));
  await expect(exportStatus(A, P, X, signal)).rejects.toMatchObject({ code: 'invalid_response' });
 });
 test('download posts the ticket and returns the exact bytes of an ndjson attachment', async () => {
  const m = mock(() => new Response('{"a":1}\n{"b":2}\n', { status: 200, headers: { 'Content-Type': 'application/x-ndjson' } }));
  const blob = await downloadExport(A, P, X, 'tkt', signal);
  expect(await blob.text()).toBe('{"a":1}\n{"b":2}\n');
  expect(JSON.parse(m.calls[0]!.init.body as string)).toEqual({ operation: 'download', org: A, project: P, id: X, ticket: 'tkt' });
 });
 test('a download that is not ndjson, or that is refused, is a fault and yields no blob', async () => {
  mock(() => new Response('<html></html>', { status: 200, headers: { 'Content-Type': 'text/html' } }));
  await expect(downloadExport(A, P, X, 'tkt', signal)).rejects.toBeInstanceOf(ApiFault);
  mock(() => new Response(JSON.stringify({ code: 'not_found', detail: 'not_found' }), { status: 404 }));
  await expect(downloadExport(A, P, X, 'tkt', signal)).rejects.toMatchObject({ status: 404, code: 'not_found' });
  mock(() => new Response(JSON.stringify({ code: 'conflict', detail: 'conflict' }), { status: 409 }));
  await expect(exportStatus(A, P, X, signal)).rejects.toMatchObject({ status: 409 });
 });
});
