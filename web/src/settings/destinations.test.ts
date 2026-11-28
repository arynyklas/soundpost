// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, test } from 'bun:test';
import { listDestinations, parseManagedDestination, saveDestination } from '../api/client';
import { ApiFault, OutcomeUnknown, type DestinationSaveRequest, type ManagedDestination } from '../api/types';
import { buildDestinationChange, buildNewDestination, destinationWords, emptyNewDestination, withSaved, type NewDestinationDraft } from './destinations';

const A = 'a'.repeat(32), P = '1'.repeat(32), D = '3'.repeat(32), E = '4'.repeat(32), C = 'c'.repeat(32);
const dest = (over: Partial<ManagedDestination> = {}): ManagedDestination => ({ id: D, channel: 'webhook', display: 'hooks.example.test', has_secret: true, enabled: true, version: '2', ...over });
const wire = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ id: D, channel: 'webhook', display: 'hooks.example.test', has_secret: true, enabled: true, version: '2', ...over });

describe('a new destination is built from its own channel and one target', () => {
 test('a webhook sends an https endpoint, email and Telegram send an address, and the secret goes only when typed', () => {
  expect(buildNewDestination(D, { ...emptyNewDestination(), endpoint: ' https://h.example.test/x ' })).toEqual({ ok: true, value: { id: D, type: 'webhook', enabled: true, endpoint: 'https://h.example.test/x' } });
  expect(buildNewDestination(D, { ...emptyNewDestination(), endpoint: 'https://h.example.test/x', secret: 's3cret', enabled: false })).toEqual({ ok: true, value: { id: D, type: 'webhook', enabled: false, endpoint: 'https://h.example.test/x', secret: 's3cret' } });
  expect(buildNewDestination(D, { ...emptyNewDestination(), channel: 'smtp', address: 'ops@example.test' })).toEqual({ ok: true, value: { id: D, type: 'smtp', enabled: true, address: 'ops@example.test' } });
  expect(buildNewDestination(D, { ...emptyNewDestination(), channel: 'telegram', address: '-1001234567890' })).toEqual({ ok: true, value: { id: D, type: 'telegram', enabled: true, address: '-1001234567890' } });
  expect(buildNewDestination(D, { ...emptyNewDestination(), channel: 'telegram', address: '@pager_room' })).toMatchObject({ ok: true });
 });
 test('what the server would refuse is refused here with a reason, before anything is sent', () => {
  const refused = (draft: Partial<NewDestinationDraft>): string => {
   const out = buildNewDestination(D, { ...emptyNewDestination(), ...draft });
   return out.ok ? 'ACCEPTED' : out.error;
  };
  expect(refused({ endpoint: 'http://h.example.test/x' })).toContain('https endpoint');
  expect(refused({ endpoint: 'https://h.example.test/x?token=1' })).toContain('without credentials, query or fragment');
  expect(refused({ endpoint: 'https://user:pw@h.example.test/x' })).toContain('without credentials, query or fragment');
  expect(refused({ endpoint: '' })).toContain('https endpoint');
  expect(refused({ channel: 'smtp', address: 'not an address' })).toContain('recipient address');
  expect(refused({ channel: 'smtp', address: 'Ops <ops@example.test>' })).toContain('recipient address');
  expect(refused({ channel: 'telegram', address: 'room' })).toContain('chat');
  expect(refused({ channel: 'sms', address: '123' })).toContain('Choose a destination type');
  expect(refused({ endpoint: 'https://h.example.test/x', secret: 'x'.repeat(4097) })).toContain('too long');
 });
 test('an address typed on a webhook, or an endpoint on email, is never sent', () => {
  const hook = buildNewDestination(D, { ...emptyNewDestination(), endpoint: 'https://h.example.test/x', address: 'a@example.test' });
  expect(hook.ok && 'address' in hook.value).toBe(false);
  const mail = buildNewDestination(D, { ...emptyNewDestination(), channel: 'smtp', address: 'ops@example.test', endpoint: 'https://h.example.test/x' });
  expect(mail.ok && 'endpoint' in mail.value).toBe(false);
 });
});

describe('a change to a destination that was read leaves its channel and target alone', () => {
 test('only the enabled state and a new secret are sent; no change is no save', () => {
  expect(buildDestinationChange(dest(), true, '')).toEqual({ ok: false, error: 'Nothing to save: change the enabled state or enter a new secret.' });
  expect(buildDestinationChange(dest(), false, '')).toEqual({ ok: true, value: { id: D, enabled: false } });
  expect(buildDestinationChange(dest(), true, 'rotated')).toEqual({ ok: true, value: { id: D, enabled: true, secret: 'rotated' } });
  const out = buildDestinationChange(dest(), false, 'rotated');
  expect(out.ok && 'type' in out.value).toBe(false);
  expect(out.ok && 'endpoint' in out.value).toBe(false);
 });
 test('an over-long secret is refused', () => {
  expect(buildDestinationChange(dest(), true, 'x'.repeat(4097))).toMatchObject({ ok: false });
 });
});

describe('the words and the merged list', () => {
 test('a destination is described by its channel, coarse target, state, secret presence and version, never a path', () => {
  const words = destinationWords(dest());
  expect(words).toBe('Webhook to hooks.example.test; enabled; secret set (write-only, never shown); version 2.');
  expect(destinationWords(dest({ channel: 'telegram', display: '', has_secret: false, enabled: false, version: '1' }))).toBe('Telegram; disabled; secret not set; version 1.');
 });
 test('a saved destination replaces the one with its ID, or is added, in ID order', () => {
  expect(withSaved([dest()], dest({ enabled: false, version: '3' }))).toEqual([dest({ enabled: false, version: '3' })]);
  expect(withSaved([dest()], dest({ id: E })).map((d) => d.id)).toEqual([D, E]);
  expect(withSaved([dest({ id: E })], dest()).map((d) => d.id)).toEqual([D, E]);
 });
});

describe('a destination answer keeps only what the page shows', () => {
 test('the fields of a redacted destination, and nothing a secret could ride in', () => {
  const parsed = parseManagedDestination(wire({ secret: 'LEAK', endpoint: 'https://h.example.test/TOKEN', address: 'ops@example.test' }));
  expect(parsed).toEqual(dest());
  expect(JSON.stringify(parsed)).not.toContain('LEAK');
  expect(JSON.stringify(parsed)).not.toContain('TOKEN');
 });
 test('a malformed destination is refused', () => {
  for (const over of [{ id: 'x' }, { channel: 'sms' }, { enabled: 'true' }, { has_secret: 1 }, { version: 2 }, { version: '02' }, { display: 5 }]) expect(() => parseManagedDestination(wire(over))).toThrow(ApiFault);
  expect(() => parseManagedDestination(null)).toThrow(ApiFault);
 });
});

const original = globalThis.fetch;
afterEach(() => { globalThis.fetch = original; });
const answer = (body: unknown, status = 200): Response => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const save: DestinationSaveRequest = { org: A, project_id: P, command_id: C, expected_version: '2', reason: 'pause while the receiver moves', destination: { id: D, enabled: false } };

describe('the destination client', () => {
 test('a list posts only the selectors and operation, and accepts only its own organization', async () => {
  let body: unknown;
  globalThis.fetch = ((_: RequestInfo | URL, init?: RequestInit) => { body = JSON.parse(String(init?.body)); return Promise.resolve(answer({ org: A, destinations: [wire()] })); }) as typeof fetch;
  expect(await listDestinations(A, P, new AbortController().signal)).toEqual([dest()]);
  expect(body).toEqual({ org: A, project_id: P, operation: 'list' });
  globalThis.fetch = (() => Promise.resolve(answer({ org: E, destinations: [] }))) as typeof fetch;
  await expect(listDestinations(A, P, new AbortController().signal)).rejects.toBeInstanceOf(ApiFault);
 });
 test('a save posts the command, the version the page read, the reason and the destination', async () => {
  let body: unknown;
  globalThis.fetch = ((_: RequestInfo | URL, init?: RequestInit) => { body = JSON.parse(String(init?.body)); return Promise.resolve(answer({ state: 'committed', destination: wire({ enabled: false, version: '3' }) })); }) as typeof fetch;
  expect(await saveDestination(save, new AbortController().signal)).toEqual(dest({ enabled: false, version: '3' }));
  expect(body).toEqual({ org: A, project_id: P, operation: 'save', command_id: C, expected_version: '2', reason: 'pause while the receiver moves', destination: { id: D, enabled: false } });
 });
 test('only a committed answer for the destination that was saved is a save', async () => {
  globalThis.fetch = (() => Promise.resolve(answer({ state: 'not_available', destination: wire() }))) as typeof fetch;
  await expect(saveDestination(save, new AbortController().signal)).rejects.toBeInstanceOf(ApiFault);
  globalThis.fetch = (() => Promise.resolve(answer({ state: 'committed', destination: wire({ id: E }) }))) as typeof fetch;
  await expect(saveDestination(save, new AbortController().signal)).rejects.toBeInstanceOf(ApiFault);
 });
 test('a 409, 403, 404 and 400 are faults with their status; nothing is returned as saved', async () => {
  for (const status of [409, 403, 404, 400]) {
   globalThis.fetch = (() => Promise.resolve(answer({ code: 'conflict', detail: 'conflict' }, status))) as typeof fetch;
   await expect(saveDestination(save, new AbortController().signal)).rejects.toMatchObject({ status });
  }
 });
 test('a transport failure is an unknown outcome, an abort is not', async () => {
  globalThis.fetch = (() => Promise.reject(new TypeError('network down'))) as typeof fetch;
  await expect(saveDestination(save, new AbortController().signal)).rejects.toBeInstanceOf(OutcomeUnknown);
  globalThis.fetch = (() => Promise.reject(new DOMException('aborted', 'AbortError'))) as typeof fetch;
  await expect(saveDestination(save, new AbortController().signal)).rejects.not.toBeInstanceOf(OutcomeUnknown);
 });
});
