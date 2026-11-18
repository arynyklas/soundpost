// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, test } from 'bun:test';
import { bindElevation, elevationFor, releaseElevation, withElevation } from './elevation';

const A = 'a'.repeat(32), B = 'b'.repeat(32), E = 'e'.repeat(32);
const NOW = 1_730_000_000_000;
const state = (over: Partial<{ id: string; expires: string; orgs: string[] }> = {}) => ({ id: E, expires: String(NOW / 1000 + 600), orgs: [A], ...over });
afterEach(() => bindElevation(null));

describe('the audited elevation handle rides a console read only for an organization it was granted for, and only while it lives', () => {
 test('no elevation: no handle, the read is the ordinary one', () => {
  expect(elevationFor(null, A, NOW)).toBeUndefined();
 });
 test('a selected organization carries the handle; another organization never does', () => {
  expect(elevationFor(state(), A, NOW)).toBe(E);
  expect(elevationFor(state(), B, NOW)).toBeUndefined();
 });
 test('an expired handle is not sent (the server would refuse it and count a miss)', () => {
  expect(elevationFor(state({ expires: String(NOW / 1000) }), A, NOW)).toBeUndefined();
  expect(elevationFor(state({ expires: String(NOW / 1000 - 1) }), A, NOW)).toBeUndefined();
  expect(elevationFor(state({ expires: String(NOW / 1000 + 1) }), A, NOW)).toBe(E);
 });
 test('a malformed handle or expiry is never sent', () => {
  expect(elevationFor(state({ id: 'nope' }), A, NOW)).toBeUndefined();
  expect(elevationFor(state({ expires: 'soon' }), A, NOW)).toBeUndefined();
 });
});

describe('withElevation: only the elevated read routes carry the handle, and never a write, a live ticket or a profile view', () => {
 test('every elevated read route of a covered organization gets exactly the handle', () => {
  bindElevation(state());
  for (const path of ['/api/v1/query', '/api/v1/query/format', '/api/v1/discover', '/api/v1/exemplars']) {
   expect(withElevation(path, { org: A, projects: [] }, NOW)).toEqual({ org: A, projects: [], elevation: E });
  }
 });
 test('other routes, other organizations, no elevation, and bodies that are not an object are returned untouched', () => {
  const body = { org: A, projects: [] };
  bindElevation(state());
  for (const path of ['/api/v1/live-tickets', '/api/v1/saved-views', '/api/v1/actions', '/api/v1/profile', '/api/v1/investigate']) expect(withElevation(path, body, NOW)).toBe(body);
  const other = { org: B };
  expect(withElevation('/api/v1/query', other, NOW)).toBe(other);
  expect(withElevation('/api/v1/query', [body], NOW)).toEqual([body]);
  expect(withElevation('/api/v1/query', 'text', NOW)).toBe('text');
  bindElevation(null);
  expect(withElevation('/api/v1/query', body, NOW)).toBe(body);
 });
 test('a console instance releases only what it bound: an older instance unmounting after a newer one bound the same elevation leaves it bound', () => {
  const oldConsole = {}, newConsole = {}, same = state();
  bindElevation(same, oldConsole);
  bindElevation(same, newConsole);
  releaseElevation(oldConsole);
  expect(withElevation('/api/v1/query', { org: A }, NOW)).toEqual({ org: A, elevation: E });
  releaseElevation(newConsole);
  const body = { org: A };
  expect(withElevation('/api/v1/query', body, NOW)).toBe(body);
 });
 test('a body that already names an elevation is the caller\'s own and is never overridden; the caller\'s object is never mutated', () => {
  bindElevation(state());
  const own = { org: A, elevation: 'c'.repeat(32) };
  expect(withElevation('/api/v1/query', own, NOW)).toBe(own);
  const plain = { org: A };
  withElevation('/api/v1/query', plain, NOW);
  expect('elevation' in plain).toBe(false);
 });
 test('an expired bound elevation sends nothing', () => {
  bindElevation(state({ expires: String(NOW / 1000 - 5) }));
  const body = { org: A };
  expect(withElevation('/api/v1/query', body, NOW)).toBe(body);
 });
});
