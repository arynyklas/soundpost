// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import type { ListEnvelope } from '../api/console';
import { appendPage, envelopeStatus } from './useConsoleList';

const env = (over: Partial<ListEnvelope<number>>): ListEnvelope<number> => ({ org: 'a'.repeat(32), projects: ['b'.repeat(32)], state: 'ready', items: [1], more: false, sections: [], ...over });

describe('console list envelope', () => {
 test('not_available carries its reason and is never an empty list', () => {
  expect(envelopeStatus(env({ state: 'not_available', reason: 'separate_grant_required', items: [] }))).toEqual({ kind: 'unsupported', reason: 'separate_grant_required', data: null });
  expect(envelopeStatus(env({ state: 'empty', items: [] })).kind).toBe('empty');
  expect(envelopeStatus(env({ state: 'incomplete' })).kind).toBe('incomplete');
  expect(envelopeStatus(env({ state: 'stale' })).kind).toBe('stale');
  expect(envelopeStatus(env({})).kind).toBe('ready');
 });
 test('a next page is appended in order and carries its own cursor; the last page ends the list', () => {
  const first = env({ items: [1, 2], more: true, nextCursor: 'c1' });
  const second = appendPage(first, env({ items: [3], more: true, nextCursor: 'c2' }));
  expect(second.items).toEqual([1, 2, 3]);
  expect(second.nextCursor).toBe('c2');
  const last = appendPage(second, env({ items: [4], more: false }));
  expect(last.items).toEqual([1, 2, 3, 4]);
  expect(last.more).toBe(false);
  expect(last.nextCursor).toBeUndefined();
 });
});
