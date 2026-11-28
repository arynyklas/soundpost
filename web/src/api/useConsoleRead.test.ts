// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { ApiFault } from './types';
import { appendUnique, settleConsole } from './useConsoleRead';

describe('a console answer is one of four states', () => {
 test('ok keeps its data, an unserved route is not_built (never an empty list)', () => {
  expect(settleConsole({ kind: 'ok', data: [1] })).toEqual({ kind: 'ok', data: [1] });
  expect(settleConsole({ kind: 'not_built' })).toEqual({ kind: 'not_built' });
 });
 test('a fault is the closed load state of the console: a missing or denied scope is one state, a throttle its own', () => {
  const s = settleConsole({ kind: 'fault', fault: new ApiFault(404, 'not_found', 'r'.repeat(32), '') });
  expect(s).toEqual({ kind: 'fault', state: { kind: 'unauthorized', status: 404, requestId: 'r'.repeat(32) } });
  expect(settleConsole({ kind: 'fault', fault: new ApiFault(429, 'rate_limited', '', '') })).toMatchObject({ kind: 'fault', state: { kind: 'rate_limited' } });
  expect(settleConsole({ kind: 'fault', fault: new ApiFault(500, 'internal', '', '') })).toMatchObject({ kind: 'fault', state: { kind: 'error' } });
 });
});

describe('later pages never repeat an item already shown', () => {
 test('an item is listed once, in the order it first appeared', () => {
  expect(appendUnique([{ id: 'a' }, { id: 'b' }], [{ id: 'b' }, { id: 'c' }], (i) => i.id)).toEqual([{ id: 'a' }, { id: 'b' }, { id: 'c' }]);
  expect(appendUnique([], [], (i: { id: string }) => i.id)).toEqual([]);
 });
});
