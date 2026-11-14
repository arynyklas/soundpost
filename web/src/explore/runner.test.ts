// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { latestOnly } from '../app/context';
import { runLatest, type RunState } from './runner';

describe('only the latest query of the current scope may publish', () => {
 test('loading is shown first, then exactly the result of the latest run', async () => {
  const published: RunState<string>[] = [];
  await runLatest(latestOnly(), () => 'k', 'k', () => Promise.resolve('answer'), (s) => published.push(s));
  expect(published).toEqual([{ kind: 'loading', key: 'k' }, { kind: 'done', key: 'k', value: 'answer' }]);
 });
 test('a slower older response that arrives after a newer run began never publishes, even if its call ignores the abort', async () => {
  const latest = latestOnly();
  const published: RunState<string>[] = [];
  const older = Promise.withResolvers<string>(), newer = Promise.withResolvers<string>();
  const a = runLatest(latest, () => 'k', 'k', () => older.promise, (s) => published.push(s));
  const b = runLatest(latest, () => 'k', 'k', () => newer.promise, (s) => published.push(s));
  newer.resolve('new');
  await b;
  older.resolve('OLD');
  await a;
  expect(published.filter((s) => s.kind === 'done')).toEqual([{ kind: 'done', key: 'k', value: 'new' }]);
  expect(JSON.stringify(published)).not.toContain('OLD');
 });
 test('beginning a newer run aborts the older request', () => {
  const latest = latestOnly();
  const signals: AbortSignal[] = [];
  const never = new Promise<string>(() => undefined);
  void runLatest(latest, () => 'k', 'k', (signal) => { signals.push(signal); return never; }, () => undefined);
  void runLatest(latest, () => 'k', 'k', (signal) => { signals.push(signal); return never; }, () => undefined);
  expect(signals.map((s) => s.aborted)).toEqual([true, false]);
 });
 test('a response for a scope that is no longer the current one never publishes, even from the latest run', async () => {
  let current = 'scope-A';
  const published: RunState<string>[] = [];
  const d = Promise.withResolvers<string>();
  const run = runLatest(latestOnly(), () => current, 'scope-A', () => d.promise, (s) => published.push(s));
  current = 'scope-B';
  d.resolve('belongs to A');
  await run;
  expect(published).toEqual([{ kind: 'loading', key: 'scope-A' }]);
 });
 test('an older failure is dropped and an abort is never a failure, but the latest failure is published with its error', async () => {
  const latest = latestOnly();
  const published: RunState<string>[] = [];
  const older = Promise.withResolvers<string>();
  const a = runLatest(latest, () => 'k', 'k', () => older.promise, (s) => published.push(s));
  const failure = new Error('boom');
  const b = runLatest(latest, () => 'k', 'k', () => Promise.reject(failure), (s) => published.push(s));
  older.reject(new DOMException('aborted', 'AbortError'));
  await Promise.all([a, b]);
  expect(published.filter((s) => s.kind === 'failed')).toEqual([{ kind: 'failed', key: 'k', error: failure }]);
  const aborted: RunState<string>[] = [];
  await runLatest(latestOnly(), () => 'k', 'k', () => Promise.reject(new DOMException('aborted', 'AbortError')), (s) => aborted.push(s));
  expect(aborted.map((s) => s.kind)).toEqual(['loading']);
 });
 test('stopping the gate (leaving the page or the scope) silences the pending run', async () => {
  const latest = latestOnly();
  const published: RunState<string>[] = [];
  const d = Promise.withResolvers<string>();
  const run = runLatest(latest, () => 'k', 'k', () => d.promise, (s) => published.push(s));
  latest.stop();
  d.resolve('late');
  await run;
  expect(published.map((s) => s.kind)).toEqual(['loading']);
 });
});
