// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Every LoadState, including stale (which no committed route can produce in a real browser here), through the real StatusPanel:
// each says its state in words, is announced through the right live-region role, and no two states share a label.
import { describe, expect, test } from 'bun:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ApiFault, LOAD_STATE_KINDS, type LoadState } from '../api/types';
import { StatusPanel } from './StatusPanel';

const states: Record<(typeof LOAD_STATE_KINDS)[number], LoadState<unknown>> = {
 loading: { kind: 'loading' },
 ready: { kind: 'ready', data: {} },
 empty: { kind: 'empty', data: {} },
 unauthorized: { kind: 'unauthorized', status: 404, requestId: 'r1' },
 unsupported: { kind: 'unsupported', reason: 'service_not_built' },
 stale: { kind: 'stale', data: {}, reason: 'freshness_stale' },
 incomplete: { kind: 'incomplete', data: {}, reason: 'shards_missing' },
 rate_limited: { kind: 'rate_limited', requestId: 'r2' },
 error: { kind: 'error', fault: new ApiFault(500, 'internal', 'r3', '') },
};
const html = (s: LoadState<unknown>): string => renderToStaticMarkup(React.createElement(StatusPanel, { state: s }));
const words = (markup: string): string => markup.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();

describe('StatusPanel for every LoadState', () => {
 test('the test covers exactly the closed set of states', () => {
  expect(Object.keys(states).sort()).toEqual([...LOAD_STATE_KINDS].sort());
 });
 for (const kind of LOAD_STATE_KINDS) {
  test(`${kind}: a bold state word, sentence text, a live-region role and no colour-only cue`, () => {
   const markup = html(states[kind]);
   expect(markup).toContain(`data-state="${kind}"`);
   const label = /<strong>([^<]+)<\/strong>/.exec(markup)?.[1] ?? '';
   expect(label.length).toBeGreaterThan(2);
   expect(words(markup).length).toBeGreaterThan(label.length + 15);
   const assertive = ['unauthorized', 'rate_limited', 'error'].includes(kind);
   expect(markup).toContain(assertive ? 'role="alert"' : 'role="status"');
   expect(markup).toContain(assertive ? 'aria-live="assertive"' : 'aria-live="polite"');
   expect(markup).not.toMatch(/\sstyle=/);
  });
 }
 test('no two states share a label, so no state is told apart by colour alone', () => {
  const labels = LOAD_STATE_KINDS.map((k) => /<strong>([^<]+)<\/strong>/.exec(html(states[k]))?.[1] ?? '');
  expect(new Set(labels).size).toBe(labels.length);
 });
 test('a signed-out answer and a not-found answer are told apart in words', () => {
  expect(words(html({ kind: 'unauthorized', status: 401, requestId: 'r' }))).toContain('Signed out');
  expect(words(html({ kind: 'unauthorized', status: 404, requestId: 'r' }))).toContain('Not found');
 });
});
