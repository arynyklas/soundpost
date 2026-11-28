// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { JobHealth, JobRunView } from '../api/types';
import { healthTone } from './model';
import { RunStrip, StripLegend } from './RunStrip';
import { STRIP_WIDTH, buildStrip, kindOfRun, stripText } from './strip';

const ns = (s: number): string => String(BigInt(1_730_000_000 + s) * 1_000_000_000n);
const window = { start: ns(0), end: ns(1000) };
const run = (id: string, status: JobRunView['status'], at: number): JobRunView => ({ id, occurrence: { key: id, scheduled: true, at_ns: ns(at), fold: 0 }, status, recovered: status === 'recovered', first_started_ns: ns(at), final_attempt: id, attempt_count: 1, failed_attempts: 0, basis_of_health: false, overlaps: [], overlap_count: 0 }) as JobRunView;
const health = (status: JobHealth['status'], evidence: JobHealth['evidence'] = {}): JobHealth => ({ status, as_of_ns: ns(1000), complete: true, reasons: [], evidence });
const view = (runs: JobRunView[], over: Record<string, unknown> = {}) => ({ runs, runs_truncation: undefined, health: health('succeeded'), erased: false, ...over });

describe('the run strip places runs at the instant they started', () => {
 test('a run is placed on a 0..1000 axis by integer arithmetic over the window', () => {
  const s = buildStrip(view([run('a', 'succeeded', 0), run('b', 'failed', 500), run('c', 'recovered', 999)]), window);
  expect(s.marks.map((m) => [m.kind, m.x])).toEqual([['ok', 0], ['failed', 500], ['retry', 999]]);
  expect(STRIP_WIDTH).toBe(1000);
  expect(kindOfRun({ status: 'running' })).toBe('running');
  expect(kindOfRun({ status: 'cancelled' })).toBe('cancelled');
 });
 test('a run outside the window is counted, not drawn; the end of the window is excluded', () => {
  const s = buildStrip(view([run('a', 'succeeded', -5), run('b', 'succeeded', 1000), run('c', 'succeeded', 10)]), window);
  expect(s.marks).toHaveLength(1);
  expect(s.outside).toBe(2);
 });
 test('a run whose start cannot be read is counted as outside, never dropped silently', () => {
  const bad = { ...run('a', 'succeeded', 5), first_started_ns: 'garbage' };
  expect(buildStrip(view([bad]), window).outside).toBe(1);
 });
 test('a missed job draws the expected run that has no record', () => {
  const s = buildStrip(view([], { health: health('missed', { expected_at_ns: ns(250) }) }), window);
  expect(s.expected).toEqual([250]);
  expect(stripText(s)).toContain('An expected run has no record.');
  expect(buildStrip(view([], { health: health('succeeded', { expected_at_ns: ns(250) }) }), window).expected).toEqual([]);
 });
});

describe('the words of the strip', () => {
 test('count the runs by outcome', () => {
  const s = buildStrip(view([run('a', 'succeeded', 1), run('b', 'succeeded', 2), run('c', 'failed', 3), run('d', 'recovered', 4)]), window);
  expect(stripText(s)).toBe('4 runs in this window: 2 succeeded, 1 failed, 1 succeeded after retry.');
 });
 test('no run in the window says so, but not when only the newest runs were read', () => {
  expect(stripText(buildStrip(view([]), window))).toBe('No run of this job started in this window.');
  const cut = buildStrip(view([run('a', 'succeeded', -50)], { runs_truncation: { reason: 'runs_limit', shown: 25, total: 40 } }), window);
  expect(stripText(cut)).toContain('None of the newest 1 runs read started in this window.');
  expect(stripText(cut)).toContain('Only the newest 1 runs were read');
 });
 test('an erased history draws nothing and says it was erased', () => {
  expect(stripText(buildStrip(view([], { erased: true }), window))).toContain('was erased');
 });
});

describe('the strip markup', () => {
 const strip = buildStrip(view([run('a', 'succeeded', 100), run('b', 'failed', 200)]), window);
 test('is an image with a name that carries the words', () => {
  const html = renderToStaticMarkup(React.createElement(RunStrip, { state: { kind: 'ready', strip }, job: 'j1' }));
  expect(html).toContain('role="img"');
  expect(html).toContain('aria-label="Runs of job j1: 2 runs in this window: 1 succeeded, 1 failed."');
  expect(html).toContain('job-r-ok');
  expect(html).toContain('job-r-failed');
  expect(html).not.toMatch(/\sstyle=/);
 });
 test('a strip that is loading or could not be read is not drawn as having no runs', () => {
  expect(renderToStaticMarkup(React.createElement(RunStrip, { state: { kind: 'loading' }, job: 'j' }))).toContain('Reading runs');
  const failed = renderToStaticMarkup(React.createElement(RunStrip, { state: { kind: 'failed' }, job: 'j' }));
  expect(failed).toContain('could not be read');
  expect(failed).not.toContain('<svg');
 });
 test('the legend names every colour in words', () => {
  const html = renderToStaticMarkup(React.createElement(StripLegend));
  for (const word of ['succeeded', 'failed', 'succeeded after retry', 'running', 'cancelled', 'expected run, no record']) expect(html).toContain(word);
 });
 test('health tones only reinforce the word: success ok, failure and missed critical, unknown outlined', () => {
  expect(healthTone('succeeded')).toBe('ok');
  expect(healthTone('failed')).toBe('crit');
  expect(healthTone('missed')).toBe('crit');
  expect(healthTone('cancelled')).toBe('high');
  expect(healthTone('unknown')).toBe('unk');
 });
});
