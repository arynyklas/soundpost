// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { RedView } from '../api/console';
import type { InvestigationView, ServiceHealth, VisibleService } from '../api/types';
import type { ViewContext } from '../app/context';
import { NO_NAMES } from '../shell/ShellContext';
import { countsByHealth, dependencyNames, durationMs, filterServices, gapsOf, healthPill, healthReason, orderServices, partWord, percent, perSecond, redCell, redReasonText, samplesOf, windowMs, wordOfProbe, type ServiceRowModel } from './model';
import { RedBody } from './ServicePage';
import { ServiceTable } from './ServicesList';

const A = 'a'.repeat(32), P = '1'.repeat(32), S = '2'.repeat(32), S2 = '3'.repeat(32), E = '4'.repeat(32), N = '5'.repeat(32);
const ctx: ViewContext = { org: A, projects: [P], environment: '', start: '1730000000000000000', end: '1730003600000000000', timezone: 'UTC', generation: 1 };
const svc = (id: string, over: Partial<VisibleService> = {}): VisibleService => ({ id, project_id: P, sources: [], environments: [E], builds: [], dependencies: [], ...over });
const health = (status: ServiceHealth['status'], over: Partial<ServiceHealth> = {}): ServiceHealth => ({ status, incidents: [], conditions: [], ...over });
const row = (id: string, word: ServiceRowModel['word'], h?: ServiceHealth, red: ServiceRowModel['red'] = 'not_built'): ServiceRowModel => ({ service: svc(id), word, health: h, red });
const pts = [{ t: '1730000000000000000', v: 450 }];
const noDuration = { p50Ms: null, p95Ms: null, p99Ms: null, points: [], p50Points: [], p95Points: [] };
const red = (over: Partial<RedView> = {}): RedView => ({
 state: 'ready', window: { start: ctx.start, end: ctx.end }, stepSeconds: 60,
 rate: { state: 'ready', perSecond: 28.4, points: [{ t: '1730000000000000000', v: 28 }, { t: '1730000060000000000', v: null }] },
 errors: { state: 'ready', ratio: 0.015, count: '30', points: [{ t: '1730000000000000000', v: 0.015 }] },
 duration: { state: 'ready', p50Ms: 450, p95Ms: 1850, p99Ms: 2710, points: pts, p50Points: pts, p95Points: pts },
 requests: '2000', gaps: [], ...over,
});

describe('health in words', () => {
 test('every state has its own word; a service whose health is not stated or could not be read is never healthy', () => {
  expect(['failing', 'degraded', 'healthy', 'unknown', 'not_assessed'].map((w) => healthPill(w as never).text)).toEqual(['Failing', 'Degraded', 'Healthy', 'Unknown', 'Not assessed']);
  expect(wordOfProbe({ kind: 'failed' })).toBe('unknown');
  const base = { kind: 'service', org: A, window: { start: '1', end: '2' }, state: 'ready', projects: [], metric_names: [], more: false, sections: [] } as unknown as InvestigationView;
  expect(wordOfProbe({ kind: 'view', view: base })).toBe('not_assessed');
  expect(wordOfProbe({ kind: 'view', view: { ...base, health: health('failing') } })).toBe('failing');
 });
 test('the reason comes from the stored incidents and conditions only', () => {
  const failing = health('failing', { incidents: [{ project_id: P, incident_id: A, severity: 'critical', version: '1' }, { project_id: P, incident_id: N, severity: 'major', version: '1' }] });
  expect(healthReason('failing', failing)).toBe('2 open incidents, 1 critical');
  expect(healthReason('degraded', health('degraded', { conditions: [{ project_id: P, condition_id: A, phase: 'firing', severity: 'major', freshness: 'fresh' }] }))).toBe('1 active condition names it, no open incident');
  expect(healthReason('unknown', undefined)).toContain('could not be read');
  expect(healthReason('not_assessed', undefined)).toContain('does not state');
 });
 test('the worst come first, then a stable order; filters and counts follow the words', () => {
  const rows = [row(S2, 'healthy'), row(S, 'failing'), row(N, 'unknown')];
  expect(orderServices(rows).map((r) => r.word)).toEqual(['failing', 'unknown', 'healthy']);
  expect(filterServices(rows, 'healthy', '').map((r) => r.service.id)).toEqual([S2]);
  expect(filterServices(rows, 'all', S.slice(0, 4)).map((r) => r.service.id)).toEqual([S]);
  expect(countsByHealth(rows)).toMatchObject({ all: 3, failing: 1, healthy: 1, unknown: 1, not_assessed: 0 });
 });
 test('dependencies are the declared names, once each and sorted', () => {
  expect(dependencyNames([{ dependencies: ['postgres', 'orders'] }, { dependencies: ['orders'] }])).toEqual(['orders', 'postgres']);
 });
});

describe('RED figures', () => {
 test('figures are in the unit a person reads; what cannot be stated is words, never 0', () => {
  expect(durationMs(450)).toBe('450 ms');
  expect(durationMs(2710)).toBe('2.71 s');
  expect(durationMs(null)).toBe('not available');
  expect(percent(0.015)).toBe('1.5%');
  expect(percent(0.0004)).toBe('0.04%');
  expect(percent(null)).toBe('not available');
  expect(perSecond(28.4)).toBe('28.4/s');
  expect(perSecond(null)).toBe('not available');
 });
 test('server points become chart samples in epoch milliseconds; a bucket with no samples stays null', () => {
  expect(samplesOf([{ t: '1730000000000000000', v: 1 }, { t: '1730000060000000000', v: null }])).toEqual([{ t: 1730000000000, v: 1 }, { t: 1730000060000, v: null }]);
  expect(gapsOf([{ start: '1730000000000000000', end: '1730000060000000000' }])).toEqual([{ from: 1730000000000, to: 1730000060000, text: 'no samples' }]);
  expect(windowMs({ start: ctx.start, end: ctx.end })).toEqual({ start: 1730000000000, end: 1730003600000 });
 });
 test('a table cell says reading, not available, not read or no samples in words', () => {
  expect(redCell('reading', 'p99').text).toBe('reading');
  expect(redCell('not_built', 'errors').text).toBe('not available');
  expect(redCell('failed', 'rate').text).toBe('not readable');
  expect(redCell('not_read', 'p99').text).toBe('not read here');
  expect(redCell(red({ duration: { state: 'empty', ...noDuration } }), 'p99')).toEqual({ text: 'no samples', figure: false });
  expect(redCell(red(), 'p99')).toEqual({ text: '2.71 s', figure: true });
  expect(redCell(red(), 'errors').text).toBe('1.5%');
 });
 test('reasons and parts are sentences and words', () => {
  expect(redReasonText('no_samples')).toContain('not zero traffic');
  expect(redReasonText('scan_capped')).toContain('partial');
  for (const reason of ['no_finished_spans', 'spans_sampled', 'list_source_not_wired']) expect(redReasonText(reason), reason).not.toContain('does not recognise');
  expect(redReasonText('no_finished_spans')).toContain('not zero latency');
  expect(redReasonText('from_the_future')).toContain('does not recognise');
  expect(redReasonText(undefined)).toBe('');
  expect(partWord('incomplete')).toBe('Partial');
  expect(partWord('empty')).toBe('No samples');
 });
});

describe('the RED section', () => {
 const body = (r: RedView): string => renderToStaticMarkup(React.createElement(RedBody, { red: r, timezone: 'UTC' }));
 test('a ready window draws the three charts with an accessible name and states the figures', () => {
  const html = body(red());
  expect(html.match(/role="img"/g)).toHaveLength(3);
  expect(html).toContain('data-testid="red-rate"');
  expect(html).toContain('Duration p99');
  expect(html).toContain('2.71 s');
  expect(html).toContain('1.5%');
 });
 test('an empty window draws no chart and says there are no samples, not zero', () => {
  const html = body(red({ state: 'empty', reason: 'no_samples', requests: null, rate: { state: 'empty', perSecond: null, points: [] }, errors: { state: 'empty', ratio: null, count: null, points: [] }, duration: { state: 'empty', ...noDuration } }));
  expect(html).not.toContain('role="img"');
  expect(html).toContain('No samples.');
  expect(html).toContain('not zero traffic');
  expect(html).toContain('>not available<');
  expect(html).not.toContain('>0/s<');
 });
 test('a partial answer says so in words and still draws what it has', () => {
  const html = body(red({ state: 'incomplete', reason: 'scan_capped' }));
  expect(html).toContain('Partial.');
  expect(html).toContain('data-testid="red-state"');
  expect(html.match(/role="img"/g)).toHaveLength(3);
 });
});

describe('the service table', () => {
 const table = (rows: ServiceRowModel[]): string => renderToStaticMarkup(React.createElement(ServiceTable, { rows, context: ctx, names: NO_NAMES, href: (s, o) => `#${s}${o?.service ? `:${o.service}` : ''}`, open: () => undefined }));
 test('each row carries its identity for the e2e contract, the health word with its reason and its environment', () => {
  const html = table([row(S, 'failing', health('failing', { incidents: [{ project_id: P, incident_id: A, severity: 'critical', version: '1' }] }))]);
  expect(html).toContain('data-testid="service-row"');
  expect(html).toContain(`data-service="${S}"`);
  expect(html).toContain(`data-project="${P}"`);
  expect(html).toContain('>Failing</span>');
  expect(html).toContain('1 open incident, 1 critical');
  expect(html).toContain(`aria-label="Open service ${S}"`);
  expect(html).toContain(E);
  expect(html).toContain('aria-label="Services admitted by the active source policies"');
 });
 test('a service with no stated health says so, and a missing metrics route is words in every figure cell', () => {
  const html = table([row(S, 'not_assessed')]);
  expect(html).toContain('>Not assessed</span>');
  expect(html).toContain('not available');
  expect(html).toContain('no samples');
  expect(html).not.toContain('>0</span>');
 });
 test('a service id from the server is only text', () => {
  const html = table([row('<img src=x onerror="window.__pwn=1">', 'unknown')]);
  expect(html).not.toMatch(/<img/i);
  expect(html).toContain('&lt;img src=x onerror=');
 });
});
