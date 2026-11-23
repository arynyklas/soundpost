// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { DeployRecord, ReleaseListItem } from '../api/console';
import type { IncidentView, ReleaseView } from '../api/types';
import type { ViewContext } from '../app/context';
import { NO_NAMES } from '../shell/ShellContext';
import { DEFAULT_RELEASE_QUERY, builtText, countCell, deployLines, deployRecordLines, regressionIssues, releaseFilter, releaseLineage, releaseListKey, releaseListRequest, shownText } from './model';
import { ReleaseTable } from './ReleasesList';

const A = 'a'.repeat(32), P = '1'.repeat(32), R = '4'.repeat(32), E = '5'.repeat(32), E2 = '6'.repeat(32), I = '3'.repeat(32), N = '8'.repeat(32), S = '9'.repeat(32);
const ctx: ViewContext = { org: A, projects: [P], environment: '', start: '1', end: '2000000000000', timezone: 'UTC', generation: 1 };
const item = (over: Partial<ReleaseListItem> = {}): ReleaseListItem => ({ project_id: P, release_id: R, label: 'v2.31.0', buildTime: '1730000000000000000', parents: [], deploys: [], deployState: 'unknown', newIssues: '1', regressedIssues: '0', resolvedIssues: '2', countsIncomplete: false, ...over });
const table = (items: ReleaseListItem[]): string => renderToStaticMarkup(React.createElement(ReleaseTable, { items, context: ctx, names: NO_NAMES, href: (s, o) => `#${s}${o?.target ? `:${o.target.id}` : ''}` }));

describe('deploy times', () => {
 test('a release with no marker is deploy time unknown; the build time is never a deploy', () => {
  expect(deployLines(item(), 'UTC')).toEqual([{ key: 'unknown', text: 'deploy time unknown' }]);
  expect(deployLines(item({ deployState: 'known', deploys: [] }), 'UTC')[0]?.text).toBe('deploy time unknown');
  const html = table([item()]);
  expect(html).toContain('deploy time unknown');
  expect(html).toContain('data-deploy="unknown"');
  expect(html).toMatch(/built \d+ Oct 2024/);
 });
 test('one line per environment, newest deploy first', () => {
  const lines = deployLines(item({ deployState: 'known', deploys: [{ environment: E, deployedAt: '1730000000000000000' }, { environment: E2, deployedAt: '1730000900000000000' }] }), 'UTC');
  expect(lines.map((l) => l.key)).toEqual([E2, E]);
  expect(lines[0]?.text).toContain('environment 66666666…');
 });
 test('the deploys route: first and last deploy and the count; no record says deploy time unknown', () => {
  const r: DeployRecord = { project_id: P, release_id: R, environment: E, first_deployed_at: '1730000000000000000', last_deployed_at: '1730000900000000000', count: '3' };
  expect(deployRecordLines([r], 'UTC')[0]?.text).toMatch(/first deployed .*last .* \(3 deploys\)/);
  expect(deployRecordLines([{ ...r, count: '1' }], 'UTC')[0]?.text).not.toContain('last');
  expect(deployRecordLines([], 'UTC')[0]?.text).toContain('Deploy time unknown');
  expect(deployRecordLines([], 'UTC')[0]?.text).toContain('build time is not a deploy time');
  expect(builtText(null, 'UTC')).toBe('build time not available');
 });
});

describe('counts', () => {
 test('a count the server cannot state is not available, never 0; an incomplete count says so', () => {
  expect(countCell(null, false)).toEqual({ text: 'not available', known: false });
  expect(countCell('0', false)).toEqual({ text: '0', known: true });
  expect(countCell('1200', true)).toEqual({ text: '1,200 (incomplete)', known: true });
  const html = table([item({ newIssues: null, countsIncomplete: true })]);
  expect(html).toContain('>not available</span>');
  expect(html).toContain('2 (incomplete)');
 });
});

describe('the release list request', () => {
 test('the environment of the scope and the regressions chip become the server filter; search is the query', () => {
  expect(releaseFilter(ctx, DEFAULT_RELEASE_QUERY)).toEqual({});
  expect(releaseFilter({ ...ctx, environment: E }, { ...DEFAULT_RELEASE_QUERY, regressionsOnly: true })).toEqual({ environment: E, has_regressions: true });
  expect(releaseListRequest(ctx, { ...DEFAULT_RELEASE_QUERY, search: ' v2 ' })).toMatchObject({ org: A, projects: [P], query: 'v2' });
  expect(releaseListKey({ ...ctx, generation: 2 }, DEFAULT_RELEASE_QUERY)).not.toBe(releaseListKey(ctx, DEFAULT_RELEASE_QUERY));
  expect(shownText(2, true)).toContain('More follow');
 });
 test('parents link to their own release page and an empty list says no parent is declared', () => {
  expect(table([item({ parents: [E] })])).toContain(`href="#releases:${E}"`);
  expect(table([item()])).toContain('no parent declared');
 });
});

describe('the lineage of a release', () => {
 const incident = { incident_id: N, org: A, project_id: P, version: '1', status: 'open', condition: { id: E, state: 'firing', freshness: 'fresh', observed_at: '1' }, links: [{ kind: 'release', id: R }, { kind: 'service', id: S }] } as unknown as IncidentView;
 const links = { incident: (p: string, i: string) => `#i:${p}:${i}`, issue: (i: string) => `#issue:${i}`, service: (s: string) => `#svc:${s}`, rules: '#rules' };
 test('is rule, incident, issue, release, service; what is not stated is not available', () => {
  const items = releaseLineage({ release: R, incidents: [incident], issues: [I], links });
  expect(items.map((i) => i.kind)).toEqual(['Rule', 'Incident', 'Issue', 'Release', 'Service']);
  expect(items[3]?.current).toBe(true);
  expect(items[2]).toMatchObject({ href: `#issue:${I}` });
  expect(items[4]).toMatchObject({ href: `#svc:${S}` });
  const none = releaseLineage({ release: R, incidents: null, issues: null, links });
  expect(none.filter((i) => i.unavailable).map((i) => i.name)).toEqual(['not available', 'not available', 'not available', 'not available']);
 });
 test('the issues of the stored evaluations are distinct, and unknown when the part is not available', () => {
  const view = { sections: [{ name: 'regression', state: 'ready' }], regressions: [{ issue: I }, { issue: I }, { issue: R }] } as unknown as ReleaseView;
  expect(regressionIssues(view)).toEqual([I, R]);
  expect(regressionIssues({ ...view, sections: [{ name: 'regression', state: 'not_available' }] })).toBeNull();
  expect(regressionIssues(undefined)).toBeNull();
 });
});
