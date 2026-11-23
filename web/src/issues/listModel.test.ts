// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { IssueListItem } from '../api/console';
import type { ViewContext } from '../app/context';
import { NO_NAMES } from '../shell/ShellContext';
import { IssueTable } from './IssuesList';
import { DEFAULT_ISSUE_QUERY, countText, issueFilter, issueListKey, issueListRequest, listNotice, ownerChoices, sectionNotes, seenText, shownText, titleText, workflowWord } from './listModel';

const A = 'a'.repeat(32), P = '1'.repeat(32), I = '3'.repeat(32), R = '4'.repeat(32), M = '5'.repeat(32);
const ctx: ViewContext = { org: A, projects: [P], environment: '', start: '1', end: '2000000000000', timezone: 'UTC', generation: 1 };
const item = (over: Partial<IssueListItem> = {}): IssueListItem => ({ project_id: P, issue_id: I, workflow: 'open', revision: '3', title: 'TypeError: x is undefined', titleState: 'ready', firstSeen: '1730000000000000000', lastSeen: '1730000100000000000', occurrences: '1942', compacted: false, releases: [R], ...over });
const table = (items: IssueListItem[]): string => renderToStaticMarkup(React.createElement(IssueTable, { items, context: ctx, names: NO_NAMES, href: (section, o) => `#${section}${o?.target ? `:${o.target.id}` : ''}` }));

describe('the issue query becomes the request', () => {
 test('the default shows open issues by last seen and sends no owner, release or search', () => {
  expect(issueFilter(DEFAULT_ISSUE_QUERY)).toEqual({ workflow: ['open'] });
  expect(issueListRequest(ctx, DEFAULT_ISSUE_QUERY)).toEqual({ org: A, projects: [P], limit: 50, sort: 'last_seen' });
 });
 test('all workflows send no workflow filter; regressed, owner and search are sent only when chosen', () => {
  expect(issueFilter({ ...DEFAULT_ISSUE_QUERY, workflow: 'all', regressed: true, owner: 'none' })).toEqual({ regressed: true, owner: 'none' });
  expect(issueListRequest(ctx, { ...DEFAULT_ISSUE_QUERY, search: '  ab12  ' }).query).toBe('ab12');
  expect(issueListRequest(ctx, { ...DEFAULT_ISSUE_QUERY, search: '   ' }).query).toBeUndefined();
 });
 test('a new scope, refresh or query is a new read', () => {
  const base = issueListKey(ctx, DEFAULT_ISSUE_QUERY);
  expect(issueListKey({ ...ctx, generation: 2 }, DEFAULT_ISSUE_QUERY)).not.toBe(base);
  expect(issueListKey(ctx, { ...DEFAULT_ISSUE_QUERY, workflow: 'resolved' })).not.toBe(base);
  expect(issueListKey({ ...ctx, end: '3' }, DEFAULT_ISSUE_QUERY)).not.toBe(base);
 });
});

describe('what the list says when it cannot say', () => {
 test('a title that cannot be read is said so; a counter or time that cannot be stated is not available, never 0', () => {
  expect(titleText({ title: null, titleState: 'not_available' })).toBe('Title not available');
  expect(titleText({ title: 'Boom', titleState: 'not_available' })).toBe('Title not available');
  expect(titleText({ title: 'Boom', titleState: 'ready' })).toBe('Boom');
  expect(countText(null)).toBe('not available');
  expect(countText('0')).toBe('0');
  expect(countText('1942')).toBe('1,942');
  expect(seenText(null, 'UTC')).toBe('not available');
 });
 test('the workflow is a word, and an unknown state is called unknown', () => {
  expect(workflowWord('open').text).toBe('Open');
  expect(workflowWord('resolved').text).toBe('Resolved');
  expect(workflowWord('ignored').text).toBe('Ignored');
  expect(workflowWord('x').text).toBe('Unknown workflow state');
 });
 test('a capped title search is partial, in words, and a not available list is not an empty one', () => {
  const n = listNotice({ state: 'incomplete', reason: 'search_scan_capped' });
  expect(n?.label).toBe('Partial');
  expect(n?.text).toContain('scan limit');
  expect(listNotice({ state: 'not_available', reason: 'separate_grant_required' })?.label).toBe('Not available');
  expect(listNotice({ state: 'ready' })).toBeNull();
  expect(listNotice({ state: 'empty' })).toBeNull();
 });
 test('a part that is not ready is listed with its own state', () => {
  expect(sectionNotes([{ name: 'titles', state: 'incomplete', reason: 'search_scan_capped' }, { name: 'issues', state: 'ready' }])).toEqual([expect.stringContaining('titles: Partial. The title search')]);
 });
 test('the count line says whether more follow', () => {
  expect(shownText(1, false)).toBe('Showing 1 issue. No more follow.');
  expect(shownText(50, true)).toContain('More follow');
 });
 test('owners that can be chosen are any, unassigned and the members with a known name, sorted by name', () => {
  expect(ownerChoices(new Map([[M, 'Zed'], [P, 'Amy']])).map((o) => o.label)).toEqual(['Any owner', 'Unassigned', 'Amy', 'Zed']);
 });
});

describe('the issue table', () => {
 test('each row names its workflow in words, links the issue and its releases, and states an unassigned owner', () => {
  const html = table([item()]);
  expect(html).toContain('data-testid="issue-row"');
  expect(html).toContain('>Open</span>');
  expect(html).toContain(`href="#issues:${I}"`);
  expect(html).toContain(`href="#releases:${R}"`);
  expect(html).toContain('Unassigned');
  expect(html).toContain('>1,942</span>');
 });
 test('a missing title and a missing count are words, not blanks or zero', () => {
  const html = table([item({ title: null, titleState: 'not_available', occurrences: null, firstSeen: null, lastSeen: null, releases: [] })]);
  expect(html).toContain('Title not available');
  expect(html).toContain('>not available</span>');
  expect(html).toContain('no release named');
  expect(html).not.toContain('>0</span>');
 });
 test('compacted evidence is marked; a GitLab link opens safely and an unsafe one is not a link', () => {
  const html = table([item({ compacted: true, gitlab: { url: 'https://git.example.test/x/-/issues/9', gitlab_project: 'x', iid: '9' } })]);
  expect(html).toContain('Evidence compacted');
  expect(html).toMatch(/href="https:\/\/git\.example\.test\/x\/-\/issues\/9" target="_blank" rel="noopener noreferrer"/);
  const bad = table([item({ gitlab: { url: 'javascript:alert(1)', gitlab_project: 'x', iid: '9' } })]);
  expect(bad).not.toContain('javascript:');
  expect(bad).toContain('x#9');
 });
 test('a title from the application is only ever text', () => {
  const html = table([item({ title: '<img src=x onerror="window.__pwn=1">' })]);
  expect(html).not.toMatch(/<img/i);
  expect(html).toContain('&lt;img src=x onerror=');
 });
 test('every row of a long list sits in one labelled region', () => {
  const html = table([item(), item({ issue_id: R })]);
  expect(html.match(/role="region"/g)).toHaveLength(1);
  expect(html).toContain('aria-label="Error issues"');
 });
});
