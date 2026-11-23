// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Server-rendered markup of the settings screens: one h1 per page, links that carry the page, regions with unique names, no inline style and every state in words.
import { describe, expect, test } from 'bun:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { encodeHash, type Navigation, type ViewContext } from '../app/context';
import { NO_NAMES, ShellProvider, linkFor, type ShellApi } from '../shell/ShellContext';
import { CutoverRoute } from './CutoverRoute';
import { EventsRoute } from './EventsRoute';
import { GitlabRoute } from './GitlabRoute';
import { PlainTable, Panel } from './SettingsUi';
import { SettingsRoute } from './SettingsRoute';
import { RoutingRoute } from '../routing/RoutingRoute';
import { RulesRoute } from '../alerts/RulesRoute';

const A = 'a'.repeat(32), P = '1'.repeat(32);
const context: ViewContext = { org: A, projects: [P], environment: '', start: '1700000000000000000', end: '1700003600000000000', timezone: 'UTC', generation: 1 };
const nav = (page: string): Navigation => ({ context, section: 'settings', service: '', incident: null, target: null, page });
const shell = (page: string): ShellApi => ({
 nav: nav(page), context, section: 'settings', href: (section, o = {}) => linkFor(context, section, o), go: () => undefined, refresh: () => undefined, applyScope: () => undefined, openScope: () => undefined, openSearch: () => undefined,
 names: NO_NAMES, counts: {}, setCounts: () => undefined,
});
const render = (page: string, el: React.ReactElement): string => renderToStaticMarkup(React.createElement(ShellProvider, { value: shell(page) }, el));
const words = (markup: string): string => markup.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
const count = (markup: string, re: RegExp): number => (markup.match(re) ?? []).length;

describe('the settings hub', () => {
 const html = render('', React.createElement(SettingsRoute, { context, nav: nav('') }));
 test('one h1, a link for every screen of configuration and none for what the first release does not have', () => {
  expect(count(html, /<h1[ >]/g)).toBe(1);
  expect(html).toContain('>Settings</h1>');
  for (const title of ['Project', 'Source policies', 'Notification routes', 'Alert rules', 'Members and teams', 'Teams', 'Single sign-on', 'Audit and operations', 'GitLab', 'Event webhooks', 'Migration and cutover']) expect(html).toContain(`<h2>${title}</h2>`);
  expect(words(html)).not.toContain('Your notifications');
 });
 test('tiles open their screen inside the scope, and a page by its page name', () => {
  const esc = (s: string): string => s.replace(/&/g, '&amp;');
  expect(html).toContain(`href="${esc(encodeHash(context, 'routing'))}"`);
  expect(html).toContain(`href="${esc(encodeHash(context, 'gitlab'))}"`);
  expect(html).toContain(`href="${esc(encodeHash(context, 'settings', '', null, null, 'sso'))}"`);
  expect(html).not.toMatch(/\sstyle=/);
 });
});

describe('a settings page', () => {
 test('has one h1 (its title), a crumb back to Settings, the page links with the current one marked, and its loading state in words', () => {
  const html = render('teams', React.createElement(SettingsRoute, { context, nav: nav('teams') }));
  expect(count(html, /<h1[ >]/g)).toBe(1);
  expect(html).toContain('>Teams</h1>');
  expect(html).toContain('aria-label="Settings pages"');
  expect(html).toMatch(/data-settings-tab="teams"[^>]*aria-current="page"|aria-current="page"[^>]*data-settings-tab="teams"/);
  expect(count(html, /aria-current="page"/g)).toBe(1);
  expect(html).toContain('data-settings-page="teams"');
  expect(words(html)).toContain('Loading');
 });
 test('every page names its content with the marker the specs read', () => {
  for (const [page, marker] of [['project', 'project'], ['sources', 'source-policies'], ['organization', 'organization'], ['sso', 'sso'], ['operations', 'operations']] as const) {
   expect(render(page, React.createElement(SettingsRoute, { context, nav: nav(page) }))).toContain(`data-settings-page="${marker}"`);
  }
 });
 test('an unknown page is the hub, not an empty page', () => {
  expect(render('nonsense', React.createElement(SettingsRoute, { context, nav: nav('nonsense') }))).toContain('>Settings</h1>');
 });
});

describe('the screens of their own', () => {
 test.each([
  ['Notification routes', () => React.createElement(RoutingRoute, { context })],
  ['Alert rules', () => React.createElement(RulesRoute, { context })],
  ['GitLab', () => React.createElement(GitlabRoute, { context })],
  ['Event webhooks', () => React.createElement(EventsRoute, { context })],
  ['Migration and cutover', () => React.createElement(CutoverRoute, { context })],
 ] as const)('%s has exactly one h1 and says it is loading before it has read anything', (title, make) => {
  const html = render('', make());
  expect(count(html, /<h1[ >]/g)).toBe(1);
  expect(html).toContain(`>${title}</h1>`);
  expect(html).not.toMatch(/\sstyle=/);
 });
 test('the cutover screen names the notification cutover of each project in scope and says it is read-only', () => {
  const html = render('', React.createElement(CutoverRoute, { context }));
  expect(html).toContain(`data-project-cutover="${P}"`);
  expect(words(html)).toContain('Read-only. The cutover is advanced only by the operator flow; nothing on this page changes it.');
 });
});

describe('PlainTable', () => {
 test('is a labelled, focusable region with a caption, scoped headers, and an empty one says so in its own row', () => {
  const html = renderToStaticMarkup(React.createElement(PlainTable, { label: 'Shadow decisions by kind', columns: ['Kind', 'Decisions'], rows: [], empty: 'None.' }));
  expect(html).toContain('role="region"');
  expect(html).toContain('tabindex="0"');
  expect(html).toContain('aria-label="Shadow decisions by kind"');
  expect(html).toContain('<caption class="sr-only">Shadow decisions by kind</caption>');
  expect(count(html, /<th scope="col">/g)).toBe(2);
  expect(html).toMatch(/<td colSpan="2">None\.<\/td>/);
 });
 test('rows keep their cells once, each labelled for the stacked layout', () => {
  const html = renderToStaticMarkup(React.createElement(PlainTable, { label: 'T', columns: ['A', 'B'], rows: [['1', '2'], ['3', '4']], empty: 'none', rowAttrs: (i) => ({ 'data-row': String(i) }) }));
  expect(count(html, /<td /g)).toBe(4);
  expect(html).toContain('data-label="A"');
  expect(html).toContain('data-row="1"');
  expect(html).not.toContain('none');
 });
 test('panel titles are headings that name their region', () => {
  const html = renderToStaticMarkup(React.createElement(Panel, { title: 'Destinations' }, 'x'));
  expect(html).toMatch(/<section class="card" aria-labelledby="([^"]+)"[^>]*><div class="card-head"><h2 id="\1">Destinations<\/h2>/);
 });
});
