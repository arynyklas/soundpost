// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { MAX_PROJECTS, decodeHash, encodeHash, type ViewContext } from '../app/context';
import { linkFor } from './ShellContext';
import { paletteEntries } from './Palette';
import { clockText, windowLabel, WINDOW_PRESETS } from './ScopeControls';
import { scopeSummary, validateScopeForm } from './ScopePicker';

const A = 'a'.repeat(32), P = '1'.repeat(32), I = '2'.repeat(32);
const ctx: ViewContext = { org: A, projects: [P], environment: '', start: '1763719198418220004', end: '1763722798418220004', timezone: 'UTC', generation: 3, span: 60 };

describe('route model', () => {
 test('the section, a sub-page and the relative span survive the address', () => {
  const nav = decodeHash(encodeHash(ctx, 'settings', '', null, null, 'sso'), 0);
  expect([nav.section, nav.page, nav.context?.span]).toEqual(['settings', 'sso', 60]);
 });
 test('old section names open the new screens; an unknown one opens Home', () => {
  expect(decodeHash('#view=queue', 0).section).toBe('incidents');
  expect(decodeHash('#view=explore', 0).section).toBe('logs');
  expect(decodeHash('#view=nowhere', 0).section).toBe('home');
  expect(decodeHash('', 0).section).toBe('home');
 });
 test('a page name that is not lowercase words is dropped; a span that is not a positive whole number is dropped', () => {
  expect(decodeHash(`#view=settings&page=%3Cb%3E&org=${A}&projects=${P}&start=1&end=2&tz=UTC`, 0).page).toBe('');
  expect(decodeHash(`#view=home&org=${A}&projects=${P}&start=1&end=2&tz=UTC&span=-5`, 0).context?.span).toBeUndefined();
  expect(decodeHash(`#view=home&org=${A}&projects=${P}&start=1&end=2&tz=UTC&span=1.5`, 0).context?.span).toBeUndefined();
 });
 test('without a scope a link names only its screen; with one it keeps the scope', () => {
  expect(linkFor(null, 'issues')).toBe('#view=issues');
  expect(linkFor(ctx, 'services', { service: I })).toContain(`service=${I}`);
  expect(linkFor(ctx, 'incidents', { incident: { project: P, id: I } })).toContain(`incident=${P}%3A${I}`);
 });
});

describe('scope picker validation', () => {
 const ok = { org: A, projects: P, environment: '', timezone: 'UTC' };
 test('a valid scope is accepted and trimmed', () => { expect(validateScopeForm({ ...ok, org: ` ${A} `, projects: ` ${P} ` })).toEqual({ ok: true, org: A, projects: [P], environment: '', timezone: 'UTC' }); });
 test('the organization, the project list, the environment and the zone are each refused in words', () => {
  expect(validateScopeForm({ ...ok, org: 'x' })).toMatchObject({ ok: false, message: expect.stringContaining('Organization ID') });
  expect(validateScopeForm({ ...ok, projects: '' })).toMatchObject({ ok: false });
  expect(validateScopeForm({ ...ok, projects: `${P}, ${P}` })).toMatchObject({ ok: false });
  expect(validateScopeForm({ ...ok, environment: 'nope' })).toMatchObject({ ok: false, message: expect.stringContaining('Environment ID') });
  expect(validateScopeForm({ ...ok, timezone: 'Mars/Base' })).toMatchObject({ ok: false, message: expect.stringContaining('Time zone') });
 });
 test(`at most ${MAX_PROJECTS} projects`, () => {
  const many = Array.from({ length: MAX_PROJECTS + 1 }, (_, i) => i.toString(16).padStart(32, '0')).join(',');
  expect(validateScopeForm({ ...ok, projects: many })).toMatchObject({ ok: false });
  expect(validateScopeForm({ ...ok, projects: many.split(',').slice(0, MAX_PROJECTS).join(',') }).ok).toBe(true);
 });
 test('the sidebar summary says what is chosen, never a name that is not known', () => {
  expect(scopeSummary(null, undefined, undefined)).toMatchObject({ title: 'No scope selected' });
  expect(scopeSummary(ctx, undefined, undefined).title).toBe(`org ${A.slice(0, 4)}…${A.slice(-4)}`);
  expect(scopeSummary(ctx, 'Example Co', 5).detail).toBe('1 of 5 projects');
 });
});

describe('window controls', () => {
 test('a preset window is named; any other is a custom window; the range is clock text in the zone', () => {
  expect(windowLabel(ctx).title).toBe('Last 1 hour');
  expect(windowLabel({ ...ctx, span: 7 }).title).toBe('Custom window');
  const { span: _span, ...absolute } = ctx;
  expect(windowLabel(absolute).title).toBe('Custom window');
  expect(clockText('1763719198418220004', 'UTC', false)).toBe('09:59');
  expect(WINDOW_PRESETS.every((p) => p.minutes > 0)).toBe(true);
 });
});

describe('search palette', () => {
 const link = (s: string, o?: { service?: string; incident?: { project: string; id: string } | null; target?: { project: string; id: string } | null }): string => linkFor(ctx, s as never, o as never);
 test('every screen can be jumped to by name', () => {
  const e = paletteEntries('metr', link, [P]);
  expect(e.map((x) => x.label)).toEqual(['Metrics']);
 });
 test('a pasted 32-hex ID offers to open it as each kind of entity, in the first selected project; it does not guess one', () => {
  const e = paletteEntries(I, link, [P]);
  expect(e.filter((x) => x.group === 'Open by ID').map((x) => x.label)).toEqual(['Open as an incident', 'Open as an issue', 'Open as a release', 'Open as a trace', 'Open as a service', 'Open as a job', 'Open as a replay', 'Open as a profile']);
  expect(e.find((x) => x.key === 'id:incident')!.href).toContain(`incident=${P}%3A${I}`);
  expect(e.find((x) => x.key === 'id:service')!.href).toContain(`service=${I}`);
 });
 test('without a scope an ID offers nothing to open (no project to read it in)', () => { expect(paletteEntries(I, link, []).some((x) => x.group === 'Open by ID')).toBe(false); });
 test('a pasted console path link becomes its hash route', () => {
  const e = paletteEntries(`/incidents/${P}:${I}?org=${A}`, link, [P]);
  expect(e[0]!.key).toBe('link');
  expect(e[0]!.href).toContain('view=incidents');
 });
});
