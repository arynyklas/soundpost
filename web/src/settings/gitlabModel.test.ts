// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { parseSettings, type GitlabSettings } from '../api/gitlab';
import { BOUNDARY, buildConnection, connectionWords, createFromWords, draftsOf, emptyMapping, expiryWords } from './gitlabModel';

const P1 = '1'.repeat(32), P2 = '2'.repeat(32);
const draft = (over: Record<string, unknown> = {}) => ({ baseUrl: 'https://gitlab.example.test', token: 'glpat-secret', mappings: [{ ...emptyMapping(P1), gitlabProject: 'shop/storefront-web', labels: 'incident, bug' }], ...over });

describe('the connection form', () => {
 test('builds the whole connection: https address, a token, normalized project paths, kinds and labels', () => {
  const built = buildConnection(draft(), false);
  expect(built).toEqual({ ok: true, value: { baseUrl: 'https://gitlab.example.test', token: 'glpat-secret', mappings: [{ projectId: P1, gitlabProject: 'shop/storefront-web', createFrom: ['incident', 'issue'], labels: ['incident', 'bug'] }] } });
 });
 test('the address is https without credentials, query or fragment', () => {
  for (const bad of ['http://gitlab.example.test', 'https://u:p@gitlab.example.test', 'https://gitlab.example.test/?t=1', 'gitlab.example.test', '']) expect(buildConnection(draft({ baseUrl: bad }), false).ok).toBe(false);
 });
 test('a token is required until one is stored, then an empty one keeps it and is never sent', () => {
  expect(buildConnection(draft({ token: '' }), false).ok).toBe(false);
  const kept = buildConnection(draft({ token: '' }), true);
  expect(kept.ok && 'token' in kept.value).toBe(false);
 });
 test('a mapping needs a project, a GitLab path, at least one kind, and a project is mapped once', () => {
  const m = emptyMapping(P1);
  expect(buildConnection(draft({ mappings: [{ ...m, project: '', gitlabProject: 'a/b' }] }), false).ok).toBe(false);
  expect(buildConnection(draft({ mappings: [{ ...m, gitlabProject: 'nogroup' }] }), false).ok).toBe(false);
  expect(buildConnection(draft({ mappings: [{ ...m, gitlabProject: 'a b/c' }] }), false).ok).toBe(false);
  expect(buildConnection(draft({ mappings: [{ ...m, gitlabProject: 'a/b', incident: false, issue: false }] }), false).ok).toBe(false);
  expect(buildConnection(draft({ mappings: [{ ...m, gitlabProject: 'a/b' }, { ...m, gitlabProject: 'c/d' }] }), false).ok).toBe(false);
  const two = buildConnection(draft({ mappings: [{ ...m, gitlabProject: '/a/b/' , issue: false }, { ...emptyMapping(P2), gitlabProject: 'c/d/e' }] }), false);
  expect(two.ok && two.value.mappings.map((x) => [x.gitlabProject, x.createFrom])).toEqual([['a/b', ['incident']], ['c/d/e', ['incident', 'issue']]]);
 });
 test('an empty mapping list is a connection with no project mapped', () => {
  const built = buildConnection(draft({ mappings: [] }), false);
  expect(built.ok && built.value.mappings).toEqual([]);
 });
 test('drafts of the read settings round trip through the builder', () => {
  const settings: GitlabSettings = parseSettings({ connected: true, base_host: 'gitlab.example.test', mappings: [{ project_id: P1, gitlab_project: 'shop/x', create_from: ['issue'], labels: ['bug'] }], token: { has_token: true } });
  const again = buildConnection({ baseUrl: 'https://gitlab.example.test', token: '', mappings: draftsOf(settings) }, true);
  expect(again.ok && again.value.mappings).toEqual(settings.mappings);
 });
});

describe('connection and expiry in words', () => {
 test('not connected, connected without a token and connected are three different sentences', () => {
  expect(connectionWords({ connected: false, token: { hasToken: false } }).label).toBe('Not connected');
  expect(connectionWords({ connected: true, token: { hasToken: false } }).label).toBe('Connected, no token');
  expect(connectionWords({ connected: true, token: { hasToken: true } }).label).toBe('Connected');
  expect(connectionWords({ connected: false, token: { hasToken: false } }).text).toContain('Nothing is sent to GitLab');
 });
 test('an expiry is relative to now, near is high, past is critical, and an unreported one is not guessed', () => {
  const now = Date.parse('2026-11-22T12:00:00Z');
  expect(expiryWords('2027-01-02', now)).toMatchObject({ label: 'in 41 days', tone: 'ok' });
  expect(expiryWords('2026-12-01', now)).toMatchObject({ label: 'in 9 days', tone: 'high' });
  expect(expiryWords('2026-11-20', now)).toMatchObject({ label: 'Expired', tone: 'crit' });
  expect(expiryWords(undefined, now)).toMatchObject({ label: 'Not reported', tone: 'unk' });
  expect(expiryWords('soon', now)).toMatchObject({ label: 'soon', tone: 'unk' });
 });
 test('what a mapping creates issues from', () => {
  expect(createFromWords(['incident', 'issue'])).toBe('Incidents, Error issues');
  expect(createFromWords(['issue'])).toBe('Error issues');
  expect(createFromWords([])).toContain('hidden');
 });
});

describe('the one-way rules', () => {
 test('the screen states that nothing is synced, read back or auto-resolved and no suspect commit is used', () => {
  const text = BOUNDARY.map((b) => `${b.head} ${b.text}`).join(' ').toLowerCase();
  for (const phrase of ['not read', 'nothing is synced', 'resolves nothing', 'no suspect commits', 'outcome unknown', 'never a duplicate']) expect(text).toContain(phrase);
 });
});
