// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, test } from 'bun:test';
import { ApiFault } from './types';
import { answerOf, externalLinkOf, gitlabCreate, gitlabLinkFrom, gitlabPreview, gitlabRecheck, gitlabSettingsDisconnect, gitlabSettingsRead, gitlabSettingsSave, gitlabSettingsTest, parseOutcome, parsePreview, parseSettings, parseTest } from './gitlab';

const A = 'a'.repeat(32), P = '1'.repeat(32), I = '2'.repeat(32), J = '3'.repeat(32), CMD = 'c'.repeat(32);
const LINK = { url: 'https://git.example.test/shop/web/-/issues/7', gitlab_project: 'shop/web', iid: 7 };
const real = globalThis.fetch;
afterEach(() => { globalThis.fetch = real; });
/** Replaces fetch with one canned answer and records what was sent. */
function answer(status: number, body: unknown, headers: Record<string, string> = { 'Content-Type': 'application/json' }): { sent: { url: string; body: Record<string, unknown> }[] } {
 const sent: { url: string; body: Record<string, unknown> }[] = [];
 globalThis.fetch = (async (url: string, init?: RequestInit) => { sent.push({ url, body: JSON.parse(String(init?.body)) as Record<string, unknown> }); return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers }); }) as typeof fetch;
 return { sent };
}
const signal = new AbortController().signal;
const entity = { kind: 'incident', id: I } as const;

describe('preview', () => {
 test('title, description, labels, the mapped project and the stored link', () => {
  const a = parsePreview({ title: 'T', description: 'D', labels: ['incident', 3, 'sev::major'], gitlab_project: 'shop/web', existing: LINK });
  expect(a).toEqual({ state: 'ready', preview: { title: 'T', description: 'D', labels: ['incident', 'sev::major'], gitlabProject: 'shop/web', existing: { url: LINK.url, gitlab_project: 'shop/web', iid: '7' } } });
 });
 test('an unmapped project is null, never an empty string project', () => {
  const a = parsePreview({ title: 'T', description: 'D', labels: [], gitlab_project: '' });
  expect(a.state === 'ready' && a.preview.gitlabProject).toBeNull();
 });
 test('the entity that holds the stored link is kept so it can be linked from', () => {
  const a = parsePreview({ title: 'T', description: 'D', labels: [], gitlab_project: 'shop/web', existing: { ...LINK, entity: { kind: 'issue', id: J } } });
  expect(a.state === 'ready' && a.preview.existingOn).toEqual({ kind: 'issue', id: J });
 });
 test('an earlier create that did not settle is reported with its state and code, never as a link', () => {
  const unknown = parsePreview({ title: 'T', description: 'D', labels: [], gitlab_project: 'shop/web', existing: { state: 'unknown', code: 'gitlab_timeout' } });
  expect(unknown.state === 'ready' && unknown.preview.existing).toBeUndefined();
  expect(unknown.state === 'ready' && unknown.preview.previous).toEqual({ state: 'unknown', code: 'gitlab_timeout' });
  const creating = parsePreview({ title: 'T', description: 'D', labels: [], gitlab_project: 'shop/web', existing: { state: 'creating' } });
  expect(creating.state === 'ready' && creating.preview.previous).toEqual({ state: 'creating' });
  const linked = parsePreview({ title: 'T', description: 'D', labels: [], gitlab_project: 'shop/web', existing: { state: 'linked', url: LINK.url, gitlab_project: 'shop/web', iid: '7' } });
  expect(linked.state === 'ready' && linked.preview.previous).toBeUndefined();
  expect(linked.state === 'ready' && linked.preview.existing?.iid).toBe('7');
 });
 test('not available carries its closed reason; a body that is not a preview is invalid', () => {
  expect(parsePreview({ state: 'not_available', reason: 'gitlab_not_connected' })).toEqual({ state: 'not_available', reason: 'gitlab_not_connected' });
  expect(() => parsePreview({ title: 1 })).toThrow(ApiFault);
  expect(() => parsePreview('x')).toThrow(ApiFault);
 });
 test('the request names the org, the project and the entity and nothing else', async () => {
  const { sent } = answer(200, { title: 'T', description: 'D', labels: [], gitlab_project: 'shop/web' });
  const r = await gitlabPreview({ org: A, project: P, entity }, signal);
  expect(r.kind).toBe('ok');
  expect(sent[0]).toEqual({ url: '/api/v1/gitlab/issues', body: { op: 'preview', org: A, project_id: P, entity: { kind: 'incident', id: I } } });
 });
});

describe('outcomes', () => {
 test('linked (flat or nested), unknown, refused, in progress, not found', () => {
  expect(parseOutcome({ state: 'linked', created: true, ...LINK })).toEqual({ state: 'linked', created: true, link: { url: LINK.url, gitlab_project: 'shop/web', iid: '7' } });
  expect(parseOutcome({ state: 'linked', created: false, link: LINK })).toMatchObject({ state: 'linked', created: false });
  expect(parseOutcome({ state: 'unknown' })).toEqual({ state: 'unknown' });
  expect(parseOutcome({ state: 'refused', code: 'gitlab_forbidden' })).toEqual({ state: 'refused', code: 'gitlab_forbidden' });
  expect(parseOutcome({ state: 'in_progress' })).toEqual({ state: 'in_progress' });
  expect(parseOutcome({ state: 'not_found' })).toEqual({ state: 'not_found' });
 });
 test('a linked answer without a link, and an unknown state, are invalid', () => {
  expect(() => parseOutcome({ state: 'linked' })).toThrow(ApiFault);
  expect(() => parseOutcome({ state: 'created' })).toThrow(ApiFault);
 });
 test('create sends a command ID, the entity and only the fields the person set', async () => {
  const { sent } = answer(200, { state: 'linked', created: true, ...LINK });
  const r = await gitlabCreate({ org: A, project: P, entity, commandId: CMD, title: 'T', labels: ['a'] }, signal);
  expect(r).toMatchObject({ state: 'linked', created: true });
  expect(sent[0]?.body).toEqual({ op: 'create', org: A, project_id: P, entity: { kind: 'incident', id: I }, command_id: CMD, title: 'T', labels: ['a'] });
 });
 test('recheck looks up and link_from names where the link comes from', async () => {
  const one = answer(200, { state: 'not_found' });
  expect(await gitlabRecheck({ org: A, project: P, entity }, signal)).toEqual({ state: 'not_found' });
  expect(one.sent[0]?.body).toEqual({ op: 'recheck', org: A, project_id: P, entity: { kind: 'incident', id: I } });
  const two = answer(200, { state: 'linked', created: false, ...LINK });
  await gitlabLinkFrom({ org: A, project: P, entity, from: { kind: 'issue', id: J } }, signal);
  expect(two.sent[0]?.body).toMatchObject({ op: 'link_from', from: { kind: 'issue', id: J } });
 });
 test('a route this installation does not serve is not_built, never an empty success', async () => {
  answer(404, 'not found', { 'Content-Type': 'text/plain' });
  expect(await gitlabCreate({ org: A, project: P, entity, commandId: CMD }, signal)).toEqual({ state: 'not_built' });
 });
 test('a 409 is another create in progress; a closed gitlab_ code is a refusal; other faults stay faults', async () => {
  answer(409, { code: 'conflict', detail: 'gitlab_in_progress' });
  expect(await gitlabCreate({ org: A, project: P, entity, commandId: CMD }, signal)).toEqual({ state: 'in_progress' });
  answer(403, { code: 'forbidden', detail: 'gitlab_forbidden' });
  expect(await gitlabCreate({ org: A, project: P, entity, commandId: CMD }, signal)).toEqual({ state: 'refused', code: 'gitlab_forbidden' });
  answer(500, { code: 'unavailable', detail: '' });
  expect((await gitlabCreate({ org: A, project: P, entity, commandId: CMD }, signal)).state).toBe('fault');
 });
 test('a connection lost after a create was sent is unknown (never retried blindly); for a read-only check it is a fault', () => {
  const lost = { kind: 'fault', fault: new ApiFault(0, 'network', '', '') } as const;
  expect(answerOf(lost, 'create')).toEqual({ state: 'unknown' });
  expect(answerOf(lost, 'recheck').state).toBe('fault');
 });
});

describe('the stored link on an incident', () => {
 test('the latest external link entry wins; entries of other types are ignored', () => {
  const timeline = [{ type: 'open' }, { type: 'external_end', external_link: { ...LINK, iid: 1 } }, { type: 'ack', ...LINK }, { type: 'external_adopt', ...LINK }];
  expect(externalLinkOf(timeline)).toEqual({ url: LINK.url, gitlab_project: 'shop/web', iid: '7' });
  expect(externalLinkOf([{ type: 'open' }])).toBeUndefined();
  expect(externalLinkOf(undefined)).toBeUndefined();
 });
});

describe('settings', () => {
 const read = { connected: true, base_host: 'git.example.test', mappings: [{ project_id: P, gitlab_project: 'shop/web', create_from: ['incident', 'x', 'issue'], labels: ['incident'] }, { project_id: 'bad', gitlab_project: 'x' }], token: { has_token: true, expires_at: '2027-01-01', scopes: ['api'] }, epoch: '4' };
 test('read keeps what the contract names and never a token', () => {
  expect(parseSettings(read)).toEqual({ connected: true, baseHost: 'git.example.test', mappings: [{ projectId: P, gitlabProject: 'shop/web', createFrom: ['incident', 'issue'], labels: ['incident'] }], token: { hasToken: true, expiresAt: '2027-01-01', scopes: ['api'] }, epoch: '4' });
  expect(() => parseSettings({ connected: 'yes' })).toThrow(ApiFault);
 });
 test('can_edit and the epoch are read as stated; an answer without can_edit does not allow editing', () => {
  expect(parseSettings({ ...read, epoch: '9', can_edit: true })).toMatchObject({ epoch: '9', canEdit: true });
  expect(parseSettings({ ...read, epoch: '9', can_edit: false })).toMatchObject({ canEdit: false });
  expect(parseSettings(read).canEdit).toBeUndefined();
 });
 test('save sends the token only when one was typed; disconnect and test have their own ops', async () => {
  const a = answer(200, { epoch: '5' });
  const m = { projectId: P, gitlabProject: 'shop/web', createFrom: ['incident' as const], labels: ['incident'] };
  await gitlabSettingsSave({ org: A, commandId: CMD, expectedEpoch: '4', reason: 'rotate', baseUrl: 'https://git.example.test', mappings: [m] }, signal);
  expect(a.sent[0]?.body).toEqual({ op: 'save', org: A, command_id: CMD, expected_epoch: '4', reason: 'rotate', connection: { base_url: 'https://git.example.test', mappings: [{ project_id: P, gitlab_project: 'shop/web', create_from: ['incident'], labels: ['incident'] }] } });
  await gitlabSettingsSave({ org: A, commandId: CMD, expectedEpoch: '4', reason: 'rotate', baseUrl: 'https://git.example.test', token: 'glpat-x', mappings: [] }, signal);
  expect((a.sent[1]?.body.connection as Record<string, unknown>).token).toBe('glpat-x');
  const d = answer(200, {});
  await gitlabSettingsDisconnect({ org: A, commandId: CMD, expectedEpoch: '5', reason: 'left' }, signal);
  expect(d.sent[0]?.body).toEqual({ op: 'disconnect', org: A, command_id: CMD, expected_epoch: '5', reason: 'left' });
  const t = answer(200, { ok: false, scopes: [], code: 'gitlab_unauthorized' });
  expect(await gitlabSettingsTest(A, signal)).toEqual({ kind: 'ok', data: { ok: false, scopes: [], code: 'gitlab_unauthorized' } });
  expect(t.sent[0]?.body).toEqual({ op: 'test', org: A });
  answer(200, read);
  expect((await gitlabSettingsRead(A, signal)).kind).toBe('ok');
 });
 test('the test answer needs an ok flag', () => {
  expect(parseTest({ ok: true, scopes: ['api'], expires_at: '2027-01-01' })).toEqual({ ok: true, scopes: ['api'], expiresAt: '2027-01-01' });
  expect(() => parseTest({ scopes: [] })).toThrow(ApiFault);
 });
});
