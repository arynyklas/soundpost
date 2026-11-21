// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, test } from 'bun:test';
import { ApiFault, OutcomeUnknown } from '../api/types';
import { adminCommand, adminRead, buildSourcePolicySetting, buildSso, buildTeam, changeSourcePolicy, describeAdminFailure, getSourceFence, nextSourcePolicy, parseAdminRead, splitIds, ssoDraft, validOrigin, type AdminSourceView } from './admin';

const A = 'a'.repeat(32), B = 'b'.repeat(32), P = '1'.repeat(32), U = '5'.repeat(32), S = '7'.repeat(32), T = '8'.repeat(32);
const orgView = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ id: A, name: 'org', projects: { [P]: 'api' }, members: { [U]: true }, admins: { [U]: true }, grants: { [`${U}:${P}`]: ['telemetry.read', 'policy.write'] }, teams: { [T]: { members: [U], projects: [P], permissions: ['issues.write'], enabled: true } }, ...over });

describe('an admin read is accepted only for the organization asked about', () => {
 test('organization view', () => {
  const v = parseAdminRead({ revision: '9', epoch: '4', organizations: [orgView()] }, A, 'organization');
  expect(v.org?.name).toBe('org');
  expect(v.epoch).toBe('4');
  expect(v.org?.grants[`${U}:${P}`]).toEqual(['telemetry.read', 'policy.write']);
  expect(v.org?.teams[T]?.enabled).toBe(true);
 });
 test('another organization, a missing view, a bad revision or a missing epoch is refused', () => {
  expect(() => parseAdminRead({ revision: '9', epoch: '4', organizations: [orgView()] }, B, 'organization')).toThrow(ApiFault);
  expect(() => parseAdminRead({ revision: '9', epoch: '4' }, A, 'organization')).toThrow(ApiFault);
  expect(() => parseAdminRead({ revision: 9, epoch: '4', organizations: [orgView()] }, A, 'organization')).toThrow(ApiFault);
  expect(() => parseAdminRead({ revision: '9', organizations: [orgView()] }, A, 'organization')).toThrow(ApiFault);
  expect(() => parseAdminRead({ revision: '9', epoch: 4, organizations: [orgView()] }, A, 'organization')).toThrow(ApiFault);
  expect(() => parseAdminRead({ revision: '9', epoch: '4', organizations: [orgView({ grants: { nope: [] } })] }, A, 'organization')).toThrow(ApiFault);
 });
 test('an organization with no members, grants or teams reads as empty', () => {
  const v = parseAdminRead({ revision: '1', epoch: '1', organizations: [{ id: A, name: 'n' }] }, A, 'organization');
  expect(v.org).toEqual({ id: A, name: 'n', projects: {}, members: {}, admins: {}, grants: {}, teams: {} });
 });
 test('settings are only the kind asked for, in key order', () => {
  const v = parseAdminRead({ revision: '1', epoch: '1', settings: { [`sso:${T}`]: { Issuer: 'https://i' }, [`sso:${S}`]: { Issuer: 'https://j' } } }, A, 'sso');
  expect(v.settings.map((s) => s.key)).toEqual([`sso:${S}`, `sso:${T}`]);
  expect(() => parseAdminRead({ revision: '1', epoch: '1', settings: { [`team:${T}`]: {} } }, A, 'sso')).toThrow(ApiFault);
 });
 test('an audit entry is the principal, action and reason', () => {
  const v = parseAdminRead({ revision: '1', epoch: '1', audits: [{ id: P, principal: U, action: 'grant', reason: 'why', time_ns: '1730000000000000000', targets: [A, P], outcome: 'allowed' }] }, A, 'audit');
  expect(v.audits[0]).toMatchObject({ principal: U, action: 'grant', reason: 'why', allowed: true });
 });
 test('a source keeps its policy as read, so a change is that object advanced by one revision', () => {
  const raw = { revision: '3', enabled: true, class: 'structured', kinds: ['metric'], templates: [{ id: 'signin', revision: '1', line: 'x' }], replay: false, max_bytes: '1048576', max_series: '1000', expires_ns: '0', labels: { job: ['api'] } };
  const v = parseAdminRead({ revision: '1', epoch: '1', sources: [{ id: S, project: P, browser: false, origins: [], expires_ns: '9', revoked: false, retired: false, closing: false, policy: raw }] }, A, 'source');
  const source = v.sources[0] as AdminSourceView;
  expect(source.policy.templates).toEqual([{ id: 'signin', revision: '1' }]);
  const next = nextSourcePolicy(source, { enabled: true, replay: true });
  expect(next).toEqual({ ...raw, revision: '4', replay: true });
 });
});

describe('forms build the exact wire configuration or say why not', () => {
 test('teams', () => {
  expect(buildTeam(`${U}, ${U} ${S}`, [P], ['policy.write', 'issues.write'], true)).toEqual({ ok: true, value: { members: [U, S], projects: [P], permissions: ['issues.write', 'policy.write'], enabled: true } });
  for (const bad of [buildTeam('nope', [P], ['policy.write'], true), buildTeam(U, [], ['policy.write'], true), buildTeam(U, [P], [], true)]) expect(bad.ok).toBe(false);
 });
 test('origins are https origins without a path', () => {
  expect(validOrigin('https://app.example.test')).toBe(true);
  expect(validOrigin('https://app.example.test:8443')).toBe(true);
  for (const bad of ['http://app.example.test', 'https://app.example.test/x', 'https://app.example.test?x=1', 'https://u:p@app.example.test', 'app.example.test', 'https://app.example.test/']) expect(validOrigin(bad)).toBe(false);
 });
 test('source access policy', () => {
  expect(buildSourcePolicySetting(P, 'https://b.example.test, https://a.example.test', false, '', true)).toEqual({ ok: true, value: { project_id: P, origins: ['https://a.example.test', 'https://b.example.test'], restricted: false, readers: [], enabled: true } });
  expect(buildSourcePolicySetting(P, '', true, '', true).ok).toBe(false);
  expect(buildSourcePolicySetting(P, 'ftp://x', false, '', true).ok).toBe(false);
  expect(buildSourcePolicySetting('x', '', false, '', true).ok).toBe(false);
  expect(buildSourcePolicySetting(P, '', true, U, true).ok).toBe(true);
 });
 test('single sign-on maps one identity subject to one account and never carries the secret', () => {
  const built = buildSso({ issuer: 'https://idp.example.test', clientId: 'soundpost', redirectUrl: 'https://sp.example.test/api/v1/oidc/callback', subjects: `alice = ${U}\n bob=${S}\n` });
  expect(built).toEqual({ ok: true, value: { Issuer: 'https://idp.example.test', ClientID: 'soundpost', RedirectURL: 'https://sp.example.test/api/v1/oidc/callback', Subjects: { alice: U, bob: S } } });
  expect(JSON.stringify(built)).not.toContain('Secret');
  const base = { issuer: 'https://idp.example.test', clientId: 'soundpost', redirectUrl: 'https://sp.example.test/cb', subjects: '' };
  for (const bad of [{ issuer: 'http://idp' }, { clientId: '' }, { redirectUrl: 'http://x' }, { subjects: 'alice' }, { subjects: `alice = nope` }, { subjects: `alice = ${U}\nalice = ${S}` }]) expect(buildSso({ ...base, ...bad }).ok).toBe(false);
 });
 test('a provider reads back as its draft', () => {
  expect(ssoDraft({ Issuer: 'https://i', ClientID: 'c', RedirectURL: 'https://r', Subjects: { alice: U } })).toEqual({ issuer: 'https://i', clientId: 'c', redirectUrl: 'https://r', subjects: `alice = ${U}` });
  expect(ssoDraft({})).toEqual({ issuer: '', clientId: '', redirectUrl: '', subjects: '' });
 });
 test('ID lists are de-duplicated', () => { expect(splitIds(`${U}, ${U}\n${S}`)).toEqual([U, S]); });
});

describe('a refused or unconfirmed admin command is described, never softened', () => {
 test('statuses', () => {
  expect(describeAdminFailure(new ApiFault(409, 'conflict', '', 'conflict')).kind).toBe('conflict');
  expect(describeAdminFailure(new ApiFault(409, 'stale', '', 'stale')).kind).toBe('stale');
  expect(describeAdminFailure(new ApiFault(403, 'forbidden', '', '')).text).toContain('last five minutes');
  expect(describeAdminFailure(new ApiFault(404, 'not_found', '', '')).kind).toBe('not_found');
  expect(describeAdminFailure(new ApiFault(400, 'invalid', '', 'invalid')).text).not.toContain('(invalid)');
  expect(describeAdminFailure(new ApiFault(500, 'unavailable', '', '')).kind).toBe('failed');
 });
 test('an unknown outcome is not "nothing changed"', () => {
  const f = describeAdminFailure(new OutcomeUnknown());
  expect(f.kind).toBe('unknown_outcome');
  expect(f.text).not.toContain('Nothing was changed');
 });
});

const original = globalThis.fetch;
afterEach(() => { globalThis.fetch = original; });
const answer = (body: unknown, status = 200): Response => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const signal = new AbortController().signal;

describe('the admin client', () => {
 test('a read posts the organization and kind', async () => {
  let body: unknown;
  globalThis.fetch = ((_: RequestInfo | URL, init?: RequestInit) => { body = JSON.parse(String(init?.body)); return Promise.resolve(answer({ revision: '1', epoch: '1', organizations: [orgView()] })); }) as typeof fetch;
  await adminRead(A, 'organization', signal);
  expect(body).toEqual({ org_id: A, kind: 'organization' });
 });
 test('a read of another organization is a fault with its status', async () => {
  globalThis.fetch = (() => Promise.resolve(answer({ code: 'not_found', detail: 'not_found' }, 404))) as typeof fetch;
  await expect(adminRead(A, 'organization', signal)).rejects.toMatchObject({ status: 404 });
 });
 test('a command carries its ID, the organization epoch it was read at, kind and payload and no control revision; a 202 names the operation', async () => {
  let body: unknown;
  globalThis.fetch = ((_: RequestInfo | URL, init?: RequestInit) => { body = JSON.parse(String(init?.body)); return Promise.resolve(answer({ revision: '12', affected_ids: [S], phase: 'fencing' }, 202)); }) as typeof fetch;
  const done = await adminCommand({ org: A, command_id: 'c'.repeat(32), expected_epoch: '11', kind: 'source_policy', payload: { id: S, reason: 'r' } }, signal);
  expect(done).toEqual({ revision: '12', phase: 'fencing', operation: S });
  expect(body).toEqual({ command_id: 'c'.repeat(32), expected_epoch: '11', org_id: A, kind: 'source_policy', payload: { id: S, reason: 'r' } });
 });
 test('a refusal and a transport failure', async () => {
  globalThis.fetch = (() => Promise.resolve(answer({ code: 'conflict' }, 409))) as typeof fetch;
  await expect(adminCommand({ org: A, command_id: 'c'.repeat(32), expected_epoch: '1', kind: 'grant', payload: {} }, signal)).rejects.toMatchObject({ status: 409 });
  globalThis.fetch = (() => Promise.reject(new TypeError('down'))) as typeof fetch;
  await expect(adminCommand({ org: A, command_id: 'c'.repeat(32), expected_epoch: '1', kind: 'grant', payload: {} }, signal)).rejects.toBeInstanceOf(OutcomeUnknown);
 });
 test('a source policy change is accepted only as the fence of that source and command', async () => {
  const fence = { operation: 'c'.repeat(32), source: S, org: A, epoch: '5', phase: 'fencing', barriers: [] };
  globalThis.fetch = (() => Promise.resolve(answer(fence, 202))) as typeof fetch;
  expect((await changeSourcePolicy({ command_id: 'c'.repeat(32), source: S, expected_revision: '1', policy: {}, reason: 'r' }, signal)).phase).toBe('fencing');
  await expect(changeSourcePolicy({ command_id: 'd'.repeat(32), source: S, expected_revision: '1', policy: {}, reason: 'r' }, signal)).rejects.toBeInstanceOf(ApiFault);
  await expect(changeSourcePolicy({ command_id: 'c'.repeat(32), source: T, expected_revision: '1', policy: {}, reason: 'r' }, signal)).rejects.toBeInstanceOf(ApiFault);
 });
 test('fence progress is read for the organization asked and nothing else', async () => {
  globalThis.fetch = (() => Promise.resolve(answer({ operation: 'c'.repeat(32), source: S, org: B, phase: 'fencing' }))) as typeof fetch;
  await expect(getSourceFence(A, 'c'.repeat(32), signal)).rejects.toBeInstanceOf(ApiFault);
  globalThis.fetch = (() => Promise.resolve(answer({ operation: 'c'.repeat(32), source: S, org: A, phase: 'complete' }))) as typeof fetch;
  expect((await getSourceFence(A, 'c'.repeat(32), signal)).phase).toBe('complete');
 });
});
