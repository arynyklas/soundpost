// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The pure models behind the settings screens: the hub, the urgency policy steps, the cutover path and the event webhook screen.
import { afterEach, describe, expect, test } from 'bun:test';
import { setMemberName } from '../api/console';
import { EVENT_NAMES, listDeliveries, listEndpoints, parseDelivery, parseEndpointList, saveEndpoint, testEndpoint, type EndpointView } from '../api/events';
import { SECTIONS } from '../app/context';
import { ApiFault, OutcomeUnknown, type NotificationPolicyView } from '../api/types';
import { CUTOVER_PHASES, activeOwnersOf, parseCutoverView, phasePath, type CutoverPhase } from './cutover';
import { pageOf, SETTINGS_PAGES, SETTINGS_TILES } from './pages';
import { urgencySteps } from './policy';
import { buildEndpointSave, deliveryWords, emptyEndpointDraft, endpointDraftOf, endpointWords, rotationWords } from './webhooks';

const hx = (c: string): string => c.repeat(32);
const policy = (over: Partial<NotificationPolicyView> = {}): NotificationPolicyView => ({
 source: 'default', revision: '1', min_operations: 20, min_failures: 5, rate_basis_points: 500, regression_min: 3, critical_codes: [],
 first_reminder_ns: '900000000000', reminder_every_ns: '3600000000000', max_suppression_ns: '86400000000000', default_zone: '', ...over,
});

describe('the settings hub', () => {
 test('every tile opens a real section or a page, and no tile is listed twice', () => {
  const ids = new Set(SECTIONS.map((s) => s.id));
  for (const t of SETTINGS_TILES) {
   expect(ids.has(t.section)).toBe(true);
   if (t.section === 'settings') expect(pageOf(t.page ?? '')).toBeDefined(); else expect(t.page).toBeUndefined();
  }
  expect(new Set(SETTINGS_TILES.map((t) => t.title)).size).toBe(SETTINGS_TILES.length);
  expect(new Set(SETTINGS_PAGES.map((p) => p.id)).size).toBe(SETTINGS_PAGES.length);
 });
 test('what the first release does not have is not offered', () => {
  const titles = SETTINGS_TILES.map((t) => t.title.toLowerCase()).join(' ');
  expect(titles).not.toContain('your notifications');
  expect(titles).not.toContain('escalat');
  expect(pageOf('destinations')).toBeUndefined();
 });
 test('every page of the hub is reachable from the hub and by its page name', () => {
  for (const p of SETTINGS_PAGES) expect(SETTINGS_TILES.some((t) => t.section === 'settings' && t.page === p.id)).toBe(true);
 });
});

describe('urgency policy steps', () => {
 test('every figure is the committed one, in words', () => {
  const steps = urgencySteps(policy({ source: 'project', revision: '4', critical_codes: ['auth_down', 'payment_failed'], rate_basis_points: 750, regression_min: 1, default_zone: 'Europe/Berlin' }));
  expect(steps.map((s) => s.id)).toEqual(['urgent', 'reminders', 'suppression', 'digest']);
  expect(steps[0]?.text).toContain('critical codes auth_down, payment_failed');
  expect(steps[0]?.text).toContain('reaches 1 occurrence,');
  expect(steps[0]?.text).toContain('at least 20 operations and 5 failures at a failure rate of at least 7.5%');
  expect(steps[0]?.badge).toBe('own policy, revision 4');
  expect(steps[1]?.text).toBe('The first reminder comes after 15 minutes, then one every 1 hour.');
  expect(steps[2]?.badge).toBe('at most 1 day');
  expect(steps[3]?.text).toContain('Europe/Berlin');
 });
 test('an empty zone is UTC and no critical code is said so', () => {
  const steps = urgencySteps(policy());
  expect(steps[0]?.text).toContain('no critical operation code is set');
  expect(steps[0]?.badge).toBe('default policy');
  expect(steps[3]?.badge).toBe('UTC');
 });
 test('nothing the policy contract does not carry is stated', () => {
  const all = urgencySteps(policy()).map((s) => `${s.title} ${s.text}`).join(' ').toLowerCase();
  for (const word of ['escalat', 'route', 'second person', 'acknowledg']) expect(all).not.toContain(word);
 });
});

describe('the cutover path', () => {
 const state = (phase: string, steps: { from: string; to: string }[]) => {
  const v = parseCutoverView({
   org: hx('a'), project: hx('1'),
   cutover: { id: hx('2'), revision: String(steps.length), phase, epoch: '1', entered_at_ns: '1', old_owner: hx('b'), new_owner: hx('c'), active_owners: activeOwnersOf(phase as CutoverPhase, hx('b'), hx('c')), frontier: [], restore: {},
    timeline: steps.map((s, i) => ({ revision: String(i + 1), from: s.from, to: s.to, epoch: '1', at_ns: String(i + 1), command: hx('5'), principal: hx('6'), digest: 'e'.repeat(64) })) },
   accounting: { pending: 0, claimed: 0, lapsed: 0, unknown: 0, unknown_digest: '9'.repeat(64) },
   shadow: { observing: true, decisions: 0, by_kind: {}, recent: [] }, history: { legacy_history: 'read_only', importer: false, spans: [] },
  }, { org: hx('a'), project: hx('1') });
  if (!v.cutover) throw new Error('no cutover');
  return v.cutover;
 };
 test('lists every phase in its fixed order, marked from the committed steps only', () => {
  const path = phasePath(state('barrier_verified', [{ from: '', to: 'shadow' }, { from: 'shadow', to: 'quiescing_old' }, { from: 'quiescing_old', to: 'barrier_verified' }]));
  expect(path.map((p) => p.phase)).toEqual([...CUTOVER_PHASES]);
  expect(path.map((p) => p.state)).toEqual(['passed', 'passed', 'current', 'not_reached', 'not_reached', 'not_reached']);
 });
 test('a rollback marks the phases it passed through and the one it is in', () => {
  const path = phasePath(state('old_active', [{ from: '', to: 'shadow' }, { from: 'shadow', to: 'quiescing_old' }, { from: 'quiescing_old', to: 'barrier_verified' }, { from: 'barrier_verified', to: 'new_active' }, { from: 'new_active', to: 'rollback_quiescing' }, { from: 'rollback_quiescing', to: 'old_active' }]));
  expect(path.map((p) => p.state)).toEqual(['passed', 'passed', 'passed', 'passed', 'passed', 'current']);
 });
 test('a cutover that has only been created is in shadow and nothing else was reached', () => {
  expect(phasePath(state('shadow', [{ from: '', to: 'shadow' }])).map((p) => p.state)).toEqual(['current', 'not_reached', 'not_reached', 'not_reached', 'not_reached', 'not_reached']);
 });
});

const endpoint = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
 id: hx('e'), name: 'gitlab-bridge', host: 'bridge.example.test', events: ['issue.new', 'issue.regressed'], enabled: true, has_secret: true, version: '3', state: 'working', ...over,
});
const view = (over: Record<string, unknown> = {}): EndpointView => parseEndpointList({ endpoints: [endpoint(over)], events: [...EVENT_NAMES] }).endpoints[0] as EndpointView;

describe('event webhook answers', () => {
 test('an endpoint is read field by field; the secret and the address path are not part of it', () => {
  const list = parseEndpointList({ endpoints: [endpoint({ secret: 'LEAK', url: 'https://bridge.example.test/path/TOKEN', secret_rotated_at: '1700000000000000000', previous_secret_until: '1700086400000000000', last_delivery: { event: 'issue.new', phase: 'accepted', attempts: 1, uncertain: false } })], events: [...EVENT_NAMES] });
  const e = list.endpoints[0] as EndpointView;
  expect(JSON.stringify(e)).not.toContain('LEAK');
  expect(JSON.stringify(e)).not.toContain('TOKEN');
  expect(e.hasSecret).toBe(true);
  expect(e.secretRotatedAt).toBe('1700000000000000000');
  expect(e.lastDelivery?.phase).toBe('accepted');
 });
 test('an answer that is not an endpoint list, or an endpoint with an unknown state, is refused', () => {
  expect(() => parseEndpointList({ endpoints: 'x' })).toThrow(ApiFault);
  expect(() => parseEndpointList({ endpoints: [endpoint({ state: 'great' })] })).toThrow(ApiFault);
  expect(() => parseEndpointList({ endpoints: [endpoint({ version: 3 })] })).toThrow(ApiFault);
 });
 test('a delivery keeps attempts, uncertainty and the closed code; an unknown count is null, never 0', () => {
  expect(parseDelivery({ event: 'issue.new', phase: 'failed', attempts: 12, uncertain: true, code: 'http_503', entity_id: hx('1') })).toEqual({ event: 'issue.new', entity: hx('1'), phase: 'failed', attempts: 12, uncertain: true, code: 'http_503' });
  expect(parseDelivery({ event: 'issue.new', phase: 'pending' }).attempts).toBeNull();
  expect(parseDelivery({ id: hx('2'), event: 'issue.reopened', entity_kind: 'issue', entity_id: hx('1'), project: hx('3'), phase: 'queued', status: 'pending', attempts: 2, possible_duplicate: true, last_outcome: 'retry', last_code: 'http_503', last_at: '1700000000000000000', eligible_at: '1' })).toEqual({ id: hx('2'), event: 'issue.reopened', entity: hx('1'), phase: 'queued', attempts: 2, uncertain: false, possibleDuplicate: true, lastCode: 'http_503', at: '1700000000000000000' });
 });
 test('the state `pending` (deliveries exist, none attempted yet) is an endpoint state of its own, and issue.reopened is one of the eight subscribable events', () => {
  expect(view({ state: 'pending' }).state).toBe('pending');
  expect(EVENT_NAMES).toHaveLength(8);
  expect(EVENT_NAMES).toContain('issue.reopened');
  expect(EVENT_NAMES).not.toContain('test.ping');
  expect(parseEndpointList({ endpoints: [endpoint({ events: ['issue.reopened'] })], events: [...EVENT_NAMES] }).endpoints[0]?.events).toEqual(['issue.reopened']);
 });
});

describe('event webhook calls', () => {
 const original = globalThis.fetch;
 afterEach(() => { globalThis.fetch = original; });
 const reply = (body: unknown, status = 200, type = 'application/json'): Response => new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers: { 'Content-Type': type } });
 const sig = new AbortController().signal;
 test('a route the installation does not serve is not_built, never an empty list', async () => {
  globalThis.fetch = (() => Promise.resolve(reply('404 page not found', 404, 'text/plain'))) as typeof fetch;
  expect(await listEndpoints(hx('a'), sig)).toEqual({ kind: 'not_built' });
  expect(await listDeliveries(hx('a'), hx('e'), sig)).toEqual({ kind: 'not_built' });
 });
 test('list and deliveries post their closed bodies', async () => {
  const seen: { url: string; body: unknown }[] = [];
  globalThis.fetch = ((url: RequestInfo | URL, init?: RequestInit) => { seen.push({ url: String(url), body: JSON.parse(String(init?.body)) }); return Promise.resolve(reply(seen.length === 1 ? { endpoints: [], events: [] } : { deliveries: [{ event: 'test.ping', phase: 'accepted', attempts: 1, uncertain: false }] })); }) as typeof fetch;
  const l = await listEndpoints(hx('a'), sig);
  expect(l.kind === 'ok' && l.data.endpoints.length).toBe(0);
  const d = await listDeliveries(hx('a'), hx('e'), sig);
  expect(d.kind === 'ok' && d.data[0]?.event).toBe('test.ping');
  expect(seen[0]).toEqual({ url: '/api/v1/events/webhooks', body: { op: 'list', org: hx('a') } });
  expect(seen[1]?.body).toEqual({ op: 'deliveries', org: hx('a'), endpoint: hx('e'), limit: 20 });
 });
 const req = { org: hx('a'), commandId: hx('c'), expectedVersion: '3', reason: 'rotate', endpoint: { id: hx('e'), name: 'x', events: ['issue.new'], enabled: true, secret: 'S'.repeat(20) } };
 test('a save is committed only when the server says so; a refusal keeps its status and a lost answer is an unknown outcome', async () => {
  globalThis.fetch = (() => Promise.resolve(reply({ state: 'committed', endpoint: endpoint({ version: '4' }) }))) as typeof fetch;
  expect((await saveEndpoint(req, sig))?.version).toBe('4');
  globalThis.fetch = (() => Promise.resolve(reply({ code: 'conflict' }, 409))) as typeof fetch;
  await expect(saveEndpoint(req, sig)).rejects.toMatchObject({ status: 409 });
  globalThis.fetch = (() => Promise.reject(new TypeError('network'))) as typeof fetch;
  await expect(saveEndpoint(req, sig)).rejects.toBeInstanceOf(OutcomeUnknown);
  globalThis.fetch = (() => Promise.resolve(reply({ nothing: true }))) as typeof fetch;
  await expect(saveEndpoint(req, sig)).rejects.toMatchObject({ code: 'invalid_response' });
  globalThis.fetch = (() => Promise.resolve(reply({ state: 'committed', endpoint: endpoint({ id: hx('f') }) }))) as typeof fetch;
  await expect(saveEndpoint(req, sig)).rejects.toMatchObject({ code: 'invalid_response' });
 });
 test('the test event is one audited-free POST of its own and says nothing about the receiver', async () => {
  let body: unknown;
  globalThis.fetch = ((_url: RequestInfo | URL, init?: RequestInit) => { body = JSON.parse(String(init?.body)); return Promise.resolve(reply({ state: 'requested', endpoint: hx('e'), project: hx('9') })); }) as typeof fetch;
  await testEndpoint({ org: hx('a'), endpoint: hx('e'), commandId: hx('c') }, sig);
  expect(body).toEqual({ op: 'test', org: hx('a'), endpoint: hx('e'), command_id: hx('c') });
  globalThis.fetch = (() => Promise.resolve(reply({ state: 'requested', endpoint: hx('f'), project: hx('9') }))) as typeof fetch;
  await expect(testEndpoint({ org: hx('a'), endpoint: hx('e'), commandId: hx('c') }, sig)).rejects.toMatchObject({ code: 'invalid_response' });
  globalThis.fetch = (() => Promise.resolve(reply({ state: 'queued' }))) as typeof fetch;
  await expect(testEndpoint({ org: hx('a'), endpoint: hx('e'), commandId: hx('c') }, sig)).rejects.toMatchObject({ code: 'invalid_response' });
 });
});

describe('the endpoint form', () => {
 test('a new endpoint needs a name, an https address, an event and a secret of 16 to 256 bytes', () => {
  const d = { ...emptyEndpointDraft(), name: 'bridge', url: 'https://bridge.example.test/hook', events: ['issue.new'], secret: 'S'.repeat(16) };
  expect(buildEndpointSave(hx('1'), d, undefined)).toEqual({ ok: true, value: { id: hx('1'), name: 'bridge', url: 'https://bridge.example.test/hook', events: ['issue.new'], enabled: true, secret: 'S'.repeat(16) } });
  expect(buildEndpointSave(hx('1'), { ...d, name: ' ' }, undefined).ok).toBe(false);
  expect(buildEndpointSave(hx('1'), { ...d, url: 'http://bridge.example.test' }, undefined).ok).toBe(false);
  expect(buildEndpointSave(hx('1'), { ...d, url: 'https://u:p@bridge.example.test/' }, undefined).ok).toBe(false);
  expect(buildEndpointSave(hx('1'), { ...d, url: 'https://bridge.example.test/?token=1' }, undefined).ok).toBe(false);
  expect(buildEndpointSave(hx('1'), { ...d, url: '' }, undefined).ok).toBe(false);
  expect(buildEndpointSave(hx('1'), { ...d, events: [] }, undefined).ok).toBe(false);
  expect(buildEndpointSave(hx('1'), { ...d, secret: '' }, undefined).ok).toBe(false);
  expect(buildEndpointSave(hx('1'), { ...d, secret: 'short' }, undefined).ok).toBe(false);
  expect(buildEndpointSave(hx('1'), { ...d, secret: 'S'.repeat(257) }, undefined).ok).toBe(false);
 });
 test('events are sent in the fixed order and only the known ones', () => {
  const d = { ...emptyEndpointDraft(), name: 'b', url: 'https://b.example.test/', events: ['release.registered', 'nonsense', 'incident.opened'], secret: 'S'.repeat(16) };
  const built = buildEndpointSave(hx('1'), d, undefined);
  expect(built.ok && built.value.events).toEqual(['incident.opened', 'release.registered']);
  const reopened = buildEndpointSave(hx('1'), { ...d, events: ['release.registered', 'issue.reopened', 'issue.resolved'] }, undefined);
  expect(reopened.ok && reopened.value.events).toEqual(['issue.resolved', 'issue.reopened', 'release.registered']);
 });
 test('a change keeps the stored address and secret; nothing changed is refused; a new secret rotates', () => {
  const e = view();
  const draft = endpointDraftOf(e);
  expect(buildEndpointSave(e.id, draft, e).ok).toBe(false);
  const paused = buildEndpointSave(e.id, { ...draft, enabled: false }, e);
  expect(paused).toEqual({ ok: true, value: { id: e.id, name: 'gitlab-bridge', events: ['issue.new', 'issue.regressed'], enabled: false } });
  const rotated = buildEndpointSave(e.id, { ...draft, secret: 'N'.repeat(32) }, e);
  expect(rotated.ok && rotated.value.secret).toBe('N'.repeat(32));
  expect(rotated.ok && 'url' in rotated.value).toBe(false);
  expect(buildEndpointSave(e.id, { ...draft, events: [...draft.events].reverse() }, e).ok).toBe(false);
  expect(buildEndpointSave(e.id, draft, view({ has_secret: false })).ok).toBe(false);
 });
});

describe('endpoint and delivery words', () => {
 test('a paused endpoint is paused whatever its last delivery did, and no delivery means no state to report', () => {
  expect(endpointWords({ enabled: false, state: 'failing' }).label).toBe('Paused');
  expect(endpointWords({ enabled: true, state: 'no_deliveries' })).toMatchObject({ label: 'No deliveries yet', tone: 'line' });
  expect(endpointWords({ enabled: true, state: 'pending' })).toMatchObject({ label: 'Pending', tone: 'line' });
  expect(endpointWords({ enabled: true, state: 'pending' }).text).toContain('none was attempted yet');
  expect(endpointWords({ enabled: true, state: 'failing' }).tone).toBe('crit');
  expect(endpointWords({ enabled: true, state: 'working' }).tone).toBe('ok');
 });
 test('an uncertain delivery is never accepted, and an unknown phase is shown as it came', () => {
  expect(deliveryWords({ phase: 'accepted', uncertain: true })).toMatchObject({ label: 'Uncertain', tone: 'unk' });
  expect(deliveryWords({ phase: 'accepted', uncertain: true }).text).toContain('Deduplicate by delivery ID');
  expect(deliveryWords({ phase: 'accepted', uncertain: false }).label).toBe('Accepted');
  expect(deliveryWords({ phase: 'half_done', uncertain: false }).label).toBe('half done');
 });
 test('the 24 hour overlap of a rotated secret is stated with its end', () => {
  const f = (ns: string): string => `T${ns}`;
  expect(rotationWords({ secretRotatedAt: '1', previousSecretUntil: '2' }, f)).toContain('Until T2 every request carries two signatures');
  expect(rotationWords({ secretRotatedAt: '1' }, f)).toContain('previous secret is no longer used');
  expect(rotationWords({}, f)).toBe('The secret was never rotated.');
 });
});

describe('the display name answer', () => {
 const original = globalThis.fetch;
 afterEach(() => { globalThis.fetch = original; });
 const reply = (body: unknown, status = 200): Response => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
 const sig = new AbortController().signal;
 const ask = { org: hx('a'), commandId: hx('c'), user: hx('1'), displayName: 'Rita Reader' };
 test('`set` and `cleared` for the named user are the only answers that count; the text is never echoed', async () => {
  globalThis.fetch = (() => Promise.resolve(reply({ user: hx('1'), state: 'set' }))) as typeof fetch;
  expect(await setMemberName(ask, sig)).toEqual({ kind: 'ok', data: { user: hx('1'), state: 'set' } });
  globalThis.fetch = (() => Promise.resolve(reply({ user: hx('1'), state: 'cleared' }))) as typeof fetch;
  expect(await setMemberName({ ...ask, displayName: '' }, sig)).toEqual({ kind: 'ok', data: { user: hx('1'), state: 'cleared' } });
  for (const body of [{ user: hx('2'), state: 'set' }, { user: hx('1'), state: 'queued' }, { user: hx('1') }, {}]) {
   globalThis.fetch = (() => Promise.resolve(reply(body))) as typeof fetch;
   const r = await setMemberName(ask, sig);
   expect(r.kind === 'fault' && r.fault.code, JSON.stringify(body)).toBe('invalid_response');
  }
 });
 test('the request is one closed body, and a refusal keeps its status', async () => {
  let sent: unknown;
  globalThis.fetch = ((_u: RequestInfo | URL, init?: RequestInit) => { sent = JSON.parse(String(init?.body)); return Promise.resolve(reply({ code: 'invalid', detail: 'display_name_invalid' }, 400)); }) as typeof fetch;
  const r = await setMemberName(ask, sig);
  expect(sent).toEqual({ org: hx('a'), command_id: hx('c'), user: hx('1'), display_name: 'Rita Reader' });
  expect(r.kind === 'fault' && [r.fault.status, r.fault.detail]).toEqual([400, 'display_name_invalid']);
 });
});
