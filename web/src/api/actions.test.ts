// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, test } from 'bun:test';
import { act, getIncident, getOperation, parseAction, parseIncident, parseQueue } from './client';
import { ApiFault, OutcomeUnknown, VersionConflict, type ActionRequest } from './types';

const A = 'a'.repeat(32), B = 'b'.repeat(32), P = '1'.repeat(32), Q = '2'.repeat(32), I = '3'.repeat(32), C = '4'.repeat(32), U = '5'.repeat(32);
const incident = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
 incident_id: I, org: A, project_id: P, version: '2', status: 'open', condition: { id: C, state: 'firing', freshness: 'fresh', observed_at: '1' }, episode_id: C, severity: 'major', impact_revision: '1', source_firing: true,
 notification: { reminders_paused: false, worse_impact_eligible: true, delivery: { name: 'delivery', state: 'not_available' } }, links: [], observed_impacts: 1, last_activity: '1',
 timeline: [{ version: '1', at: '1', type: 'open', origin: 'system', actor: U }, { version: '2', at: '2', type: 'ack', origin: 'human', actor: U }], ...over,
});
const req = (over: Partial<ActionRequest> = {}): ActionRequest => ({ org: A, command_id: 'c'.repeat(32), expected_version: '1', project_id: P, target_id: I, entity_kind: 'incident', kind: 'ack', payload: {}, ...over });
const committed = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ state: 'committed', entity_kind: 'incident', kind: 'ack', target_id: I, revision: '2', incident: incident(), ...over });

describe('an incident is accepted only for the scope it was requested for', () => {
 test('matching', () => { expect(parseIncident(incident(), { org: A, project: P, id: I }).version).toBe('2'); });
 test('another organization, project or ID is refused', () => {
  for (const want of [{ org: B, project: P, id: I }, { org: A, project: Q, id: I }, { org: A, project: P, id: C }]) expect(() => parseIncident(incident(), want)).toThrow(ApiFault);
 });
 test('a source flag that contradicts the condition is refused', () => { expect(() => parseIncident(incident({ source_firing: false }), { org: A, project: P, id: I })).toThrow(ApiFault); });
 test('a timeline that does not match the revision is refused', () => { expect(() => parseIncident(incident({ version: '3' }), { org: A, project: P, id: I })).toThrow(ApiFault); });
 test('a version that is not a decimal string is refused', () => { expect(() => parseIncident(incident({ version: 2 }), { org: A, project: P, id: I })).toThrow(ApiFault); });
});

describe('an action response is accepted only for the action that was sent', () => {
 test('committed at the committed revision', () => { expect(parseAction(committed(), req()).incident?.version).toBe('2'); });
 test('another target, kind or entity is refused', () => {
  for (const raw of [committed({ target_id: C }), committed({ kind: 'resolve' }), committed({ entity_kind: 'issue' })]) expect(() => parseAction(raw, req())).toThrow(ApiFault);
 });
 test('a committed answer needs its incident at the same revision', () => {
  expect(() => parseAction(committed({ revision: '3' }), req())).toThrow(ApiFault);
  expect(() => parseAction(committed({ incident: undefined }), req())).toThrow(ApiFault);
  expect(() => parseAction(committed({ incident: incident({ org: B }) }), req())).toThrow(ApiFault);
 });
 test('not_available carries no incident and no revision', () => {
  expect(parseAction({ state: 'not_available', reason: 'issue_control_handler_not_built', entity_kind: 'incident', kind: 'ack', target_id: I }, req()).state).toBe('not_available');
  expect(() => parseAction({ state: 'not_available', reason: 'x', entity_kind: 'incident', kind: 'ack', target_id: I, revision: '2' }, req())).toThrow(ApiFault);
  expect(() => parseAction({ state: 'healthy', entity_kind: 'incident', kind: 'ack', target_id: I }, req())).toThrow(ApiFault);
 });
});

describe('queue', () => {
 const queue = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ org: A, projects: [P], state: 'incomplete', entries: [incident()], truncated: false, sections: [{ name: 'delivery', state: 'not_available' }], ...over });
 test('matching', () => { expect(parseQueue(queue(), A, [P]).entries).toHaveLength(1); });
 test('another organization, other projects or an entry from another project are refused', () => {
  expect(() => parseQueue(queue({ org: B }), A, [P])).toThrow(ApiFault);
  expect(() => parseQueue(queue({ projects: [Q] }), A, [P])).toThrow(ApiFault);
  expect(() => parseQueue(queue({ entries: [incident({ project_id: Q })] }), A, [P])).toThrow(ApiFault);
 });
});

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });
const respond = (status: number, body: unknown): void => {
 globalThis.fetch = (async () => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', 'X-Request-ID': 'd'.repeat(32) } })) as unknown as typeof fetch;
};
const signal = new AbortController().signal;

describe('act() maps the server answer without hiding or inventing a result', () => {
 test('a version conflict carries the current revision and is not an ordinary fault', async () => {
  respond(409, { code: 'conflict', detail: 'incident_version_conflict', current_version: '8', request_id: 'e'.repeat(32) });
  const error = await act(req(), signal).catch((e: unknown) => e);
  expect(error).toBeInstanceOf(VersionConflict);
  expect((error as VersionConflict).currentVersion).toBe('8');
 });
 test('another conflict (resolved, reused command ID) is a typed fault with its detail, not a version conflict', async () => {
  respond(409, { code: 'conflict', detail: 'incident_resolved', retryable: false });
  const error = await act(req(), signal).catch((e: unknown) => e);
  expect(error).toBeInstanceOf(ApiFault);
  expect((error as ApiFault).detail).toBe('incident_resolved');
 });
 test('a conflict with a non-decimal revision is not trusted', async () => {
  respond(409, { code: 'conflict', detail: 'incident_version_conflict', current_version: '<b>8</b>' });
  expect(await act(req(), signal).catch((e: unknown) => e)).toBeInstanceOf(ApiFault);
 });
 test('501 not_available is returned as the explicit answer', async () => {
  respond(501, { state: 'not_available', reason: 'issue_control_handler_not_built', entity_kind: 'incident', kind: 'ack', target_id: I });
  expect((await act(req(), signal)).state).toBe('not_available');
 });
 test('a transport failure is an unknown outcome, never a plain failure', async () => {
  globalThis.fetch = (async () => { throw new TypeError('network down'); }) as unknown as typeof fetch;
  expect(await act(req(), signal).catch((e: unknown) => e)).toBeInstanceOf(OutcomeUnknown);
 });
 test('denied and missing keep one status shape', async () => {
  respond(404, { code: 'not_found', detail: 'not_found' });
  const error = (await act(req(), signal).catch((e: unknown) => e)) as ApiFault;
  expect([error.status, error.code]).toEqual([404, 'not_found']);
 });
 test('a committed answer is returned only after it is validated', async () => {
  respond(200, committed());
  expect((await act(req(), signal)).revision).toBe('2');
  respond(200, committed({ target_id: C }));
  expect(await act(req(), signal).catch((e: unknown) => e)).toBeInstanceOf(ApiFault);
 });
 test('reads validate their scope too', async () => {
  respond(200, incident());
  expect((await getIncident(A, P, I, signal)).incident_id).toBe(I);
  expect(await getIncident(B, P, I, signal).catch((e: unknown) => e)).toBeInstanceOf(ApiFault);
  respond(200, { id: B, state: 'ready', phase: 'fencing', physical_deadline: '1', backup_deadline: '2', applied_barriers: 1, pending_groups: 63, generation: '1', holds: 0 });
  expect(await getOperation(A, I, signal).catch((e: unknown) => e)).toBeInstanceOf(ApiFault);
 });
});
