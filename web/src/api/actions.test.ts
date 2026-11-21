// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, test } from 'bun:test';
import { act, getIncident, getOperation, parseAction, parseIncident, parseQueue } from './client';
import { ApiFault, OutcomeUnknown, VersionConflict, type ActionRequest } from './types';

const A = 'a'.repeat(32), B = 'b'.repeat(32), P = '1'.repeat(32), Q = '2'.repeat(32), I = '3'.repeat(32), C = '4'.repeat(32), U = '5'.repeat(32);
const incident = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
 incident_id: I, org: A, project_id: P, version: '2', status: 'open', condition: { id: C, state: 'firing', freshness: 'fresh', observed_at: '1' }, episode_id: C, severity: 'major', impact_revision: '1', source_firing: true,
 notification: { reminders_paused: false, worse_impact_eligible: true, urgency: { state: 'empty', reason: 'no_notification_policy_state' }, delivery: { state: 'empty', reason: 'no_delivery_created', attention: 'none' }, digest: { state: 'empty', reason: 'no_notification_policy_state', sent: 0 }, unread_change: { state: 'empty', reason: 'no_notification_policy_state', changed: false, queue_revision: '0', seen_revision: '0' } }, links: [], observed_impacts: 1, last_activity: '1',
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

describe('a committed issue answer is accepted only for the issue that was acted on', () => {
 const issueReq = (over: Partial<ActionRequest> = {}): ActionRequest => ({ org: A, command_id: 'c'.repeat(32), expected_version: '3', project_id: P, target_id: I, entity_kind: 'issue', kind: 'ignore', payload: { reason: 'noise' }, ...over });
 const issue = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ id: I, workflow: 'ignored', revision: '4', grouping_version: 1, ...over });
 const answer = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ state: 'committed', entity_kind: 'issue', kind: 'ignore', target_id: I, revision: '4', issue: issue(), ...over });
 test('the committed issue at the committed revision', () => {
  const parsed = parseAction(answer(), issueReq());
  expect([parsed.issue?.workflow, parsed.issue?.revision, parsed.incident]).toEqual(['ignored', '4', undefined]);
  expect(parseAction(answer({ issue: issue({ workflow: 'resolved', resolution_time_ns: '9', fixed_descendants: [C] }) }), issueReq({ kind: 'ignore' })).issue?.resolution_time_ns).toBe('9');
 });
 test('another issue, a different revision, an unknown workflow or a bad time is refused', () => {
  for (const raw of [answer({ issue: issue({ id: C }) }), answer({ revision: '5' }), answer({ issue: issue({ workflow: 'archived' }) }), answer({ issue: issue({ resolution_time_ns: 'soon' }) }), answer({ issue: issue({ revision: 4 }) }), answer({ issue: undefined })]) expect(() => parseAction(raw, issueReq())).toThrow(ApiFault);
 });
 test('an issue answer never carries an incident, and an incident answer never carries an issue', () => {
  expect(() => parseAction(answer({ incident: incident() }), issueReq())).toThrow(ApiFault);
  expect(() => parseAction(committed({ issue: issue() }), req())).toThrow(ApiFault);
 });
 test('not_available for an issue carries no issue', () => {
  expect(parseAction({ state: 'not_available', reason: 'issue_control_handler_not_built', entity_kind: 'issue', kind: 'ignore', target_id: I }, issueReq()).state).toBe('not_available');
  expect(() => parseAction({ state: 'not_available', reason: 'x', entity_kind: 'issue', kind: 'ignore', target_id: I, issue: issue() }, issueReq())).toThrow(ApiFault);
 });
 test('a moved revision and a transition the workflow forbids are two conflicts with the current revision; an incident detail is not an issue conflict', async () => {
  respond(409, { code: 'conflict', detail: 'issue_version_conflict', current_version: '9', request_id: 'e'.repeat(32) });
  let error = await act(issueReq(), signal).catch((e: unknown) => e);
  expect([error instanceof VersionConflict, (error as VersionConflict).detail, (error as VersionConflict).currentVersion]).toEqual([true, 'issue_version_conflict', '9']);
  respond(409, { code: 'conflict', detail: 'issue_state_conflict', current_version: '3' });
  error = await act(issueReq(), signal).catch((e: unknown) => e);
  expect([error instanceof VersionConflict, (error as VersionConflict).detail]).toEqual([true, 'issue_state_conflict']);
  respond(409, { code: 'conflict', detail: 'incident_version_conflict', current_version: '9' });
  expect(await act(issueReq(), signal).catch((e: unknown) => e)).toBeInstanceOf(ApiFault);
  respond(409, { code: 'conflict', detail: 'issue_version_conflict', current_version: '9' });
  expect(await act(req(), signal).catch((e: unknown) => e)).toBeInstanceOf(ApiFault);
 });
 test('a committed issue answer is returned only after it is validated; a permission refusal keeps one status shape', async () => {
  respond(200, answer());
  expect((await act(issueReq(), signal)).issue?.revision).toBe('4');
  respond(200, answer({ issue: issue({ id: C }) }));
  expect(await act(issueReq(), signal).catch((e: unknown) => e)).toBeInstanceOf(ApiFault);
  respond(404, { code: 'not_found', detail: 'not_found' });
  expect(((await act(issueReq(), signal).catch((e: unknown) => e)) as ApiFault).status).toBe(404);
 });
});

describe('notification state is accepted only in a shape the product can show', () => {
 const ready = (entries: unknown[], attention = 'failed'): Record<string, unknown> => incident({ notification: { ...(incident().notification as object), delivery: { state: 'ready', attention, counts: { failed: 1 }, entries } } });
 const entry = { id: C, kind: 'open', route: 'immediate', phase: 'failed', status: 'failed', attempts: 1, eligible_at: '5' };
 test('a ready delivery with a known entry is accepted', () => { expect(parseIncident(ready([entry]), { org: A, project: P, id: I }).notification.delivery.entries?.[0]?.status).toBe('failed'); });
 test('an unknown delivery status, a bad entry id or a section without a state is refused', () => {
  for (const raw of [ready([{ ...entry, status: 'delivered' }]), ready([{ ...entry, id: 'x' }]), ready([entry], 'great'), incident({ notification: { reminders_paused: false, worse_impact_eligible: true } })]) expect(() => parseIncident(raw, { org: A, project: P, id: I })).toThrow(ApiFault);
 });
 test('a ready urgency needs a known tier', () => {
  const n = incident().notification as Record<string, unknown>;
  expect(() => parseIncident(incident({ notification: { ...n, urgency: { state: 'ready', tier: 'loud' } } }), { org: A, project: P, id: I })).toThrow(ApiFault);
 });
});
