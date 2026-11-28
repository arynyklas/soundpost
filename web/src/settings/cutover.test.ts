// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, test } from 'bun:test';
import { ApiFault } from '../api/types';
import { activeOwnersOf, getCutover, kindCounts, orderedSpans, ownerStatement, parseCutoverView, restoreWarning, CUTOVER_PHASES, type CutoverPhase, type CutoverState } from './cutover';

const hx = (c: string): string => c.repeat(32);
const ORG = hx('a'), PRJ = hx('1'), OLD = hx('b'), NEW = hx('c'), GEN = hx('d');
const H = (c: string): string => c.repeat(64);
const want = { org: ORG, project: PRJ };
const state = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
 id: hx('2'), revision: '4', phase: 'shadow', epoch: '1', entered_at_ns: '1700000000000000000', old_owner: OLD, new_owner: NEW, active_owners: [OLD],
 frontier: [{ source: hx('3'), version: '2', cursor: { group: hx('4'), index: '17' } }], restore: {},
 timeline: [{ revision: '1', from: 'shadow', to: 'quiescing_old', epoch: '1', at_ns: '1700000000000000001', command: hx('5'), principal: hx('6'), digest: H('e'), evidence_digest: H('f') }], ...over,
});
const view = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
 org: ORG, project: PRJ, cutover: state(),
 accounting: { pending: 1, claimed: 2, lapsed: 3, unknown: 4, unknown_digest: H('9') },
 shadow: { observing: true, decisions: 3, by_kind: { reminder: 1, incident: 2 }, recent: [{ id: hx('7'), subject: 'issue 42', kind: 'incident', recipient: hx('8'), decided_ns: '1700000000000000002', digest: H('a') }] },
 history: { legacy_owner: OLD, legacy_history: 'read_only', importer: false, spans: [{ owner: OLD, side: 'legacy', phase: 'shadow', from_ns: '1700000000000000000' }] }, ...over,
});
const bad = (raw: unknown): void => { expect(() => parseCutoverView(raw, want)).toThrow(ApiFault); };

describe('the decoder', () => {
 test('the creating step of a cutover has no previous phase: the server sends an empty `from`, and the decoder keeps it as the creation step', () => {
  const first = { revision: '1', from: '', to: 'shadow', epoch: '0', at_ns: '1700000000000000000', command: hx('5'), principal: hx('6'), digest: H('e') };
  const v = parseCutoverView(view({ cutover: state({ phase: 'shadow', timeline: [first] }) }), want);
  expect(v.cutover?.timeline[0]?.from).toBe('');
  expect(v.cutover?.timeline[0]?.to).toBe('shadow');
  bad(view({ cutover: state({ timeline: [{ ...first, from: 'nowhere' }] }) }));
 });
 test('accepts the real shape and keeps decimal strings', () => {
  const v = parseCutoverView(view(), want);
  expect(v.cutover?.phase).toBe('shadow');
  expect(v.cutover?.entered_at_ns).toBe('1700000000000000000');
  expect(v.cutover?.frontier[0]?.cursor.index).toBe('17');
  expect(v.accounting.unknown).toBe(4);
  expect(v.shadow.by_kind).toEqual({ incident: 2, reminder: 1 });
  expect(v.history.spans[0]?.to_ns).toBeUndefined();
 });
 test('cutover null means no cutover', () => {
  const v = parseCutoverView(view({ cutover: null, history: { legacy_history: 'read_only', importer: false, spans: [] } }), want);
  expect(v.cutover).toBeNull();
 });
 test('numbers that are safe integers are accepted as decimals, others are not', () => {
  expect(parseCutoverView(view({ cutover: state({ epoch: 3 }) }), want).cutover?.epoch).toBe('3');
  bad(view({ cutover: state({ epoch: 1.5 }) }));
  bad(view({ cutover: state({ epoch: -1 }) }));
  bad(view({ cutover: state({ epoch: '01' }) }));
  bad(view({ cutover: state({ epoch: '18446744073709551616' }) }));
 });
 test('another organization or project is refused', () => {
  bad(view({ org: hx('9') }));
  bad(view({ project: hx('9') }));
 });
 test('unknown fields anywhere are refused', () => {
  bad(view({ extra: 1 }));
  bad(view({ cutover: state({ reason: 'x' }) }));
  bad(view({ accounting: { pending: 1, claimed: 2, lapsed: 3, unknown: 4, unknown_digest: H('9'), more: 1 } }));
 });
 test('IDs must be 32 lowercase hex, hashes 64', () => {
  bad(view({ cutover: state({ old_owner: 'A'.repeat(32), active_owners: ['A'.repeat(32)] }) }));
  bad(view({ cutover: state({ id: 'short' }) }));
  bad(view({ accounting: { pending: 1, claimed: 2, lapsed: 3, unknown: 4, unknown_digest: 'abc' } }));
 });
 test('unknown phases, sides and a wrong legacy_history or importer are refused', () => {
  bad(view({ cutover: state({ phase: 'done' }) }));
  bad(view({ history: { legacy_owner: OLD, legacy_history: 'read_only', importer: false, spans: [{ side: 'other', phase: 'shadow', from_ns: '1' }] } }));
  bad(view({ history: { legacy_history: 'writable', importer: false, spans: [] } }));
  bad(view({ history: { legacy_history: 'read_only', importer: true, spans: [] } }));
 });
 test('active owners must be what the phase says', () => {
  bad(view({ cutover: state({ active_owners: [NEW] }) }));
  bad(view({ cutover: state({ phase: 'barrier_verified', active_owners: [OLD] }) }));
  expect(parseCutoverView(view({ cutover: state({ phase: 'barrier_verified', active_owners: [] }) }), want).cutover?.active_owners).toEqual([]);
  expect(parseCutoverView(view({ cutover: state({ phase: 'new_active', active_owners: [NEW] }) }), want).cutover?.active_owners).toEqual([NEW]);
  bad(view({ cutover: state({ phase: 'new_active', active_owners: [OLD] }) }));
  for (const p of ['shadow', 'quiescing_old', 'old_active']) expect(parseCutoverView(view({ cutover: state({ phase: p, active_owners: [OLD] }) }), want).cutover?.active_owners).toEqual([OLD]);
 });
 test('counts must be unsigned 32-bit integers and observing a boolean', () => {
  bad(view({ accounting: { pending: -1, claimed: 2, lapsed: 3, unknown: 4, unknown_digest: H('9') } }));
  bad(view({ shadow: { observing: 'yes', decisions: 0, by_kind: {}, recent: [] } }));
  bad(view({ shadow: { observing: true, decisions: 0, by_kind: { reminder: 1.5 }, recent: [] } }));
 });
 test('control and non-ASCII characters in text fields are refused', () => {
  bad(view({ shadow: { observing: true, decisions: 1, by_kind: {}, recent: [{ id: hx('7'), subject: 'a\u0000b', kind: 'k', decided_ns: '1', digest: H('a') }] } }));
  bad(view({ shadow: { observing: true, decisions: 1, by_kind: { 'x\ny': 1 }, recent: [] } }));
  bad(view({ shadow: { observing: true, decisions: 1, by_kind: {}, recent: [{ id: hx('7'), subject: 'é', kind: 'k', decided_ns: '1', digest: H('a') }] } }));
 });
 test('non-objects and missing sections are refused', () => {
  for (const raw of [null, [], 'x', 3]) bad(raw);
  const { history: _h, ...rest } = view();
  bad(rest);
 });
});

describe('the request', () => {
 const original = globalThis.fetch;
 afterEach(() => { globalThis.fetch = original; });
 const answer = (body: unknown, status = 200): Response => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
 test('posts the closed body and decodes the answer', async () => {
  let seen: { url: string; body: unknown } | null = null;
  globalThis.fetch = ((url: RequestInfo | URL, init?: RequestInit) => { seen = { url: String(url), body: JSON.parse(String(init?.body)) }; return Promise.resolve(answer(view())); }) as typeof fetch;
  const v = await getCutover(ORG, PRJ, new AbortController().signal);
  expect(seen).toEqual({ url: '/api/v1/cutover', body: { org: ORG, project_id: PRJ } });
  expect(v.project).toBe(PRJ);
 });
 test('a 404 is a fault with status 404 and a mismatched answer is invalid_response', async () => {
  globalThis.fetch = (() => Promise.resolve(answer({ code: 'not_found' }, 404))) as typeof fetch;
  await expect(getCutover(ORG, PRJ, new AbortController().signal)).rejects.toMatchObject({ status: 404 });
  globalThis.fetch = (() => Promise.resolve(answer(view({ project: hx('9') })))) as typeof fetch;
  await expect(getCutover(ORG, PRJ, new AbortController().signal)).rejects.toMatchObject({ code: 'invalid_response' });
 });
});

const at = (phase: CutoverPhase, restore: CutoverState['restore'] = {}): CutoverState => {
 const v = parseCutoverView(view({ cutover: state({ phase, active_owners: activeOwnersOf(phase, OLD, NEW), restore }) }), want).cutover;
 if (!v) throw new Error('no cutover');
 return v;
};

describe('who owns notifications now', () => {
 test('no cutover: the product is the only owner', () => {
  const s = ownerStatement(null);
  expect(s.owner).toBeNull();
  expect(s.headline).toContain('only owner');
 });
 test('owner per phase', () => {
  const expected: Record<CutoverPhase, string | null> = { shadow: OLD, quiescing_old: OLD, barrier_verified: null, new_active: NEW, rollback_quiescing: null, old_active: OLD };
  for (const p of CUTOVER_PHASES) expect(ownerStatement(at(p)).owner).toBe(expected[p]);
 });
 test('handover phases say that no owner is active', () => {
  for (const p of ['barrier_verified', 'rollback_quiescing'] as const) expect(ownerStatement(at(p)).headline).toContain('No owner is active');
 });
 test('only phases where the product is not the owner say its decisions are never sent', () => {
  expect(ownerStatement(at('shadow')).detail).toContain('never sent');
  expect(ownerStatement(at('old_active')).detail).toContain('never sent');
  expect(ownerStatement(at('new_active')).detail).not.toContain('never sent');
 });
});

describe('restore warning', () => {
 test('present only while a restore is pending, and names the generation', () => {
  expect(restoreWarning(null)).toBeNull();
  expect(restoreWarning(at('shadow'))).toBeNull();
  expect(restoreWarning(at('shadow', { acknowledged: GEN }))).toBeNull();
  expect(restoreWarning(at('new_active', { pending: GEN }))).toContain(GEN);
 });
});

describe('ordering and counts', () => {
 test('spans are ordered by exact start instant, ties keep the server order', () => {
  const s = (from: string, side: 'legacy' | 'product' | 'handover') => ({ side, phase: 'shadow' as const, from_ns: from });
  const out = orderedSpans([s('1700000000000000010', 'product'), s('9', 'legacy'), s('1700000000000000010', 'handover'), s('1700000000000000009', 'handover')]);
  expect(out.map((x) => x.side)).toEqual(['legacy', 'handover', 'product', 'handover']);
 });
 test('kinds are listed largest first, ties by name', () => {
  expect(kindCounts({ b: 1, a: 1, c: 5 })).toEqual([{ kind: 'c', count: 5 }, { kind: 'a', count: 1 }, { kind: 'b', count: 1 }]);
 });
});
