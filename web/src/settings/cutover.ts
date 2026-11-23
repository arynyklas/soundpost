// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
import { apiFault, jsonPost } from '../api/client';
import { ApiFault } from '../api/types';
import type { Id } from '../api/types';

/** The read-only notification cutover page (internal/control/cutover_view.go, POST /api/v1/cutover).
 * The decoder accepts the answer only for exactly the requested organization and project, with exactly the known fields
 * (a closed shape: an unknown field, a bad ID or a malformed number is a fault, never rendered). All text is shown as React
 * text; nothing here produces HTML. */

export const CUTOVER_PHASES = ['shadow', 'quiescing_old', 'barrier_verified', 'new_active', 'rollback_quiescing', 'old_active'] as const;
export type CutoverPhase = (typeof CUTOVER_PHASES)[number];
export const SPAN_SIDES = ['legacy', 'product', 'handover'] as const;
export type SpanSide = (typeof SPAN_SIDES)[number];

export interface CutoverStep { revision: string; from: CutoverPhase | ''; to: CutoverPhase; epoch: string; at_ns: string; command: Id; principal: Id; digest: string; evidence_digest?: string }
export interface CutoverFrontier { source: Id; version: string; cursor: { group: Id; index: string } }
export interface CutoverState {
 id: Id; revision: string; phase: CutoverPhase; epoch: string; entered_at_ns: string; old_owner: Id; new_owner: Id; active_owners: Id[];
 frontier: CutoverFrontier[]; restore: { pending?: Id; acknowledged?: Id }; timeline: CutoverStep[];
}
export interface ShadowRow { id: Id; subject: string; kind: string; recipient?: Id; decided_ns: string; digest: string }
export interface HistorySpan { owner?: Id; side: SpanSide; phase: CutoverPhase; from_ns: string; to_ns?: string }
export interface CutoverView {
 org: Id; project: Id; cutover: CutoverState | null;
 accounting: { pending: number; claimed: number; lapsed: number; unknown: number; unknown_digest: string };
 shadow: { observing: boolean; decisions: number; by_kind: Record<string, number>; recent: ShadowRow[] };
 history: { legacy_owner?: Id; legacy_history: 'read_only'; importer: false; spans: HistorySpan[] };
}

const ID = /^[0-9a-f]{32}$/;
const HASH = /^[0-9a-f]{64}$/;
const DEC = /^(0|[1-9][0-9]{0,19})$/;
const TEXT = /^[\x20-\x7e]{1,256}$/;
const MAX_ROWS = 1000;

const bad = (): never => { throw new ApiFault(200, 'invalid_response', '', 'response does not match the request'); };
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
/** Only the listed keys may be present; the required ones must be. */
function shape(v: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
 if (!isRecord(v)) return bad();
 for (const k of required) if (!(k in v)) return bad();
 for (const k of Object.keys(v)) if (!required.includes(k) && !optional.includes(k)) return bad();
 return v;
}
const id = (v: unknown): Id => (typeof v === 'string' && ID.test(v) ? v : bad());
const hash = (v: unknown): string => (typeof v === 'string' && HASH.test(v) ? v : bad());
const text = (v: unknown): string => (typeof v === 'string' && TEXT.test(v) ? v : bad());
/** A decimal string, or a safe integer number, as the decimal string; anything else is a fault. */
function dec(v: unknown): string {
 if (typeof v === 'number') return Number.isSafeInteger(v) && v >= 0 ? String(v) : bad();
 return typeof v === 'string' && DEC.test(v) && BigInt(v) <= 18446744073709551615n ? v : bad();
}
const u32 = (v: unknown): number => (typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 4294967295 ? v : bad());
function phase(v: unknown): CutoverPhase { return (CUTOVER_PHASES as readonly unknown[]).includes(v) ? (v as CutoverPhase) : bad(); }
function list(v: unknown, max = MAX_ROWS): unknown[] { return Array.isArray(v) && v.length <= max ? v : bad(); }

function step(raw: unknown): CutoverStep {
 const r = shape(raw, ['revision', 'from', 'to', 'epoch', 'at_ns', 'command', 'principal', 'digest'], ['evidence_digest']);
 const out: CutoverStep = { revision: dec(r.revision), from: r.from === '' ? '' : phase(r.from), to: phase(r.to), epoch: dec(r.epoch), at_ns: dec(r.at_ns), command: id(r.command), principal: id(r.principal), digest: hash(r.digest) };
 if (r.evidence_digest !== undefined) out.evidence_digest = hash(r.evidence_digest);
 return out;
}
function frontier(raw: unknown): CutoverFrontier {
 const r = shape(raw, ['source', 'version', 'cursor']);
 const c = shape(r.cursor, ['group', 'index']);
 return { source: id(r.source), version: dec(r.version), cursor: { group: id(c.group), index: dec(c.index) } };
}
function state(raw: unknown): CutoverState {
 const r = shape(raw, ['id', 'revision', 'phase', 'epoch', 'entered_at_ns', 'old_owner', 'new_owner', 'active_owners', 'frontier', 'restore', 'timeline']);
 const rs = shape(r.restore, [], ['pending', 'acknowledged']);
 const restore: CutoverState['restore'] = {};
 if (rs.pending !== undefined) restore.pending = id(rs.pending);
 if (rs.acknowledged !== undefined) restore.acknowledged = id(rs.acknowledged);
 const ph = phase(r.phase), oldOwner = id(r.old_owner), newOwner = id(r.new_owner);
 const active = list(r.active_owners, 2).map(id);
 const want = activeOwnersOf(ph, oldOwner, newOwner);
 if (active.length !== want.length || active.some((a, i) => a !== want[i])) return bad();
 return { id: id(r.id), revision: dec(r.revision), phase: ph, epoch: dec(r.epoch), entered_at_ns: dec(r.entered_at_ns), old_owner: oldOwner, new_owner: newOwner, active_owners: active, frontier: list(r.frontier).map(frontier), restore, timeline: list(r.timeline).map(step) };
}
function shadowRow(raw: unknown): ShadowRow {
 const r = shape(raw, ['id', 'subject', 'kind', 'decided_ns', 'digest'], ['recipient']);
 const out: ShadowRow = { id: id(r.id), subject: text(r.subject), kind: text(r.kind), decided_ns: dec(r.decided_ns), digest: hash(r.digest) };
 if (r.recipient !== undefined) out.recipient = id(r.recipient);
 return out;
}
function span(raw: unknown): HistorySpan {
 const r = shape(raw, ['side', 'phase', 'from_ns'], ['owner', 'to_ns']);
 if (!(SPAN_SIDES as readonly unknown[]).includes(r.side)) return bad();
 const out: HistorySpan = { side: r.side as SpanSide, phase: phase(r.phase), from_ns: dec(r.from_ns) };
 if (r.owner !== undefined) out.owner = id(r.owner);
 if (r.to_ns !== undefined) out.to_ns = dec(r.to_ns);
 return out;
}

/** Accepts a cutover view only for exactly the requested organization and project. */
export function parseCutoverView(raw: unknown, want: { org: Id; project: Id }): CutoverView {
 const r = shape(raw, ['org', 'project', 'cutover', 'accounting', 'shadow', 'history']);
 if (r.org !== want.org || r.project !== want.project) return bad();
 const a = shape(r.accounting, ['pending', 'claimed', 'lapsed', 'unknown', 'unknown_digest']);
 const s = shape(r.shadow, ['observing', 'decisions', 'by_kind', 'recent']);
 if (typeof s.observing !== 'boolean') return bad();
 const byKindRaw = s.by_kind;
 if (!isRecord(byKindRaw) || Object.keys(byKindRaw).length > 64) return bad();
 const by_kind: Record<string, number> = {};
 for (const k of Object.keys(byKindRaw).sort()) by_kind[text(k)] = u32(byKindRaw[k]);
 const h = shape(r.history, ['legacy_history', 'importer', 'spans'], ['legacy_owner']);
 if (h.legacy_history !== 'read_only' || h.importer !== false) return bad();
 const history: CutoverView['history'] = { legacy_history: 'read_only', importer: false, spans: list(h.spans).map(span) };
 if (h.legacy_owner !== undefined) history.legacy_owner = id(h.legacy_owner);
 const view: CutoverView = {
  org: want.org, project: want.project, cutover: r.cutover === null ? null : state(r.cutover),
  accounting: { pending: u32(a.pending), claimed: u32(a.claimed), lapsed: u32(a.lapsed), unknown: u32(a.unknown), unknown_digest: hash(a.unknown_digest) },
  shadow: { observing: s.observing, decisions: u32(s.decisions), by_kind, recent: list(s.recent, 50).map(shadowRow) }, history,
 };
 return view;
}

/** POST /api/v1/cutover: the project's notification ownership, shadow decisions and history boundary, under the caller's own policy.write grant or organization administration. Anything else is the usual 404. */
export async function getCutover(org: Id, project: Id, signal: AbortSignal): Promise<CutoverView> {
 const response = await jsonPost('/api/v1/cutover', { org, project_id: project }, signal);
 if (!response.ok) throw await apiFault(response);
 return parseCutoverView(await response.json() as unknown, { org, project });
}

// ---- pure summaries ----

/** Mirrors control.CutoverActiveOwners: only shadow, quiescing_old and old_active are owned by the old owner, only new_active by the new one; the two handover phases have no normal owner. */
export function activeOwnersOf(p: CutoverPhase, oldOwner: Id, newOwner: Id): Id[] {
 switch (p) {
  case 'shadow': case 'quiescing_old': case 'old_active': return [oldOwner];
  case 'new_active': return [newOwner];
  default: return [];
 }
}

export const PHASE_WORDS: Record<CutoverPhase, string> = {
 shadow: 'Shadow', quiescing_old: 'Quiescing the old owner', barrier_verified: 'Barrier verified', new_active: 'New owner active', rollback_quiescing: 'Rolling back: quiescing the new owner', old_active: 'Old owner active (rolled back)',
};

export interface OwnerStatement { headline: string; owner: Id | null; detail: string }
/** Who owns normal notifications now, stated from the committed phase. No cutover means the product is the only owner. */
export function ownerStatement(c: CutoverState | null): OwnerStatement {
 if (c === null) return { headline: 'The product is the only owner of normal notifications.', owner: null, detail: 'This project has no cutover, so there is no legacy owner and no history boundary.' };
 switch (c.phase) {
  case 'shadow': return { headline: 'The old owner sends normal notifications.', owner: c.old_owner, detail: 'The product only watches: its decisions are recorded as shadow decisions and never sent.' };
  case 'quiescing_old': return { headline: 'The old owner still sends normal notifications while it quiesces.', owner: c.old_owner, detail: 'The product has not taken over; its decisions are still recorded and never sent.' };
  case 'barrier_verified': return { headline: 'No owner is active: this is the handover.', owner: null, detail: 'The barrier is verified; the new owner has not been activated yet, so normal notifications are not being sent by either side.' };
  case 'new_active': return { headline: 'The new owner sends normal notifications.', owner: c.new_owner, detail: 'The old owner has been quiesced; shadow observation has ended.' };
  case 'rollback_quiescing': return { headline: 'No owner is active: this is a rollback handover.', owner: null, detail: 'The new owner is being quiesced before the old owner is restored; normal notifications are not being sent by either side.' };
  case 'old_active': return { headline: 'The old owner sends normal notifications again (rolled back).', owner: c.old_owner, detail: 'The product is not the active owner; its decisions are recorded as shadow decisions and never sent.' };
 }
}

/** The warning shown while a disaster restore still has to be acknowledged; null when there is none. */
export function restoreWarning(c: CutoverState | null): string | null {
 if (c === null || c.restore.pending === undefined) return null;
 return `A restore (generation ${c.restore.pending}) is pending acknowledgement. The product may not send until the operator acknowledges it.`;
}

/** Spans oldest first by start instant (exact, no floating point); equal starts keep the server order. */
export function orderedSpans(spans: readonly HistorySpan[]): HistorySpan[] {
 return spans.map((s, i) => ({ s, i })).sort((x, y) => { const a = BigInt(x.s.from_ns), b = BigInt(y.s.from_ns); return a < b ? -1 : a > b ? 1 : x.i - y.i; }).map((e) => e.s);
}

const SIDE_WORDS: Record<SpanSide, string> = { legacy: 'Legacy (external, read-only)', product: 'Product', handover: 'Handover (no owner)' };
export const sideWords = (side: SpanSide): string => SIDE_WORDS[side];

/** Shadow counts by kind, largest first, ties by name. */
export function kindCounts(by: Record<string, number>): { kind: string; count: number }[] {
 return Object.entries(by).map(([kind, count]) => ({ kind, count })).sort((a, b) => b.count - a.count || (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0));
}

export type PathState = 'current' | 'passed' | 'not_reached';
export const PATH_WORDS: Record<PathState, string> = { current: 'Current', passed: 'Passed', not_reached: 'Not reached' };
/** Every phase of the cutover in its fixed order, each marked from the committed timeline only: the current one, the ones a committed step passed through, and the ones never reached. */
export function phasePath(c: CutoverState): { phase: CutoverPhase; state: PathState }[] {
 const seen = new Set<string>();
 for (const s of c.timeline) { seen.add(s.to); if (s.from !== '') seen.add(s.from); }
 return CUTOVER_PHASES.map((phase) => ({ phase, state: phase === c.phase ? 'current' : seen.has(phase) ? 'passed' : 'not_reached' }));
}
