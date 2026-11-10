// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The live view reducer. A live view is built only from the events the server sent: it never guesses what it did not
// receive. Every loss is shown as a gap with its exact bounds, a revoke clears what was buffered at once and nothing can put a
// row back afterwards, and what it holds in memory is bounded with the amount it dropped kept visible.
import type { Cursor, Id, Label, LiveEvent } from '../api/types';

export interface LiveLimits { maxItems: number; maxBytes: number }
/** 500 rows or gaps and about one megabyte of text, whichever comes first. */
export const DEFAULT_LIVE_LIMITS: LiveLimits = { maxItems: 500, maxBytes: 1 << 20 };

export interface LiveRow { kind: 'row'; sequence: string; project: Id; time: string; id: Id; multiplicity: string; line: string; labels: Label[]; streamLabels: Label[]; metadata: Label[] }
/** A statement of loss. `announced` is false when the view itself noticed that sequences were skipped without a gap event. */
export interface LiveGapItem { kind: 'gap'; sequence: string | null; reason: string; from: string; to: string; after: Cursor[]; through: Cursor[]; announced: boolean }
export type LiveItem = LiveRow | LiveGapItem;
/** How a view ended. 'revoked' and 'error' come from the server's stream; 'stopped', 'interrupted', 'failed' and 'refused' are this
 * browser's own observations ('failed': the server answered the ticket or stream request with a typed failure that is not a denial).
 * Only 'refused' (the server denied this reader) and 'revoked' clear what was held. */
export interface LiveEnd { kind: 'revoked' | 'error' | 'stopped' | 'interrupted' | 'failed' | 'refused'; reason: string; code: string }
export interface LiveView {
 phase: 'idle' | 'connecting' | 'live' | 'ended';
 streamId: Id | '';
 /** Sequence of the last event handled: the Last-Event-ID of a resume. '0' means none. */
 lastSequence: string;
 items: LiveItem[];
 bytes: number;
 /** Rows received since the view started, shown or not. */
 received: number;
 /** Items dropped from the bounded view. They were delivered; they are only no longer held. */
 evicted: number;
 /** Every gap ever shown, including ones evicted from view. */
 gaps: number;
 duplicates: number;
 heartbeats: number;
 lastHeartbeatAt: number | null;
 watermarks: Cursor[];
 replaced: boolean;
 end: LiveEnd | null;
}
export interface LiveContext { now: number; projects: Id[]; limits: LiveLimits }

export const initialLive = (): LiveView => ({ phase: 'idle', streamId: '', lastSequence: '0', items: [], bytes: 0, received: 0, evicted: 0, gaps: 0, duplicates: 0, heartbeats: 0, lastHeartbeatAt: null, watermarks: [], replaced: false, end: null });

/** A fresh attachment forgets everything; a resumed one keeps its rows and its position so the gap, if any, lands in the right place. */
export function beginAttachment(view: LiveView, resume: boolean): LiveView {
 if (!resume) return { ...initialLive(), phase: 'connecting' };
 return { ...view, phase: 'connecting', end: null, replaced: false };
}

const labelChars = (labels: Label[]): number => labels.reduce((n, l) => n + l.name.length + l.value.length, 0);
const sizeOf = (item: LiveItem): number => (item.kind === 'row' ? 64 + item.line.length + labelChars(item.labels) + labelChars(item.streamLabels) + labelChars(item.metadata) : 64 + item.reason.length);

function cleared(view: LiveView, end: LiveEnd): LiveView {
 return { ...view, phase: 'ended', items: [], bytes: 0, watermarks: [], end };
}
function violation(view: LiveView, reason: string): LiveView {
 return cleared(view, { kind: 'error', reason, code: 'invalid_response' });
}

function append(view: LiveView, added: LiveItem[], limits: LiveLimits): LiveView {
 const items = [...view.items, ...added];
 let bytes = view.bytes + added.reduce((n, i) => n + sizeOf(i), 0);
 let evicted = view.evicted;
 let from = 0;
 while (items.length - from > limits.maxItems || (bytes > limits.maxBytes && items.length - from > 1)) {
  bytes -= sizeOf(items[from] as LiveItem);
  from++;
  evicted++;
 }
 return { ...view, items: from === 0 ? items : items.slice(from), bytes, evicted };
}

/** Applies one server event. After the view has ended nothing is applied: no row can appear after a revoke or a terminal error. */
export function applyLiveEvent(view: LiveView, ev: LiveEvent, ctx: LiveContext): LiveView {
 if (view.phase === 'ended') return view;
 if (ev.type === 'open') {
  if (view.phase === 'live') return violation(view, 'duplicate_open');
  return { ...view, phase: 'live', replaced: view.streamId !== '' && view.streamId !== ev.stream_id, streamId: ev.stream_id, watermarks: ev.watermarks ?? [] };
 }
 if (view.phase !== 'live') return violation(view, 'event_before_open');
 if (ev.stream_id !== view.streamId) return violation(view, 'stream_mismatch');
 const last = BigInt(view.lastSequence);
 switch (ev.type) {
  case 'heartbeat': return { ...view, heartbeats: view.heartbeats + 1, lastHeartbeatAt: ctx.now, watermarks: ev.watermarks ?? view.watermarks };
  case 'revoke': return cleared(view, { kind: 'revoked', reason: ev.reason ?? 'scope_revoked', code: ev.failure?.code ?? '' });
  case 'error': return { ...view, phase: 'ended', end: { kind: 'error', reason: ev.reason ?? 'unavailable', code: ev.failure?.code ?? '' } };
  case 'record': {
   if (ev.entry === undefined || ev.sequence === undefined || ev.project === undefined) return violation(view, 'malformed_record');
   if (!ctx.projects.includes(ev.project)) return violation(view, 'foreign_project');
   const sequence = BigInt(ev.sequence);
   if (sequence <= last) return { ...view, duplicates: view.duplicates + 1 };
   const added: LiveItem[] = [];
   let gaps = view.gaps;
   if (sequence > last + 1n) {
    added.push({ kind: 'gap', sequence: null, reason: 'unannounced_sequence_jump', from: String(last + 1n), to: String(sequence - 1n), after: [], through: [], announced: false });
    gaps++;
   }
   const e = ev.entry;
   added.push({ kind: 'row', sequence: ev.sequence, project: ev.project, time: e.time, id: e.id, multiplicity: e.multiplicity, line: e.line, labels: ev.labels ?? [], streamLabels: e.stream_labels, metadata: e.structured_metadata });
   return append({ ...view, lastSequence: ev.sequence, received: view.received + 1, gaps }, added, ctx.limits);
  }
  case 'gap': {
   if (ev.gap === undefined) return violation(view, 'malformed_gap');
   const g = ev.gap;
   const from = BigInt(g.from_sequence), to = BigInt(g.to_sequence);
   if (to <= last) return { ...view, duplicates: view.duplicates + 1 };
   const added: LiveItem[] = [];
   let gaps = view.gaps;
   if (from > last + 1n) {
    added.push({ kind: 'gap', sequence: null, reason: 'unannounced_sequence_jump', from: String(last + 1n), to: String(from - 1n), after: [], through: [], announced: false });
    gaps++;
   }
   added.push({ kind: 'gap', sequence: ev.sequence ?? null, reason: g.reason, from: g.from_sequence, to: g.to_sequence, after: g.after ?? [], through: g.through ?? [], announced: true });
   gaps++;
   return append({ ...view, lastSequence: g.to_sequence, gaps }, added, ctx.limits);
  }
  default: return violation(view, 'unknown_event');
 }
}

/** The browser's own end of a view (stopped by the person, the connection was lost, the server refused this reader).
 * It never replaces how the server ended a view. A refusal means access is gone, so what was held is cleared. */
export function endAttachment(view: LiveView, end: LiveEnd): LiveView {
 if (view.end !== null) return view;
 return end.kind === 'refused' ? cleared(view, end) : { ...view, phase: 'ended', end };
}
