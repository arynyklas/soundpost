// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Pure model of the replay page: the strict parser of one NDJSON line of POST /api/v1/replays/stream, the bridge item a line
// becomes for the sandboxed viewer, and the summary the page states in words. No chunk content is interpreted here: the viewer
// frame decodes and chain-verifies every chunk itself (packages/replay-viewer); this file never reimplements that.
import { ApiFault, type Id } from '../api/types';

/** The gap reasons the viewer accepts (packages/replay-viewer GAP_REASONS). */
export type GapReason = 'missing_chunk' | 'hash_mismatch' | 'dependency_mismatch' | 'recorder_gap' | 'conflicting_chunk' | 'invalid_chunk' | 'no_checkpoint' | 'recorder_version';
/** One item the host hands to the viewer frame; the same closed shape the viewer's bridge rebuilds. */
export type ReplayItem =
 | { readonly kind: 'chunk'; readonly bytes: Uint8Array }
 | { readonly kind: 'gap'; readonly reason: GapReason; readonly from: string; readonly through: string }
 | { readonly kind: 'unsupported' }
 | { readonly kind: 'revoke'; readonly reason: 'authority_revoked' | 'deleted' }
 | { readonly kind: 'error' };
export type ReplayStream = AsyncIterable<ReplayItem>;

export type ReplayLine =
 | { type: 'open'; org: Id; project: Id; replay: Id }
 | { type: 'checkpoint' | 'delta'; sequence: string; policy: string; loss: string; chunk: Record<string, unknown> }
 | { type: 'gap'; sequence: string; through: string; reason: string }
 | { type: 'unsupported'; sequence: string; reason: string }
 | { type: 'revoke'; reason: 'authority_revoked' | 'deleted' }
 | { type: 'error'; code: string }
 | { type: 'truncated'; next: string }
 | { type: 'end' }
 | { type: 'not_available'; reason: string };

const ID32 = /^[0-9a-f]{32}$/;
const DEC = /^(0|[1-9][0-9]{0,19})$/;
const CODE = /^[a-z_]{1,48}$/;
const MAX_LINE_CHARS = 2 << 20;
const isRec = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const bad = (): never => { throw new ApiFault(200, 'invalid_response', '', 'response does not match the request'); };
const dec = (v: unknown): string => (typeof v === 'string' && DEC.test(v) ? v : bad());
const code = (v: unknown): string => (typeof v === 'string' && CODE.test(v) ? v : bad());
const decOrNumber = (v: unknown): string => (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? String(v) : dec(v));

/** One line of the stream, accepted only if it is a closed line type for exactly the requested replay. */
export function parseReplayLine(text: string, want: { org: Id; project: Id; replay: Id }): ReplayLine {
 if (text.length > MAX_LINE_CHARS) return bad();
 let raw: unknown;
 try { raw = JSON.parse(text); } catch { return bad(); }
 if (!isRec(raw) || typeof raw.type !== 'string') return bad();
 switch (raw.type) {
  case 'open':
   if (raw.org !== want.org || raw.project !== want.project || raw.replay !== want.replay || !ID32.test(want.replay)) return bad();
   return { type: 'open', org: want.org, project: want.project, replay: want.replay };
  case 'checkpoint': case 'delta':
   if (!isRec(raw.chunk)) return bad();
   return { type: raw.type, sequence: dec(raw.sequence), policy: decOrNumber(raw.policy_revision), loss: dec(raw.loss), chunk: raw.chunk };
  case 'gap': {
   const from = dec(raw.sequence), through = dec(raw.through);
   if (BigInt(from) < 1n || BigInt(from) > BigInt(through)) return bad();
   return { type: 'gap', sequence: from, through, reason: code(raw.reason) };
  }
  case 'unsupported': return { type: 'unsupported', sequence: dec(raw.sequence), reason: code(raw.reason) };
  case 'revoke':
   if (raw.reason !== 'authority_revoked' && raw.reason !== 'deleted') return bad();
   return { type: 'revoke', reason: raw.reason };
  case 'error': return { type: 'error', code: code(raw.code) };
  case 'truncated': return { type: 'truncated', next: dec(raw.next_sequence) };
  case 'end': return { type: 'end' };
  case 'not_available': return { type: 'not_available', reason: code(raw.reason) };
 }
 return bad();
}

/** Splits a text stream into lines without ever holding more than one oversized line. */
export function lineSplitter(): (chunk: string) => string[] {
 let rest = '';
 return (chunk) => {
  rest += chunk;
  if (rest.length > MAX_LINE_CHARS && !rest.includes('\n')) return bad();
  const lines = rest.split('\n');
  rest = lines.pop() ?? '';
  return lines.filter((l) => l !== '');
 };
}

/** Gap reasons outside the viewer's closed set are mapped to the nearest one it knows, never dropped: a chunk that contradicts the immutable checkpoint index is a conflicting chunk. */
export function gapReason(reason: string): GapReason {
 switch (reason) {
  case 'missing_chunk': case 'hash_mismatch': case 'dependency_mismatch': case 'recorder_gap': case 'conflicting_chunk': case 'invalid_chunk': case 'no_checkpoint': case 'recorder_version': return reason;
  case 'index_mismatch': return 'conflicting_chunk';
  default: return 'invalid_chunk';
 }
}

const encoder = new TextEncoder();
/** The viewer item of a line, or null when the line is only a page-level fact (open, end, truncated, not_available). */
export function toItem(line: ReplayLine): ReplayItem | null {
 switch (line.type) {
  case 'checkpoint': case 'delta': return { kind: 'chunk', bytes: encoder.encode(JSON.stringify(line.chunk)) };
  case 'gap': return { kind: 'gap', reason: gapReason(line.reason), from: line.sequence, through: line.through };
  case 'unsupported': return { kind: 'unsupported' };
  case 'revoke': return { kind: 'revoke', reason: line.reason };
  case 'error': return { kind: 'error' };
  default: return null;
 }
}

export type Terminal = 'streaming' | 'end' | 'truncated' | 'revoked' | 'deleted' | 'error' | 'not_available';
export interface GapNote { from: string; through: string; reason: string; resumedAt: string | null }
export interface ReplaySummary {
 chunks: number;
 checkpoints: number;
 policies: string[];
 loss: bigint;
 lossReported: boolean;
 gaps: GapNote[];
 unsupported: number;
 terminal: Terminal;
 next?: string;
 code?: string;
 reason?: string;
}
export const emptySummary = (): ReplaySummary => ({ chunks: 0, checkpoints: 0, policies: [], loss: 0n, lossReported: false, gaps: [], unsupported: 0, terminal: 'streaming' });

/** Folds one line into the summary (pure). A gap is open until the next checkpoint line names where playback resumed. */
export function summarize(prev: ReplaySummary, line: ReplayLine): ReplaySummary {
 const s: ReplaySummary = { ...prev, policies: [...prev.policies], gaps: prev.gaps.map((g) => ({ ...g })) };
 switch (line.type) {
  case 'checkpoint': case 'delta':
   s.chunks += 1;
   s.loss += BigInt(line.loss);
   s.lossReported = true;
   if (!s.policies.includes(line.policy)) s.policies.push(line.policy);
   if (line.type === 'checkpoint') {
    s.checkpoints += 1;
    for (const g of s.gaps) if (g.resumedAt === null) g.resumedAt = line.sequence;
   }
   break;
  case 'gap': s.gaps.push({ from: line.sequence, through: line.through, reason: line.reason, resumedAt: null }); break;
  case 'unsupported': s.unsupported += 1; s.gaps.push({ from: line.sequence, through: line.sequence, reason: line.reason, resumedAt: null }); break;
  case 'end': s.terminal = 'end'; break;
  case 'truncated': s.terminal = 'truncated'; s.next = line.next; break;
  case 'revoke': s.terminal = line.reason === 'deleted' ? 'deleted' : 'revoked'; s.reason = line.reason; break;
  case 'error': s.terminal = 'error'; s.code = line.code; break;
  case 'not_available': s.terminal = 'not_available'; s.reason = line.reason; break;
  case 'open': break;
 }
 return s;
}

const REASON_TEXT: Record<string, string> = {
 missing_chunk: 'a chunk never arrived', hash_mismatch: 'a chunk did not continue the verified chain', dependency_mismatch: 'a chunk named a different checkpoint than the one applied',
 recorder_gap: 'the recorder declared a gap', conflicting_chunk: 'two different chunks claimed the same sequence, or a chunk contradicted the checkpoint index',
 invalid_chunk: 'a chunk failed validation', no_checkpoint: 'no checkpoint preceded the chunk', recorder_version: 'a recorder version this server cannot reconstruct', index_mismatch: 'a chunk contradicted the checkpoint index',
};
export function gapReasonText(reason: string): string { return REASON_TEXT[reason] ?? 'unspecified reason'; }

/** One sentence per gap: where it is, why, and that playback resumes only at a later verified checkpoint. It describes the recording as received; the viewer's own status says where playback is. */
export function gapSentence(g: GapNote): string {
 const range = g.from === g.through ? `sequence ${g.from}` : `sequences ${g.from} to ${g.through}`;
 const resume = g.resumedAt === null ? 'No later checkpoint exists in what was received, so playback stays paused there.' : `In this recording playback resumes only at checkpoint ${g.resumedAt}; nothing between is shown.`;
 return `History gap at ${range}: ${gapReasonText(g.reason)}. ${resume}`;
}

/** The text of the recording-loss row: reported loss is a count of events the recorder dropped, absence of a report is not proof of none. */
export function lossText(s: ReplaySummary): string {
 if (!s.lossReported) return 'unknown (no chunk has been delivered yet)';
 return s.loss === 0n ? 'none reported by the recorder (a report of none is not proof that nothing was dropped)' : `${s.loss} events were dropped by the recorder before upload and are not in this replay`;
}
