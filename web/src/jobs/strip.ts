// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The run strip of a job: the runs the job view returned, placed at the instant each first started inside the scope's window, with the words
// that say the same thing for a reader who cannot see the drawing. Nanosecond instants stay BigInt: they never pass through a JavaScript number.
import type { JobHealth, JobRunView, JobTruncation } from '../api/types';

export type RunKind = 'ok' | 'retry' | 'failed' | 'running' | 'cancelled';

/** What a strip is built from: the runs a job view returned and what that view states about its health and erasure. */
export interface StripInput { runs: readonly JobRunView[]; runs_truncation?: JobTruncation | undefined; health?: JobHealth | undefined; erased: boolean }
/** The strip is drawn on a 0..STRIP_WIDTH axis; the drawing scales it to the width it has. */
export const STRIP_WIDTH = 1000;

export interface StripMark { id: string; kind: RunKind; x: number }
export interface Strip {
 marks: StripMark[];
 /** Positions of occurrences the schedule expected and no run answered (the verdict is missed, from observer evidence). */
 expected: number[];
 counts: Record<RunKind, number>;
 /** Runs the view returned that started outside the window. */
 outside: number;
 /** The view read only the newest runs: older runs inside the window may exist and are not drawn. */
 truncated: boolean;
 /** How many runs the view returned. */
 read: number;
 erased: boolean;
}

export const RUN_KIND_WORD: Record<RunKind, string> = { ok: 'succeeded', retry: 'succeeded after retry', failed: 'failed', running: 'running', cancelled: 'cancelled' };
export const RUN_KINDS: readonly RunKind[] = ['ok', 'failed', 'retry', 'running', 'cancelled'];

/** A run's own status as a strip kind. A recovered run is its own kind: it succeeded, after a failed attempt. */
export function kindOfRun(run: Pick<JobRunView, 'status'>): RunKind {
 switch (run.status) {
  case 'succeeded': return 'ok';
  case 'recovered': return 'retry';
  case 'failed': return 'failed';
  case 'cancelled': return 'cancelled';
  case 'running': return 'running';
 }
}

function place(ns: string, start: bigint, span: bigint): number | null {
 let t: bigint;
 try { t = BigInt(ns); } catch { return null; }
 if (t < start || t >= start + span) return null;
 return Number(((t - start) * BigInt(STRIP_WIDTH)) / span);
}

/** The runs of a job view placed in the window. A run outside the window is counted, not drawn; a run whose start cannot be read is counted as outside, never dropped silently. */
export function buildStrip(view: StripInput, window: { start: string; end: string }): Strip {
 const start = BigInt(window.start);
 const span = BigInt(window.end) - start;
 const counts: Record<RunKind, number> = { ok: 0, retry: 0, failed: 0, running: 0, cancelled: 0 };
 const marks: StripMark[] = [];
 let outside = 0;
 for (const run of view.runs) {
  const x = span > 0n ? place(run.first_started_ns, start, span) : null;
  if (x === null) { outside++; continue; }
  const kind = kindOfRun(run);
  counts[kind]++;
  marks.push({ id: run.id, kind, x });
 }
 const expectedAt = view.health?.status === 'missed' ? view.health.evidence.expected_at_ns : undefined;
 const ex = expectedAt !== undefined && span > 0n ? place(expectedAt, start, span) : null;
 return { marks, expected: ex === null ? [] : [ex], counts, outside, truncated: view.runs_truncation !== undefined, read: view.runs.length, erased: view.erased };
}

/** The strip in words: counts by outcome, what lies outside the window, and what the reading could not see. */
export function stripText(strip: Strip): string {
 if (strip.erased) return 'The history of this job was erased: no run is retained, so none is drawn.';
 const parts = RUN_KINDS.filter((k) => strip.counts[k] > 0).map((k) => `${strip.counts[k]} ${RUN_KIND_WORD[k]}`);
 const drawn = strip.marks.length;
 const head = drawn === 0
  ? (strip.truncated ? `None of the newest ${strip.read} runs read started in this window.` : 'No run of this job started in this window.')
  : `${drawn} run${drawn === 1 ? '' : 's'} in this window: ${parts.join(', ')}.`;
 const more: string[] = [];
 if (strip.expected.length > 0) more.push('An expected run has no record.');
 if (strip.outside > 0) more.push(`${strip.outside} run${strip.outside === 1 ? '' : 's'} read started outside this window and ${strip.outside === 1 ? 'is' : 'are'} not drawn.`);
 if (strip.truncated) more.push(`Only the newest ${strip.read} runs were read; older runs inside the window may exist and are not drawn.`);
 return [head, ...more].join(' ');
}

/** Everything the list needs to place one job: what its view returned, or why there is no drawing. */
export type StripState =
 | { kind: 'loading' }
 | { kind: 'ready'; strip: Strip }
 | { kind: 'failed' };
