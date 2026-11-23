// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The "lines per interval" histogram of a log result. It counts only the lines this page holds, and says so: a bucket the page cannot
// speak for (outside the part a page limit returned, or empty in an answer that is not complete) is "no samples", never zero.
import type { LogEntry } from '../api/types';
import { nsToMs } from './chartModel';

export interface LogBucket { start: number; end: number; values: number[] | null }
export interface LogHistogram { buckets: LogBucket[]; /** The width of one bucket in ms. */ width: number; counted: number; /** What the counts cover, in words. */ note: string }

const SECOND = 1000, MINUTE = 60 * SECOND, HOUR = 60 * MINUTE, DAY = 24 * HOUR;
const WIDTHS = [SECOND, 5 * SECOND, 10 * SECOND, 30 * SECOND, MINUTE, 2 * MINUTE, 5 * MINUTE, 10 * MINUTE, 15 * MINUTE, 30 * MINUTE, HOUR, 2 * HOUR, 6 * HOUR, 12 * HOUR, DAY, 7 * DAY];
export const MAX_BUCKETS = 60;

/** The smallest round bucket width that keeps the window within MAX_BUCKETS buckets. */
export function bucketWidth(spanMs: number): number {
 for (const w of WIDTHS) if (spanMs / w <= MAX_BUCKETS) return w;
 return WIDTHS[WIDTHS.length - 1] ?? DAY;
}

export function widthWords(ms: number): string {
 if (ms >= DAY) return `${ms / DAY} ${ms === DAY ? 'day' : 'days'}`;
 if (ms >= HOUR) return `${ms / HOUR} ${ms === HOUR ? 'hour' : 'hours'}`;
 if (ms >= MINUTE) return `${ms / MINUTE} ${ms === MINUTE ? 'minute' : 'minutes'}`;
 return `${ms / SECOND} ${ms === SECOND ? 'second' : 'seconds'}`;
}

export interface HistogramInput {
 entries: readonly Pick<LogEntry, 'time' | 'multiplicity'>[];
 window: { start: string; end: string };
 /** The project answered completely (every shard). An empty bucket of any other answer is unknown, not zero. */
 complete: boolean;
 /** A page limit cut the result: only one end of the window is covered. */
 limitReached: boolean;
 order: 'backward' | 'forward';
}

/** Counts the held lines per bucket of the window. With a page limit the covered part is the one the page reached (newest first: from the oldest line returned onward; oldest first: up to the newest line returned). */
export function logHistogram(input: HistogramInput): LogHistogram | null {
 const start = nsToMs(input.window.start), end = nsToMs(input.window.end);
 if (!(end > start)) return null;
 const width = bucketWidth(end - start);
 const n = Math.max(1, Math.ceil((end - start) / width));
 const counts = new Array<number>(n).fill(0);
 let counted = 0, oldest = Infinity, newest = -Infinity;
 for (const e of input.entries) {
  const t = nsToMs(e.time);
  if (t < oldest) oldest = t;
  if (t > newest) newest = t;
  const i = Math.floor((t - start) / width);
  if (i < 0 || i >= n) continue;
  const m = Number(BigInt(e.multiplicity));
  counts[i] = (counts[i] ?? 0) + m;
  counted += m;
 }
 const coveredFrom = input.limitReached && input.order === 'backward' ? oldest : -Infinity;
 const coveredTo = input.limitReached && input.order === 'forward' ? newest : Infinity;
 const buckets: LogBucket[] = counts.map((c, i) => {
  const bs = start + i * width, be = Math.min(end, bs + width);
  const covered = bs >= coveredFrom && be <= coveredTo + 1;
  return { start: bs, end: be, values: covered && !(c === 0 && !input.complete) ? [c] : null };
 });
 const cut = input.limitReached ? ' A page limit cut this result, so buckets outside the part it reached have no samples here.' : '';
 const partial = input.complete ? '' : ' The answer is not complete, so an empty bucket is not shown as zero.';
 return { buckets, width, counted, note: `Counts the ${counted} ${counted === 1 ? 'line' : 'lines'} this page holds, per ${widthWords(width)}.${cut}${partial}` };
}
