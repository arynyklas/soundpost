// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Words for the replay list. A figure the server did not state is "not stated", never zero: an unknown recording is not a complete one, and an unknown count of gaps is not no gaps.
import type { ReplayListItem } from '../api/console';
import type { Tone } from '../ui/primitives';

export interface RecordingView { word: string; tone: Tone; detail: string }

/** How completely the recording was captured, in words, with the number of gaps only when the server states it. */
export function recordingView(item: Pick<ReplayListItem, 'recording' | 'gaps'>): RecordingView {
 const gaps = item.gaps === null ? '' : item.gaps === '1' ? '1 gap' : `${item.gaps} gaps`;
 switch (item.recording) {
  case 'complete': return { word: 'Complete', tone: 'ok', detail: item.gaps !== null && item.gaps !== '0' ? gaps : 'no gap reported' };
  case 'partial': return { word: 'Partial', tone: 'high', detail: gaps === '' ? 'gaps not counted' : gaps };
  case 'gap': return { word: 'Has a gap', tone: 'high', detail: gaps === '' ? 'gaps not counted' : gaps };
  case 'unknown': return { word: 'Not stated', tone: 'unk', detail: 'the server did not state how complete it is' };
 }
}

/** The recorded length: from the first to the last chunk, or "not stated". Exact nanoseconds in, whole seconds out (a replay is minutes, not nanoseconds). */
export function lengthText(firstAt: string | null, lastAt: string | null): string {
 if (firstAt === null || lastAt === null) return 'not stated';
 const ns = BigInt(lastAt) - BigInt(firstAt);
 if (ns < 0n) return 'not stated';
 const seconds = Number(ns / 1_000_000_000n);
 if (seconds < 60) return `${(Number(ns / 1_000_000n) / 1000).toFixed(1)} s`;
 const min = Math.floor(seconds / 60);
 return `${min} min ${seconds % 60} s`;
}

export const chunksText = (n: string | null): string => (n === null ? 'not stated' : n === '1' ? '1 chunk' : `${n} chunks`);
