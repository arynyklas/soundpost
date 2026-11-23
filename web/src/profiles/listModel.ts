// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// Words for the profile list. Every profile keeps its own unit (samples or milliseconds); an unknown unit, coverage or window is "not stated", never zero, and an unsupported runtime is its reason in words.
import type { ProfileListItem } from '../api/console';
import type { Tone } from '../ui/primitives';

export const unitWord = (u: ProfileListItem['unit']): string => (u === 'unknown' ? 'unit not stated' : u);

/** A closed reason token in words ("unsupported_in_browser" reads "unsupported in browser"). The token itself stays in the title of its cell. */
export const reasonWords = (token: string): string => token.replace(/_/g, ' ');

export interface CoverageView { word: string; tone: Tone; detail: string }
/** What the profile says about its own coverage. Unknown coverage with a reason is an unsupported runtime; unknown without one is simply not stated. */
export function coverageView(item: Pick<ProfileListItem, 'coverage' | 'unsupportedReason'>): CoverageView {
 switch (item.coverage) {
  case 'complete': return { word: 'Complete', tone: 'ok', detail: 'every capability reported full coverage' };
  case 'partial': return { word: 'Partial', tone: 'high', detail: item.unsupportedReason !== undefined ? reasonWords(item.unsupportedReason) : 'some of the execution is missing and is not estimated' };
  case 'unknown': return item.unsupportedReason !== undefined
   ? { word: 'Unsupported', tone: 'unk', detail: reasonWords(item.unsupportedReason) }
   : { word: 'Not stated', tone: 'unk', detail: 'the server did not state the coverage' };
 }
}

/** The window the profile's observations span, or "not stated". Times come formatted by the caller; this only decides whether there is a window. */
export function windowText(first: string | null, last: string | null, fmt: (ns: string) => string): string {
 if (first === null && last === null) return 'not stated';
 if (first !== null && last !== null) return first === last ? fmt(first) : `${fmt(first)} to ${fmt(last)}`;
 return first !== null ? `from ${fmt(first)}` : `until ${fmt(last ?? '0')}`;
}
