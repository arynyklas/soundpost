// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// The selection and stored-frames flow of the issue page, apart from React: which occurrence is open, under what read key it was
// chosen, and the one frame lookup the page makes from the frames the stored record names (never typed or guessed).
import type { ErrorOccurrenceDetail, FramesRequest, Id, IssueEvidenceView, OccurrenceEvidence } from '../api/types';
import { scopeKey, type ViewContext } from '../app/context';
import { MAX_FRAMES } from '../evidence/model';

/** The key of everything read for one issue in one scope. A new scope, project, issue or generation is a new key. */
export function issueReadKey(context: ViewContext, project: Id, issue: Id): string {
 return `${scopeKey(context)}|${project}|${issue}|${context.generation}`;
}

/** The key of the stored read behind one occurrence of the issue. */
export function occurrenceReadKey(context: ViewContext, project: Id, issue: Id, occurrence: Id): string {
 return `${scopeKey(context)}|${project}|${issue}|${occurrence}|${context.generation}`;
}

/** An occurrence is chosen under the read key that was current when it was chosen. */
export interface Selection { key: string; id: Id }

/** The chosen occurrence for this key, or null. A selection made under another scope, project, issue or generation is dropped, so a stored record can never be shown for an issue it was not chosen in. */
export function selectedFor(held: Selection | null, key: string): Id | null {
 return held !== null && held.key === key ? held.id : null;
}

/** The occurrence the person chose, looked up in the issue view as it is now: the current occurrences first, then the late history. A view that no longer lists it shows nothing; the browser never keeps an occurrence the server stopped naming. */
export function chosenOccurrence(view: IssueEvidenceView | undefined, selected: Id | null): OccurrenceEvidence | undefined {
 if (view === undefined || selected === null) return undefined;
 return [...view.occurrences, ...view.late_history].find((o) => o.occurrence_id === selected);
}

/** The lookup of a stored record's frames: the request, the key that scopes the read, and how many stored frames are not sent. `null` when the record stores no frames, so there is nothing to map and no read. */
export interface StoredFramesPlan { request: FramesRequest; key: string; unsent: number }

export function storedFramesPlan(context: ViewContext, project: Id, detail: ErrorOccurrenceDetail): StoredFramesPlan | null {
 if (detail.frames.length === 0) return null;
 const sent = detail.frames.slice(0, MAX_FRAMES);
 return {
  request: { org: context.org, project, build: detail.build_id, frames: sent, include_sources: false },
  key: `${scopeKey(context)}|${project}|frames|${detail.build_id}|${JSON.stringify(sent)}|${context.generation}`,
  unsent: detail.frames.length - sent.length,
 };
}
