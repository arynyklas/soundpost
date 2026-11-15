// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"slices"

	"github.com/arynyklas/soundpost/internal/model"
)

// The issue book's two append-only lists are bounded without a permanent refusal
// (R01-2). A project whose book is full of gaps or command records must keep
// declaring losses and acting on issues, so a full list makes room by an exact,
// deterministic rule instead of answering Quota for the rest of the project's life.

// appendIssueGap adds a declared gap to the book's list. With room it is a plain
// append. At maxIssueGaps the oldest gap that has a later gap of the same data
// group absorbs it (coalesceIssueGaps) so the list stays at the bound; a group
// holds its own checkpoint, so one of the existing gaps (or, last, the new gap
// itself) always shares a group with another, and a refusal is possible only when
// every gap is of a different group, which the group bound makes unreachable.
func appendIssueGap(gaps []model.EvidenceGap, g model.EvidenceGap) ([]model.EvidenceGap, error) {
	if len(gaps) < maxIssueGaps {
		return append(gaps, g), nil
	}
	for i := range gaps {
		for j := i + 1; j < len(gaps); j++ {
			if gaps[i].Group == gaps[j].Group {
				merged := coalesceIssueGaps(gaps[i], gaps[j])
				out := slices.Delete(slices.Clone(gaps), i, i+1)
				out[j-1] = merged
				return append(out, g), nil
			}
		}
	}
	for i := range gaps {
		if gaps[i].Group == g.Group {
			out := slices.Delete(slices.Clone(gaps), i, i+1)
			return append(out, coalesceIssueGaps(gaps[i], g)), nil
		}
	}
	return nil, model.Fail(model.Quota)
}

// coalesceIssueGaps is the one gap that stands for older and newer, two gaps of
// one data group (older was declared first). The lost count is the exact sum, the
// cursor span runs from the first gap's After to the last one's Through, the time
// range is the union, the signals are the union in first-seen order, the reason
// is the older gap's and the recording time and ID are the newer's, so a reader
// sees the newest declaration; Merged counts the declarations absorbed.
func coalesceIssueGaps(older, newer model.EvidenceGap) model.EvidenceGap {
	out := newer
	out.After, out.Through = min(older.After, newer.After), max(older.Through, newer.Through)
	out.Count = older.Count + newer.Count
	out.Start, out.End = min(older.Start, newer.Start), max(older.End, newer.End)
	out.Signals = slices.Clone(older.Signals)
	for _, k := range newer.Signals {
		if !slices.Contains(out.Signals, k) {
			out.Signals = append(out.Signals, k)
		}
	}
	out.Reason = older.Reason
	out.Merged = older.Merged + newer.Merged + 1
	return out
}

// evictOldestIssueCommand removes the explicit command record the book committed
// first (the lowest book revision; records written before revisions were stamped
// carry none and go first, in ID order) to make room for a new one. A command ID
// that was evicted is no longer recognized as a retry: an old command re-sent
// after a thousand newer ones is evaluated as a new one, and the issue's own
// revision check refuses a stale action.
func evictOldestIssueCommand(commands map[string]IssueCommandEntry) {
	oldest, found := "", false
	for key, entry := range commands {
		if !found || entry.Rev < commands[oldest].Rev || entry.Rev == commands[oldest].Rev && key < oldest {
			oldest, found = key, true
		}
	}
	if found {
		delete(commands, oldest)
	}
}
