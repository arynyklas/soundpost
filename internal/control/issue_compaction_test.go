// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// Occurrence-ledger compaction (06.02-W3), verified by control: evidence only
// leaves a ledger by being folded into an aggregate that control recomputes.

func (f *issFx) ledger(fp byte, from, to int) []model.GroupingEvidence {
	var out []model.GroupingEvidence
	for i := from; i <= to; i++ {
		out = append(out, f.evidence(fp, uint64(i)))
	}
	return out
}

func clone(t *testing.T, gi model.GroupingIssue) model.GroupingIssue {
	t.Helper()
	raw, err := json.Marshal(gi)
	if err != nil {
		t.Fatal(err)
	}
	var out model.GroupingIssue
	if err = json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestControlVerifiesEveryCompaction(t *testing.T) {
	f := newIssFx(t)
	prior := f.ledger(1, 1, model.GroupingWindowMax)
	f.must(control.IssueCommand{Records: []control.IssueRecordChange{f.record(f.issue(1, 1, prior...))}})
	revision := model.Revision(1)
	try := func(next model.GroupingIssue) error {
		t.Helper()
		_, err := f.commit(control.IssueCommand{ExpectedRevision: revision, Records: []control.IssueRecordChange{f.record(next)}})
		return err
	}
	// The genuine compaction: the oldest half folded, one new occurrence appended.
	fresh := f.evidence(1, model.GroupingWindowMax+1)
	genuine := f.issue(1, 2, append(append([]model.GroupingEvidence(nil), prior[model.GroupingWindowKeep:]...), fresh)...)
	genuine.Compacted = (*model.GroupingCompaction)(nil).Fold(prior[:model.GroupingWindowKeep])
	with := func(mutate func(*model.GroupingIssue)) model.GroupingIssue {
		out := clone(t, genuine)
		mutate(&out)
		return out
	}
	overCap := f.issue(1, 2, append(append([]model.GroupingEvidence(nil), prior...), fresh)...)
	partial := f.issue(1, 2, append(append(append([]model.GroupingEvidence(nil), prior[:100]...), prior[612:]...), fresh)...)
	partial.Compacted = (*model.GroupingCompaction)(nil).Fold(prior[100:612])
	deep := f.issue(1, 2, append(append([]model.GroupingEvidence(nil), prior[1000:]...), fresh)...)
	deep.Compacted = (*model.GroupingCompaction)(nil).Fold(prior[:1000])
	tooMuchTail := with(func(gi *model.GroupingIssue) { gi.Compacted.Recent = append(gi.Compacted.Recent, model.ID{0x66}) })
	newWithAggregate := f.issue(2, 1, f.evidence(2, 1))
	newWithAggregate.Compacted = (*model.GroupingCompaction)(nil).Fold(f.ledger(2, 2, 3))

	for name, c := range map[string]struct {
		code model.Code
		next model.GroupingIssue
	}{
		"count one too small":     {model.Invalid, with(func(gi *model.GroupingIssue) { gi.Compacted.Count-- })},
		"count one too large":     {model.Invalid, with(func(gi *model.GroupingIssue) { gi.Compacted.Count++ })},
		"first event moved":       {model.Invalid, with(func(gi *model.GroupingIssue) { gi.Compacted.FirstEvent-- })},
		"last event moved":        {model.Invalid, with(func(gi *model.GroupingIssue) { gi.Compacted.LastEvent++ })},
		"first arrival moved":     {model.Invalid, with(func(gi *model.GroupingIssue) { gi.Compacted.FirstArrival++ })},
		"last arrival moved":      {model.Invalid, with(func(gi *model.GroupingIssue) { gi.Compacted.LastArrival++ })},
		"release first event":     {model.Invalid, with(func(gi *model.GroupingIssue) { gi.Compacted.Releases[0].FirstEvent++ })},
		"release dropped":         {model.Invalid, with(func(gi *model.GroupingIssue) { gi.Compacted.Releases = nil })},
		"tail altered":            {model.Invalid, with(func(gi *model.GroupingIssue) { gi.Compacted.Recent[0] = model.ID{0x77} })},
		"tail shortened":          {model.Invalid, with(func(gi *model.GroupingIssue) { gi.Compacted.Recent = gi.Compacted.Recent[1:] })},
		"tail over its bound":     {model.Quota, tooMuchTail},
		"tail names a window ID":  {model.Invalid, with(func(gi *model.GroupingIssue) { gi.Compacted.Recent[0] = gi.Occurrences[0].OccurrenceID })},
		"removal without a fold":  {model.Invalid, with(func(gi *model.GroupingIssue) { gi.Compacted = nil })},
		"aggregate with no count": {model.Invalid, with(func(gi *model.GroupingIssue) { gi.Compacted = &model.GroupingCompaction{} })},
		"fold booked as late":     {model.Invalid, with(func(gi *model.GroupingIssue) { gi.LateCompacted, gi.Compacted = gi.Compacted, nil })},
		"removal not a prefix":    {model.Invalid, partial},
		"kept evidence edited":    {model.Invalid, with(func(gi *model.GroupingIssue) { gi.Occurrences[0].EventTime++ })},
		"kept evidence reordered": {model.Invalid, with(func(gi *model.GroupingIssue) {
			gi.Occurrences[0], gi.Occurrences[1] = gi.Occurrences[1], gi.Occurrences[0]
		})},
		"fold leaves under a keep": {model.Invalid, deep},
		"window over the cap":      {model.Quota, overCap},
		"new issue with fold":      {model.Invalid, newWithAggregate},
	} {
		if err := try(c.next); code(err) != c.code {
			t.Errorf("%s: %v, want %s", name, err, c.code)
		}
	}
	if s := f.snap(); s.Revision != 1 || len(s.Issues) != 1 || len(s.Issues[0].Occurrences) != model.GroupingWindowMax || s.Issues[0].Compacted != nil {
		t.Fatalf("a refused compaction changed the book: revision %d, %d occurrences", s.Revision, len(s.Issues[0].Occurrences))
	}

	if err := try(genuine); err != nil {
		t.Fatalf("the genuine compaction: %v", err)
	}
	revision++
	stored := f.snap().Issues[0]
	if !reflect.DeepEqual(stored.Compacted, genuine.Compacted) || len(stored.Occurrences) != model.GroupingWindowKeep+1 || stored.Compacted.Count != model.GroupingWindowKeep {
		t.Fatalf("stored %d occurrences, aggregate %+v", len(stored.Occurrences), stored.Compacted)
	}

	// From the compacted state the aggregate is monotone and changes only by a fold.
	next := func(more ...model.GroupingEvidence) model.GroupingIssue {
		out := f.issue(1, 3, append(append([]model.GroupingEvidence(nil), genuine.Occurrences...), more...)...)
		out.Compacted = genuine.Compacted.Clone()
		return out
	}
	regress := next(f.evidence(1, 2000))
	regress.Compacted = nil
	edited := next(f.evidence(1, 2000))
	edited.Compacted.FirstEvent--
	grown := next(f.evidence(1, 2000))
	grown.Compacted = grown.Compacted.Fold(f.ledger(1, 3000, 3000))
	for name, c := range map[string]model.GroupingIssue{"aggregate dropped": regress, "aggregate edited without a removal": edited, "aggregate grown without a removal": grown} {
		if err := try(c); code(err) != model.Invalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A second fold continues from the first: the oldest kept evidence moves into the aggregate.
	chained := f.issue(1, 3, append(append([]model.GroupingEvidence(nil), genuine.Occurrences[1:]...), f.evidence(1, 2000))...)
	chained.Compacted = genuine.Compacted.Fold(genuine.Occurrences[:1])
	if err := try(chained); err != nil {
		t.Fatalf("a chained compaction: %v", err)
	}
	revision++
	if got := f.snap().Issues[0].Compacted; got.Count != model.GroupingWindowKeep+1 || got.Recent[len(got.Recent)-1] != genuine.Occurrences[0].OccurrenceID {
		t.Fatalf("chained aggregate %+v", got)
	}

	// An occurrence ID is held by one issue: a dedup tail ID is held too.
	tailID := f.snap().Issues[0].Compacted.Recent[3]
	thief := f.issue(2, 1, f.evidence(2, 1))
	thief.Occurrences[0].OccurrenceID = tailID
	if err := try(thief); code(err) != model.Conflict {
		t.Fatalf("another issue claiming a tail ID: %v", err)
	}
	thief.Occurrences[0].OccurrenceID = f.evidence(2, 1).OccurrenceID
	if err := try(thief); err != nil {
		t.Fatalf("an unrelated new issue: %v", err)
	}
}

// The late-history ledger folds by the same rule with its own aggregate.
func TestControlVerifiesLateHistoryCompaction(t *testing.T) {
	f := newIssFx(t)
	late := f.ledger(1, 1, model.GroupingWindowMax)
	gi := f.issue(1, 1)
	gi.LateHistory = late
	f.must(control.IssueCommand{Records: []control.IssueRecordChange{f.record(gi)}})
	next := f.issue(1, 2)
	next.LateHistory = append(append([]model.GroupingEvidence(nil), late[model.GroupingWindowKeep:]...), f.evidence(1, 2000))
	next.LateCompacted = (*model.GroupingCompaction)(nil).Fold(late[:model.GroupingWindowKeep])
	forged := clone(t, next)
	forged.LateCompacted.LastEvent++ // a well-formed aggregate that is not the fold of what left the ledger
	for name, c := range map[string]model.GroupingIssue{"forged late bound": forged} {
		if _, err := f.commit(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(c)}}); code(err) != model.Invalid {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := f.commit(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(next)}}); err != nil {
		t.Fatalf("the genuine late compaction: %v", err)
	}
	if got := f.snap().Issues[0]; got.Compacted != nil || got.LateCompacted == nil || got.LateCompacted.Count != model.GroupingWindowKeep {
		t.Fatalf("stored %+v", got)
	}
}

// R01-3: a fold is exact whatever side of the resolution boundary the folded
// evidence lies on, so a hot resolved issue can make room; a forged aggregate is
// still refused.
func TestControlFoldsPostBoundaryEvidenceExactly(t *testing.T) {
	f := newIssFx(t)
	boundary := model.UnixNano(1000 + 500)
	prior := f.ledger(1, 1, model.GroupingWindowMax)
	resolved := f.issue(1, 1, prior...)
	resolved.Workflow, resolved.ResolutionTime = "resolved", &boundary
	f.must(control.IssueCommand{Records: []control.IssueRecordChange{f.record(resolved)}})
	next := f.issue(1, 2, append(append([]model.GroupingEvidence(nil), prior[model.GroupingWindowKeep:]...), f.evidence(1, 2000))...)
	next.Compacted = (*model.GroupingCompaction)(nil).Fold(prior[:model.GroupingWindowKeep])
	next.Workflow, next.ResolutionTime = "resolved", &boundary
	forged := clone(t, next)
	forged.Compacted.LastEvent++
	if _, err := f.commit(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(forged)}}); code(err) != model.Invalid {
		t.Fatalf("a forged aggregate: %v", err)
	}
	if _, err := f.commit(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(next)}}); err != nil {
		t.Fatalf("folding evidence after the boundary of a resolved issue: %v", err)
	}
	if got := f.snap().Issues[0].Compacted; got.Count != model.GroupingWindowKeep || got.LastEvent <= boundary {
		t.Fatalf("aggregate %+v", got)
	}
}
