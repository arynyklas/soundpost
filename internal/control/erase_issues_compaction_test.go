// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// Privacy deletion over compacted issues (06.02-W3). A folded aggregate keeps no
// per-evidence record, build or producer IDs; it is dropped whole whenever a
// predicate cannot be shown not to reach it, never left attributing counts or
// times to deleted evidence.

type foldedSeed struct {
	markers []marker
	issue   model.GroupingIssue
	// Evidence i has event time 1000+10*i. The aggregate holds i in [0,512), the
	// window i in [512,1024].
}

func (f *issEraseFx) eventOf(i int) int64 { return int64(1000 + 10*i) }

func (f *issEraseFx) seedFolded() foldedSeed {
	f.t.Helper()
	s := foldedSeed{}
	var all []model.GroupingEvidence
	for i := 0; i <= model.GroupingWindowMax; i++ {
		m := newMarker(byte(10+i/200), byte(1+i%200))
		s.markers = append(s.markers, m)
		all = append(all, f.ev(1, m, f.eventOf(i), uint64(i+1)))
	}
	first := f.issue(1, 1, all[:model.GroupingWindowMax]...)
	f.must(control.IssueCommand{Records: []control.IssueRecordChange{f.record(first)}, Checkpoint: &control.IssueCheckpoint{Group: f.group, Index: model.GroupingWindowMax}})
	next := f.issue(1, 2, all[model.GroupingWindowKeep:]...)
	next.Compacted = (*model.GroupingCompaction)(nil).Fold(all[:model.GroupingWindowKeep])
	next.ObservedReleases = []model.ID{s.markers[5].release, s.markers[700].release}
	expl := json.RawMessage("[" + explanation(s.markers[5].occurrence, f.eventOf(5)) + "," + explanation(s.markers[700].occurrence, f.eventOf(700)) + "]")
	f.must(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{{Issue: next, Explanations: expl}},
		Effects: []control.IssueEffect{{ID: model.ID{0xEE, 5}, Kind: "regression", Issue: next.ID, Occurrence: s.markers[5].occurrence}, {ID: model.ID{0xEE, 7}, Kind: "regression", Issue: next.ID, Occurrence: s.markers[700].occurrence}}})
	s.issue = f.snap().Issues[0]
	if s.issue.Compacted == nil || s.issue.Compacted.Count != model.GroupingWindowKeep || len(s.issue.Occurrences) != model.GroupingWindowKeep+1 {
		f.t.Fatalf("fixture: %d in the window, aggregate %+v", len(s.issue.Occurrences), s.issue.Compacted)
	}
	// The folded evidence survives only as counts, bounds, release first events and tail IDs.
	for _, c := range []string{s.markers[5].occurrence.String(), s.markers[5].release.String()} {
		if !f.stateHolds(c) {
			f.t.Fatalf("fixture: %s not in the state", c)
		}
	}
	return s
}

func (f *issEraseFx) rangeOver(start, end int64, signals ...model.Kind) control.DeleteScope {
	return control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: signals, Start: model.UnixNano(start), End: model.UnixNano(end)}
}

func (f *issEraseFx) entity(ids ...model.ID) control.DeleteScope {
	return control.DeleteScope{Mode: model.DeleteEntity, Projects: []model.ID{f.project}, Entities: ids, Signals: []model.Kind{model.Replay}}
}

func TestRangeOverlappingAnAggregateDropsItWhole(t *testing.T) {
	f := newIssEraseFx(t)
	s := f.seedFolded()
	// A range inside the aggregate's bounds that reaches no evidence still in the window.
	f.saga(f.rangeOver(f.eventOf(100), f.eventOf(110), model.ErrorKind))
	got := f.snap().Issues[0]
	if got.Compacted != nil || len(got.Occurrences) != model.GroupingWindowKeep+1 || got.Revision != s.issue.Revision+1 {
		t.Fatalf("aggregate %+v, %d in the window, revision %d", got.Compacted, len(got.Occurrences), got.Revision)
	}
	for _, c := range []string{s.markers[5].occurrence.String(), s.markers[5].release.String(), s.markers[400].occurrence.String()} {
		f.gone(c)
	}
	// What the window still holds, and what hangs off it, stays.
	f.kept(s.markers[700].record.String())
	book := f.snap()
	if e := string(book.Explanations[got.ID]); strings.Contains(e, s.markers[5].occurrence.String()) || !strings.Contains(e, s.markers[700].occurrence.String()) {
		t.Fatalf("explanations %s", e)
	}
	if len(book.Effects) != 1 || book.Effects[0].Occurrence != s.markers[700].occurrence {
		t.Fatalf("effects %+v", book.Effects)
	}
	if !reflect.DeepEqual(got.ObservedReleases, []model.ID{s.markers[700].release}) {
		t.Fatalf("observed releases %v: the dropped aggregate's release survived", got.ObservedReleases)
	}
}

func TestRangeOutsideAnAggregateOrOfAnotherSignalKeepsIt(t *testing.T) {
	f := newIssEraseFx(t)
	s := f.seedFolded()
	before := f.snap()
	f.saga(f.rangeOver(f.eventOf(2000), f.eventOf(3000), model.ErrorKind)) // after everything
	f.saga(f.rangeOver(0, f.eventOf(0), model.ErrorKind))                  // ends exactly where the aggregate starts: half-open, not reached
	f.saga(f.rangeOver(f.eventOf(100), f.eventOf(110), model.Metric))      // overlapping, but not the error signal
	if after := f.snap(); !reflect.DeepEqual(after.Issues, before.Issues) || !reflect.DeepEqual(after.Explanations, before.Explanations) {
		t.Fatalf("a range that reaches no evidence changed the issue:\n%+v\n%+v", before.Issues[0].Compacted, after.Issues[0].Compacted)
	}
	f.kept(s.markers[5].occurrence.String())
	// The range starts just past the aggregate's last event.
	f.saga(f.rangeOver(f.eventOf(511)+1, f.eventOf(511)+5, model.ErrorKind))
	if got := f.snap().Issues[0]; got.Compacted == nil || got.Compacted.Count != model.GroupingWindowKeep {
		t.Fatalf("aggregate after a range past its last event: %+v", got.Compacted)
	}
}

// A range whose first instant is the aggregate's last event reaches it.
func TestRangeStartingAtTheLastEventOfAnAggregateDropsIt(t *testing.T) {
	f := newIssEraseFx(t)
	f.seedFolded()
	f.saga(f.rangeOver(f.eventOf(511), f.eventOf(511)+1, model.ErrorKind))
	if got := f.snap().Issues[0]; got.Compacted != nil || len(got.Occurrences) != model.GroupingWindowKeep+1 {
		t.Fatalf("aggregate %+v after a range that starts at its last event", got.Compacted)
	}
}

// Window evidence is erased as before; an aggregate that does not overlap the
// range survives, so an issue with an empty window but a count is still an issue.
func TestRangeOverTheWindowKeepsAnAggregateOutsideIt(t *testing.T) {
	f := newIssEraseFx(t)
	s := f.seedFolded()
	f.saga(f.rangeOver(f.eventOf(512), f.eventOf(2000), model.ErrorKind))
	snap := f.snap()
	if len(snap.Issues) != 1 {
		t.Fatalf("issues %d: an issue holding an aggregate was removed with its window", len(snap.Issues))
	}
	got := snap.Issues[0]
	if len(got.Occurrences) != 0 || got.Compacted == nil || got.Compacted.Count != model.GroupingWindowKeep || got.Compacted.LastEvent != model.UnixNano(f.eventOf(511)) {
		t.Fatalf("issue %+v", got)
	}
	f.gone(s.markers[700].record.String())
	f.kept(s.markers[5].occurrence.String())
	if e := string(snap.Explanations[got.ID]); !strings.Contains(e, s.markers[5].occurrence.String()) || strings.Contains(e, s.markers[700].occurrence.String()) {
		t.Fatalf("explanations %s", e)
	}
	// Everything: the issue goes with its book entries.
	f.saga(f.rangeOver(0, f.eventOf(2000), model.ErrorKind))
	if snap = f.snap(); len(snap.Issues) != 0 || len(snap.Effects) != 0 || len(snap.Explanations) != 0 {
		t.Fatalf("after erasing every evidence: %+v", snap)
	}
	f.gone(s.markers[5].occurrence.String())
}

func TestEntityNamingATailOccurrenceOrFoldedReleaseDropsTheAggregate(t *testing.T) {
	// The deletion's own predicate keeps the entity ID it names; every other ID the
	// aggregate held must go.
	for name, c := range map[string]struct {
		entity func(s foldedSeed) model.ID
		gone   func(s foldedSeed) []model.ID
	}{
		"a tail occurrence":           {func(s foldedSeed) model.ID { return s.markers[300].occurrence }, func(s foldedSeed) []model.ID { return []model.ID{s.markers[5].occurrence, s.markers[300].release} }},
		"a release first seen folded": {func(s foldedSeed) model.ID { return s.markers[5].release }, func(s foldedSeed) []model.ID { return []model.ID{s.markers[5].occurrence, s.markers[400].release} }},
	} {
		t.Run(name, func(t *testing.T) {
			f := newIssEraseFx(t)
			s := f.seedFolded()
			f.saga(f.entity(c.entity(s)))
			got := f.snap().Issues[0]
			if got.Compacted != nil || len(got.Occurrences) != model.GroupingWindowKeep+1 || got.Revision != s.issue.Revision+1 {
				t.Fatalf("aggregate %+v, %d in the window, revision %d", got.Compacted, len(got.Occurrences), got.Revision)
			}
			for _, id := range c.gone(s) {
				f.gone(id.String())
			}
			f.kept(s.markers[700].record.String())
		})
	}
}

// An entity naming a window evidence's record drops that evidence only.
func TestEntityNamingAWindowRecordKeepsTheAggregate(t *testing.T) {
	f := newIssEraseFx(t)
	s := f.seedFolded()
	f.saga(f.entity(s.markers[700].record))
	got := f.snap().Issues[0]
	if !reflect.DeepEqual(got.Compacted, s.issue.Compacted) || len(got.Occurrences) != model.GroupingWindowKeep || got.Revision != s.issue.Revision+1 {
		t.Fatalf("aggregate %+v, %d in the window, revision %d", got.Compacted, len(got.Occurrences), got.Revision)
	}
	if !reflect.DeepEqual(got.ObservedReleases, []model.ID{s.markers[5].release}) {
		t.Fatalf("observed releases %v: the release the aggregate still names must stay, the dropped evidence's must go", got.ObservedReleases)
	}
	f.gone(s.markers[700].occurrence.String())
	f.kept(s.markers[5].occurrence.String())
}

// The residual, pinned: the aggregate keeps no record IDs, so an entity naming the
// record of an evidence that was folded cannot be attributed to the aggregate and
// leaves it. The count and times it holds are not content, and the record itself
// is in no ledger any more.
func TestEntityNamingAFoldedRecordCannotBeAttributed(t *testing.T) {
	f := newIssEraseFx(t)
	s := f.seedFolded()
	f.saga(f.entity(s.markers[5].record))
	if got := f.snap().Issues[0]; !reflect.DeepEqual(got, s.issue) {
		t.Fatalf("an entity that names nothing the issue holds changed it: %+v", got.Compacted)
	}
}

// The late-history aggregate is erased by the same rule as the occurrence one.
func TestRangeOverlappingALateAggregateDropsIt(t *testing.T) {
	f := newIssEraseFx(t)
	var late []model.GroupingEvidence
	for i := range model.GroupingWindowMax {
		late = append(late, f.ev(2, newMarker(byte(30+i/200), byte(1+i%200)), f.eventOf(i), uint64(i+1)))
	}
	gi := f.issue(2, 1)
	gi.LateHistory = late
	f.must(control.IssueCommand{Records: []control.IssueRecordChange{f.record(gi)}})
	next := f.issue(2, 2)
	next.LateHistory = late[model.GroupingWindowKeep:]
	next.LateCompacted = (*model.GroupingCompaction)(nil).Fold(late[:model.GroupingWindowKeep])
	f.must(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(next)}})
	f.saga(f.rangeOver(f.eventOf(100), f.eventOf(110), model.ErrorKind))
	got := f.snap().Issues[0]
	if got.LateCompacted != nil || len(got.LateHistory) != model.GroupingWindowKeep || got.Revision != 3 {
		t.Fatalf("late aggregate %+v, %d in the late window, revision %d", got.LateCompacted, len(got.LateHistory), got.Revision)
	}
	f.gone(newMarker(30, 6).occurrence.String())
}
