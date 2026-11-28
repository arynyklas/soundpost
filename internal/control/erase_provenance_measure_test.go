// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/conditions"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/jobs"
	"github.com/arynyklas/soundpost/internal/model"
)

// 09.08x-W1 / 11.03-W4: measure, on states the real producers' reducers fold, what a
// historical range deletion does to an incident, a condition and a job whose
// evidence interval straddles the range, and what the per-state provenance changes.
//
// Ground truth is the producer's own input: a state is AFFECTED when a record it
// folded has its time inside the range's half-open [start,end), whether or not
// that record has since rolled out of the state's bounded part. For each state the
// outcome is one of
//
//	erased          affected and dropped                      (right)
//	residue         affected and kept: derived data survives  (the W4 residual)
//	over-erased     not affected and dropped                  (fail-closed or hull)
//	kept            not affected and kept                     (right)
//
// The corpus is 200 conditions, 200 incidents and 54 jobs. Every state is built twice,
// once as this build writes it (with provenance) and once as a legacy build wrote it
// (the same state with the provenance member removed), and the deletion runs over
// each at begin/completion and as the late pass of a later effect.

const (
	provStart = model.UnixNano(1_000_000)
	provEnd   = model.UnixNano(2_000_000)
)

type provItem struct {
	book     string // incident, condition, job
	class    string
	id       model.ID
	state    json.RawMessage
	affected bool
}

// provTimes are the times of one class: n times before the start, then k inside,
// then m after the end, ascending.
func provTimes(rng *rand.Rand, before, inside, after int) []model.UnixNano {
	var out []model.UnixNano
	for range before {
		out = append(out, model.UnixNano(1_000+rng.Int64N(int64(provStart)-2_000)))
	}
	for range inside {
		out = append(out, provStart+model.UnixNano(rng.Int64N(int64(provEnd-provStart))))
	}
	for range after {
		out = append(out, provEnd+model.UnixNano(rng.Int64N(10_000_000)))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func provAffected(times []model.UnixNano) bool {
	for _, at := range times {
		if at >= provStart && at < provEnd {
			return true
		}
	}
	return false
}

func provConditions(t *testing.T, rng *rand.Rand, per int) []provItem {
	t.Helper()
	classes := []struct {
		name                  string
		before, inside, after int
	}{
		{"before", 12, 0, 0},
		{"after", 0, 0, 12},
		{"visible inside", 5, 2, 3},
		{"straddle none inside", 8, 0, 8},
		// The condition's freshness moves on: an unknown evaluation after the first event past the
		// range, then healthy evidence, so the state no longer names the time of its first event.
		{"rolled out (3 inside, then 20 after)", 0, 3, 20},
	}
	var out []provItem
	for _, c := range classes {
		for range per {
			times := provTimes(rng, c.before, c.inside, c.after)
			id, epoch := model.NewID(), model.NewID()
			var st conditions.State
			for i, at := range times {
				if c.inside > 0 && c.after >= 20 && i == c.inside+1 {
					next, err := conditions.Observe(st, conditions.Observation{At: times[i-1], Health: conditions.HealthUnknown, Reason: "timeout"})
					if err != nil {
						t.Fatal(err)
					}
					st = next
				}
				status := "firing"
				if i%3 == 2 {
					status = "recovered"
				}
				next, err := conditions.Reduce(st, model.ConditionEvent{Condition: id, Epoch: epoch, Sequence: model.Uint64(i + 1), At: at, Status: status, Severity: "warning"})
				if err != nil {
					t.Fatal(err)
				}
				st = next
			}
			raw, err := json.Marshal(st)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, provItem{book: "condition", class: c.name, id: id, state: raw, affected: provAffected(times)})
		}
	}
	return out
}

func provIncidents(t *testing.T, rng *rand.Rand, org, project model.ID, per int) []provItem {
	t.Helper()
	classes := []struct {
		name                  string
		before, inside, after int
	}{
		{"before", 6, 0, 0},
		{"after", 0, 0, 6},
		{"visible inside", 3, 2, 3},
		{"straddle none inside", 4, 0, 4},
	}
	var out []provItem
	for _, c := range classes {
		for range per {
			times := provTimes(rng, c.before, c.inside, c.after)
			id, cond, actor := model.NewID(), model.NewID(), model.NewID()
			var st incidents.State
			for i, at := range times {
				a := incidents.Action{CommandID: model.NewID(), ExpectedVersion: st.Version, Actor: actor, Target: incidents.Target{Org: org, Project: project, Incident: id}}
				if i == 0 {
					a.Type, a.Origin = incidents.TypeOpen, incidents.OriginSystem
					a.Impact = &incidents.Impact{Condition: cond, Episode: model.NewID(), Severity: incidents.SeverityMinor, State: incidents.ConditionFiring, Freshness: incidents.FreshnessFresh}
				} else {
					owner := model.NewID()
					a.Type, a.Origin, a.Owner = incidents.TypeAssign, incidents.OriginHuman, &owner
				}
				next, _, err := incidents.Apply(st, a, at)
				if err != nil {
					t.Fatal(err)
				}
				st = next
			}
			raw, err := json.Marshal(st)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, provItem{book: "incident", class: c.name, id: id, state: raw, affected: provAffected(times)})
		}
	}
	return out
}

func provJobs(t *testing.T, rng *rand.Rand, org, project model.ID, per int) []provItem {
	t.Helper()
	classes := []struct {
		name                  string
		before, inside, after int
		n                     int
	}{
		{"before", 6, 0, 0, per},
		{"after", 0, 0, 6, per},
		{"visible inside", 3, 2, 3, per},
		{"straddle none inside", 4, 0, 4, per},
		// 3 runs inside the range and 5 after it are the oldest of 520, so the 8 that the state
		// compacts out cover the range and run past its end: every time the state still names
		// (and the compaction's through_ns) lies after the end.
		{"rolled out (3 inside, 5 after, 512 later)", 0, 3, 5 + 512, per / 2},
	}
	var out []provItem
	for _, c := range classes {
		for range c.n {
			times := provTimes(rng, c.before, c.inside, c.after)
			if strings.HasPrefix(c.name, "rolled") {
				// The oldest 8 runs are the 3 inside and 5 of the later ones; the other 512 follow them.
				for i := 8; i < len(times); i++ {
					times[i] += 20_000_000
				}
			}
			job, epoch := model.NewID(), model.NewID()
			st := jobs.JobState{Org: org, Project: project}
			for i, at := range times {
				var run, attempt model.ID
				run[0], run[1], run[2], attempt[0], attempt[1], attempt[2] = 0xa1, byte(i>>8), byte(i), 0xa2, byte(i>>8), byte(i)
				next, _, err := jobs.ReduceEvent(st, model.JobAttemptEvent{Job: job, Run: run, Attempt: attempt, Schedule: fmt.Sprintf("m-%d", i), Ordinal: 1, Epoch: epoch, Sequence: 1, State: "started", Observed: at})
				if err != nil {
					t.Fatal(err)
				}
				st = next
			}
			raw, err := json.Marshal(st)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, provItem{book: "job", class: c.name, id: job, state: raw, affected: provAffected(times)})
		}
	}
	return out
}

// legacy returns the state as a build before the provenance wrote it.
func (it provItem) legacy(t *testing.T) json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(it.state, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "provenance")
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *eraseFx) seedItems(items []provItem, legacy bool) {
	f.t.Helper()
	if err := f.store.Update(f.ctx, func(st *control.State) error {
		if st.IncidentBooks == nil {
			st.IncidentBooks = map[string]json.RawMessage{}
		}
		if st.ConditionBooks == nil {
			st.ConditionBooks = map[string]json.RawMessage{}
		}
		if st.JobBooks == nil {
			st.JobBooks = map[string]json.RawMessage{}
		}
		for _, it := range items {
			state := it.state
			if legacy {
				state = it.legacy(f.t)
			}
			key := f.org.String() + ":" + f.project.String() + ":" + it.id.String()
			var rec any
			switch it.book {
			case "incident":
				rec = control.IncidentRecord{Org: f.org, Project: f.project, ID: it.id, Version: 1, State: state}
			case "condition":
				rec = control.ConditionRecord{Org: f.org, Project: f.project, ID: it.id, Version: 1, State: state}
			default:
				rec = control.JobRecord{Org: f.org, Project: f.project, Job: it.id, Version: 1, State: state}
			}
			raw, err := json.Marshal(rec)
			if err != nil {
				return err
			}
			switch it.book {
			case "incident":
				st.IncidentBooks[key] = raw
			case "condition":
				st.ConditionBooks[key] = raw
			default:
				st.JobBooks[key] = raw
			}
		}
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
}

// erasedItems reports, per state ID, whether the control state now holds a tombstone.
func (f *eraseFx) erasedItems() map[model.ID]bool {
	f.t.Helper()
	out := map[model.ID]bool{}
	read := func(books map[string]json.RawMessage) {
		for _, raw := range books {
			var rec struct {
				ID    model.ID `json:"id"`
				Job   model.ID `json:"job"`
				State struct {
					Erased string `json:"erased"`
				} `json:"state"`
			}
			if err := json.Unmarshal(raw, &rec); err != nil {
				f.t.Fatal(err)
			}
			id := rec.ID
			if id == (model.ID{}) {
				id = rec.Job
			}
			out[id] = rec.State.Erased != ""
		}
	}
	if err := f.store.View(f.ctx, func(st control.State) error {
		read(st.IncidentBooks)
		read(st.ConditionBooks)
		read(st.JobBooks)
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return out
}

type provTally struct{ erased, residue, over, kept int }

func provMeasure(items []provItem, erased map[model.ID]bool) (byBook map[string]*provTally, byClass map[string]*provTally) {
	byBook, byClass = map[string]*provTally{}, map[string]*provTally{}
	for _, it := range items {
		for _, tally := range []*provTally{tallyOf(byBook, it.book), tallyOf(byClass, it.book+": "+it.class)} {
			switch gone := erased[it.id]; {
			case it.affected && gone:
				tally.erased++
			case it.affected:
				tally.residue++
			case gone:
				tally.over++
			default:
				tally.kept++
			}
		}
	}
	return
}

func tallyOf(m map[string]*provTally, k string) *provTally {
	if m[k] == nil {
		m[k] = &provTally{}
	}
	return m[k]
}

func provRange() control.DeleteScope {
	return control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: nil, Signals: []model.Kind{model.Metric}, Start: provStart, End: provEnd}
}

// runProvenanceMeasure builds the corpus, runs one range deletion over it as the
// begin/completion erasure (when late is false) or as the late pass of a later
// effect (when late is true: the states are written after the deletion completed
// and the next effect of the project re-runs the erasure over them), and returns
// the per-book and per-class tallies; it logs them.
func runProvenanceMeasure(t *testing.T, legacy, late bool) map[string]*provTally {
	t.Helper()
	f := newEraseFx(t)
	rng := rand.New(rand.NewPCG(9, 8))
	items := append(append(provConditions(t, rng, 40), provIncidents(t, rng, f.org, f.project, 50)...), provJobs(t, rng, f.org, f.project, 12)...)
	req := provRange()
	req.Projects = []model.ID{f.project}
	if late {
		f.saga(req)
		f.seedItems(items, legacy)
		// The next effect of the project: a condition committed at a time outside the range.
		f.commitCondition(f.newSeed(f.project, "CANARYLATEEFFECT"), int64(provEnd)+5)
	} else {
		f.seedItems(items, legacy)
		f.saga(req)
	}
	erased := f.erasedItems()
	byBook, byClass := provMeasure(items, erased)
	var overErased []model.OverErased
	for _, id := range sortedOps(f) {
		if op, _, err := f.store.DeletionOperation(f.ctx, id); err == nil {
			overErased = op.OverErased
		}
	}
	mode := map[bool]string{false: "with provenance", true: "legacy states"}[legacy]
	pass := map[bool]string{false: "begin+completion", true: "late pass"}[late]
	t.Logf("MEASURE [%s, %s] corpus: %d conditions, %d incidents, %d jobs; receipt over_erased=%v", mode, pass, countBook(items, "condition"), countBook(items, "incident"), countBook(items, "job"), overErased)
	for _, book := range []string{"condition", "incident", "job"} {
		ta := byBook[book]
		t.Logf("MEASURE [%s, %s] %-9s erased=%-3d residue(affected, kept)=%-3d over-erased=%-3d kept=%-3d", mode, pass, book, ta.erased, ta.residue, ta.over, ta.kept)
	}
	var classes []string
	for k := range byClass {
		classes = append(classes, k)
	}
	sort.Strings(classes)
	for _, k := range classes {
		ta := byClass[k]
		t.Logf("MEASURE [%s, %s]   %-58s erased=%-3d residue=%-3d over-erased=%-3d kept=%-3d", mode, pass, k, ta.erased, ta.residue, ta.over, ta.kept)
	}
	return byBook
}

func sortedOps(f *eraseFx) []model.ID {
	var ids []model.ID
	_ = f.store.View(f.ctx, func(st control.State) error {
		for _, op := range st.Deletions {
			ids = append(ids, op.Predicate.Operation)
		}
		return nil
	})
	return ids
}

func countBook(items []provItem, book string) int {
	n := 0
	for _, it := range items {
		if it.book == book {
			n++
		}
	}
	return n
}

// A state this build wrote carries its provenance, the earliest and latest record time it
// folded: the range deletion keeps no affected state (no rolled-out evidence survives).
// The interval cannot tell a state that spans the range from one with a record inside it,
// so a condition or a job that straddles the range without a record inside (40 and 12
// of the corpus) is erased in both passes: at begin as the window rule already did, and
// now in the late pass too (a legacy state is kept there). No other state is erased:
// nothing before or after the range. An incident's timeline never rolls out (a full
// timeline is a quota error), so no affected incident survives; it has no provenance
// and keeps the window rule: an incident that straddles the range is erased at begin.
func TestRangeDeletionOverProvenanceStatesLeavesNoResidue(t *testing.T) {
	for _, late := range []bool{false, true} {
		got := runProvenanceMeasure(t, false, late)
		for book, straddling := range map[string]int{"condition": 40, "job": 12} {
			if ta := got[book]; ta.residue != 0 || ta.over != straddling {
				t.Errorf("late=%v %s: residue=%d over-erased=%d, want 0 and the %d that straddle the range (%+v)", late, book, ta.residue, ta.over, straddling, *ta)
			}
		}
		wantOver := map[bool]int{false: 50, true: 0}[late]
		if ta := got["incident"]; ta.residue != 0 || ta.over != wantOver {
			t.Errorf("late=%v incident: residue=%d over-erased=%d, want 0 and %d (%+v)", late, ta.residue, ta.over, wantOver, *ta)
		}
	}
}

// Legacy states (written before the provenance) keep the old, documented behaviour: this
// is the measured residue the upgrade leaves for states that already exist. The numbers are
// logged; the test pins the direction (there is residue, nothing legacy is silently kept
// that the old rule erased), not a count that depends on the PRNG of the corpus.
func TestRangeDeletionOverLegacyStatesKeepsTheDocumentedResidue(t *testing.T) {
	for _, late := range []bool{false, true} {
		got := runProvenanceMeasure(t, true, late)
		if got["condition"].residue == 0 || got["job"].residue == 0 {
			t.Errorf("late=%v: the corpus shows no rolled-out residue for legacy states: conditions %+v jobs %+v", late, *got["condition"], *got["job"])
		}
	}
}
