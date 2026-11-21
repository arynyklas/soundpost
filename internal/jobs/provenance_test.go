// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package jobs_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/jobs"
	"github.com/arynyklas/soundpost/internal/model"
)

// 09.08x-W1: the state records the earliest and the latest record time it was
// folded from, so the time of a run that left through Compaction still reaches a
// historical range deletion.

// blank is a job state with the org and project a committed one always carries (a state with
// a zero ID cannot be marshalled).
func blank() jobs.JobState { return jobs.JobState{Org: model.ID{0x0a}, Project: model.ID{0x0b}} }

func provSpan(t *testing.T, p *model.Provenance) [2]model.UnixNano {
	t.Helper()
	if p == nil {
		t.Fatal("the state has no provenance")
	}
	return [2]model.UnixNano{p.From, p.To}
}

// manual is a started event of a manual (unscheduled) run number i observed at the given time.
func manual(i int, observed model.UnixNano) model.JobAttemptEvent {
	var run, attempt model.ID
	run[0], run[1], run[2], attempt[0], attempt[1], attempt[2] = 0xa1, byte(i>>8), byte(i), 0xa2, byte(i>>8), byte(i)
	return ev(run, attempt, fmt.Sprintf("m-%d", i), 1, 1, "started", observed, nil)
}

func TestReduceEventRecordsTheObservedTimeInTheProvenance(t *testing.T) {
	st := mustReduce(t, blank(), ev(runA, att1, "m-1", 1, 1, "started", 500, nil))
	if got := provSpan(t, st.Provenance); got != [2]model.UnixNano{500, 500} {
		t.Fatalf("provenance after the first event: %v", got)
	}
	end := model.UnixNano(900)
	st = mustReduce(t, st, ev(runA, att1, "m-1", 1, 2, "succeeded", 500, &end))
	// The record's time is Observed, the time the data rows are ranged by; the terminal time is payload.
	if got := provSpan(t, st.Provenance); got != [2]model.UnixNano{500, 500} {
		t.Fatalf("provenance after the terminal event: %v", got)
	}
	st = mustReduce(t, st, manual(2, 300))
	if got := provSpan(t, st.Provenance); got != [2]model.UnixNano{300, 500} {
		t.Fatalf("provenance after an older run: %v", got)
	}
}

// The residual W4 names, for a job: runs older than the retained ones leave through
// Compaction; the state keeps their count and newest time but not where each came from.
func TestProvenanceKeepsTheTimesOfRunsThatLeftTheState(t *testing.T) {
	st := blank()
	const first = model.UnixNano(1_000)
	for i := range jobs.MaxRetainedRuns + 8 {
		st = mustReduce(t, st, manual(i, first+model.UnixNano(i)*10))
	}
	if st.Compaction.Runs != 8 || len(st.Runs) != jobs.MaxRetainedRuns {
		t.Fatalf("fixture invalid: %d runs compacted, %d kept", st.Compaction.Runs, len(st.Runs))
	}
	if got, want := provSpan(t, st.Provenance), [2]model.UnixNano{first, first + model.UnixNano(jobs.MaxRetainedRuns+7)*10}; got != want {
		t.Fatalf("provenance %v, want %v (the oldest compacted run is the first time)", got, want)
	}
	if !st.Provenance.Meets(first, first+1) {
		t.Fatal("a range over the oldest compacted run does not meet the provenance")
	}
}

// The interval is the join of the times folded: any order of arrival gives the same one.
func TestProvenanceDoesNotDependOnTheOrderOfEvents(t *testing.T) {
	times := []model.UnixNano{700, 100, 400, 900, 250}
	var want [2]model.UnixNano
	for _, order := range [][]int{{0, 1, 2, 3, 4}, {4, 3, 2, 1, 0}, {2, 0, 4, 1, 3}} {
		st := blank()
		for _, i := range order {
			st = mustReduce(t, st, manual(i, times[i]))
		}
		got := provSpan(t, st.Provenance)
		if want == ([2]model.UnixNano{}) {
			want = got
		}
		if got != want || got != [2]model.UnixNano{100, 900} {
			t.Fatalf("order %v: provenance %v", order, got)
		}
	}
}

// An event that changes nothing (a duplicate, or one older than everything compacted out) was not folded.
func TestProvenanceIgnoresEventsThatAreNotFolded(t *testing.T) {
	st := mustReduce(t, blank(), ev(runA, att1, "m-1", 1, 1, "started", 500, nil))
	dup, outcome, err := jobs.ReduceEvent(st, ev(runA, att1, "m-1", 1, 1, "started", 500, nil))
	if err != nil || outcome != jobs.Duplicate || provSpan(t, dup.Provenance) != [2]model.UnixNano{500, 500} {
		t.Fatalf("duplicate: %v %+v %v", outcome, dup.Provenance, err)
	}
	full := blank()
	for i := range jobs.MaxRetainedRuns + 1 {
		full = mustReduce(t, full, manual(i, 10_000+model.UnixNano(i)*10))
	}
	old, outcome, err := jobs.ReduceEvent(full, manual(9_999, 100))
	if err != nil || outcome != jobs.Ignored || old.Provenance.Meets(0, 1_000) {
		t.Fatalf("an event older than the compacted history was recorded: %v %+v %v", outcome, old.Provenance, err)
	}
}

// A schedule observation is not recorded: what it leaves in the state names its own times and
// is never rolled out. A state that only holds observations has folded no attempt, so the
// first attempt starts its provenance. A correction is an operator action, not a record.
func TestObservationsAreNotRecordedAndTheFirstAttemptAfterOneStartsTheProvenance(t *testing.T) {
	def := &jobs.Definition{Revision: 1, EffectiveFrom: 100, Overlap: "allow"}
	st, outcome, err := jobs.Observe(blank(), jobs.ScheduleEvidence{Job: jobID, Observer: observe, ObservedAt: 700, CompleteThrough: 700, Healthy: true, Definition: def})
	if err != nil || outcome != jobs.Applied || st.Provenance != nil || st.Version == 0 {
		t.Fatalf("observe: %v %+v v%d %v", outcome, st.Provenance, st.Version, err)
	}
	end := model.UnixNano(600)
	st = mustReduce(t, st, ev(runA, att1, "m-1", 1, 1, "failed", 500, &end))
	if provSpan(t, st.Provenance) != [2]model.UnixNano{500, 500} {
		t.Fatalf("the first attempt after an observation did not start the provenance: %+v", st.Provenance)
	}
	later, _, err := jobs.Observe(st, jobs.ScheduleEvidence{Job: jobID, Observer: observe, ObservedAt: 800, CompleteThrough: 800, Healthy: true, Definition: def})
	if err != nil || provSpan(t, later.Provenance) != [2]model.UnixNano{500, 500} {
		t.Fatalf("an observation changed the provenance: %+v %v", later.Provenance, err)
	}
	fixed, outcome, err := jobs.ApplyCorrection(st, jobs.Correction{CommandID: model.NewID(), Job: jobID, Attempt: att1, Version: 1, State: jobs.AttemptSucceeded, Reason: "operator"}, model.ID{5}, 9_000)
	if err != nil || outcome != jobs.Applied || provSpan(t, fixed.Provenance) != provSpan(t, st.Provenance) {
		t.Fatalf("a correction is an operator action, not a record: %v %+v %v", outcome, fixed.Provenance, err)
	}
}

// A state written before the field exists names an unknown set of earlier times, and the runs
// that already left it are among them: starting a provenance now would read as complete.
func TestAJobStateWrittenBeforeTheProvenanceStaysWithout(t *testing.T) {
	legacy := mustReduce(t, blank(), ev(runA, att1, "m-1", 1, 1, "started", 500, nil))
	legacy.Provenance = nil
	next := mustReduce(t, legacy, manual(2, 900))
	if next.Provenance != nil {
		t.Fatalf("a legacy state started a provenance: %+v", next.Provenance)
	}
	next, _, err := jobs.Observe(next, jobs.ScheduleEvidence{Job: jobID, Observer: observe, ObservedAt: 950, CompleteThrough: 950, Healthy: true})
	if err != nil || next.Provenance != nil {
		t.Fatalf("a legacy state started a provenance from an observation: %+v %v", next.Provenance, err)
	}
	raw, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"provenance"`) {
		t.Fatalf("a state without provenance writes the member: %s", raw)
	}
}

func TestJobProvenanceWireFormIsAnOptionalMember(t *testing.T) {
	st := mustReduce(t, blank(), ev(runA, att1, "m-1", 1, 1, "started", 500, nil))
	raw, err := json.Marshal(st)
	if err != nil || !strings.Contains(string(raw), `"provenance":{"from_ns":"500","to_ns":"500"}`) {
		t.Fatalf("%s %v", raw, err)
	}
	var members map[string]json.RawMessage
	if err = json.Unmarshal(raw, &members); err != nil {
		t.Fatal(err)
	}
	delete(members, "provenance")
	older, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	var old jobs.JobState
	if err = json.Unmarshal(older, &old); err != nil || old.Provenance != nil || old.Version != st.Version {
		t.Fatalf("an old state: %+v %v", old.Provenance, err)
	}
}
