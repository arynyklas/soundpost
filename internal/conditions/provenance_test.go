// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package conditions_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/conditions"
	"github.com/arynyklas/soundpost/internal/model"
)

// 09.08x-W1: the state records the earliest and the latest record time it was
// folded from, so the time of an event that rolled out of Recent still reaches a
// historical range deletion.

func span(t *testing.T, p *model.Provenance) [2]int64 {
	t.Helper()
	if p == nil {
		t.Fatal("the state has no provenance")
	}
	return [2]int64{int64(p.From), int64(p.To)}
}

func TestReduceRecordsTheEventTimeInTheProvenance(t *testing.T) {
	s := reduce(t, conditions.State{}, event(epoch1, 1, 500, "firing"))
	if got := span(t, s.Provenance); got != [2]int64{500, 500} {
		t.Fatalf("provenance after the first event: %v", got)
	}
	s = reduce(t, s, event(epoch1, 2, 900, "recovered"))
	if got := span(t, s.Provenance); got != [2]int64{500, 900} {
		t.Fatalf("provenance after the second event: %v", got)
	}
}

// The residual W4 names: more events than Recent holds, the oldest inside a range, every time
// the state still names after it. The provenance still covers the rolled-out event.
func TestProvenanceKeepsTheTimesThatRolledOutOfRecent(t *testing.T) {
	var s conditions.State
	const first = 100
	for i := range 3 * conditions.MaxRecent {
		s = reduce(t, s, event(epoch1, uint64(i+1), int64(first+1_000*i), "firing"))
	}
	if len(s.Recent) != conditions.MaxRecent || s.Recent[0].At <= first {
		t.Fatalf("fixture invalid: the first event did not roll out of Recent (%v)", s.Recent[0].At)
	}
	if got, want := span(t, s.Provenance), [2]int64{first, first + 1_000*int64(3*conditions.MaxRecent-1)}; got != want {
		t.Fatalf("provenance %v, want %v", got, want)
	}
	if !s.Provenance.Meets(first, first+1) {
		t.Fatal("a range over the rolled-out event does not meet the provenance")
	}
}

// Two numbers however much the state folds.
func TestProvenanceIsBoundedWhateverTheStateFolds(t *testing.T) {
	var s conditions.State
	var size int
	for i := range 500 {
		s = reduce(t, s, event(epoch1, uint64(i+1), int64(7+13*i), "firing"))
		if i == 150 {
			raw, _ := json.Marshal(s)
			size = len(raw)
		}
	}
	raw, _ := json.Marshal(s)
	if len(raw) > size+64 { // only the digits of the times and sequences may grow
		t.Fatalf("the state grew with the events folded: %d bytes after 151 events, %d after 500", size, len(raw))
	}
	if got := span(t, s.Provenance); got != [2]int64{7, 7 + 13*499} {
		t.Fatalf("provenance %v", got)
	}
}

// An event that changes nothing (an old or duplicate one) was not folded: its time is not evidence the state derives from.
func TestProvenanceIgnoresEventsThatAreNotFolded(t *testing.T) {
	s := reduce(t, conditions.State{}, event(epoch1, 5, 500, "firing"))
	for name, e := range map[string]model.ConditionEvent{
		"stale":     event(epoch1, 4, 100, "firing"),
		"duplicate": event(epoch1, 5, 500, "firing"),
	} {
		got, err := conditions.Reduce(s, e)
		if err != nil || got.Version != s.Version || span(t, got.Provenance) != [2]int64{500, 500} {
			t.Errorf("%s: version %d -> %d, provenance %+v, err %v", name, s.Version, got.Version, got.Provenance, err)
		}
	}
}

func TestObserveRecordsTheEvaluationTimeOnlyWhenItChangesTheState(t *testing.T) {
	s := reduce(t, conditions.State{}, event(epoch1, 1, 500, "firing"))
	got, err := conditions.Observe(s, conditions.Observation{At: 400, Health: conditions.HealthOK})
	if err != nil || got.Version != s.Version || span(t, got.Provenance) != [2]int64{500, 500} {
		t.Fatalf("a healthy observation of a fresh state changes nothing and records nothing: %+v %v", got.Provenance, err)
	}
	got, err = conditions.Observe(s, conditions.Observation{At: 800, Health: conditions.HealthUnknown, Reason: "timeout"})
	if err != nil || got.Version != s.Version+1 || span(t, got.Provenance) != [2]int64{500, 800} {
		t.Fatalf("an unknown observation is folded: %+v %v", got.Provenance, err)
	}
	// An observation older than the newest freshness evidence is not folded either.
	got, err = conditions.Observe(s, conditions.Observation{At: 450, Health: conditions.HealthUnknown, Reason: "timeout"})
	if err != nil || got.Version != s.Version || span(t, got.Provenance) != [2]int64{500, 500} {
		t.Fatalf("an observation older than the newest freshness evidence changes nothing: %+v %v", got.Provenance, err)
	}
}

func TestJoinRecordsBothTheEventAndTheEvaluation(t *testing.T) {
	s, err := conditions.Join(conditions.State{}, event(epoch1, 1, 500, "firing"), conditions.Observation{At: 700, Health: conditions.HealthUnknown, Reason: "timeout"})
	if err != nil || span(t, s.Provenance) != [2]int64{500, 700} {
		t.Fatalf("join: %+v %v", s.Provenance, err)
	}
}

// A state written before the field exists names an unknown set of earlier times, and what
// already rolled out of Recent is among them: starting a provenance now would read as complete.
func TestAStateWrittenBeforeTheProvenanceStaysWithout(t *testing.T) {
	legacy := reduce(t, conditions.State{}, event(epoch1, 1, 500, "firing"))
	legacy.Provenance = nil
	next := reduce(t, legacy, event(epoch1, 2, 900, "recovered"))
	if next.Provenance != nil {
		t.Fatalf("a legacy state started a provenance: %+v", next.Provenance)
	}
	next, err := conditions.Observe(next, conditions.Observation{At: 950, Health: conditions.HealthUnknown, Reason: "timeout"})
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

func TestProvenanceWireFormIsAnOptionalMember(t *testing.T) {
	s := reduce(t, conditions.State{}, event(epoch1, 1, 500, "firing"))
	raw, err := json.Marshal(s)
	if err != nil || !strings.Contains(string(raw), `"provenance":{"from_ns":"500","to_ns":"500"}`) {
		t.Fatalf("%s %v", raw, err)
	}
	var back conditions.State
	if err = json.Unmarshal(raw, &back); err != nil || back.Provenance == nil || back.Provenance.Validate() != nil || span(t, back.Provenance) != [2]int64{500, 500} {
		t.Fatalf("round trip: %+v %v", back.Provenance, err)
	}
	// A state a build before the member wrote decodes, without one.
	var members map[string]json.RawMessage
	if err = json.Unmarshal(raw, &members); err != nil {
		t.Fatal(err)
	}
	delete(members, "provenance")
	older, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	var old conditions.State
	if err = json.Unmarshal(older, &old); err != nil || old.Provenance != nil || old.Version != s.Version {
		t.Fatalf("an old state: %+v %v", old.Provenance, err)
	}
}
