// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// A job's book keeps its occurrences, runs and attempts as maps inside the one member `state` of the job's record: at the gate a
// job record is 40 KB in minute 1 and over 140 KB in minute 20, and an update adds one entry to a map or changes one. The delta that
// says only the members of the record that changed (a whole `state`) was not smaller than half of it, so those updates were written
// whole: the job books were still 3 KB of a settle round's patch in minute 1 and 32 KB in minute 20 (cs1, set:JobBooks per
// settlement command). The delta goes into the object members: the entries of a map that changed.

// jobBookState is a job state of n occurrences, runs and attempts (maps) and a history, as the encoder of a record writes it (keys in order).
func jobBookState(n int, history int) map[string]any {
	maps := func(prefix string) map[string]any {
		m := map[string]any{}
		for i := range n {
			m[fmt.Sprintf("%s-%05d", prefix, i*2)] = map[string]any{"at_ns": 1_000_000 + i, "status": "ok", "detail": "a run of the job with its inputs and what it produced", "digest": fmt.Sprintf("%064d", i)}
		}
		return m
	}
	h := make([]any, history)
	for i := range h {
		h[i] = map[string]any{"n": i, "kind": "attempt"}
	}
	return map[string]any{"occurrences": maps("occ"), "runs": maps("run"), "attempts": maps("att"), "history": h, "incomplete_intervals": []any{}}
}

func jobBookRecord(t *testing.T, version int, state map[string]any, commands int) []byte {
	t.Helper()
	rawState, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	rec := JobRecord{Org: model.ID{1}, Project: model.ID{2}, Job: model.ID{3}, Version: model.Revision(version), State: rawState}
	for i := range commands {
		rec.Commands = append(rec.Commands, commandEntry(i))
	}
	return jobRecordBytes(t, rec)
}

func TestRecordDeltaOfAJobBookCarriesTheMapEntriesThatChanged(t *testing.T) {
	const entries = 120
	before := jobBookRecord(t, 7, jobBookState(entries, 50), 300)
	if len(before) < 60<<10 {
		t.Fatalf("the record is %d bytes: not the size of the gate's job books", len(before))
	}
	state := jobBookState(entries, 50)
	// a new member in the middle of the map
	state["occurrences"].(map[string]any)["occ-00101"] = map[string]any{"at_ns": 5, "status": "new", "detail": "an occurrence between two others", "digest": fmt.Sprintf("%064d", 9)}
	// a changed member
	state["runs"].(map[string]any)["run-00040"] = map[string]any{"at_ns": 6, "status": "done", "detail": "a run that finished", "digest": fmt.Sprintf("%064d", 10)}
	// a member that is gone
	delete(state["attempts"].(map[string]any), "att-00020")
	state["history"] = append(state["history"].([]any), map[string]any{"n": 50, "kind": "attempt"})
	after := jobBookRecord(t, 8, state, 301)
	op, ok := recordDeltaOp([]string{"JobBooks", "k"}, before, after)
	if !ok {
		t.Fatalf("the record of %d bytes is written whole: its update changed 4 entries of its maps", len(after))
	}
	if len(op.Value) > 2500 {
		t.Errorf("the delta of one update is %d bytes on a record of %d", len(op.Value), len(after))
	}
	got, err := applyRecordDelta(before, wireOf(t, op))
	if err != nil || !bytes.Equal(got, after) {
		t.Fatalf("the delta does not take the record to the one the proposer holds: %v", err)
	}
}

// Whatever the maps of a record do, a delta is either the record the proposer left byte for byte or it is not proposed.
func TestRecordDeltaOfMapEntriesIsTheRecordTheProposerLeftOrIsNotUsed(t *testing.T) {
	rng := rand.New(rand.NewPCG(108, 7))
	used := 0
	for round := range 60 {
		n := 20 + rng.IntN(60)
		before := jobBookRecord(t, 1, jobBookState(n, 5), 10)
		state := jobBookState(n, 5)
		for range 1 + rng.IntN(6) {
			name := []string{"occurrences", "runs", "attempts"}[rng.IntN(3)]
			m := state[name].(map[string]any)
			key := fmt.Sprintf("%s-%05d", name[:3], rng.IntN(2*n+3))
			switch rng.IntN(3) {
			case 0:
				delete(m, key)
			default:
				m[key] = map[string]any{"at_ns": rng.IntN(1000), "status": fmt.Sprint("s", rng.IntN(5)), "detail": "x<&>\u2028\"é", "digest": "d"}
			}
		}
		if rng.IntN(4) == 0 {
			state["extra"] = map[string]any{"k": rng.IntN(10)} // a new member in the middle of the state
		}
		after := jobBookRecord(t, 2, state, 10)
		op, ok := recordDeltaOp([]string{"JobBooks", "k"}, before, after)
		if !ok {
			continue
		}
		used++
		got, err := applyRecordDelta(before, wireOf(t, op))
		if err != nil || !bytes.Equal(got, after) {
			t.Fatalf("round %d: the delta does not reproduce the record: %v", round, err)
		}
	}
	if used < 30 {
		t.Errorf("only %d of 60 updates of maps were written as deltas", used)
	}
}
