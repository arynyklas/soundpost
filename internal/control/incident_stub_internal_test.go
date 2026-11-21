// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// R01-4: pruned-incident stubs are bounded oldest first, by pruning time then key,
// and nothing else is touched: a live incident, another project's stub, and a live
// state that merely contains the stub's text under a label are all left alone.
func TestIncidentStubsAreBoundedOldestFirst(t *testing.T) {
	org, project, other := model.ID{1}, model.ID{2}, model.ID{3}
	prefix := org.String() + ":" + project.String() + ":"
	st := &State{IncidentBooks: map[string]json.RawMessage{}}
	put := func(project model.ID, n int, state func(rec IncidentRecord) json.RawMessage) string {
		rec := IncidentRecord{Org: org, Project: project, ID: model.ID{0xb0, byte(n >> 8), byte(n)}, Version: 1}
		rec.State = state(rec)
		raw, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		key := incidentKey(org, project, rec.ID)
		st.IncidentBooks[key] = raw
		return key
	}
	stub := func(at model.UnixNano) func(IncidentRecord) json.RawMessage {
		return func(rec IncidentRecord) json.RawMessage { return prunedIncidentState(rec, at) }
	}
	var keys []string
	for n := range 10 {
		keys = append(keys, put(project, n, stub(model.UnixNano(100+n/2)))) // pairs share a pruning time: the key breaks the tie
	}
	live := put(project, 100, func(rec IncidentRecord) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{"incident_id":%q,"org_id":%q,"project_id":%q,"version":"1","status":"open","labels":{"erased":"pruned"}}`, rec.ID.String(), rec.Org.String(), rec.Project.String()))
	})
	foreign := put(other, 200, stub(1))
	if got := boundIncidentStubs(st, prefix, 4); got != 6 {
		t.Fatalf("dropped %d stubs, want 6", got)
	}
	for i, key := range keys {
		_, held := st.IncidentBooks[key]
		if want := i >= 6; held != want {
			t.Fatalf("stub %d held=%v, want %v (oldest first)", i, held, want)
		}
	}
	if _, ok := st.IncidentBooks[live]; !ok {
		t.Fatal("a live incident whose label reads like a stub was dropped")
	}
	if _, ok := st.IncidentBooks[foreign]; !ok {
		t.Fatal("another project's stub was dropped")
	}
	if got := boundIncidentStubs(st, prefix, 4); got != 0 {
		t.Fatalf("a second pass dropped %d", got)
	}
}
