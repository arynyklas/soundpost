// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package profile

import (
	"encoding/json"
	"os"
	"testing"
	"testing/fstest"
)

// TestProfilesListsOnlyAcceptedProfilesInOrderAsCopies: the listing the console
// reads is every accepted (complete) pinned profile, ordered by identifier,
// with all of its feature sets; a profile whose inventory is not accepted is
// never listed (Resolve refuses it too), and the listing aliases nothing in
// the registry.
func TestProfilesListsOnlyAcceptedProfilesInOrderAsCopies(t *testing.T) {
	files := fstest.MapFS{}
	for id := range pins {
		raw, err := os.ReadFile("../../../profiles/query/" + id + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if id == "logql-loki-3.5.2" { // one profile whose inventory is not accepted
			var doc map[string]json.RawMessage
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			doc["complete"] = json.RawMessage("false")
			if raw, err = json.Marshal(doc); err != nil {
				t.Fatal(err)
			}
		}
		files[id+".json"] = &fstest.MapFile{Data: raw}
	}
	r, err := Load(files)
	if err != nil {
		t.Fatal(err)
	}
	got := r.Profiles()
	if len(got) != 2 || got[0].ID != "promql-prometheus-3.1.0" || got[1].ID != "promql-prometheus-3.13.5" {
		ids := []string{}
		for _, p := range got {
			ids = append(ids, p.ID)
		}
		t.Fatalf("listed %v, want the two accepted profiles in identifier order", ids)
	}
	if _, err := r.Resolve("logql-loki-3.5.2", "x"); err == nil {
		t.Fatal("the unaccepted profile resolves")
	}
	for _, p := range got {
		if !p.Complete || len(p.FeatureSets) == 0 || p.Commit == "" || len(p.Configuration) != 0 || len(p.Obligations) != 0 {
			t.Fatalf("%s: listing must carry the sets and the pin only: %+v", p.ID, p)
		}
		registered := r.profiles[p.ID]
		if len(p.FeatureSets) != len(registered.FeatureSets) {
			t.Fatalf("%s lists %d sets of %d registered", p.ID, len(p.FeatureSets), len(registered.FeatureSets))
		}
		for i := range p.FeatureSets {
			if p.FeatureSets[i].ID != registered.FeatureSets[i].ID {
				t.Fatalf("%s set %d out of order", p.ID, i)
			}
		}
	}
	// Mutating the listing must not reach the registry.
	for _, p := range got {
		for i := range p.FeatureSets {
			p.FeatureSets[i].ID = "tampered"
			for j := range p.FeatureSets[i].Enabled {
				p.FeatureSets[i].Enabled[j] = "tampered"
			}
		}
	}
	again := r.Profiles()
	for _, p := range again {
		for _, set := range p.FeatureSets {
			if set.ID == "tampered" {
				t.Fatalf("%s: the listing aliases the registry", p.ID)
			}
			for _, f := range set.Enabled {
				if f == "tampered" {
					t.Fatalf("%s: the listing's feature slices alias the registry", p.ID)
				}
			}
		}
	}
}
