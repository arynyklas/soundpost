// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package profile

import (
	"encoding/json"
	"testing"
)

func TestResolveSelectsAndIsolatesFeatureConfiguration(t *testing.T) {
	id := "promql-prometheus-3.1.0"
	r := Registry{profiles: map[string]Profile{id: {ID: id, Commit: pins[id], ManifestVersion: 1, Complete: true, FeatureSets: []FeatureSet{{ID: "off"}, {ID: "on", Enabled: []string{"experimental"}}}, Configuration: map[string]json.RawMessage{"lookback_ns": json.RawMessage(`"300000000000"`)}, Obligations: []string{"case"}}}}
	on, e := r.Resolve(id, "on")
	if e != nil {
		t.Fatal(e)
	}
	off, e := r.Resolve(id, "off")
	if e != nil {
		t.Fatal(e)
	}
	if on.ActiveFeatureSet.ID != "on" || len(on.ActiveFeatureSet.Enabled) != 1 || len(off.ActiveFeatureSet.Enabled) != 0 {
		t.Fatal("selection not explicit")
	}
	if on.Identity == "" || on.ConfigurationHash == "" || on.Identity == off.Identity {
		t.Fatal("execution identity did not bind selected feature set")
	}
	on.ActiveFeatureSet.Enabled[0] = "mutated"
	on.FeatureSets[1].Enabled[0] = "mutated"
	on.Configuration["lookback_ns"][0] = 'x'
	on.Obligations[0] = "mutated"
	again, e := r.Resolve(id, "on")
	if e != nil {
		t.Fatal(e)
	}
	if again.ActiveFeatureSet.Enabled[0] != "experimental" || again.FeatureSets[1].Enabled[0] != "experimental" || string(again.Configuration["lookback_ns"]) != `"300000000000"` || again.Obligations[0] != "case" {
		t.Fatal("caller mutated registry-owned profile state")
	}
}
