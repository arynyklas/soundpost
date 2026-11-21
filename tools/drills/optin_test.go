// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"slices"
	"testing"
)

// `--scenario all` is a sweep that must never reset a machine or need tools it was not given: an opt_in scenario runs only
// when it is named.
func TestAllSkipsOptInScenariosButANamedRunSelectsThem(t *testing.T) {
	m, err := LoadManifest("../../drills/scenarios.yaml")
	if err != nil {
		t.Fatal(err)
	}
	all, err := m.Select("all")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"vm-hard-reset", "node-loss-journeys"} {
		if slices.Contains(all, name) {
			t.Errorf("`all` selected the opt-in scenario %s", name)
		}
		one, err := m.Select(name)
		if err != nil || len(one) != 1 || one[0] != name {
			t.Errorf("naming %s selects %v, %v", name, one, err)
		}
		if !m.spec(name).OptIn {
			t.Errorf("%s is not marked opt_in in drills/scenarios.yaml", name)
		}
	}
	if !slices.Contains(all, "node-kill-restart") || !slices.Contains(all, "power-loss") {
		t.Errorf("`all` lost the ordinary scenarios: %v", all)
	}
}
