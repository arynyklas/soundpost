// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"strings"
	"testing"

	q "github.com/arynyklas/soundpost/internal/conformance/query"
)

// A scenario that ran on several layouts passes only if it passed on every one:
// the second layout can never overwrite a failure of the first.
func TestMergeOutcomesRequiresEveryLayoutToPass(t *testing.T) {
	single := []q.ScenarioOutcome{{Name: "hot-read", Passed: true}, {Name: "restart", Passed: false}}
	distributed := []q.ScenarioOutcome{{Name: "restart", Passed: true}, {Name: "hot-read", Passed: false}, {Name: "flush", Passed: true}}
	got := mergeOutcomes(append([]q.ScenarioOutcome(nil), single...), distributed)
	want := map[string]bool{"hot-read": false, "restart": false, "flush": true}
	if len(got) != len(want) {
		t.Fatalf("%d outcomes %v", len(got), got)
	}
	for _, o := range got {
		if w, ok := want[o.Name]; !ok || o.Passed != w {
			t.Errorf("%s passed=%v, want %v", o.Name, o.Passed, w)
		}
	}
}

func TestSmokeRejectsAnUnknownLayout(t *testing.T) {
	err := runSmoke([]string{"--storage", "real", "--control", "real", "--modes", "single,sharded", "--cases", "x.json"})
	if err == nil || !strings.Contains(err.Error(), `unknown mode "sharded"`) {
		t.Fatalf("%v", err)
	}
}
