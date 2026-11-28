// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build soundpost_diag

package control_test

import (
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/diagstat"
)

// ruleLayoutPage is the two fields of the control section of the diagnostic page as the endpoint serves them: the snapshot encoded to JSON and
// decoded again, so what is read is what a drill's client reads, field names and types included.
func ruleLayoutPage(t *testing.T) (layout string, marker float64) {
	t.Helper()
	raw, err := json.Marshal(diagstat.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var page struct {
		Control map[string]json.RawMessage `json:"control"`
	}
	if err = json.Unmarshal(raw, &page); err != nil {
		t.Fatal(err)
	}
	for name, into := range map[string]any{"rule_layout": &layout, "rule_marker_index": &marker} {
		field, ok := page.Control[name]
		if !ok {
			t.Fatalf("the control section of the diagnostic page has no %q field: %v", name, page.Control)
		}
		if err = json.Unmarshal(field, into); err != nil {
			t.Fatalf("%s: %v (%s)", name, err, field)
		}
	}
	return layout, marker
}

// The diagnostic page tells a drill which side of the one-way point (D108) a voter is on: rule_layout is "blob" with rule_marker_index 0 before the
// marker command is applied, "ledger" and the revision of that command after it. The page is the JSON of the snapshot, not the method.
func TestTheDiagnosticPageNamesTheRuleLayoutAndTheMarker(t *testing.T) {
	f := newRuleFxProtocol10(t) // the last store opened is the one the page reports
	if layout, marker := ruleLayoutPage(t); layout != "blob" || marker != 0 {
		t.Fatalf("before any rule command the page says rule_layout %q, rule_marker_index %v; want \"blob\", 0", layout, marker)
	}
	revision := f.revision()
	if _, err := f.eval(f.lease(), f.evaluation(1, 60, 0, control.RuleModeLive, `{"n":1}`, recordingIntent(1))); err != nil {
		t.Fatal(err)
	}
	layout, marker := ruleLayoutPage(t)
	if want := float64(revision) + 1; layout != "ledger" || marker != want {
		t.Fatalf("after the first rule command the page says rule_layout %q, rule_marker_index %v; want \"ledger\", %v", layout, marker, want)
	}
	if _, at := f.store.RuleLayout(); float64(at) != marker {
		t.Fatalf("the page says marker %v, the store %d", marker, at)
	}
}
