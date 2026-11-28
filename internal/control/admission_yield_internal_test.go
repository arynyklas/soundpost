// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"testing"
	"time"
)

// An admission command is a patch that writes ledger records and steps the revision, and nothing else.
func TestLedgerOnlyPatchIsTheAdmissionCommand(t *testing.T) {
	step := []patchOp{revisionOp(5), {Op: opSet, Path: []string{"revision_clock"}, Value: []byte(`[1]`)}}
	rec := patchOp{Op: opSet, Path: []string{"Reservations", "r"}, Value: []byte(`{}`)}
	quota := patchOp{Op: opSet, Path: []string{"Quotas", "org:o", "bytes"}, Value: []byte(`1`)}
	settle := patchOp{Op: opSet, Path: []string{"settlement"}, Value: []byte(`{}`)}
	other := patchOp{Op: opSet, Path: []string{"Orgs", "o", "Settings", "k"}, Value: []byte(`1`)}
	audits := patchOp{Op: opArray, Path: []string{"Audits"}, Value: []byte(`[]`)}
	book := patchOp{Op: opSet, Path: []string{"JobBooks", "k"}, Value: []byte(`{}`)}
	for _, tc := range []struct {
		name string
		ops  []patchOp
		want bool
	}{
		{"reserve", append(append([]patchOp{}, step...), rec, quota), true},
		{"settle", append(append([]patchOp{}, step...), settle), true},
		{"a step alone", step, true},
		{"books alone are a writer's", append(append([]patchOp{}, step...), book), false},
		{"a round of books and admission is admission's", append(append([]patchOp{}, step...), rec, book), true},
		{"empty", nil, false},
		{"an organization row", append(append([]patchOp{}, step...), other), false},
		{"a ledger and an audit", append(append([]patchOp{}, step...), rec, audits), false},
		{"an empty path", []patchOp{{Op: opSet}}, false},
	} {
		if got := ledgerOnlyPatch(&statePatch{Ops: tc.ops}); got != tc.want {
			t.Errorf("%s: ledgerOnlyPatch = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A writer that lost opens one window; the next one opens no earlier than admissionYieldEvery after the
// first, so admission keeps most of the time whatever the other writers do.
func TestAdmissionYieldWindowIsBoundedAndSpaced(t *testing.T) {
	var s Store
	t0 := time.Unix(1000, 0)
	if s.admissionYielding(t0) {
		t.Fatal("yielding before any writer lost")
	}
	s.noteWriterLost(t0)
	if !s.admissionYielding(t0.Add(admissionYield - time.Nanosecond)) {
		t.Fatal("a writer that lost opened no window")
	}
	if s.admissionYielding(t0.Add(admissionYield)) {
		t.Fatal("the window did not end")
	}
	// A loss inside the spacing opens nothing new.
	s.noteWriterLost(t0.Add(admissionYieldEvery - time.Nanosecond))
	if s.admissionYielding(t0.Add(admissionYieldEvery)) {
		t.Fatal("a loss before the spacing elapsed opened a window")
	}
	s.noteWriterLost(t0.Add(admissionYieldEvery))
	if !s.admissionYielding(t0.Add(admissionYieldEvery + time.Millisecond)) {
		t.Fatal("a loss after the spacing opened no window")
	}
}

// The scale a test sets stretches the window and the spacing alike; one that is not above 1 leaves both as they are (the product never sets it).
func TestAdmissionYieldScaleStretchesTheWindowAndTheSpacing(t *testing.T) {
	t0 := time.Unix(1000, 0)
	var s Store
	s.admissionYieldScale.Store(8)
	s.noteWriterLost(t0)
	if !s.admissionYielding(t0.Add(8*admissionYield - time.Nanosecond)) {
		t.Fatal("the scaled window ended early")
	}
	if s.admissionYielding(t0.Add(8 * admissionYield)) {
		t.Fatal("the scaled window did not end")
	}
	s.noteWriterLost(t0.Add(8*admissionYieldEvery - time.Nanosecond))
	if s.admissionYielding(t0.Add(8 * admissionYieldEvery)) {
		t.Fatal("a loss before the scaled spacing elapsed opened a window")
	}
	s.noteWriterLost(t0.Add(8 * admissionYieldEvery))
	if !s.admissionYielding(t0.Add(8*admissionYieldEvery + time.Millisecond)) {
		t.Fatal("a loss after the scaled spacing opened no window")
	}
	for _, scale := range []int64{0, 1, -3} {
		var p Store
		p.admissionYieldScale.Store(scale)
		p.noteWriterLost(t0)
		if !p.admissionYielding(t0.Add(admissionYield-time.Nanosecond)) || p.admissionYielding(t0.Add(admissionYield)) {
			t.Fatalf("scale %d changed the window", scale)
		}
	}
}
