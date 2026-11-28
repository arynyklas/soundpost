// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package staleretry

import "testing"

func TestSinceCountsEachWriterApartAndTotalsThem(t *testing.T) {
	before := Snapshot()
	Note(Rules)
	Note(Rules)
	Note(Outbox)
	Note(Conditions)
	Note(Incidents)
	Note(Incidents)
	Note(Incidents)
	got := Snapshot().Since(before)
	if got != (Counts{Rules: 2, Outbox: 1, Conditions: 1, Incidents: 3}) || got.Total() != 7 {
		t.Fatalf("counted %+v (total %d)", got, got.Total())
	}
}
