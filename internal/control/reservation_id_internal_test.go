// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"testing"
	"time"
)

// TestReservationIDsAreOrderedByTime pins the property the ledger's write set relies on (D81): the
// reservation rows are keyed by identity, and identities made later sort after the ones made earlier, so a
// reservation and the finalize that follows it are written to the end of the table.
func TestReservationIDsAreOrderedByTime(t *testing.T) {
	prev := newReservationID()
	seen := map[string]bool{prev.String(): true}
	for range 40 {
		time.Sleep(2 * time.Millisecond)
		id := newReservationID()
		if id.String() <= prev.String() {
			t.Fatalf("identity %s made after %s does not sort after it", id, prev)
		}
		if seen[id.String()] {
			t.Fatalf("identity %s made twice", id)
		}
		seen[id.String()] = true
		prev = id
	}
}
