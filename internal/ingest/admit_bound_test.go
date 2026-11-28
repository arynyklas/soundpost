// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package ingest

import "testing"

// A request that arrives when maxInFlight are in progress is refused at once (503 with Retry-After at the HTTP layer), is not
// counted, and what was in progress is not disturbed; a request that leaves makes room for exactly one.
func TestARequestBeyondTheBoundIsRefusedAndNotCounted(t *testing.T) {
	s := &Service{}
	for i := range maxInFlight {
		if !s.Enter() {
			t.Fatalf("request %d of %d was refused", i+1, maxInFlight)
		}
	}
	for range 100 {
		if s.Enter() {
			t.Fatal("a request beyond the bound entered")
		}
	}
	if got := s.inFlight.Load(); got != maxInFlight {
		t.Fatalf("%d in flight after the refusals, want %d", got, maxInFlight)
	}
	s.Leave()
	if !s.Enter() {
		t.Fatal("a request that found room was refused")
	}
	if s.Enter() {
		t.Fatal("two requests entered where one left")
	}
	if got := outcomes.bounded.Load(); got < 101 {
		t.Fatalf("%d refusals counted, want at least 101", got)
	}
}
