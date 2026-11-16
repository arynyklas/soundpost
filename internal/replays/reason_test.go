// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replays

import "testing"

// ReasonAllowed is the closed vocabulary the HTTP stream pins every line to: each kind has its own reasons, nothing else passes, and every
// reason code this package defines belongs to exactly one kind.
func TestReasonAllowedPinsEachKindsVocabulary(t *testing.T) {
	owner := map[string]EventKind{
		ReasonMissingChunk: EventGap, ReasonHashMismatch: EventGap, ReasonDependencyMismatch: EventGap, ReasonRecorderGap: EventGap,
		ReasonConflictingChunk: EventGap, ReasonInvalidChunk: EventGap, ReasonIndexMismatch: EventGap, ReasonNoCheckpoint: EventGap,
		ReasonRecorderVersion: EventUnsupported, ReasonAuthorityRevoked: EventRevoke, ReasonDeleted: EventRevoke,
	}
	kinds := []EventKind{EventCheckpoint, EventDelta, EventGap, EventUnsupported, EventRevoke, EventError}
	for reason, want := range owner {
		for _, kind := range kinds {
			if got := ReasonAllowed(kind, reason); got != (kind == want) {
				t.Fatalf("ReasonAllowed(%s, %q) = %v, but the reason belongs to %s", kind, reason, got, want)
			}
		}
	}
	for _, kind := range kinds {
		wantEmpty := kind == EventCheckpoint || kind == EventDelta || kind == EventError
		if got := ReasonAllowed(kind, ""); got != wantEmpty {
			t.Fatalf("ReasonAllowed(%s, \"\") = %v", kind, got)
		}
		for _, made := range []string{"the recorder sneezed", "MISSING_CHUNK", "missing_chunk ", "authority_revoked\n"} {
			if ReasonAllowed(kind, made) {
				t.Fatalf("ReasonAllowed(%s, %q) accepted a code outside the closed set", kind, made)
			}
		}
	}
	if ReasonAllowed("rewind", "") || ReasonAllowed("", "") || ReasonAllowed("rewind", ReasonMissingChunk) {
		t.Fatal("an event kind outside the closed set carries no reason")
	}
}
