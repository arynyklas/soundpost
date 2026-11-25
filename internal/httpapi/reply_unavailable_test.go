// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"net/http/httptest"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// A transient `unavailable` (no leader for a moment: an election, a leader transfer) is the retryable 503 of
// docs/operations/upgrade.md on every route that uses the shared reply, with Retry-After, so a client that holds
// a command id (the admin commands) asks again safely. `corrupt` is 503 too but is never retryable.
func TestReplyMapsUnavailableToRetryable503(t *testing.T) {
	for _, c := range []struct {
		name       string
		code       model.Code
		retryable  bool
		retryAfter string
	}{
		{"unavailable", model.Unavailable, true, "1"},
		{"corrupt", model.Corrupt, false, ""},
	} {
		w := httptest.NewRecorder()
		reply(w, nil, model.Fail(c.code))
		if w.Code != 503 || w.Header().Get("Retry-After") != c.retryAfter {
			t.Fatalf("%s: status %d Retry-After %q, want 503 %q", c.name, w.Code, w.Header().Get("Retry-After"), c.retryAfter)
		}
		var got model.Fault
		if model.StrictJSON(w.Body.Bytes(), &got) != nil || got.Code != c.code || got.Retryable != c.retryable {
			t.Fatalf("%s: body %s, want code %s retryable %t", c.name, w.Body.String(), c.code, c.retryable)
		}
	}
}
