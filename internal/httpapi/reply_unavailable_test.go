// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"errors"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func leaderGap() *model.Fault {
	f := model.Fail(model.Unavailable)
	f.Retryable = true // what the replication layer says of a moment without a leader (replica.ErrNoLeader)
	return f
}

// `unavailable` is the retryable 503 of docs/operations/upgrade.md only when the fault says it is a moment
// without a leader (an election, a leader transfer): then the answer carries a Retry-After of 1 to 3 seconds, so
// a client that holds a command id (the admin commands) asks again safely. An engine or a group that failed
// closed, a closing node and a bare error are 503 `unavailable` with retryable:false and no Retry-After: no retry
// mends them, and a client that retried would ask forever. `corrupt` is 503 too and is never retryable. All of
// it holds on every route that uses the shared reply.
func TestReplyMapsOnlyALeaderGapToRetryable503(t *testing.T) {
	for _, c := range []struct {
		name      string
		err       error
		retryable bool
	}{
		{"leader gap", leaderGap(), true},
		{"failed closed", model.Fail(model.Unavailable), false},
		{"not a typed fault", errors.New("an engine that failed"), false},
		{"corrupt", model.Fail(model.Corrupt), false},
	} {
		w := httptest.NewRecorder()
		reply(w, nil, c.err)
		var got model.Fault
		if model.StrictJSON(w.Body.Bytes(), &got) != nil || got.Retryable != c.retryable {
			t.Fatalf("%s: body %s, want retryable %t", c.name, w.Body.String(), c.retryable)
		}
		after := w.Header().Get("Retry-After")
		if w.Code != 503 || c.retryable != (after != "") {
			t.Fatalf("%s: status %d Retry-After %q, want 503 and a Retry-After exactly when retryable", c.name, w.Code, after)
		}
		if c.retryable {
			if seconds, err := strconv.Atoi(after); err != nil || seconds < 1 || seconds > 3 {
				t.Fatalf("%s: Retry-After %q, want whole seconds from 1 to 3", c.name, after)
			}
		}
	}
}

// The Retry-After of a leader gap is drawn, not fixed: the clients refused in one election must not all come
// back in the same second.
func TestReplyRetryAfterOfALeaderGapIsSpreadOverOneToThreeSeconds(t *testing.T) {
	seen := map[string]bool{}
	for range 300 {
		w := httptest.NewRecorder()
		reply(w, nil, leaderGap())
		seen[w.Header().Get("Retry-After")] = true
	}
	for after := range seen {
		if after != "1" && after != "2" && after != "3" {
			t.Fatalf("Retry-After %q, want 1, 2 or 3", after)
		}
	}
	if len(seen) < 2 {
		t.Fatalf("300 answers carried the single Retry-After %v: it is not randomized", seen)
	}
}

// A route that set its own Retry-After before replying (the login-start cap: 60) keeps it.
func TestReplyKeepsARetryAfterTheRouteSet(t *testing.T) {
	w := httptest.NewRecorder()
	w.Header().Set("Retry-After", "60")
	reply(w, nil, leaderGap())
	if w.Code != 503 || w.Header().Get("Retry-After") != "60" {
		t.Fatalf("status %d Retry-After %q, want 503 and the route's 60", w.Code, w.Header().Get("Retry-After"))
	}
}
