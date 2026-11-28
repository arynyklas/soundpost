// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func fenceNotReached(code model.Code) *model.Fault {
	f := model.Fail(code)
	f.Retryable = true // what the replication layer says of a fence no quorum answered in time (replica.ErrNoQuorum)
	return f
}

// docs/operations/upgrade.md: while two voters are down a write is refused with a typed retryable 503 with code
// stale, unavailable or timeout. `stale` and `timeout` that say they are retryable (a read fence or a wait that
// no quorum answered in time) are that 503 with a Retry-After of 1 to 3 seconds and keep their code; the
// optimistic-revision `stale` and a deadline of the caller's own making keep the 400 they always had, with no
// Retry-After, since the same request asked again is refused again.
func TestReplyAnswersAFenceNoQuorumReachedWithRetryable503(t *testing.T) {
	for _, c := range []struct {
		name      string
		fault     *model.Fault
		status    int
		retryable bool
	}{
		{"stale, no quorum", fenceNotReached(model.Stale), 503, true},
		{"timeout, no quorum", fenceNotReached(model.Timeout), 503, true},
		{"stale, optimistic revision", model.Fail(model.Stale), 400, false},
		{"timeout, plain deadline", model.Fail(model.Timeout), 400, false},
	} {
		w := httptest.NewRecorder()
		reply(w, nil, c.fault)
		var got model.Fault
		if model.StrictJSON(w.Body.Bytes(), &got) != nil || got.Code != c.fault.Code || got.Retryable != c.retryable {
			t.Fatalf("%s: body %s, want code %s retryable %t", c.name, w.Body.String(), c.fault.Code, c.retryable)
		}
		after := w.Header().Get("Retry-After")
		if w.Code != c.status || c.retryable != (after != "") {
			t.Fatalf("%s: status %d Retry-After %q, want %d and a Retry-After exactly when retryable", c.name, w.Code, after, c.status)
		}
		if c.retryable {
			if seconds, err := strconv.Atoi(after); err != nil || seconds < 1 || seconds > 3 {
				t.Fatalf("%s: Retry-After %q, want whole seconds from 1 to 3", c.name, after)
			}
		}
	}
}

// The artifact upload keeps its 409 for a stale policy epoch (the client re-resolves and resumes) and the
// query route its 409 for state that moved; a retryable stale is the 503 on both.
func TestArtifactAndQueryRepliesAnswerARetryableStaleWith503(t *testing.T) {
	for _, c := range []struct {
		name  string
		reply func(w *httptest.ResponseRecorder, err error)
	}{
		{"artifact", func(w *httptest.ResponseRecorder, err error) { artifactReply(w, nil, err) }},
		{"query", func(w *httptest.ResponseRecorder, err error) { queryReply(w, nil, err) }},
	} {
		w := httptest.NewRecorder()
		c.reply(w, model.Fail(model.Stale))
		if w.Code != 409 || w.Header().Get("Retry-After") != "" {
			t.Fatalf("%s: a plain stale answered %d Retry-After %q, want 409 and none", c.name, w.Code, w.Header().Get("Retry-After"))
		}
		w = httptest.NewRecorder()
		c.reply(w, fenceNotReached(model.Stale))
		after, err := strconv.Atoi(w.Header().Get("Retry-After"))
		if w.Code != 503 || err != nil || after < 1 || after > 3 {
			t.Fatalf("%s: a retryable stale answered %d Retry-After %q, want 503 and 1 to 3", c.name, w.Code, w.Header().Get("Retry-After"))
		}
		var got model.Fault
		if model.StrictJSON(w.Body.Bytes(), &got) != nil || got.Code != model.Stale || !got.Retryable {
			t.Fatalf("%s: body %s", c.name, w.Body.String())
		}
	}
}
