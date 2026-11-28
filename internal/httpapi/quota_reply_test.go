// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"net/http/httptest"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// A retryable quota refusal (a capacity that frees up, such as the concurrent-export cap) is
// 429 with Retry-After on every route that uses the shared reply; a permanent quota keeps 400.
func TestReplyMapsRetryableQuotaToTooManyRequests(t *testing.T) {
	retryable := model.Fail(model.Quota)
	retryable.Retryable = true
	for _, c := range []struct {
		name       string
		fault      *model.Fault
		status     int
		retryAfter string
	}{
		{"retryable quota", retryable, 429, "1"},
		{"permanent quota", model.Fail(model.Quota), 400, ""},
	} {
		w := httptest.NewRecorder()
		reply(w, nil, c.fault)
		if w.Code != c.status || w.Header().Get("Retry-After") != c.retryAfter {
			t.Fatalf("%s: status %d Retry-After %q, want %d %q", c.name, w.Code, w.Header().Get("Retry-After"), c.status, c.retryAfter)
		}
		var got model.Fault
		if model.StrictJSON(w.Body.Bytes(), &got) != nil || got.Code != model.Quota || got.Retryable != c.fault.Retryable {
			t.Fatalf("%s: body lost the fault: %s", c.name, w.Body.String())
		}
	}
}
