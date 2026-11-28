// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"github.com/arynyklas/soundpost/internal/model"
	"net/http/httptest"
	"testing"
)

// Upload admission refuses with a retryable quota fault: 429 + Retry-After.
// A non-retryable quota (the durable per-source byte quota) keeps its status.
func TestArtifactReplyUploadAdmissionIsRetryable(t *testing.T) {
	w := httptest.NewRecorder()
	f := model.Fail(model.Quota)
	f.Retryable = true
	artifactReply(w, nil, f)
	if w.Code != 429 || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("status %d retry-after %q", w.Code, w.Header().Get("Retry-After"))
	}
	var got model.Fault
	if model.StrictJSON(w.Body.Bytes(), &got) != nil || got.Code != model.Quota || !got.Retryable {
		t.Fatalf("body: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	artifactReply(w, nil, model.Fail(model.Quota))
	if w.Code != 400 || w.Header().Get("Retry-After") != "" {
		t.Fatalf("durable quota changed: %d %q", w.Code, w.Header().Get("Retry-After"))
	}
}
