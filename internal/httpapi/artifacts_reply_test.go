// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"github.com/arynyklas/soundpost/internal/model"
	"net/http/httptest"
	"testing"
)

func TestArtifactReplyStatusMapping(t *testing.T) {
	for _, c := range []struct {
		code   model.Code
		status int
	}{{model.Stale, 409}, {model.Conflict, 409}, {model.TooLarge, 400}, {model.Quota, 400}, {model.Invalid, 400}, {model.NotFound, 404}} {
		w := httptest.NewRecorder()
		artifactReply(w, nil, model.Fail(c.code))
		if w.Code != c.status {
			t.Fatalf("%v: status %d want %d", c.code, w.Code, c.status)
		}
		var f model.Fault
		if model.StrictJSON(w.Body.Bytes(), &f) != nil || f.Code != c.code {
			t.Fatalf("%v: body code lost: %s", c.code, w.Body.String())
		}
	}
}
