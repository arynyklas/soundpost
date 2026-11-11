// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts_test

import (
	"bytes"
	"context"
	"errors"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"testing"
)

// The buffered transform keeps the strict-JSON and private-content checks.
func TestUploadStillRejectsMalformedBodies(t *testing.T) {
	f := newArtifactFixture(t)
	for _, c := range []struct {
		name    string
		raw     string
		private bool
	}{
		{"duplicate key", `{"version":3,"sources":["a.ts"],"sources":["b.ts"],"names":[],"mappings":"AAAA"}`, false},
		{"duplicate key private", `{"version":3,"sources":["a.ts"],"sources":["b.ts"],"names":[],"mappings":"AAAA","sourcesContent":["x"]}`, true},
		{"content length mismatch", `{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA","sourcesContent":["x","y"]}`, true},
		{"trailing value", `{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA"} {}`, false},
	} {
		raw := []byte(c.raw)
		m := f.manifest(raw)
		m.SourceContent = c.private
		_, err := f.app.Artifacts.Put(context.Background(), f.scope(t, auth.Permission("artifacts.write")), m, bytes.NewReader(raw))
		var fault *model.Fault
		if !errors.As(err, &fault) || fault.Code != model.Invalid {
			t.Fatalf("%s: want invalid, got %v", c.name, err)
		}
	}
}
