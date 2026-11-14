// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

// A release is registered through the product's own route as an organization
// administrator, read back through the evidence route, renamed as a new label
// revision, and refused (nothing committed) for a reader, a stale control
// revision, or a seam that is not wired.
func TestReleaseRegisterRouteIsAdminOnlyAndCommitsThroughTheRegistry(t *testing.T) {
	e := newEvEnv(t, nil, nil, true)
	p := model.NewID()
	org := e.org("release register", p)
	admin := e.user(org, "register-admin@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	reader := e.user(org, "register-reader@example.test")
	e.grant(org, reader, p, true, auth.Read)

	revision := func() model.Uint64 {
		var r model.Revision
		if err := e.app.Control.View(e.ctx, func(st model.ControlState) error { r = st.Revision; return nil }); err != nil {
			t.Fatal(err)
		}
		return model.Uint64(r)
	}
	root, child, build := model.NewID(), model.NewID(), model.NewID()
	artifact := model.NewID()
	rel := func(id model.ID, label string, entityRevision string, parents ...model.ID) map[string]any {
		ps := []string{}
		for _, parent := range parents {
			ps = append(ps, parent.String())
		}
		return map[string]any{"id": id.String(), "org": org.String(), "project": p.String(), "build_id": build.String(), "parents": ps, "build_time_ns": "5",
			"debug_artifacts": []map[string]any{{"artifact_id": artifact.String(), "debug_id": "debug-1", "sha256": model.HashCanonical([]byte("map")).String()}},
			"display_label":   label, "revision": entityRevision}
	}
	register := func(who person, expected model.Uint64, release map[string]any) (int, []byte) {
		return e.post(who, "/api/v1/releases/register", map[string]any{"org": org.String(), "project": p.String(), "command_id": model.NewID().String(), "expected_revision": expected, "release": release}, nil)
	}

	if status, raw := register(reader, revision(), rel(root, "v1.0", "0")); status < 400 {
		t.Fatalf("a project reader registered a release: %d %s", status, raw)
	}
	if status, raw := register(admin, revision()+7, rel(root, "v1.0", "0")); status != http.StatusConflict {
		t.Fatalf("a stale control revision must be a 409: %d %s", status, raw)
	}
	if status, raw := e.post(admin, "/api/v1/evidence/release", map[string]any{"org": org.String(), "project": p.String(), "release": root.String()}, nil); status != 404 {
		t.Fatalf("a refused registration left a release: %d %s", status, raw)
	}

	if status, raw := register(admin, revision(), rel(root, "v1.0", "0")); status != 200 {
		t.Fatalf("register root: %d %s", status, raw)
	}
	if status, raw := register(admin, revision(), rel(child, "v1.1", "0", root)); status != 200 {
		t.Fatalf("register child: %d %s", status, raw)
	}
	if status, raw := register(admin, revision(), rel(child, "v1.1-renamed", "1", root)); status != 200 {
		t.Fatalf("rename child: %d %s", status, raw)
	}
	status, raw := e.post(admin, "/api/v1/evidence/release", map[string]any{"org": org.String(), "project": p.String(), "release": child.String(), "compare": []string{root.String()}}, nil)
	if status != 200 {
		t.Fatalf("read back: %d %s", status, raw)
	}
	var v httpapi.ReleaseView
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Release == nil || v.Release.Label != "v1.1-renamed" || len(v.Release.DebugArtifacts) != 1 || v.Release.DebugArtifacts[0].ArtifactID != artifact || len(v.Parents) != 1 || v.Parents[0].ID != root || !v.Parents[0].Known {
		t.Fatalf("registered release not read back: %s", raw)
	}
	if len(v.Comparisons) != 1 || v.Comparisons[0].Order != "descendant" {
		t.Fatalf("ancestry from the registered parent edge: %s", raw)
	}
}

// With no release registry wired the route does not exist as a writer: it
// answers a refusal and nothing is committed.
func TestReleaseRegisterRouteAbsentWithoutARegistry(t *testing.T) {
	e := newEvEnv(t, nil, nil, false)
	p := model.NewID()
	org := e.org("release register none", p)
	admin := e.user(org, "register-none@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	status, raw := e.post(admin, "/api/v1/releases/register", map[string]any{"org": org.String(), "project": p.String(), "command_id": model.NewID().String(), "expected_revision": "0", "release": map[string]any{}}, nil)
	if status < 400 {
		t.Fatalf("registered without a registry: %d %s", status, raw)
	}
}
