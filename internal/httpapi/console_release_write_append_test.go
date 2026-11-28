// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// A CI token (release.write only, no session, no way to read the control revision) registers releases and records deploys
// as idempotent appends: the server supplies the revision, a replay returns the original, a conflicting body is a 409.
func TestReleaseWriteTokenAppendsWithoutAControlRevision(t *testing.T) {
	w := newReleaseTokenWorld(t)
	e := w.e
	_, bearer := w.issue(w.org, w.admin.ID, []model.ID{w.p}, auth.ReleaseWrite)
	art := model.NewID()
	rel := func(id, build model.ID, label string) map[string]any {
		return map[string]any{"id": id.String(), "org": w.org.String(), "project": w.p.String(), "build_id": build.String(), "parents": []string{w.r1.String()}, "build_time_ns": "77",
			"debug_artifacts": []map[string]any{{"artifact_id": art.String(), "debug_id": "debug-ci", "sha256": model.HashCanonical([]byte("ci")).String()}}, "display_label": label, "revision": "0"}
	}
	post := func(command model.ID, release map[string]any, extra map[string]any) (int, []byte) {
		body := map[string]any{"org": w.org.String(), "project": w.p.String(), "command_id": command.String(), "release": release}
		for k, v := range extra {
			body[k] = v
		}
		return e.post(person{}, "/api/v1/releases/register", body, bearer)
	}
	registered := func(raw []byte) (string, string) {
		var v struct{ ID, Revision string }
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("%v: %s", err, raw)
		}
		return v.ID, v.Revision
	}
	id, build, command := model.NewID(), model.NewID(), model.NewID()

	// No expected_revision at all.
	status, raw := post(command, rel(id, build, "ci-1"), nil)
	if status != 200 {
		t.Fatalf("a CI token registers without a control revision: %d %s", status, raw)
	}
	gotID, gotRev := registered(raw)
	// Another commit moves the control revision; a wrong expected_revision from a token is ignored.
	e.cmd(w.org, "create_project", auth.AdminPayload{ID: model.NewID(), Name: "moved"})
	other := model.NewID()
	if status, raw = post(model.NewID(), rel(other, model.NewID(), "ci-2"), map[string]any{"expected_revision": "1"}); status != 200 {
		t.Fatalf("a stale expected_revision from a token is ignored: %d %s", status, raw)
	}
	// Replay of the same command, same body: the original answer, nothing new committed.
	revBefore := w.revision()
	if status, raw = post(command, rel(id, build, "ci-1"), nil); status != 200 {
		t.Fatalf("replay: %d %s", status, raw)
	}
	if rid, rrev := registered(raw); rid != gotID || rrev != gotRev || w.revision() != revBefore {
		t.Fatalf("a replay must return the original and commit nothing: %s %s revision %d -> %d", rid, rrev, revBefore, w.revision())
	}
	// A new command id for the same natural key and identical body: the same original again.
	if status, raw = post(model.NewID(), rel(id, build, "ci-1"), nil); status != 200 || w.revision() != revBefore {
		t.Fatalf("the same release again: %d %s", status, raw)
	}
	// Conflicts: same command other release; same identity other build, other parents, other label (a rename); a revision bump.
	for name, c := range map[string]struct {
		command model.ID
		release map[string]any
	}{
		"same command, another release": {command, rel(model.NewID(), build, "ci-1")},
		"same release, another build":   {model.NewID(), rel(id, model.NewID(), "ci-1")},
		"same release, a rename":        {model.NewID(), rel(id, build, "renamed")},
		"same release, another time":    {model.NewID(), func() map[string]any { r := rel(id, build, "ci-1"); r["build_time_ns"] = "78"; return r }()},
		"same release, a revision":      {model.NewID(), func() map[string]any { r := rel(id, build, "renamed"); r["revision"] = "1"; return r }()},
	} {
		if status, raw = post(c.command, c.release, nil); status != http.StatusConflict {
			t.Errorf("%s: %d %s", name, status, raw)
		}
	}
	if w.revision() != revBefore {
		t.Fatal("a refused append committed something")
	}
	// The stored release is untouched.
	var label string
	var revision model.Revision
	if err := e.app.Control.View(e.ctx, func(st model.ControlState) error {
		r := st.Releases[model.ReleaseScopeKey(w.org, w.p, id)]
		label, revision = r.DisplayLabel, r.Revision
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if label != "ci-1" || revision != 1 {
		t.Fatalf("stored: %q revision %d", label, revision)
	}
	// Another project and organization stay refused.
	for name, c := range map[string]struct{ org, project model.ID }{"another project": {w.org, w.q}, "another organization": {w.orgB, w.p}} {
		r := rel(model.NewID(), model.NewID(), "x")
		r["org"], r["project"] = c.org.String(), c.project.String()
		status, raw := e.post(person{}, "/api/v1/releases/register", map[string]any{"org": c.org.String(), "project": c.project.String(), "command_id": model.NewID().String(), "release": r}, bearer)
		if status != 404 {
			t.Errorf("%s: %d %s", name, status, raw)
		}
	}

	// Deploys: the same command id is one deploy; a conflicting replay is a 409; a new command is another recording.
	dep := model.NewID()
	deploy := func(command model.ID, at any) (int, []byte) {
		body := map[string]any{"op": "record", "org": w.org.String(), "project": w.p.String(), "release": w.r2.String(), "environment": w.env.String(), "command_id": command.String()}
		if at != nil {
			body["deployed_at"] = at
		}
		return e.post(person{}, "/api/v1/releases/deploys", body, bearer)
	}
	count := func(raw []byte) string {
		var v struct{ Count string }
		_ = json.Unmarshal(raw, &v)
		return v.Count
	}
	if status, raw = deploy(dep, nil); status != 200 || count(raw) != "1" {
		t.Fatalf("deploy: %d %s", status, raw)
	}
	if status, raw = deploy(dep, nil); status != 200 || count(raw) != "1" {
		t.Fatalf("a replay of the same command must not count: %d %s", status, raw)
	}
	if status, raw = deploy(dep, "1700000000000000000"); status != http.StatusConflict {
		t.Fatalf("a conflicting replay: %d %s", status, raw)
	}
	if status, raw = deploy(model.NewID(), nil); status != 200 || count(raw) != "2" {
		t.Fatalf("a new command is a new deploy: %d %s", status, raw)
	}
}
