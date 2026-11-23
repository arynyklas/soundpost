// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/gitlab/gitlabtest"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

const gitlabIssueToken = "tok-0123456789abcdef-issue"

// TestGitLabCreateForAnErrorIssue drives the native one-way create for an error
// issue produced by the real ingest and producer path, through the real routes,
// scopes and issue lifecycle, against a local stub GitLab (NO real GitLab
// instance). The stub listens on the host's own address, admitted by an egress
// allow-list prefix, so the production dialer runs unchanged.
func TestGitLabCreateForAnErrorIssue(t *testing.T) {
	r := newIssueRig(t)
	r.ingest("SecretClassNameError", 5, false, true)
	r.tick(r.workers())
	snap := r.snapshot()
	if len(snap.Issues) != 1 {
		t.Fatalf("setup: issues %+v", snap.Issues)
	}
	issue := snap.Issues[0].ID
	stub := gitlabtest.New(t)
	srv := httptest.NewTLSServer(httpapi.NewServer("", r.app.Auth, nil, func(mux *http.ServeMux) {
		r.app.RegisterConsole(mux, appcore.ConsoleConfig{PublicOrigin: "https://console.example.test", EgressAllow: []netip.Prefix{stub.Allow}, RootCAs: stub.Pool})
	}).Handler)
	t.Cleanup(srv.Close)

	login := func(email, password string) auth.Session {
		s, err := r.app.Auth.Login(r.ctx, email, password, "")
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	post := func(s auth.Session, path string, body any) (int, map[string]any, string) {
		t.Helper()
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", srv.URL+path, bytes.NewReader(raw))
		req.Header.Set("Cookie", "__Host-soundpost="+s.Token)
		req.Header.Set("X-CSRF-Token", s.CSRF)
		req.Header.Set("Origin", srv.URL)
		req.Header.Set("Content-Type", "application/json")
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		var m map[string]any
		_ = json.Unmarshal(out, &m)
		return resp.StatusCode, m, string(out)
	}
	owner := login("workers@example.test", "worker wiring password 2026")
	status, read, raw := post(owner, "/api/v1/gitlab/settings", map[string]any{"op": "read", "org": r.org.String()})
	if status != 200 {
		t.Fatalf("read: %d %s", status, raw)
	}
	status, _, raw = post(owner, "/api/v1/gitlab/settings", map[string]any{"op": "save", "org": r.org.String(), "command_id": model.NewID().String(), "expected_epoch": read["epoch"], "reason": "connect",
		"connection": map[string]any{"base_url": stub.URL, "token": gitlabIssueToken, "mappings": []map[string]any{{"project_id": r.project.String(), "gitlab_project": "shop/web", "create_from": []string{"issue"}, "labels": []string{}}}}})
	if status != 200 || strings.Contains(raw, gitlabIssueToken) {
		t.Fatalf("save: %d %s", status, raw)
	}
	entity := map[string]any{"kind": "issue", "id": issue.String()}
	call := func(s auth.Session, op string, extra map[string]any) (int, map[string]any, string) {
		body := map[string]any{"op": op, "org": r.org.String(), "project_id": r.project.String(), "entity": entity}
		if op == "create" {
			body["command_id"] = model.NewID().String()
		}
		for k, v := range extra {
			body[k] = v
		}
		return post(s, "/api/v1/gitlab/issues", body)
	}

	status, out, raw := call(owner, "preview", nil)
	if status != 200 || out["state"] != "ready" || out["title"] != "Soundpost issue "+issue.String()[:8] || out["existing"] != nil {
		t.Fatalf("preview: %d %s", status, raw)
	}
	// Who may not create: a reader and a member holding only incidents.write.
	_, _ = r.member("gl-issue-reader@example.test", auth.Read)
	reader := login("gl-issue-reader@example.test", "issue actions member password")
	_, _ = r.member("gl-issue-incwriter@example.test", auth.IncidentsWrite)
	incWriter := login("gl-issue-incwriter@example.test", "issue actions member password")
	for name, s := range map[string]auth.Session{"reader": reader, "incidents.write only": incWriter} {
		if status, _, raw = call(s, "create", nil); status != 404 {
			t.Fatalf("%s created: %d %s", name, status, raw)
		}
	}
	if stub.Posts() != 0 {
		t.Fatalf("a refused caller reached GitLab: %d", stub.Posts())
	}

	// An issues.write holder creates: identifiers and status only reach GitLab.
	_, _ = r.member("gl-issue-writer@example.test", auth.IssuesWrite)
	writer := login("gl-issue-writer@example.test", "issue actions member password")
	status, out, raw = call(writer, "create", nil)
	if status != 200 || out["state"] != "linked" || out["created"] != true || out["iid"] != "1" || out["gitlab_project"] != "shop/web" {
		t.Fatalf("create: %d %s", status, raw)
	}
	issues := stub.Issues()
	if stub.Posts() != 1 || len(issues) != 1 {
		t.Fatalf("posts %d issues %d", stub.Posts(), len(issues))
	}
	d := issues[0].Description
	if !strings.Contains(d, issue.String()) || !strings.Contains(d, model.ExternalMarker(r.org, "issue", issue)) || !strings.Contains(d, "open") ||
		strings.Contains(d, "SecretClassNameError") || strings.Contains(issues[0].Title, "SecretClassNameError") || issues[0].Title != "Soundpost issue "+issue.String()[:8] {
		t.Fatalf("what GitLab received: %+v", issues[0])
	}
	for _, seen := range stub.Tokens() {
		if seen != gitlabIssueToken {
			t.Fatalf("PRIVATE-TOKEN %q", seen)
		}
	}
	// The link is stored on the issue record (and nowhere is the marker or token shown).
	stored := r.snapshot().Issues[0].External
	if len(stored) != 1 || stored[0].State != model.ExternalLinked || stored[0].IID != 1 || stored[0].Project != "shop/web" || !strings.HasPrefix(stored[0].URL, stub.URL) {
		t.Fatalf("stored link %+v", stored)
	}
	// One GitLab issue per entity: the stored link comes back, from any writer, and a recheck agrees.
	if status, out, raw = call(owner, "create", nil); status != 200 || out["state"] != "linked" || out["created"] != false || stub.Posts() != 1 {
		t.Fatalf("second create: %d %s posts %d", status, raw, stub.Posts())
	}
	if status, out, raw = call(writer, "recheck", nil); status != 200 || out["state"] != "linked" || out["iid"] != "1" {
		t.Fatalf("recheck: %d %s", status, raw)
	}
	if status, out, raw = call(reader, "preview", nil); status != 200 || out["existing"] == nil || !strings.Contains(raw, `"state":"linked"`) {
		t.Fatalf("preview of a linked issue: %d %s", status, raw)
	}
	// Markdown copy of the issue: identifiers only.
	status, md, raw := post(reader, "/api/v1/issues/markdown", map[string]any{"org": r.org.String(), "project_id": r.project.String(), "id": issue.String(), "format": "description"})
	if status != 200 || md["state"] != "ready" || strings.Contains(raw, "SecretClassNameError") || !strings.Contains(raw, issue.String()) {
		t.Fatalf("issue markdown: %d %s", status, raw)
	}
	status, md, raw = post(reader, "/api/v1/issues/markdown", map[string]any{"org": r.org.String(), "project_id": r.project.String(), "id": issue.String(), "format": "link"})
	if want := "https://console.example.test/#view=issues&org=" + r.org.String() + "&projects=" + r.project.String() + "&target=" + r.project.String() + ":" + issue.String(); status != 200 || md["markdown"] != want {
		t.Fatalf("issue link: %d %s", status, raw)
	}
	// The issue is unchanged by the link otherwise: still open, same grouping.
	if got := r.snapshot().Issues[0]; got.Workflow != "open" {
		t.Fatalf("workflow %q", got.Workflow)
	}
}
