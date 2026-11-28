// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/gitlab/gitlabtest"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
)

// These tests drive the GitLab routes of the real application (real control store,
// auth, incidents service and the production egress path) against a local stub
// GitLab. NO real GitLab instance is involved.
//
// The stub listens on the host's own non-loopback IPv4 address, which the test
// allows with an egress allow-list prefix exactly as an administrator would; the
// production dialer therefore runs unchanged (no test seam is involved).

const gitlabTestToken = "tok-0123456789abcdef-test"

// stubView adapts the shared stub to the helper names the tests use.
type stubView struct{ *gitlabtest.Server }

func (s stubView) snapshot() (int, []gitlabtest.Issue, []string) {
	return s.Posts(), s.Issues(), s.Tokens()
}

func (s stubView) set(f func(*gitlabtest.Behaviour)) { s.Set(f) }

type gitlabEnv struct {
	*actEnv
	stub                          stubView
	baseURL                       string
	org, other                    model.ID
	p1, p2, q1                    model.ID
	alice, writer, reader, nobody person
	otherAdmin                    person
}

// glSeed is what building the gitlab environment's organizations makes: identifiers and the people with their sessions.
type glSeed struct {
	org, other, p1, p2, q1                model.ID
	alice, writer, reader, nobody, otherA person
}

// glSnapshot is the installation they are made on, seeded once (five users: eleven password KDFs, about five
// CPU-seconds under -race, which every test of this file used to pay) and copied by every test.
var glSnapshot isoSnapshot[glSeed]

func newGitLabEnv(t *testing.T) *gitlabEnv {
	t.Helper()
	stub := gitlabtest.New(t)
	e := &gitlabEnv{stub: stubView{stub}, baseURL: stub.URL}
	dir, session, s := glSnapshot.get(t, func(iso *isoEnv) glSeed {
		var s glSeed
		s.p1, s.p2, s.q1 = model.NewID(), model.NewID(), model.NewID()
		s.org = iso.org("gitlab org", s.p1, s.p2)
		s.other = iso.org("gitlab other org", s.q1)
		admin := func(org model.ID, who person) {
			iso.cmd(org, "org_admin", auth.AdminPayload{UserID: who.ID, Enabled: true})
		}
		s.alice = iso.user(s.org, "alice-gl@example.test")
		admin(s.org, s.alice)
		s.writer = iso.user(s.org, "writer-gl@example.test")
		iso.grant(s.org, s.writer, s.p1, true, auth.IncidentsWrite)
		s.reader = iso.user(s.org, "reader-gl@example.test")
		iso.grant(s.org, s.reader, s.p1, true, auth.Read)
		s.nobody = iso.user(s.org, "nobody-gl@example.test")
		s.otherA = iso.user(s.other, "alice-other-gl@example.test")
		admin(s.other, s.otherA)
		return s
	})
	iso := newIsoEnvAt(t, dir, session)
	e.actEnv = newConsoleEnvOn(t, iso, appcore.ConsoleConfig{PublicOrigin: "https://console.example.test", EgressAllow: []netip.Prefix{stub.Allow}, RootCAs: stub.Pool})
	e.p1, e.p2, e.q1, e.org, e.other = s.p1, s.p2, s.q1, s.org, s.other
	e.alice, e.writer, e.reader, e.nobody, e.otherAdmin = iso.rebind(s.alice), iso.rebind(s.writer), iso.rebind(s.reader), iso.rebind(s.nobody), iso.rebind(s.otherA)
	return e
}

func (e *gitlabEnv) settings(who person, body map[string]any) (int, []byte) {
	return e.post(who, "/api/v1/gitlab/settings", body)
}

func (e *gitlabEnv) issuesCall(who person, body map[string]any) (int, []byte) {
	return e.post(who, "/api/v1/gitlab/issues", body)
}

func (e *gitlabEnv) epoch(who person) string {
	e.t.Helper()
	status, raw := e.settings(who, map[string]any{"op": "read", "org": e.org.String()})
	if status != 200 {
		e.t.Fatalf("read: %d %s", status, raw)
	}
	var v struct{ Epoch string }
	_ = json.Unmarshal(raw, &v)
	return v.Epoch
}

// connect saves the connection of the stub with a mapping of p1.
func (e *gitlabEnv) connect() {
	e.t.Helper()
	status, raw := e.settings(e.alice, map[string]any{"op": "save", "org": e.org.String(), "command_id": model.NewID().String(), "expected_epoch": e.epoch(e.alice), "reason": "connect gitlab",
		"connection": map[string]any{"base_url": e.baseURL, "token": gitlabTestToken, "mappings": []map[string]any{{"project_id": e.p1.String(), "gitlab_project": "shop/web", "create_from": []string{"incident", "issue"}, "labels": []string{"soundpost"}}}}})
	if status != 200 || strings.Contains(string(raw), gitlabTestToken) {
		e.t.Fatalf("save: %d %s", status, raw)
	}
}

func (e *gitlabEnv) create(who person, org, project, incident model.ID, extra map[string]any) (int, map[string]any, []byte) {
	e.t.Helper()
	body := map[string]any{"op": "create", "org": org.String(), "project_id": project.String(), "entity": map[string]any{"kind": "incident", "id": incident.String()}, "command_id": model.NewID().String()}
	for k, v := range extra {
		body[k] = v
	}
	status, raw := e.issuesCall(who, body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return status, out, raw
}

func (e *gitlabEnv) call(who person, op string, incident model.ID) (int, map[string]any, []byte) {
	e.t.Helper()
	status, raw := e.issuesCall(who, map[string]any{"op": op, "org": e.org.String(), "project_id": e.p1.String(), "entity": map[string]any{"kind": "incident", "id": incident.String()}})
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return status, out, raw
}

// noToken fails when the token appears anywhere a person, a log or an audit could
// read it.
func (e *gitlabEnv) noToken(bodies ...[]byte) {
	e.t.Helper()
	for _, b := range bodies {
		if strings.Contains(string(b), gitlabTestToken) {
			e.t.Fatalf("token in a response: %s", b)
		}
	}
	if err := e.app.Control.View(e.ctx, func(st control.State) error {
		raw, _ := json.Marshal(st.Audits)
		if strings.Contains(string(raw), gitlabTestToken) {
			e.t.Errorf("token in an audit entry")
		}
		for _, o := range st.Orgs {
			settings, _ := json.Marshal(o.Settings)
			if strings.Contains(string(settings), gitlabTestToken) {
				e.t.Errorf("token in the organization settings")
			}
			for _, sealed := range o.Secrets {
				if sealed == gitlabTestToken {
					e.t.Errorf("token stored unsealed")
				}
			}
		}
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
}

func TestGitLabSettingsRoutes(t *testing.T) {
	e := newGitLabEnv(t)
	status, raw := e.settings(e.alice, map[string]any{"op": "read", "org": e.org.String()})
	var v struct {
		Connected bool
		CanEdit   bool `json:"can_edit"`
		Mappings  []any
		Token     struct {
			HasToken bool `json:"has_token"`
		}
	}
	if err := json.Unmarshal(raw, &v); status != 200 || err != nil || v.Connected || !v.CanEdit || len(v.Mappings) != 0 || v.Token.HasToken {
		t.Fatalf("empty read: %d %s", status, raw)
	}
	e.connect()
	status, raw = e.settings(e.alice, map[string]any{"op": "read", "org": e.org.String()})
	var full struct {
		Connected bool
		BaseHost  string `json:"base_host"`
		Mappings  []struct {
			ProjectID string `json:"project_id"`
		}
		Token struct {
			HasToken bool `json:"has_token"`
		}
	}
	if err := json.Unmarshal(raw, &full); status != 200 || err != nil || !full.Connected || !full.Token.HasToken || len(full.Mappings) != 1 || full.BaseHost != strings.TrimPrefix(e.baseURL, "https://") {
		t.Fatalf("read: %d %s", status, raw)
	}
	e.noToken(raw)

	// test: GitLab's own answer about the token; recorded for the page.
	status, raw = e.settings(e.alice, map[string]any{"op": "test", "org": e.org.String()})
	var tested struct {
		OK        bool
		Scopes    []string
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &tested); status != 200 || err != nil || !tested.OK || len(tested.Scopes) != 1 || tested.ExpiresAt != "2027-03-04" {
		t.Fatalf("test: %d %s", status, raw)
	}
	_, raw = e.settings(e.alice, map[string]any{"op": "read", "org": e.org.String()})
	if !strings.Contains(string(raw), `"expires_at":"2027-03-04"`) || !strings.Contains(string(raw), `"scopes":["api"]`) {
		t.Fatalf("token metadata not recorded: %s", raw)
	}
	_, _, tokens := e.stub.snapshot()
	for _, seen := range tokens {
		if seen != gitlabTestToken {
			t.Fatalf("PRIVATE-TOKEN %q", seen)
		}
	}

	// A member reads the redacted connection (only the projects they can see); a
	// member with no grant sees no mapping; a non-member and another organization's
	// administrator get the one not-found.
	_, raw = e.settings(e.reader, map[string]any{"op": "read", "org": e.org.String()})
	if !strings.Contains(string(raw), `"can_edit":false`) || !strings.Contains(string(raw), e.p1.String()) {
		t.Fatalf("reader read: %s", raw)
	}
	e.noToken(raw)
	_, raw = e.settings(e.nobody, map[string]any{"op": "read", "org": e.org.String()})
	if strings.Contains(string(raw), e.p1.String()) || !strings.Contains(string(raw), `"connected":true`) {
		t.Fatalf("grantless member read: %s", raw)
	}
	var foreign string
	for name, c := range map[string]struct {
		who  person
		body map[string]any
	}{
		"other org admin read": {e.otherAdmin, map[string]any{"op": "read", "org": e.org.String()}},
		"unknown org read":     {e.alice, map[string]any{"op": "read", "org": model.NewID().String()}},
		"other org admin test": {e.otherAdmin, map[string]any{"op": "test", "org": e.org.String()}},
	} {
		status, raw := e.settings(c.who, c.body)
		got := denial(t, status, raw)
		if status != 404 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		if foreign == "" {
			foreign = got
		} else if got != foreign {
			t.Fatalf("%s is distinguishable: %s vs %s", name, got, foreign)
		}
	}
	// Only an organization administrator writes or tests.
	epoch := e.epoch(e.alice)
	save := func(base string) map[string]any {
		return map[string]any{"op": "save", "org": e.org.String(), "command_id": model.NewID().String(), "expected_epoch": epoch, "reason": "x",
			"connection": map[string]any{"base_url": base, "token": gitlabTestToken + "2", "mappings": []any{}}}
	}
	for name, who := range map[string]person{"writer": e.writer, "reader": e.reader, "nobody": e.nobody, "other admin": e.otherAdmin} {
		if status, raw := e.settings(who, save("https://gitlab.example.test")); status != 404 {
			t.Errorf("%s saved: %d %s", name, status, raw)
		}
		if status, raw := e.settings(who, map[string]any{"op": "test", "org": e.org.String()}); status != 404 {
			t.Errorf("%s tested: %d %s", name, status, raw)
		}
		if status, raw := e.settings(who, map[string]any{"op": "disconnect", "org": e.org.String(), "command_id": model.NewID().String(), "expected_epoch": epoch, "reason": "x"}); status != 404 {
			t.Errorf("%s disconnected: %d %s", name, status, raw)
		}
	}
	// The egress rules apply to the base URL at save time.
	for name, base := range map[string]string{"loopback": "https://127.0.0.1:8443", "metadata": "https://169.254.169.254", "private": "https://10.255.255.1", "http": "http://gitlab.example.test", "credentials": "https://u:p@gitlab.example.test", "query": "https://gitlab.example.test/?x=1"} {
		status, raw := e.settings(e.alice, save(base))
		if status != 400 {
			t.Errorf("%s base url: %d %s", name, status, raw)
		}
		e.noToken(raw)
	}
	// Shape: unknown ops and fields are refused.
	for name, body := range map[string]map[string]any{
		"unknown op":         {"op": "export", "org": e.org.String()},
		"read with command":  {"op": "read", "org": e.org.String(), "command_id": model.NewID().String()},
		"save without epoch": {"op": "save", "org": e.org.String(), "command_id": model.NewID().String(), "reason": "x", "connection": map[string]any{"base_url": e.baseURL, "mappings": []any{}}},
		"extra field":        {"op": "read", "org": e.org.String(), "scope": "org.admin"},
	} {
		if status, raw := e.settings(e.alice, body); status != 400 {
			t.Errorf("%s: %d %s", name, status, raw)
		}
	}
	// disconnect clears it; create then is a typed refusal.
	status, raw = e.settings(e.alice, map[string]any{"op": "disconnect", "org": e.org.String(), "command_id": model.NewID().String(), "expected_epoch": e.epoch(e.alice), "reason": "gone"})
	if status != 200 || strings.Contains(string(raw), `"connected":true`) {
		t.Fatalf("disconnect: %d %s", status, raw)
	}
	incident, _, _ := e.open(e.org, e.p1, incidents.SeverityMajor)
	if status, out, raw := e.create(e.alice, e.org, e.p1, incident, nil); status != 200 || out["state"] != "refused" || out["code"] != "gitlab_not_connected" {
		t.Fatalf("create after disconnect: %d %s", status, raw)
	}
}

func TestGitLabCreateFlowIsScopedAndExactlyOnce(t *testing.T) {
	e := newGitLabEnv(t)
	e.connect()
	incident, _, _ := e.open(e.org, e.p1, incidents.SeverityCritical)
	e.record(e.org, e.p1, incident, 1, incidents.Action{Type: incidents.TypeNote, Note: "SECRET-NOTE-TEXT with customer detail"})
	e.record(e.org, e.p1, incident, 2, incidents.Action{Type: incidents.TypeTitle, Title: "SECRET-TITLE-TEXT"})
	sibling, _, _ := e.open(e.org, e.p2, incidents.SeverityMajor)
	foreign, _, _ := e.open(e.other, e.q1, incidents.SeverityMajor)

	// preview is readable by a reader: the defaults and no existing link.
	status, out, raw := e.call(e.reader, "preview", incident)
	if status != 200 || out["state"] != "ready" || out["gitlab_project"] != "shop/web" || out["title"] != "Soundpost incident "+incident.String()[:8] || out["existing"] != nil {
		t.Fatalf("preview: %d %s", status, raw)
	}
	if d, _ := out["description"].(string); !strings.Contains(d, incident.String()) || strings.Contains(d, "SECRET") || strings.Contains(d, "soundpost-ref-") {
		t.Fatalf("preview description: %s", d)
	}
	if status, out, raw = e.call(e.alice, "preview", sibling); status != 404 {
		// the preview of the sibling project goes through its own project id
		_ = out
		t.Fatalf("preview of a project outside the request: %d %s", status, raw)
	}

	// Who may not create: the one not-found, nothing sent to GitLab.
	var baseline string
	for name, c := range map[string]struct {
		who      person
		org, prj model.ID
		inc      model.ID
	}{
		"reader":                {e.reader, e.org, e.p1, incident},
		"member without grant":  {e.nobody, e.org, e.p1, incident},
		"other org admin":       {e.otherAdmin, e.org, e.p1, incident},
		"writer of p1 on p2":    {e.writer, e.org, e.p2, sibling},
		"admin, foreign entity": {e.alice, e.org, e.p1, foreign},
		"admin, other org":      {e.alice, e.other, e.q1, foreign},
		"admin, missing entity": {e.alice, e.org, e.p1, model.NewID()},
	} {
		status, _, raw := e.create(c.who, c.org, c.prj, c.inc, nil)
		got := denial(t, status, raw)
		if status != 404 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		if baseline == "" {
			baseline = got
		} else if got != baseline {
			t.Fatalf("%s is distinguishable: %s vs %s", name, got, baseline)
		}
	}
	if posts, _, _ := e.stub.snapshot(); posts != 0 {
		t.Fatalf("a refused caller reached GitLab: %d", posts)
	}

	// The writer creates; GitLab gets identifiers only.
	status, out, raw = e.create(e.writer, e.org, e.p1, incident, nil)
	if status != 200 || out["state"] != "linked" || out["created"] != true || out["gitlab_project"] != "shop/web" || out["iid"] != "1" || !strings.HasPrefix(fmt.Sprint(out["url"]), e.baseURL) {
		t.Fatalf("create: %d %s", status, raw)
	}
	posts, issues, tokens := e.stub.snapshot()
	if posts != 1 || len(issues) != 1 {
		t.Fatalf("posts %d issues %d", posts, len(issues))
	}
	marker := model.ExternalMarker(e.org, "incident", incident)
	d := issues[0].Description
	if !strings.Contains(d, marker) || !strings.Contains(d, incident.String()) || !strings.Contains(d, "critical") || strings.Contains(d, "SECRET") || strings.Contains(issues[0].Title, "SECRET") || issues[0].Title != "Soundpost incident "+incident.String()[:8] || issues[0].Labels != "soundpost" {
		t.Fatalf("what GitLab received: %+v", issues[0])
	}
	for _, seen := range tokens {
		if seen != gitlabTestToken {
			t.Fatalf("PRIVATE-TOKEN %q", seen)
		}
	}
	e.noToken(raw)

	// One GitLab issue per entity, ever: the stored link comes back.
	status, out, raw = e.create(e.alice, e.org, e.p1, incident, nil)
	if status != 200 || out["state"] != "linked" || out["created"] != false || out["iid"] != "1" {
		t.Fatalf("second create: %d %s", status, raw)
	}
	if posts, _, _ := e.stub.snapshot(); posts != 1 {
		t.Fatalf("second POST: %d", posts)
	}
	if status, out, raw = e.call(e.writer, "recheck", incident); status != 200 || out["state"] != "linked" || out["iid"] != "1" {
		t.Fatalf("recheck: %d %s", status, raw)
	}
	// The preview now shows the stored link; the view and the timeline copy carry it, never the marker.
	if _, out, raw = e.call(e.reader, "preview", incident); out["existing"] == nil || !strings.Contains(string(raw), `"state":"linked"`) || strings.Contains(string(raw), marker) {
		t.Fatalf("preview of a linked incident: %s", raw)
	}
	if status, ans, raw := e.markdown(e.reader, "incidents", mdBody(e.org, e.p1, incident, "timeline")); status != 200 || !strings.Contains(ans.Markdown, "`external_begin`") || !strings.Contains(ans.Markdown, "`external_end`") || strings.Contains(ans.Markdown, marker) {
		t.Fatalf("timeline copy: %d %s", status, raw)
	}

	// An unmapped project is a typed refusal and GitLab is not called.
	if status, out, raw = e.create(e.alice, e.org, e.p2, sibling, nil); status != 200 || out["state"] != "refused" || out["code"] != "gitlab_mapping_missing" {
		t.Fatalf("unmapped project: %d %s", status, raw)
	}
	// link_from adopts the stored link of another entity the caller may write.
	second, _, _ := e.open(e.org, e.p1, incidents.SeverityMinor)
	status, raw = e.issuesCall(e.writer, map[string]any{"op": "link_from", "org": e.org.String(), "project_id": e.p1.String(), "entity": map[string]any{"kind": "incident", "id": second.String()}, "from": map[string]any{"kind": "incident", "id": incident.String()}})
	if status != 200 || !strings.Contains(string(raw), `"state":"linked"`) || !strings.Contains(string(raw), `"iid":"1"`) {
		t.Fatalf("link_from: %d %s", status, raw)
	}
	if posts, _, _ := e.stub.snapshot(); posts != 1 {
		t.Fatalf("link_from created: %d", posts)
	}
	status, raw = e.issuesCall(e.reader, map[string]any{"op": "link_from", "org": e.org.String(), "project_id": e.p1.String(), "entity": map[string]any{"kind": "incident", "id": second.String()}, "from": map[string]any{"kind": "incident", "id": incident.String()}})
	if status != 404 {
		t.Fatalf("a reader linked: %d %s", status, raw)
	}

	// The closed request shape.
	for name, body := range map[string]map[string]any{
		"unknown op":         {"op": "delete", "org": e.org.String(), "project_id": e.p1.String(), "entity": map[string]any{"kind": "incident", "id": incident.String()}},
		"create no command":  {"op": "create", "org": e.org.String(), "project_id": e.p1.String(), "entity": map[string]any{"kind": "incident", "id": incident.String()}},
		"recheck w/ command": {"op": "recheck", "org": e.org.String(), "project_id": e.p1.String(), "command_id": model.NewID().String(), "entity": map[string]any{"kind": "incident", "id": incident.String()}},
		"entity kind":        {"op": "preview", "org": e.org.String(), "project_id": e.p1.String(), "entity": map[string]any{"kind": "release", "id": incident.String()}},
		"link_from no from":  {"op": "link_from", "org": e.org.String(), "project_id": e.p1.String(), "entity": map[string]any{"kind": "incident", "id": incident.String()}},
		"title on preview":   {"op": "preview", "org": e.org.String(), "project_id": e.p1.String(), "title": "x", "entity": map[string]any{"kind": "incident", "id": incident.String()}},
		"extra field":        {"op": "preview", "org": e.org.String(), "project_id": e.p1.String(), "actor": "x", "entity": map[string]any{"kind": "incident", "id": incident.String()}},
	} {
		if status, raw := e.issuesCall(e.alice, body); status != 400 {
			t.Errorf("%s: %d %s", name, status, raw)
		}
	}
	e.noToken()
}

func TestGitLabUncertainOutcomeThenRecheckAndRefusals(t *testing.T) {
	e := newGitLabEnv(t)
	e.connect()
	// 5xx after the issue was made: unknown, then a recheck links it without a second POST.
	first, _, _ := e.open(e.org, e.p1, incidents.SeverityMajor)
	e.stub.set(func(b *gitlabtest.Behaviour) { b.CreateThenFail = 500 })
	status, out, raw := e.create(e.alice, e.org, e.p1, first, nil)
	if status != 200 || out["state"] != "unknown" || out["code"] != "gitlab_server_error" {
		t.Fatalf("5xx: %d %s", status, raw)
	}
	e.stub.set(func(b *gitlabtest.Behaviour) { b.CreateThenFail = 0 })
	if status, out, raw = e.call(e.alice, "recheck", first); status != 200 || out["state"] != "linked" || out["iid"] != "1" {
		t.Fatalf("recheck: %d %s", status, raw)
	}
	if posts, _, _ := e.stub.snapshot(); posts != 1 {
		t.Fatalf("posts %d", posts)
	}
	// 401/403/404 are definite refusals with closed codes; the entity can be created later.
	for status, code := range map[int]string{401: "gitlab_unauthorized", 403: "gitlab_forbidden", 404: "gitlab_not_found"} {
		inc, _, _ := e.open(e.org, e.p1, incidents.SeverityMinor)
		e.stub.set(func(b *gitlabtest.Behaviour) { b.PostStatus = status })
		st, out, raw := e.create(e.alice, e.org, e.p1, inc, nil)
		if st != 200 || out["state"] != "refused" || out["code"] != code {
			t.Fatalf("%d: %d %s", status, st, raw)
		}
		e.stub.set(func(b *gitlabtest.Behaviour) { b.PostStatus = 0 })
		if st, out, raw = e.create(e.alice, e.org, e.p1, inc, nil); st != 200 || out["state"] != "linked" {
			t.Fatalf("retry after %d: %d %s", status, st, raw)
		}
	}
	e.noToken()
}

func TestGitLabTwoConcurrentCreatesMakeOneIssue(t *testing.T) {
	e := newGitLabEnv(t)
	e.connect()
	incident, _, _ := e.open(e.org, e.p1, incidents.SeverityMajor)
	e.stub.set(func(b *gitlabtest.Behaviour) { b.PostDelay = 400 * time.Millisecond })
	var wg sync.WaitGroup
	statuses := make([]int, 2)
	outs := make([]map[string]any, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			who := e.alice
			if i == 1 {
				who = e.writer
			}
			statuses[i], outs[i], _ = e.create(who, e.org, e.p1, incident, nil)
		}()
	}
	wg.Wait()
	linked, busy := 0, 0
	for i := range 2 {
		switch {
		case statuses[i] == 200 && outs[i]["state"] == "linked":
			linked++
		case statuses[i] == 409 && outs[i]["detail"] == "in_progress":
			busy++
		default:
			t.Fatalf("call %d: %d %v", i, statuses[i], outs[i])
		}
	}
	if linked != 1 || busy != 1 {
		t.Fatalf("linked %d busy %d", linked, busy)
	}
	if posts, _, _ := e.stub.snapshot(); posts != 1 {
		t.Fatalf("posts %d", posts)
	}
}

func TestGitLabCreateRefusesBlockedBaseURLAtCallTime(t *testing.T) {
	// A connection whose base URL points at a blocked address (stored before the rule
	// existed, or by an older build) is refused at call time, GitLab not reached.
	e := newGitLabEnv(t)
	e.connect()
	incident, _, _ := e.open(e.org, e.p1, incidents.SeverityMajor)
	if err := e.app.Control.Update(e.ctx, func(st *control.State) error {
		o := st.Orgs[e.org.String()]
		var conn auth.GitLabConnection
		if err := json.Unmarshal(o.Settings[auth.GitLabSettingKey], &conn); err != nil {
			return err
		}
		conn.BaseURL = "https://127.0.0.1:9"
		raw, _ := json.Marshal(conn)
		o.Settings[auth.GitLabSettingKey] = raw
		st.Orgs[e.org.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	status, out, raw := e.create(e.alice, e.org, e.p1, incident, nil)
	if status != 200 || out["state"] != "refused" || out["code"] != "gitlab_egress_blocked" {
		t.Fatalf("%d %s", status, raw)
	}
	if posts, _, tokens := e.stub.snapshot(); posts != 0 || len(tokens) != 0 {
		t.Fatalf("stub reached: %d %d", posts, len(tokens))
	}
}
