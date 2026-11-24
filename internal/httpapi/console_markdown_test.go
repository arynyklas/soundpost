// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
)

// newConsoleEnv serves the human-action routes and the console routes of the real
// application (appcore.App.RegisterConsole) over the real control store, auth and
// incidents service.
func newConsoleEnv(t *testing.T, cfg appcore.ConsoleConfig) *actEnv {
	t.Helper()
	return newConsoleEnvOn(t, newIsoEnv(t), cfg)
}

// newConsoleEnvOn is newConsoleEnv over iso.
func newConsoleEnvOn(t *testing.T, iso *isoEnv, cfg appcore.ConsoleConfig) *actEnv {
	t.Helper()
	e := &actEnv{isoEnv: iso, poller: &fakePoller{}}
	e.actions = e.app.Actions
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterActionRoutes(mux, e.app.Auth, e.app.Actions)
		e.app.RegisterConsole(mux, cfg)
	}).Handler)
	t.Cleanup(e.srv.Close)
	return e
}

const hostileText = "<img src=x onerror=alert(1)> [click](https://evil.example/x) *bold* _it_ `tick` # head | cell | ![i](x) \\"

// note commits an incident note or title straight through the real service (the
// action route for them belongs to another slice).
func (e *actEnv) record(org, project, incident model.ID, version uint64, a incidents.Action) {
	e.t.Helper()
	scope, err := e.app.Auth.Authorize(e.ctx, e.actor.Cred, org, []model.ID{project}, auth.OrgAdmin)
	if err != nil {
		e.t.Fatal(err)
	}
	a.CommandID, a.ExpectedVersion, a.Target = model.NewID(), model.Revision(version), incidents.Target{Org: org, Project: project, Incident: incident}
	if _, err = e.app.Incidents.Act(e.ctx, scope, a, 0); err != nil {
		e.t.Fatal(a.Type, err)
	}
}

func mdBody(org, project, id model.ID, format string) map[string]any {
	return map[string]any{"org": org.String(), "project_id": project.String(), "id": id.String(), "format": format}
}

func (e *actEnv) markdown(who person, kind string, body map[string]any) (int, httpapi.MarkdownAnswer, []byte) {
	e.t.Helper()
	status, raw := e.post(who, "/api/v1/"+kind+"/markdown", body)
	var out httpapi.MarkdownAnswer
	if status == 200 {
		if err := json.Unmarshal(raw, &out); err != nil {
			e.t.Fatalf("answer: %v %s", err, raw)
		}
	}
	return status, out, raw
}

func TestMarkdownCopyOfAnIncident(t *testing.T) {
	const origin = "https://console.example.test"
	e := newConsoleEnv(t, appcore.ConsoleConfig{PublicOrigin: origin})
	p1, p2 := model.NewID(), model.NewID()
	org := e.org("markdown org", p1, p2)
	alice := e.user(org, "alice-md@example.test")
	e.admin(org, alice)
	reader := e.user(org, "reader-md@example.test")
	e.grant(org, reader, p1, true, auth.Read)
	incident, _, _ := e.open(org, p1, incidents.SeverityCritical)
	release := model.NewID()

	r := e.respond(e.post(alice, "/api/v1/actions", act(org, p1, incident, "link", 1, map[string]any{"link": map[string]any{"kind": "release", "id": release.String()}})))
	if r.Revision == nil || *r.Revision != 2 {
		t.Fatalf("link: %+v", r)
	}
	e.record(org, p1, incident, 2, incidents.Action{Type: incidents.TypeTitle, Title: hostileText})
	e.record(org, p1, incident, 3, incidents.Action{Type: incidents.TypeNote, Note: "first line\n" + hostileText + "\n# not a heading\n\n- not a list"})
	r = e.respond(e.post(alice, "/api/v1/actions", act(org, p1, incident, "ack", 4, map[string]any{"reason": hostileText})))
	if r.Revision == nil || *r.Revision != 5 {
		t.Fatalf("ack: %+v", r)
	}

	// link: the hash form of the notifications.
	status, ans, raw := e.markdown(reader, "incidents", mdBody(org, p1, incident, "link"))
	want := origin + "/#view=incidents&org=" + org.String() + "&projects=" + p1.String() + "&incident=" + p1.String() + ":" + incident.String()
	if status != 200 || ans.State != httpapi.StateReady || ans.Markdown != want {
		t.Fatalf("link: %d %s", status, raw)
	}

	// description: identifiers, severity, status, linked entity IDs, link; no user text.
	status, ans, raw = e.markdown(reader, "incidents", mdBody(org, p1, incident, "description"))
	if status != 200 || ans.State != httpapi.StateReady {
		t.Fatalf("description: %d %s", status, raw)
	}
	for _, need := range []string{incident.String(), p1.String(), "critical", "open", release.String(), want} {
		if !strings.Contains(ans.Markdown, need) {
			t.Errorf("description lacks %q:\n%s", need, ans.Markdown)
		}
	}
	for _, leak := range []string{"onerror", "click", "evil.example", "first line"} {
		if strings.Contains(ans.Markdown, leak) {
			t.Errorf("description carries user text %q:\n%s", leak, ans.Markdown)
		}
	}

	// timeline: chronological, escaped, notes block-quoted.
	status, ans, raw = e.markdown(reader, "incidents", mdBody(org, p1, incident, "timeline"))
	if status != 200 || ans.State != httpapi.StateReady {
		t.Fatalf("timeline: %d %s", status, raw)
	}
	md := ans.Markdown
	for _, bad := range []string{"<img", "](https://evil", "onerror=alert(1)", "*bold*", "`tick`", "| cell |", "![i]"} {
		if i := strings.Index(md, bad); i >= 0 && (i == 0 || md[i-1] != '\\') {
			t.Errorf("unescaped %q in the timeline:\n%s", bad, md)
		}
	}
	for _, need := range []string{`\<img`, "\\[click\\]\\(https:\u200b//evil\\.example/x\\)", "`note`", "`title`", "`ack`", "`open`", alice.ID.String(), release.String()} {
		if !strings.Contains(md, need) {
			t.Errorf("timeline lacks %q:\n%s", need, md)
		}
	}
	times := regexp.MustCompile("`(\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\dZ)`").FindAllStringSubmatch(md, -1)
	if len(times) != 5 {
		t.Fatalf("%d UTC RFC3339 times for 5 entries:\n%s", len(times), md)
	}
	for i := 1; i < len(times); i++ {
		if times[i][1] < times[i-1][1] {
			t.Errorf("timeline is not chronological: %v", times)
		}
	}
	for i, line := range strings.Split(md, "\n") {
		if strings.Contains(line, "first line") || strings.Contains(line, "not a heading") || strings.Contains(line, "not a list") {
			if !strings.HasPrefix(line, "    > ") {
				t.Errorf("note line %d is not inside its block quote: %q", i, line)
			}
		}
		if strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "# Soundpost incident") && !strings.HasPrefix(line, "## Timeline") {
			t.Errorf("a heading was injected: %q", line)
		}
	}
	// Titles and notes are in the copy because the caller may already read them; the
	// reader who reads them via the incident view sees the same text.
	if !strings.Contains(md, "first line") {
		t.Error("the note is missing from the timeline copy")
	}
}

func TestMarkdownWithoutPublicOrigin(t *testing.T) {
	e := newConsoleEnv(t, appcore.ConsoleConfig{})
	p1 := model.NewID()
	org := e.org("no origin org", p1)
	alice := e.user(org, "alice-noorigin@example.test")
	e.admin(org, alice)
	incident, _, _ := e.open(org, p1, incidents.SeverityMinor)
	status, ans, raw := e.markdown(alice, "incidents", mdBody(org, p1, incident, "link"))
	if status != 200 || ans.State != httpapi.StateNotAvailable || ans.Reason != "public_origin_not_configured" || ans.Markdown != "" {
		t.Fatalf("link: %d %s", status, raw)
	}
	status, ans, raw = e.markdown(alice, "incidents", mdBody(org, p1, incident, "description"))
	if status != 200 || ans.State != httpapi.StateReady || strings.Contains(ans.Markdown, "Open in Soundpost") || !strings.Contains(ans.Markdown, incident.String()) {
		t.Fatalf("description: %d %s", status, raw)
	}
}

func TestMarkdownScopeAndShape(t *testing.T) {
	e := newConsoleEnv(t, appcore.ConsoleConfig{PublicOrigin: "https://console.example.test"})
	p1, p2, q1 := model.NewID(), model.NewID(), model.NewID()
	org := e.org("markdown scope org", p1, p2)
	other := e.org("markdown other org", q1)
	alice := e.user(org, "alice-mds@example.test")
	e.admin(org, alice)
	reader := e.user(org, "reader-mds@example.test")
	e.grant(org, reader, p1, true, auth.Read)
	writer := e.user(org, "writer-mds@example.test")
	e.grant(org, writer, p1, true, auth.IncidentsWrite)
	nobody := e.user(org, "nobody-mds@example.test")
	incident, _, _ := e.open(org, p1, incidents.SeverityMajor)
	sibling, _, _ := e.open(org, p2, incidents.SeverityMajor)
	foreign, _, _ := e.open(other, q1, incidents.SeverityMajor)

	for who, p := range map[string]person{"admin": alice, "reader": reader, "writer": writer} {
		if status, ans, raw := e.markdown(p, "incidents", mdBody(org, p1, incident, "description")); status != 200 || ans.State != httpapi.StateReady {
			t.Fatalf("%s: %d %s", who, status, raw)
		}
	}
	// Everything the caller may not see is the one not-found, whatever the format.
	var baseline string
	for name, c := range map[string]struct {
		who  person
		body map[string]any
	}{
		"no grant":            {nobody, mdBody(org, p1, incident, "description")},
		"sibling project":     {reader, mdBody(org, p2, sibling, "description")},
		"missing incident":    {alice, mdBody(org, p1, model.NewID(), "description")},
		"other org incident":  {alice, mdBody(org, p1, foreign, "description")},
		"other org named":     {alice, mdBody(other, q1, foreign, "description")},
		"other org's project": {alice, mdBody(org, q1, foreign, "link")},
		"guessed project":     {alice, mdBody(org, model.NewID(), incident, "timeline")},
	} {
		status, _, raw := e.markdown(c.who, "incidents", c.body)
		got := denial(t, status, raw)
		if status != 404 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		if baseline == "" {
			baseline = got
		}
		if got != baseline {
			t.Fatalf("%s is distinguishable: %s vs %s", name, got, baseline)
		}
	}
	// Shape: closed formats, no widening field, session needs the CSRF token.
	for name, mutate := range map[string]func(map[string]any){
		"unknown format": func(b map[string]any) { b["format"] = "html" },
		"empty format":   func(b map[string]any) { delete(b, "format") },
		"zero id":        func(b map[string]any) { b["id"] = model.ID{}.String() },
		"extra field":    func(b map[string]any) { b["permission"] = "org.admin" },
		"actor":          func(b map[string]any) { b["actor"] = alice.ID.String() },
	} {
		body := mdBody(org, p1, incident, "link")
		mutate(body)
		if status, raw := e.post(alice, "/api/v1/incidents/markdown", body); status != 400 {
			t.Errorf("%s: %d %s", name, status, raw)
		}
	}
	if status, raw := e.post(alice, "/api/v1/issues/markdown", mdBody(org, p1, incident, "timeline")); status != 400 {
		t.Errorf("an issue timeline was accepted: %d %s", status, raw)
	}
	if status, _ := e.post(person{}, "/api/v1/incidents/markdown", mdBody(org, p1, incident, "link")); status != 401 {
		t.Errorf("no credential: %d", status)
	}
	if status, raw := e.do(alice, "POST", "/api/v1/incidents/markdown", mdBody(org, p1, incident, "link"), func(r *http.Request) { r.Header.Del("X-CSRF-Token") }); status != 403 {
		t.Errorf("no CSRF token: %d %s", status, raw)
	}
	// The issue route has the same not-found rules: an issue nobody has is the same
	// answer for a reader, an admin and a caller without a grant.
	var issueBaseline string
	for name, c := range map[string]struct {
		who  person
		body map[string]any
	}{
		"reader":  {reader, mdBody(org, p1, model.NewID(), "description")},
		"admin":   {alice, mdBody(org, p1, model.NewID(), "link")},
		"nobody":  {nobody, mdBody(org, p1, model.NewID(), "description")},
		"writer":  {writer, mdBody(org, p1, model.NewID(), "description")},
		"foreign": {alice, mdBody(other, q1, model.NewID(), "description")},
	} {
		status, _, raw := e.markdown(c.who, "issues", c.body)
		got := denial(t, status, raw)
		if status != 404 {
			t.Fatalf("issue %s: %d %s", name, status, raw)
		}
		if issueBaseline == "" {
			issueBaseline = got
		}
		if got != issueBaseline {
			t.Fatalf("issue %s is distinguishable: %s vs %s", name, got, issueBaseline)
		}
	}
}

func TestMarkdownTimelineDefusesGitLabTriggers(t *testing.T) {
	e := newConsoleEnv(t, appcore.ConsoleConfig{PublicOrigin: "https://console.example.test"})
	p1 := model.NewID()
	org := e.org("trigger org", p1)
	alice := e.user(org, "alice-trg@example.test")
	e.admin(org, alice)
	incident, _, _ := e.open(org, p1, incidents.SeverityMajor)
	const trig = "@user @all #123 !45 &6 %milestone ~label ~\"two words\" $snippet [[wiki]] group/project#1 deadbeef1234567890abcdef https://evil.example/x user@example.com <!-- x -->"
	e.record(org, p1, incident, 1, incidents.Action{Type: incidents.TypeTitle, Title: "@user #123 !45 ~label $snippet [[w]] user@example.com"})
	e.record(org, p1, incident, 2, incidents.Action{Type: incidents.TypeNote, Note: "/close\n/assign @me\n" + trig})
	r := e.respond(e.post(alice, "/api/v1/actions", act(org, p1, incident, "ack", 3, map[string]any{"reason": trig})))
	if r.Revision == nil {
		t.Fatal("ack")
	}
	_, ans, raw := e.markdown(alice, "incidents", mdBody(org, p1, incident, "timeline"))
	for _, bad := range []string{"@u", "@a", "@m", "#1", "!4", "&6", "%m", "~l", "~\"", "$s", "[[", "group/project#", "deadbeef1234", "://evil", "<!--", "> /close", "> /assign"} {
		if strings.Contains(ans.Markdown, bad) {
			t.Errorf("trigger %q survives:\n%s", bad, raw)
		}
	}
}
