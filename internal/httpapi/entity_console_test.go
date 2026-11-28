// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
)

// entityEnv is the real stack behind the entity routes of the console API: real control store and auth, the application's own
// investigator and evidence handlers as BindIssueActions wires them, the real incident and issue services.
type entityEnv struct{ *issueEnv }

func newEntityEnv(t *testing.T) *entityEnv {
	t.Helper()
	e := &entityEnv{newIssueEnv(t)}
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterActionRoutes(mux, e.app.Auth, e.actions)
		httpapi.RegisterInvestigateRoutes(mux, e.app.Auth, e.app.Investigator)
		httpapi.RegisterEvidenceRoutes(mux, e.app.Auth, e.app.Evidence)
		httpapi.RegisterRelatedRoutes(mux, e.app.Auth, httpapi.NewRelated(e.app.Control))
	}).Handler)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *entityEnv) investigate(who person, org model.ID, kind string, target model.ID, projects ...model.ID) (int, []byte) {
	e.t.Helper()
	ids := make([]string, len(projects))
	for i, p := range projects {
		ids[i] = p.String()
	}
	return e.post(who, "/api/v1/investigate", map[string]any{"org": org.String(), "kind": kind, "projects": ids, "target": target.String(), "window": map[string]any{"start": "10", "end": "20"}, "limit": 10})
}

func (e *entityEnv) evidenceIssue(who person, org, project, issue model.ID) (int, []byte) {
	e.t.Helper()
	return e.post(who, "/api/v1/evidence/issue", map[string]any{"org": org.String(), "project": project.String(), "issue": issue.String()})
}

func (e *entityEnv) evidenceOccurrence(who person, org, project, issue, occurrence model.ID) (int, []byte) {
	e.t.Helper()
	return e.post(who, "/api/v1/evidence/occurrence", map[string]any{"org": org.String(), "project": project.String(), "issue": issue.String(), "occurrence": occurrence.String()})
}

func (e *entityEnv) related(who person, org, project, incident model.ID) (int, []byte) {
	e.t.Helper()
	return e.post(who, "/api/v1/incidents/related", map[string]any{"org": org.String(), "project_id": project.String(), "incident_id": incident.String()})
}

func decodeAs[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("not the expected JSON: %v\n%s", err, raw)
	}
	return v
}

// listed returns an occurrence the issue's evidence lists.
func (e *entityEnv) listed(org, project, issue model.ID) model.ID {
	e.t.Helper()
	system, err := e.app.Auth.AuthorizeSystem(e.ctx, org, []model.ID{project}, auth.IssuesWrite)
	if err != nil {
		e.t.Fatal(err)
	}
	book, err := e.app.Control.IssueBook(e.ctx, system, project)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, gi := range book.Issues {
		if gi.ID == issue && len(gi.Occurrences) > 0 {
			return gi.Occurrences[0].OccurrenceID
		}
	}
	e.t.Fatal("no listed occurrence")
	return model.ID{}
}

// adopt links an issue to a tracker issue through the lifecycle service, the way the GitLab group will, as who.
func (e *entityEnv) adopt(who person, org, project, issue model.ID, revision uint64) {
	e.t.Helper()
	scope, err := e.app.Auth.Authorize(e.ctx, who.Cred, org, []model.ID{project}, auth.IssuesWrite)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err = e.svc.Act(e.ctx, scope, issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: model.Revision(revision), IssueID: issue, Kind: "external_adopt",
		External: &model.ExternalOp{Provider: "gitlab", Kind: model.ExternalAdopt, Marker: model.ExternalMarker(org, "issue", issue), Project: "shop/web", Result: model.ExternalLinked, IID: 12, URL: "https://git.example.test/shop/web/-/issues/12"}}); err != nil {
		e.t.Fatal(err)
	}
}

// ---- incident title and notes ----

func TestIncidentTitleAndNoteOverHTTP(t *testing.T) {
	e := newEntityEnv(t)
	p1 := model.NewID()
	org := e.org("title org", p1)
	erin := e.user(org, "erin-title@example.test")   // incidents.write on p1
	frank := e.user(org, "frank-title@example.test") // telemetry.read on p1
	e.grant(org, erin, p1, true, auth.IncidentsWrite)
	e.grant(org, frank, p1, true, auth.Read)
	incident, _, _ := e.open(org, p1, incidents.SeverityMajor)

	// An unnamed incident says "" (the console shows its own fallback).
	if v := e.incident(frank, org, p1, incident); v.Title != "" {
		t.Fatalf("a never-named incident has the title %q", v.Title)
	}
	status, raw := e.post(erin, "/api/v1/actions", act(org, p1, incident, "title", 1, map[string]any{"title": "  Checkout errors in eu-west  "}))
	r := e.respond(status, raw)
	if r.Incident == nil || r.Incident.Title != "Checkout errors in eu-west" || r.Incident.Version != 2 || r.Incident.Timeline[1].Type != "title" || r.Incident.Timeline[1].Title != "Checkout errors in eu-west" || r.Incident.Timeline[1].Actor != erin.ID {
		t.Fatalf("title: %s", raw)
	}
	if !strings.Contains(string(raw), `"title":"Checkout errors in eu-west"`) {
		t.Fatalf("the wire member is title: %s", raw)
	}

	// A stale expected version is the typed 409 with the current version.
	status, raw = e.post(erin, "/api/v1/actions", act(org, p1, incident, "title", 1, map[string]any{"title": "Late rename"}))
	if c := decodeAs[conflictBody](t, raw); status != 409 || c.Detail != "incident_version_conflict" || c.CurrentVersion != "2" {
		t.Fatalf("stale title: %d %s", status, raw)
	}

	// The same command retried is the first result, not a second timeline entry.
	body := act(org, p1, incident, "note", 2, map[string]any{"note": "Rolled back the 14:02 deploy.\nWatching the error rate."})
	first := e.respond(e.post(erin, "/api/v1/actions", body))
	again := e.respond(e.post(erin, "/api/v1/actions", body))
	if first.Incident.Version != 3 || again.Incident.Version != 3 || len(again.Incident.Timeline) != 3 || again.Incident.Timeline[2].Note != "Rolled back the 14:02 deploy.\nWatching the error rate." {
		t.Fatalf("note retry: %+v %+v", first.Incident, again.Incident)
	}

	// Refusals: typed 400s that name nothing but the closed token.
	for name, tc := range map[string]struct {
		kind    string
		payload map[string]any
		detail  string
	}{
		"empty title":          {"title", map[string]any{"title": "   "}, "incident_title_invalid"},
		"missing title":        {"title", map[string]any{}, "incident_title_invalid"},
		"title too long":       {"title", map[string]any{"title": strings.Repeat("a", 161)}, "incident_title_invalid"},
		"title with a newline": {"title", map[string]any{"title": "a\nb"}, "incident_title_invalid"},
		"title with a reason":  {"title", map[string]any{"title": "ok", "reason": "why"}, "incident_reason_invalid"},
		"title with a note":    {"title", map[string]any{"title": "ok", "note": "x"}, "action_payload_invalid"},
		"title on an ack":      {"ack", map[string]any{"title": "ok"}, "action_payload_invalid"},
		"note on an ack":       {"ack", map[string]any{"note": "ok"}, "action_payload_invalid"},
		"empty note":           {"note", map[string]any{"note": ""}, "incident_note_invalid"},
		"blank note":           {"note", map[string]any{"note": " \n "}, "incident_note_invalid"},
		"note too long":        {"note", map[string]any{"note": strings.Repeat("a", 2001)}, "incident_note_invalid"},
		"note with a tab":      {"note", map[string]any{"note": "a\tb"}, "incident_note_invalid"},
		"note with a reason":   {"note", map[string]any{"note": "ok", "reason": "why"}, "incident_reason_invalid"},
	} {
		status, raw = e.post(erin, "/api/v1/actions", act(org, p1, incident, tc.kind, 3, tc.payload))
		if status != 400 || !strings.Contains(string(raw), `"detail":"`+tc.detail+`"`) {
			t.Fatalf("%s: %d %s, want 400 %s", name, status, raw, tc.detail)
		}
	}
	// Nothing above committed.
	if v := e.incident(erin, org, p1, incident); v.Version != 3 || v.Title != "Checkout errors in eu-west" {
		t.Fatalf("a refused action changed the incident: %+v", v)
	}

	// Readers see the title and the notes, and cannot add either (the one denial a missing grant gets).
	v := e.incident(frank, org, p1, incident)
	if v.Title != "Checkout errors in eu-west" || len(v.Timeline) != 3 || v.Timeline[2].Note == "" {
		t.Fatalf("a reader does not see title and note: %+v", v)
	}
	for _, kind := range []string{"title", "note"} {
		payload := map[string]any{"title": "hijack"}
		if kind == "note" {
			payload = map[string]any{"note": "hijack"}
		}
		if status, raw = e.post(frank, "/api/v1/actions", act(org, p1, incident, kind, 3, payload)); status != http.StatusNotFound {
			t.Fatalf("a reader's %s: %d %s", kind, status, raw)
		}
	}

	// A note after the incident was resolved, the title in the queue and the investigation summary.
	e.respond(e.post(erin, "/api/v1/actions", act(org, p1, incident, "resolve", 3, map[string]any{"reason": "fixed"})))
	post := e.respond(e.post(erin, "/api/v1/actions", act(org, p1, incident, "note", 4, map[string]any{"note": "post-incident: tighten the alert"})))
	if post.Incident.Status != "resolved" || post.Incident.Timeline[len(post.Incident.Timeline)-1].Type != "note" {
		t.Fatalf("a note after resolve: %+v", post.Incident)
	}
	if q := e.queueView(frank, org, p1); len(q.Entries) != 1 || q.Entries[0].Title != "Checkout errors in eu-west" {
		t.Fatalf("queue title: %+v", q.Entries)
	}
	status, raw = e.investigate(frank, org, "incident", incident, p1)
	if view := decodeAs[httpapi.InvestigationView](t, raw); status != 200 || view.Incident == nil || view.Incident.Title != "Checkout errors in eu-west" {
		t.Fatalf("investigate incident title: %d %s", status, raw)
	}
}

// ---- error issue owner ----

func TestIssueAssignOverHTTP(t *testing.T) {
	e := newEntityEnv(t)
	p1, p2 := model.NewID(), model.NewID()
	org := e.org("assign org", p1, p2)
	pO := model.NewID()
	orgO := e.org("assign other org", pO)
	admin := e.user(org, "admin-assign@example.test")
	gina := e.user(org, "gina-assign@example.test")     // issues.write on p1
	gina2 := e.user(org, "gina2-assign@example.test")   // issues.write on p2 only
	erin := e.user(org, "erin-assign@example.test")     // incidents.write on p1
	frank := e.user(org, "frank-assign@example.test")   // telemetry.read on p1
	member := e.user(org, "member-assign@example.test") // a member with no grant
	outsider := e.user(orgO, "outsider-assign@example.test")
	e.admin(org, admin)
	e.grant(org, gina, p1, true, auth.IssuesWrite)
	e.grant(org, gina2, p2, true, auth.IssuesWrite)
	e.grant(org, erin, p1, true, auth.IncidentsWrite)
	e.grant(org, frank, p1, true, auth.Read)
	issue := e.seed(org, p1, 1)
	owner := func(id model.ID) map[string]any { return map[string]any{"owner": id.String()} }

	// gina assigns a member: committed, the owner in the answer, one audit with a fixed reason naming the owner.
	status, raw, command := e.issueAct(gina, org, p1, issue, "assign", 1, owner(member.ID))
	r := e.committed(status, raw, "open", "2")
	if r.Issue.Owner == nil || *r.Issue.Owner != member.ID || !strings.Contains(string(raw), `"owner":"`+member.ID.String()+`"`) {
		t.Fatalf("assign answer: %s", raw)
	}
	rows := e.audits("issues.assign")
	if len(rows) != 1 || rows[0].Principal != gina.ID || rows[0].Reason != "owner assigned" || len(rows[0].Targets) != 2 || rows[0].Targets[0] != issue || rows[0].Targets[1] != member.ID {
		t.Fatalf("audit: %+v", rows)
	}
	// A retry of the command is the first result and not a second audit.
	status, raw = e.retry(gina, org, p1, issue, command, "assign", 1, owner(member.ID))
	if again := e.committed(status, raw, "open", "2"); again.Issue.Owner == nil || *again.Issue.Owner != member.ID || len(e.audits("issues.assign")) != 1 {
		t.Fatalf("retry: %s", raw)
	}

	// A stale revision is the typed 409 with the current one; the same owner again is a state conflict.
	status, raw, _ = e.issueAct(gina, org, p1, issue, "assign", 1, owner(admin.ID))
	if c := decodeAs[conflictBody](t, raw); status != 409 || c.Detail != "issue_version_conflict" || c.CurrentVersion != "2" {
		t.Fatalf("stale assign: %d %s", status, raw)
	}
	status, raw, _ = e.issueAct(gina, org, p1, issue, "assign", 2, owner(member.ID))
	if c := decodeAs[conflictBody](t, raw); status != 409 || c.Detail != "issue_state_conflict" || c.CurrentVersion != "2" {
		t.Fatalf("same owner: %d %s", status, raw)
	}

	// The owner must belong to the caller's organization: a stranger, another organization's member and a guess are the one 400.
	var want string
	for name, id := range map[string]model.ID{"another organization's member": outsider.ID, "a guessed user": model.NewID()} {
		status, raw, _ = e.issueAct(gina, org, p1, issue, "assign", 2, owner(id))
		if status != 400 || !strings.Contains(string(raw), `"detail":"issue_owner_unknown"`) {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		if got := denial(t, status, raw); want == "" {
			want = got
		} else if got != want {
			t.Fatalf("%s is told apart: %q vs %q", name, got, want)
		}
	}
	// An organization administrator is a valid owner (with a reason of the caller's own), and the owner can be cleared.
	status, raw, _ = e.issueAct(gina, org, p1, issue, "assign", 2, map[string]any{"owner": admin.ID.String(), "reason": "handover to the platform lead"})
	if r = e.committed(status, raw, "open", "3"); *r.Issue.Owner != admin.ID {
		t.Fatalf("assign an administrator: %s", raw)
	}
	if rows = e.audits("issues.assign"); rows[len(rows)-1].Reason != "handover to the platform lead" {
		t.Fatalf("the caller's reason is not audited: %+v", rows)
	}
	status, raw, _ = e.issueAct(gina, org, p1, issue, "assign", 3, map[string]any{})
	if r = e.committed(status, raw, "open", "4"); r.Issue.Owner != nil || strings.Contains(string(raw), `"owner"`) {
		t.Fatalf("unassign: %s", raw)
	}
	if rows = e.audits("issues.assign"); rows[len(rows)-1].Reason != "owner cleared" {
		t.Fatalf("unassign audit: %+v", rows[len(rows)-1])
	}
	status, raw, _ = e.issueAct(gina, org, p1, issue, "assign", 4, map[string]any{"owner": nil})
	if c := decodeAs[conflictBody](t, raw); status != 409 || c.Detail != "issue_state_conflict" {
		t.Fatalf("unassign of an unassigned issue: %d %s", status, raw)
	}

	// The payload is closed: no title or note on an issue, no owner on another kind, no external operation anywhere.
	for name, tc := range map[string]struct {
		kind    string
		payload map[string]any
	}{
		"a title":               {"assign", map[string]any{"title": "x"}},
		"a note":                {"assign", map[string]any{"note": "x"}},
		"an owner on a resolve": {"resolve", map[string]any{"owner": member.ID.String(), "reason": "r"}},
	} {
		if status, raw, _ = e.issueAct(gina, org, p1, issue, tc.kind, 4, tc.payload); status != 400 || !strings.Contains(string(raw), "action_payload_invalid") {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
	}
	incident, _, _ := e.open(org, p1, incidents.SeverityMinor)
	for _, kind := range []string{"external_begin", "external_end", "external_adopt"} {
		if status, raw, _ = e.issueAct(gina, org, p1, issue, kind, 4, map[string]any{}); status != 400 || !strings.Contains(string(raw), "action_kind_unknown") {
			t.Fatalf("the console must not expose %s: %d %s", kind, status, raw)
		}
		if status, raw = e.post(erin, "/api/v1/actions", act(org, p1, incident, kind, 1, nil)); status != 400 || !strings.Contains(string(raw), "action_kind_unknown") {
			t.Fatalf("the console must not expose incident %s: %d %s", kind, status, raw)
		}
	}

	// Only issues.write (or administration) on THIS project assigns; everyone else gets the one denial a missing issue gets.
	missing := model.NewID()
	status, raw, _ = e.issueAct(gina, org, p1, missing, "assign", 1, owner(member.ID))
	missingBody := denial(t, status, raw)
	if status != 404 {
		t.Fatalf("a missing issue: %d %s", status, raw)
	}
	for name, who := range map[string]person{"read only": frank, "incidents.write": erin, "issues.write on another project": gina2, "another organization": outsider, "a member with no grant": member} {
		before := len(e.audits("issues.assign"))
		status, raw, _ = e.issueAct(who, org, p1, issue, "assign", 4, owner(member.ID))
		if status != 404 || denial(t, status, raw) != missingBody {
			t.Fatalf("%s: %d %s, want the denial %q", name, status, raw, missingBody)
		}
		if len(e.audits("issues.assign")) != before {
			t.Fatalf("%s: a refused assign was audited", name)
		}
	}
	if view := e.issueRevision(org, p1, issue); view != 4 {
		t.Fatalf("the issue moved to revision %d", view)
	}
}

// issueRevision reads the stored revision of an issue.
func (e *entityEnv) issueRevision(org, project, issue model.ID) uint64 {
	e.t.Helper()
	system, err := e.app.Auth.AuthorizeSystem(e.ctx, org, []model.ID{project}, auth.IssuesWrite)
	if err != nil {
		e.t.Fatal(err)
	}
	book, err := e.app.Control.IssueBook(e.ctx, system, project)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, gi := range book.Issues {
		if gi.ID == issue {
			return uint64(gi.Revision)
		}
	}
	e.t.Fatal("issue not found")
	return 0
}

// ---- project readers see error issues ----

func TestProjectReadersSeeErrorIssues(t *testing.T) {
	e := newEntityEnv(t)
	p1, p2 := model.NewID(), model.NewID()
	org := e.org("reader org", p1, p2)
	pO := model.NewID()
	orgO := e.org("reader other org", pO)
	admin := e.user(org, "admin-reader@example.test")
	gina := e.user(org, "gina-reader@example.test")       // issues.write on p1 only
	erin := e.user(org, "erin-reader@example.test")       // incidents.write on p1 only
	frank := e.user(org, "frank-reader@example.test")     // telemetry.read on p1
	frankB := e.user(org, "frankb-reader@example.test")   // telemetry.read on p2 only
	revoked := e.user(org, "revoked-reader@example.test") // telemetry.read on p1, revoked below
	outsider := e.user(orgO, "outsider-reader@example.test")
	e.admin(org, admin)
	e.grant(org, gina, p1, true, auth.IssuesWrite)
	e.grant(org, erin, p1, true, auth.IncidentsWrite)
	e.grant(org, frank, p1, true, auth.Read)
	e.grant(org, frankB, p2, true, auth.Read)
	e.grant(org, revoked, p1, true, auth.Read)
	e.grant(orgO, outsider, pO, true, auth.Read)

	i1, i2 := e.seed(org, p1, 1), e.seed(org, p2, 2)
	member := e.user(org, "owner-reader@example.test")
	if status, raw, _ := e.issueAct(gina, org, p1, i1, "assign", 1, map[string]any{"owner": member.ID.String()}); status != 200 {
		t.Fatalf("assign: %d %s", status, raw)
	}
	e.adopt(gina, org, p1, i1, 2)
	occurrence := e.listed(org, p1, i1)

	// The investigate issue kind: a reader and an issues.write holder are served, with the owner and the link; an administrator too.
	for name, who := range map[string]person{"reader": frank, "issues.write": gina, "administrator": admin} {
		status, raw := e.investigate(who, org, "issue", i1, p1)
		v := decodeAs[httpapi.InvestigationView](t, raw)
		if status != 200 || v.State != httpapi.StateReady || v.Issue == nil || v.Issue.ID != i1 || v.Issue.ProjectID != p1 || v.Issue.Revision != 3 || v.Issue.Owner == nil || *v.Issue.Owner != member.ID ||
			len(v.Issue.External) != 1 || v.Issue.External[0].State != "linked" || v.Issue.External[0].URL != "https://git.example.test/shop/web/-/issues/12" || v.Issue.External[0].IID == nil || *v.Issue.External[0].IID != 12 || v.Issue.External[0].Project != "shop/web" {
			t.Fatalf("investigate issue for the %s: %d %s", name, status, raw)
		}
		if strings.Contains(string(raw), "soundpost-ref-") || strings.Contains(string(raw), `"marker"`) {
			t.Fatalf("the %s sees the marker: %s", name, raw)
		}
	}
	// Release records stay administration: a reader is told so, and nothing is probed.
	status, raw := e.investigate(frank, org, "release", model.NewID(), p1)
	if v := decodeAs[httpapi.InvestigationView](t, raw); status != 200 || v.State != httpapi.StateNotAvailable || v.Reason != httpapi.ReasonReleaseRecordsAdmin {
		t.Fatalf("a reader asking a release: %d %s", status, raw)
	}

	// Evidence: the grouping facts for a reader, the occurrence detail only with telemetry.read.
	status, raw = e.evidenceIssue(frank, org, p1, i1)
	view := decodeAs[httpapi.IssueView](t, raw)
	sections := map[string]httpapi.ViewSection{}
	for _, s := range view.Sections {
		sections[s.Name] = s
	}
	if status != 200 || view.Grouping == nil || view.Grouping.Owner == nil || *view.Grouping.Owner != member.ID || len(view.Grouping.External) != 1 || len(view.Occurrences) != 1 || view.Occurrences[0].OccurrenceID != occurrence ||
		view.Reason == httpapi.ReasonIssueNeedsAdmin || sections["occurrence_detail"].State != httpapi.StateReady {
		t.Fatalf("evidence for a reader: %d %s", status, raw)
	}
	status, raw = e.evidenceIssue(gina, org, p1, i1)
	view = decodeAs[httpapi.IssueView](t, raw)
	sections = map[string]httpapi.ViewSection{}
	for _, s := range view.Sections {
		sections[s.Name] = s
	}
	if status != 200 || view.Grouping == nil || sections["occurrence_detail"].State != httpapi.StateNotAvailable || sections["occurrence_detail"].Reason != httpapi.ReasonOccurrenceNeedsTelemetry {
		t.Fatalf("evidence for an issues.write holder (no telemetry.read): %d %s", status, raw)
	}
	// A person with only incidents.write is not a reader of issues: the typed answer, nothing read.
	status, raw = e.evidenceIssue(erin, org, p1, i1)
	if v := decodeAs[httpapi.IssueView](t, raw); status != 200 || v.State != httpapi.StateNotAvailable || v.Reason != httpapi.ReasonIssueNeedsAdmin || v.Grouping != nil || strings.Contains(string(raw), "fingerprint") {
		t.Fatalf("evidence for an incident writer: %d %s", status, raw)
	}
	// The stored error record is read under the reader's own telemetry.read scope; it is not stored here, and the answer says that.
	status, raw = e.evidenceOccurrence(frank, org, p1, i1, occurrence)
	if v := decodeAs[httpapi.ErrorOccurrenceView](t, raw); status != 200 || v.Reason != httpapi.ReasonOccurrenceNotStored || v.State != httpapi.StateNotAvailable {
		t.Fatalf("occurrence for a reader: %d %s", status, raw)
	}
	status, raw = e.evidenceOccurrence(gina, org, p1, i1, occurrence)
	if v := decodeAs[httpapi.ErrorOccurrenceView](t, raw); status != 200 || v.Reason != httpapi.ReasonOccurrenceNeedsTelemetry || v.Detail != nil {
		t.Fatalf("occurrence for an issues.write holder: %d %s", status, raw)
	}
	// An occurrence the issue does not list is never reachable by guessing.
	if status, raw = e.evidenceOccurrence(frank, org, p1, i1, model.NewID()); status != 404 {
		t.Fatalf("a guessed occurrence: %d %s", status, raw)
	}

	// Adversarial: every one of these is the one 404 a missing issue gets, over both routes.
	e.grant(org, revoked, p1, false, auth.Read)
	type probe struct {
		who     person
		org     model.ID
		project model.ID
		issue   model.ID
	}
	probes := map[string]probe{
		"a reader of project B asking project A's issue under A": {frankB, org, p1, i1},
		"a reader of project A asking project B's issue under B": {frank, org, p2, i2},
		"a reader of project A asking B's issue under A":         {frank, org, p1, i2},
		"a reader of project B asking A's issue under B":         {frankB, org, p2, i1},
		"another organization asking this one":                   {outsider, org, p1, i1},
		"another organization asking its own project for it":     {outsider, orgO, pO, i1},
		"a revoked reader": {revoked, org, p1, i1},
		"an incident writer asking under a project it holds none": {erin, org, p2, i2},
		"a guessed issue":   {frank, org, p1, model.NewID()},
		"a guessed project": {frank, org, model.NewID(), i1},
	}
	var base string
	for name, c := range probes {
		for route, call := range map[string]func() (int, []byte){
			"investigate": func() (int, []byte) { return e.investigate(c.who, c.org, "issue", c.issue, c.project) },
			"evidence":    func() (int, []byte) { return e.evidenceIssue(c.who, c.org, c.project, c.issue) },
			"occurrence":  func() (int, []byte) { return e.evidenceOccurrence(c.who, c.org, c.project, c.issue, occurrence) },
		} {
			status, raw := call()
			if status != 404 || strings.Contains(string(raw), i1.String()) || strings.Contains(string(raw), i2.String()) {
				t.Fatalf("%s over %s: %d %s", name, route, status, raw)
			}
			if got := denial(t, status, raw); base == "" {
				base = got
			} else if got != base {
				t.Fatalf("%s over %s is told apart: %q vs %q", name, route, got, base)
			}
		}
	}

	// A reader cannot act on what she reads.
	for _, kind := range []string{"resolve", "ignore", "assign"} {
		payload := map[string]any{"reason": "reader"}
		if kind == "assign" {
			payload = map[string]any{"owner": member.ID.String()}
		}
		if status, raw, _ = e.issueAct(frank, org, p1, i1, kind, 3, payload); status != 404 {
			t.Fatalf("a reader's %s: %d %s", kind, status, raw)
		}
	}
	if rev := e.issueRevision(org, p1, i1); rev != 3 {
		t.Fatalf("a reader changed the issue: revision %d", rev)
	}
}

// ---- related incidents ----

func TestRelatedIncidentsOverHTTP(t *testing.T) {
	e := newEntityEnv(t)
	p1, p2 := model.NewID(), model.NewID()
	org := e.org("related org", p1, p2)
	pO := model.NewID()
	orgO := e.org("related other org", pO)
	admin := e.user(org, "admin-related@example.test")
	erin := e.user(org, "erin-related@example.test")   // incidents.write on p1
	frank := e.user(org, "frank-related@example.test") // telemetry.read on p1
	bob := e.user(org, "bob-related@example.test")     // telemetry.read on p2 only
	gina := e.user(org, "gina-related@example.test")   // issues.write on p1 (no incident grant)
	outsider := e.user(orgO, "outsider-related@example.test")
	e.admin(org, admin)
	e.grant(org, erin, p1, true, auth.IncidentsWrite)
	e.grant(org, frank, p1, true, auth.Read)
	e.grant(org, bob, p2, true, auth.Read)
	e.grant(org, gina, p1, true, auth.IssuesWrite)
	e.grant(orgO, outsider, pO, true, auth.Read)

	svc1, rel1, svc2, iss1 := model.NewID(), model.NewID(), model.NewID(), model.NewID()
	link := func(who person, project, incident model.ID, kind string, id model.ID, version uint64) {
		t.Helper()
		status, raw := e.post(who, "/api/v1/actions", act(org, project, incident, "link", version, map[string]any{"link": map[string]any{"kind": kind, "id": id.String()}}))
		e.respond(status, raw)
	}
	a, _, _ := e.open(org, p1, incidents.SeverityMajor)
	b, _, _ := e.open(org, p1, incidents.SeverityMinor)
	c, _, _ := e.open(org, p1, incidents.SeverityCritical)
	d, _, _ := e.open(org, p1, incidents.SeverityMinor)
	x, _, _ := e.open(org, p1, incidents.SeverityMinor)
	f, _, _ := e.open(org, p2, incidents.SeverityMajor) // another project of the same organization
	link(erin, p1, a, "service", svc1, 1)
	link(erin, p1, a, "release", rel1, 2)
	link(erin, p1, b, "service", svc1, 1)
	link(erin, p1, c, "release", rel1, 1)
	link(erin, p1, c, "issue", iss1, 2)
	link(erin, p1, d, "service", svc1, 1)
	link(erin, p1, x, "service", svc2, 1)
	link(admin, p2, f, "service", svc1, 1)
	e.respond(e.post(erin, "/api/v1/actions", act(org, p1, d, "resolve", 2, map[string]any{"reason": "done"})))

	// A is related to B (a shared service) and C (a shared release): only structured links, only open incidents of the project.
	status, raw := e.related(frank, org, p1, a)
	got := decodeAs[httpapi.RelatedView](t, raw)
	if status != 200 || len(got.Proposals) != 2 || got.More {
		t.Fatalf("related to A: %d %s", status, raw)
	}
	byID := map[model.ID]httpapi.RelatedProposal{}
	for _, p := range got.Proposals {
		byID[p.IncidentID] = p
	}
	pb, pc := byID[b], byID[c]
	if pb.ProjectID != p1 || pb.Status != "open" || pb.Severity != "minor" || len(pb.Shared) != 1 || pb.Shared[0] != (incidents.Link{Kind: incidents.LinkService, ID: svc1}) ||
		pc.ProjectID != p1 || pc.Status != "open" || pc.Severity != "critical" || len(pc.Shared) != 1 || pc.Shared[0] != (incidents.Link{Kind: incidents.LinkRelease, ID: rel1}) {
		t.Fatalf("proposals: %s", raw)
	}
	for _, leaked := range []model.ID{d, x, f, a} {
		if strings.Contains(string(raw), leaked.String()) {
			t.Fatalf("the answer names %s: %s", leaked, raw)
		}
	}
	if !strings.Contains(string(raw), `"proposals":[`) || strings.Contains(string(raw), `"more"`) {
		t.Fatalf("shape: %s", raw)
	}
	// Deterministic order: by incident ID.
	if a1, a2 := got.Proposals[0].IncidentID, got.Proposals[1].IncidentID; a1.String() > a2.String() {
		t.Fatalf("not ordered: %s", raw)
	}
	// The same links are seen from B and from C, the other way round; a resolved target has none; the list is never null.
	for name, tc := range map[string]struct {
		target model.ID
		want   []model.ID
	}{"from B": {b, []model.ID{a}}, "from C": {c, []model.ID{a}}, "a resolved target": {d, nil}, "an unrelated incident": {x, nil}} {
		status, raw = e.related(frank, org, p1, tc.target)
		v := decodeAs[httpapi.RelatedView](t, raw)
		if status != 200 || len(v.Proposals) != len(tc.want) || !strings.Contains(string(raw), `"proposals":[`) {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		for i, w := range tc.want {
			if v.Proposals[i].IncidentID != w {
				t.Fatalf("%s: %s", name, raw)
			}
		}
	}
	// An organization administrator and an incident writer read it too; the other project's incident, which shares the service, is
	// related to nothing here and F's own project answers for itself.
	for name, who := range map[string]person{"administrator": admin, "incident writer": erin} {
		if status, raw = e.related(who, org, p1, a); status != 200 || len(decodeAs[httpapi.RelatedView](t, raw).Proposals) != 2 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
	}
	if status, raw = e.related(bob, org, p2, f); status != 200 || len(decodeAs[httpapi.RelatedView](t, raw).Proposals) != 0 || strings.Contains(string(raw), a.String()) {
		t.Fatalf("F's project: %d %s", status, raw)
	}

	// Adversarial: all the same 404 as a missing incident, none of them names or counts anything.
	if status, raw = e.related(frank, org, p1, model.NewID()); status != 404 {
		t.Fatalf("a missing incident: %d %s", status, raw)
	}
	missing := denial(t, 404, raw)
	for name, call := range map[string]func() (int, []byte){
		"a reader of project B asking project A":            func() (int, []byte) { return e.related(bob, org, p1, a) },
		"a reader of project A asking B for an A incident":  func() (int, []byte) { return e.related(frank, org, p2, a) },
		"a reader of project A asking for B's incident":     func() (int, []byte) { return e.related(frank, org, p1, f) },
		"a reader of project A asking project B":            func() (int, []byte) { return e.related(frank, org, p2, f) },
		"an issues.write holder (no incident grant)":        func() (int, []byte) { return e.related(gina, org, p1, a) },
		"another organization asking this one":              func() (int, []byte) { return e.related(outsider, org, p1, a) },
		"another organization asking its own project for A": func() (int, []byte) { return e.related(outsider, orgO, pO, a) },
		"a guessed project":                                 func() (int, []byte) { return e.related(frank, org, model.NewID(), a) },
	} {
		status, raw = call()
		if status != 404 || denial(t, status, raw) != missing || strings.Contains(string(raw), "proposals") {
			t.Fatalf("%s: %d %s, want %q", name, status, raw, missing)
		}
	}
	// A revoked reader is refused at once.
	e.grant(org, frank, p1, false, auth.Read)
	if status, raw = e.related(frank, org, p1, a); status != 404 || denial(t, status, raw) != missing {
		t.Fatalf("a revoked reader: %d %s", status, raw)
	}
	// It reads and changes nothing: the incidents are as they were.
	if v := e.incident(admin, org, p1, a); v.Version != 3 {
		t.Fatalf("a related read changed an incident: %+v", v)
	}
	// The body is closed: no scope field, no unknown member.
	if status, raw = e.post(admin, "/api/v1/incidents/related", map[string]any{"org": org.String(), "project_id": p1.String(), "incident_id": a.String(), "projects": []string{p2.String()}}); status != 400 {
		t.Fatalf("an unknown member: %d %s", status, raw)
	}
}
