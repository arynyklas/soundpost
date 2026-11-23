// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
)

// fakeReleaseSource serves fixed per-project data, refusing a project outside the scope exactly as the
// real source does.
type fakeReleaseSource struct {
	mu    sync.Mutex
	data  map[model.ID]httpapi.ReleaseListProject
	err   error
	calls int
}

func (f *fakeReleaseSource) ReleaseList(_ context.Context, scope auth.Scope, project model.ID) (httpapi.ReleaseListProject, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return httpapi.ReleaseListProject{}, f.err
	}
	if !scope.AllowsProject(project) {
		return httpapi.ReleaseListProject{}, model.Fail(model.NotFound)
	}
	return f.data[project], nil
}

type releaseListAnswer struct {
	Org        string   `json:"org"`
	Projects   []string `json:"projects"`
	State      string   `json:"state"`
	Reason     string   `json:"reason"`
	Items      []releaseItem
	More       bool   `json:"more"`
	NextCursor string `json:"next_cursor"`
	Sections   []struct {
		Name, State, Reason string
	} `json:"sections"`
}

type releaseItem struct {
	ProjectID string   `json:"project_id"`
	ReleaseID string   `json:"release_id"`
	BuildID   string   `json:"build_id"`
	Label     string   `json:"label"`
	BuildTime string   `json:"build_time"`
	Parents   []string `json:"parents"`
	Deploys   []struct {
		Environment string `json:"environment"`
		DeployedAt  string `json:"deployed_at"`
	} `json:"deploys"`
	DeployState     string `json:"deploy_state"`
	NewIssues       *int   `json:"new_issues"`
	RegressedIssues *int   `json:"regressed_issues"`
	ResolvedIssues  *int   `json:"resolved_issues"`
	CountsState     string `json:"counts_state"`
}

func labels(v releaseListAnswer) []string {
	out := make([]string, len(v.Items))
	for i, it := range v.Items {
		out[i] = it.Label
	}
	return out
}

// releaseWorld is an organization with two projects, three registered releases in the first, one
// environment, a fake issue source over the same releases and people with different reach.
type releaseWorld struct {
	e                   *evEnv
	org, p, q, env      model.ID
	r1, r2, r3          model.ID
	admin, reader, qr   person
	stranger            person
	source              *fakeReleaseSource
	adminScope          auth.Scope
	rec                 map[model.ID]model.Release
	orgB                model.ID
	readerB, readerSame person
}

func newReleaseWorld(t *testing.T) *releaseWorld {
	t.Helper()
	w := &releaseWorld{source: &fakeReleaseSource{data: map[model.ID]httpapi.ReleaseListProject{}}}
	w.e = consoleEnv(t, w.source)
	e := w.e
	w.p, w.q = model.NewID(), model.NewID()
	w.org = e.org("release list", w.p, w.q)
	w.orgB = e.org("release list B", model.NewID())
	w.admin = e.user(w.org, "rl-admin@example.test")
	e.cmd(w.org, "org_admin", auth.AdminPayload{UserID: w.admin.ID, Enabled: true})
	w.reader = e.user(w.org, "rl-reader@example.test")
	e.grant(w.org, w.reader, w.p, true, auth.Read)
	w.readerSame = e.user(w.org, "rl-reader2@example.test")
	e.grant(w.org, w.readerSame, w.p, true, auth.Read)
	w.qr = e.user(w.org, "rl-q@example.test")
	e.grant(w.org, w.qr, w.q, true, auth.Read)
	w.stranger = e.user(w.orgB, "rl-stranger@example.test")
	src := e.source(w.org, w.p, sharedIDs{model.NewID(), model.NewID(), model.NewID()}, []model.Kind{model.Metric})
	w.env = src.Environment
	var err error
	if w.adminScope, err = e.app.Auth.Authorize(e.ctx, w.admin.Cred, w.org, []model.ID{w.p}, auth.OrgAdmin); err != nil {
		t.Fatal(err)
	}
	w.rec = map[model.ID]model.Release{}
	mk := func(label string, at int64, parents ...model.ID) model.ID {
		id := model.NewID()
		r := model.Release{ID: id, Org: w.org, Project: w.p, BuildID: model.NewID(), Parents: parents, BuildTime: model.UnixNano(at), DisplayLabel: label,
			DebugArtifacts: []model.ReleaseDebugArtifact{{ArtifactID: model.NewID(), DebugID: "debug-" + label, SHA256: model.HashCanonical([]byte(label))}}}
		e.register(w.adminScope, r)
		w.rec[id] = r
		return id
	}
	w.r1 = mk("v1.0", 100)
	w.r2 = mk("v2.0-Beta", 200, w.r1)
	w.r3 = mk("v3.0", 300, w.r2)
	return w
}

func (w *releaseWorld) records() []model.Release {
	var out []model.Release
	for _, id := range []model.ID{w.r1, w.r2, w.r3} {
		r := w.rec[id]
		r.DebugArtifacts, r.History = nil, nil
		out = append(out, r)
	}
	return out
}

func evidence(at int64, release *model.ID) model.GroupingEvidence {
	return model.GroupingEvidence{OccurrenceID: model.NewID(), RecordID: model.NewID(), EventTime: model.UnixNano(at), ReleaseID: release, Ancestry: "known"}
}

// issueData: i1 first seen in r1, resolved with r2 as the fixed descendant, regressed on r3; i2 first
// seen in r2; i3 has folded evidence naming r1; i4's earliest evidence names no release.
func (w *releaseWorld) issueData(t *testing.T) httpapi.ReleaseListProject {
	t.Helper()
	r1, r2, r3 := w.r1, w.r2, w.r3
	i1 := model.GroupingIssue{ID: model.NewID(), Org: w.org, Project: w.p, Workflow: "resolved", Occurrences: []model.GroupingEvidence{evidence(20, &r2), evidence(10, &r1)},
		FixedDescendants: []model.ID{r2}, ResolutionFrontier: []model.ID{r2}}
	i2 := model.GroupingIssue{ID: model.NewID(), Org: w.org, Project: w.p, Workflow: "open", Occurrences: []model.GroupingEvidence{evidence(30, &r2)}}
	i3 := model.GroupingIssue{ID: model.NewID(), Org: w.org, Project: w.p, Workflow: "open", Occurrences: []model.GroupingEvidence{evidence(50, &r2)},
		Compacted: &model.GroupingCompaction{Count: 5, FirstEvent: 5, LastEvent: 8, Releases: []model.GroupingCompactedRelease{{Release: r1, FirstEvent: 5}}}, ObservedReleases: []model.ID{r1}}
	i4 := model.GroupingIssue{ID: model.NewID(), Org: w.org, Project: w.p, Workflow: "open", Occurrences: []model.GroupingEvidence{evidence(9, &r3), evidence(1, nil)}}
	return httpapi.ReleaseListProject{Releases: w.records(), IssuesKnown: true, Issues: []model.GroupingIssue{i1, i2, i3, i4},
		Explanations: map[model.ID][]issues.Explanation{
			i1.ID: {{OccurrenceID: model.NewID(), EvidenceRelease: r3, Decision: issues.RegressionDecision{Eligible: true}},
				{OccurrenceID: model.NewID(), EvidenceRelease: r2, Decision: issues.RegressionDecision{Eligible: false, Reason: "not_a_descendant"}}}}}
}

func (w *releaseWorld) list(who person, extra map[string]any, projects ...model.ID) (int, releaseListAnswer, []byte) {
	w.e.t.Helper()
	if len(projects) == 0 {
		projects = []model.ID{w.p}
	}
	ids := make([]string, len(projects))
	for i, p := range projects {
		ids[i] = p.String()
	}
	body := map[string]any{"org": w.org.String(), "projects": ids}
	for k, v := range extra {
		body[k] = v
	}
	status, raw := w.e.post(who, "/api/v1/releases/list", body, nil)
	var v releaseListAnswer
	if status == 200 {
		if err := json.Unmarshal(raw, &v); err != nil {
			w.e.t.Fatalf("release list: %v\n%s", err, raw)
		}
	}
	return status, v, raw
}

func (w *releaseWorld) deploy(who person, release model.ID, at any) (int, []byte) {
	body := map[string]any{"op": "record", "org": w.org.String(), "project": w.p.String(), "release": release.String(), "environment": w.env.String(), "command_id": model.NewID().String()}
	switch v := at.(type) {
	case nil:
	case int64:
		body["deployed_at"] = strconv.FormatInt(v, 10)
	default:
		body["deployed_at"] = v
	}
	return w.e.post(who, "/api/v1/releases/deploys", body, nil)
}

func TestReleaseListDerivesCountsStatesAndDeploys(t *testing.T) {
	w := newReleaseWorld(t)
	w.source.data[w.p] = w.issueData(t)
	deployed := time.Now().Add(-time.Hour).UnixNano()
	if status, raw := w.deploy(w.admin, w.r2, deployed); status != 200 {
		t.Fatalf("record: %d %s", status, raw)
	}

	status, v, raw := w.list(w.reader, nil)
	if status != 200 {
		t.Fatalf("list: %d %s", status, raw)
	}
	if got := labels(v); !slices.Equal(got, []string{"v3.0", "v2.0-Beta", "v1.0"}) {
		t.Fatalf("newest build first: %v", got)
	}
	by := map[string]releaseItem{}
	for _, it := range v.Items {
		by[it.Label] = it
	}
	want := map[string][3]int{"v1.0": {2, 0, 0}, "v2.0-Beta": {1, 0, 1}, "v3.0": {0, 1, 0}}
	for label, c := range want {
		it := by[label]
		if it.NewIssues == nil || it.RegressedIssues == nil || it.ResolvedIssues == nil || *it.NewIssues != c[0] || *it.RegressedIssues != c[1] || *it.ResolvedIssues != c[2] {
			t.Errorf("%s counts: %+v (new %v regressed %v resolved %v), want %v", label, it, it.NewIssues, it.RegressedIssues, it.ResolvedIssues, c)
		}
	}
	if by["v1.0"].CountsState != "incomplete" || by["v2.0-Beta"].CountsState != "ready" || by["v3.0"].CountsState != "ready" {
		t.Fatalf("counts states (folded evidence names v1.0): %+v", by)
	}
	if v.State != "incomplete" || v.Reason != httpapi.ReasonIssueCountsCompacted {
		t.Fatalf("envelope: %s %s", v.State, v.Reason)
	}
	r2 := by["v2.0-Beta"]
	if r2.DeployState != "known" || len(r2.Deploys) != 1 || r2.Deploys[0].Environment != w.env.String() {
		t.Fatalf("v2 deploys: %+v", r2)
	}
	if r2.Deploys[0].DeployedAt == "" || r2.BuildTime != "200" || len(r2.Parents) != 1 || r2.Parents[0] != w.r1.String() {
		t.Fatalf("v2: %+v", r2)
	}
	if by["v1.0"].DeployState != "unknown" || by["v1.0"].Deploys == nil || len(by["v1.0"].Deploys) != 0 {
		t.Fatalf("a release without a marker has no deploy and says so (empty list, state unknown): %+v", by["v1.0"])
	}
	// Debug artifacts are never listed.
	for _, leak := range []string{"debug-", "artifact", "sha256", "history"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("a debug artifact detail (%q) reached the list: %s", leak, raw)
		}
	}
	sections := map[string]string{}
	for _, s := range v.Sections {
		sections[s.Name] = s.State
	}
	if sections["releases"] != "ready" || sections["deploys"] != "ready" || sections["issue_counts"] != "incomplete" {
		t.Fatalf("sections: %+v", v.Sections)
	}
}

func TestReleaseListFiltersSortAndPaging(t *testing.T) {
	w := newReleaseWorld(t)
	w.source.data[w.p] = w.issueData(t)
	if status, raw := w.deploy(w.admin, w.r2, time.Now().Add(-time.Hour).UnixNano()); status != 200 {
		t.Fatalf("record: %d %s", status, raw)
	}
	check := func(name string, extra map[string]any, want ...string) {
		t.Helper()
		status, v, raw := w.list(w.reader, extra)
		if status != 200 || !slices.Equal(labels(v), want) {
			t.Errorf("%s: %d %v want %v\n%s", name, status, labels(v), want, raw)
		}
	}
	check("environment", map[string]any{"environment": w.env.String()}, "v2.0-Beta")
	check("another environment", map[string]any{"environment": model.NewID().String()})
	check("deployed after the deploy", map[string]any{"deployed_after": "9223372036854775807"})
	check("deployed after long ago", map[string]any{"deployed_after": "1"}, "v2.0-Beta")
	check("has regressions", map[string]any{"has_regressions": true}, "v3.0")
	check("has no regressions", map[string]any{"has_regressions": false}, "v2.0-Beta", "v1.0")
	check("label (case-insensitive)", map[string]any{"query": "BETA"}, "v2.0-Beta")
	check("id prefix", map[string]any{"query": w.r1.String()[:12]}, "v1.0")
	check("window on build time", map[string]any{"window": map[string]any{"start": "150", "end": "250"}}, "v2.0-Beta")
	check("sort by deploy: the deployed first", map[string]any{"sort": "deployed_at", "limit": 1}, "v2.0-Beta")

	for _, bad := range []map[string]any{{"sort": "label"}, {"limit": 201}, {"deployed_after": "0"}, {"query": "a\u0000b"}, {"cursor": "garbage"}, {"unknown": 1}} {
		if status, _, raw := w.list(w.reader, bad); status != 400 {
			t.Errorf("%v: %d %s", bad, status, raw)
		}
	}

	// Paging: a page of one, the cursor continues, a cursor of another request or caller is refused.
	status, page1, raw := w.list(w.reader, map[string]any{"limit": 1})
	if status != 200 || !page1.More || page1.NextCursor == "" || !slices.Equal(labels(page1), []string{"v3.0"}) {
		t.Fatalf("page 1: %d %s", status, raw)
	}
	status, page2, raw := w.list(w.reader, map[string]any{"limit": 1, "cursor": page1.NextCursor})
	if status != 200 || !page2.More || !slices.Equal(labels(page2), []string{"v2.0-Beta"}) {
		t.Fatalf("page 2: %d %s", status, raw)
	}
	status, page3, raw := w.list(w.reader, map[string]any{"limit": 1, "cursor": page2.NextCursor})
	if status != 200 || page3.More || page3.NextCursor != "" || !slices.Equal(labels(page3), []string{"v1.0"}) {
		t.Fatalf("page 3: %d %s", status, raw)
	}
	for name, c := range map[string]struct {
		who   person
		extra map[string]any
	}{
		"another request": {w.reader, map[string]any{"limit": 1, "query": "v", "cursor": page1.NextCursor}},
		"another sort":    {w.reader, map[string]any{"limit": 1, "sort": "deployed_at", "cursor": page1.NextCursor}},
		"another caller":  {w.readerSame, map[string]any{"limit": 1, "cursor": page1.NextCursor}},
	} {
		status, _, raw := w.list(c.who, c.extra)
		var f struct{ Detail string }
		_ = json.Unmarshal(raw, &f)
		if status != 400 || f.Detail != httpapi.ReasonCursorInvalid {
			t.Errorf("%s: %d %s", name, status, raw)
		}
	}
}

func TestReleaseListCountsAreNullWhenIssueEvidenceCannotBeRead(t *testing.T) {
	w := newReleaseWorld(t)
	w.source.data[w.p] = httpapi.ReleaseListProject{Releases: w.records()} // IssuesKnown false
	status, v, raw := w.list(w.reader, nil)
	if status != 200 || len(v.Items) != 3 {
		t.Fatalf("list: %d %s", status, raw)
	}
	for _, it := range v.Items {
		if it.NewIssues != nil || it.RegressedIssues != nil || it.ResolvedIssues != nil || it.CountsState != "not_available" {
			t.Fatalf("an unknown count is null, never 0: %+v", it)
		}
	}
	if strings.Contains(string(raw), `"new_issues":0`) || !strings.Contains(string(raw), `"new_issues":null`) {
		t.Fatalf("null expected: %s", raw)
	}
	if v.State != "incomplete" || v.Reason != httpapi.ReasonIssueCountsAbsent {
		t.Fatalf("envelope: %s %s", v.State, v.Reason)
	}
	// A filter on an unknown count excludes: it can neither say yes nor no.
	for _, flag := range []bool{true, false} {
		if _, v, _ = w.list(w.reader, map[string]any{"has_regressions": flag}); len(v.Items) != 0 {
			t.Fatalf("has_regressions=%v over unknown counts listed %d items", flag, len(v.Items))
		}
	}
	// A project with no issues at all is a known zero.
	w.source.data[w.p] = httpapi.ReleaseListProject{Releases: w.records(), IssuesKnown: true}
	if _, v, raw = w.list(w.reader, nil); v.State != "ready" || *v.Items[0].NewIssues != 0 || v.Items[0].CountsState != "ready" {
		t.Fatalf("known zero: %s", raw)
	}
	// No releases at all.
	w.source.data[w.p] = httpapi.ReleaseListProject{IssuesKnown: true}
	if _, v, _ = w.list(w.reader, nil); v.State != "empty" || len(v.Items) != 0 || v.Items == nil {
		t.Fatalf("empty: %+v", v)
	}
	// A capped registry says so.
	w.source.data[w.p] = httpapi.ReleaseListProject{Releases: w.records(), IssuesKnown: true, Capped: true}
	if _, v, _ = w.list(w.reader, nil); v.State != "incomplete" || v.Reason != httpapi.ReasonReleaseScanCapped {
		t.Fatalf("capped: %+v", v)
	}
	// A failing source is an error, never an empty list.
	w.source.err = model.Fail(model.Unavailable)
	if status, _, _ = w.list(w.reader, nil); status != http.StatusServiceUnavailable {
		t.Fatalf("a failing source: %d", status)
	}
}

func TestReleaseListScopeIsolation(t *testing.T) {
	w := newReleaseWorld(t)
	w.source.data[w.p] = w.issueData(t)
	w.source.data[w.q] = httpapi.ReleaseListProject{IssuesKnown: true}
	// A reader of the other project, a user of another organization, an unknown project and a
	// project the reader has no grant on: the same 404, and the source is never asked.
	missing := model.NewID()
	for name, c := range map[string]struct {
		who      person
		projects []model.ID
	}{
		"reader of another project": {w.qr, []model.ID{w.p}},
		"stranger":                  {w.stranger, []model.ID{w.p}},
		"unknown project":           {w.reader, []model.ID{missing}},
		"one project too many":      {w.reader, []model.ID{w.p, w.q}},
	} {
		before := w.source.calls
		status, _, raw := w.list(c.who, nil, c.projects...)
		if status != 404 || w.source.calls != before {
			t.Errorf("%s: %d %s (source calls %d -> %d)", name, status, raw, before, w.source.calls)
		}
	}
	// The administrator may list both projects; a member's grant is exactly its projects.
	if status, v, raw := w.list(w.admin, nil, w.p, w.q); status != 200 || len(v.Items) != 3 {
		t.Fatalf("administrator: %d %s", status, raw)
	}
	// Revoked grant: not listed any more.
	w.e.grant(w.org, w.reader, w.p, false, auth.Read)
	if status, _, raw := w.list(w.reader, nil); status != 404 {
		t.Fatalf("a revoked grant: %d %s", status, raw)
	}
	// No credential.
	if status, _, _ := w.list(person{}, nil); status < 400 {
		t.Fatalf("anonymous: %d", status)
	}
}

func TestReleaseListWithoutASourceIsNotAvailable(t *testing.T) {
	e := consoleEnv(t, nil)
	p := model.NewID()
	org := e.org("release list none", p)
	reader := e.user(org, "rl-none@example.test")
	e.grant(org, reader, p, true, auth.Read)
	status, raw := e.post(reader, "/api/v1/releases/list", map[string]any{"org": org.String(), "projects": []string{p.String()}}, nil)
	var v releaseListAnswer
	if err := json.Unmarshal(raw, &v); err != nil || status != 200 || v.State != "not_available" || v.Reason != httpapi.ReasonListSourceNotWired || len(v.Items) != 0 {
		t.Fatalf("%d %s", status, raw)
	}
}

type deployAnswer struct {
	ProjectID string `json:"project_id"`
	ReleaseID string `json:"release_id"`
	Env       string `json:"environment"`
	First     string `json:"first_deployed_at"`
	Last      string `json:"last_deployed_at"`
	Count     string `json:"count"`
}

func TestDeployRoutesRecordListAndRefuse(t *testing.T) {
	w := newReleaseWorld(t)
	e := w.e
	t1 := time.Now().Add(-2 * time.Hour).UnixNano()
	status, raw := w.deploy(w.admin, w.r2, t1)
	var rec deployAnswer
	if err := json.Unmarshal(raw, &rec); err != nil || status != 200 || rec.Count != "1" || rec.Env != w.env.String() || rec.ReleaseID != w.r2.String() || rec.First != rec.Last {
		t.Fatalf("record: %d %s", status, raw)
	}
	status, raw = w.deploy(w.admin, w.r2, time.Now().Add(-4*time.Hour).UnixNano())
	var again deployAnswer
	if err := json.Unmarshal(raw, &again); err != nil || status != 200 || again.Count != "2" || again.Last != rec.Last || again.First == rec.First {
		t.Fatalf("redeploy keeps the earliest first and counts: %d %s", status, raw)
	}
	// Server clock default.
	if status, raw = w.deploy(w.admin, w.r3, nil); status != 200 {
		t.Fatalf("default time: %d %s", status, raw)
	}
	// Refusals; nothing is committed for any of them.
	cases := map[string]struct {
		who  person
		body map[string]any
		want int
		note string
	}{
		"a reader":                    {w.reader, nil, 404, ""},
		"a member of another project": {w.qr, nil, 404, ""},
		"another organization":        {w.stranger, nil, 404, ""},
		"unknown environment":         {w.admin, map[string]any{"environment": model.NewID().String()}, 400, auth.DeployEnvironmentUnknown},
		"unknown release":             {w.admin, map[string]any{"release": model.NewID().String()}, 404, ""},
		"future":                      {w.admin, map[string]any{"deployed_at": "9223372036854775807"}, 400, auth.DeployTimeInvalid},
		"zero time":                   {w.admin, map[string]any{"deployed_at": "0"}, 400, auth.DeployTimeInvalid},
		"negative time":               {w.admin, map[string]any{"deployed_at": "-5"}, 400, auth.DeployTimeInvalid},
		"no command":                  {w.admin, map[string]any{"command_id": nil}, 400, ""},
		"unknown op":                  {w.admin, map[string]any{"op": "erase"}, 400, ""},
		"list fields on record":       {w.admin, map[string]any{"projects": []string{w.p.String()}}, 400, ""},
	}
	for name, c := range cases {
		body := map[string]any{"op": "record", "org": w.org.String(), "project": w.p.String(), "release": w.r1.String(), "environment": w.env.String(), "command_id": model.NewID().String()}
		for k, v := range c.body {
			if v == nil {
				delete(body, k)
			} else {
				body[k] = v
			}
		}
		status, raw := e.post(c.who, "/api/v1/releases/deploys", body, nil)
		var f struct{ Detail string }
		_ = json.Unmarshal(raw, &f)
		if status != c.want || c.note != "" && f.Detail != c.note {
			t.Errorf("%s: %d %s", name, status, raw)
		}
	}
	list := func(who person, org model.ID, release string, projects ...model.ID) (int, []deployAnswer) {
		ids := make([]string, len(projects))
		for i, p := range projects {
			ids[i] = p.String()
		}
		body := map[string]any{"op": "list", "org": org.String(), "projects": ids}
		if release != "" {
			body["release"] = release
		}
		status, raw := e.post(who, "/api/v1/releases/deploys", body, nil)
		var v struct {
			Items []deployAnswer `json:"items"`
		}
		if status == 200 {
			if err := json.Unmarshal(raw, &v); err != nil || v.Items == nil {
				t.Fatalf("list: %v %s", err, raw)
			}
		}
		return status, v.Items
	}
	if status, items := list(w.reader, w.org, "", w.p); status != 200 || len(items) != 2 {
		t.Fatalf("a reader lists only markers, one per recorded (release, environment): %d %+v", status, items)
	}
	if status, items := list(w.reader, w.org, w.r1.String(), w.p); status != 200 || len(items) != 0 {
		t.Fatalf("a release without a marker has no item: %d %+v", status, items)
	}
	if status, items := list(w.reader, w.org, w.r2.String(), w.p); status != 200 || len(items) != 1 || items[0].Count != "2" {
		t.Fatalf("one release: %d %+v", status, items)
	}
	for name, c := range map[string]struct {
		who      person
		org      model.ID
		projects []model.ID
	}{
		"reader of another project":  {w.qr, w.org, []model.ID{w.p}},
		"another organization":       {w.stranger, w.org, []model.ID{w.p}},
		"a project beyond the grant": {w.reader, w.org, []model.ID{w.p, w.q}},
	} {
		if status, _ := list(c.who, c.org, "", c.projects...); status != 404 {
			t.Errorf("list, %s: %d", name, status)
		}
	}
	if status, _ := e.post(w.reader, "/api/v1/releases/deploys", map[string]any{"op": "list", "org": w.org.String(), "projects": []string{}}, nil); status != 400 {
		t.Fatalf("no projects: %d", status)
	}

	// A bearer server token that reads may list but never record.
	issued, err := e.app.Auth.IssueServerToken(e.ctx, e.actor.Cred, w.org, w.reader.ID, []model.ID{w.p}, []auth.Permission{auth.Read}, time.Now().Add(time.Hour).Unix(), "deploy list token")
	if err != nil {
		t.Fatal(err)
	}
	bearer := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+issued.Token) }
	if status, _ := e.post(person{}, "/api/v1/releases/deploys", map[string]any{"op": "list", "org": w.org.String(), "projects": []string{w.p.String()}}, bearer); status != 200 {
		t.Fatalf("a reading token lists: %d", status)
	}
	if status, _ := e.post(person{}, "/api/v1/releases/deploys", map[string]any{"op": "record", "org": w.org.String(), "project": w.p.String(), "release": w.r1.String(), "environment": w.env.String(), "command_id": model.NewID().String()}, bearer); status != 404 {
		t.Fatalf("a reading token recorded a deploy: %d", status)
	}
	// The audit rows name identifiers only.
	for _, a := range auditsOf(t, e, w.org) {
		if a.Action == "releases.deploy" && (len(a.Targets) != 4 || a.Principal != w.admin.ID) {
			t.Fatalf("deploy audit: %+v", a)
		}
	}
}
