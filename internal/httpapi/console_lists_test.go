// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
)

// clEnv serves the console list and RED routes over the real node pieces: the real control store and auth, the real
// storage engine behind the scan, the application's own cache for the cursors and the real issue lifecycle for the
// regressed filter and the workflow actions. Records are seeded through the lifecycle's own system door and the real
// HTTP ingest route.
type clEnv struct {
	*isoEnv
	srv *httptest.Server
	svc *issues.Service
}

func newClEnv(t *testing.T, titleBudget int) *clEnv {
	t.Helper()
	e := &clEnv{isoEnv: newIsoEnv(t)}
	var err error
	if e.svc, err = e.app.NewIssueActions(wallClock{}); err != nil {
		t.Fatal(err)
	}
	lists := httpapi.NewConsoleLists(httpapi.ConsoleListsConfig{State: e.app.Control, Scanner: e.app.Storage, Titles: httpapi.NewStorageErrorSource(e.app.Storage),
		Regressions: e.svc, Tickets: e.app.Cache, TitleReadBudget: titleBudget})
	red := httpapi.NewServiceRED(e.app.Storage)
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterConsoleListRoutes(mux, e.app.Auth, lists)
		httpapi.RegisterServiceREDRoute(mux, e.app.Auth, red)
	}).Handler)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *clEnv) post(who person, path string, body any) (int, []byte) {
	e.t.Helper()
	return (&evEnv{isoEnv: e.isoEnv, srv: e.srv}).post(who, path, body, nil)
}

type clBody map[string]any

func (e *clEnv) issueList(who person, org model.ID, projects []model.ID, extra clBody) (int, []byte) {
	e.t.Helper()
	ids := make([]string, len(projects))
	for i, p := range projects {
		ids[i] = p.String()
	}
	body := clBody{"org": org.String(), "projects": ids}
	for k, v := range extra {
		body[k] = v
	}
	return e.post(who, "/api/v1/issues/list", body)
}

func decodeList[T any](t *testing.T, status int, raw []byte) httpapi.ConsoleList[T] {
	t.Helper()
	if status != 200 {
		t.Fatalf("status %d: %s", status, raw)
	}
	var v httpapi.ConsoleList[T]
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("not a list answer: %v\n%s", err, raw)
	}
	return v
}

func issueIDs(l httpapi.ConsoleList[httpapi.IssueListItem]) []model.ID {
	out := make([]model.ID, len(l.Items))
	for i, it := range l.Items {
		out[i] = it.IssueID
	}
	return out
}

func listSectionOf(sections []httpapi.ViewSection, name string) httpapi.ViewSection {
	for _, s := range sections {
		if s.Name == name {
			return s
		}
	}
	return httpapi.ViewSection{}
}

// issueSpec is one issue to seed: its fingerprint, how many occurrences, the time of the newest, and the class of
// the stored error record behind the newest occurrence ("" stores no record at all).
type issueSpec struct {
	fp      byte
	n       int
	newest  model.UnixNano
	class   string
	release *model.ID
}

type seededIssues struct {
	byFP map[byte]model.ID
}

// seedIssues lands the occurrences of every spec through the lifecycle's system door and, for the newest occurrence of
// a spec with a class, stores the matching error record through the real ingest route.
func (e *clEnv) seedIssues(org, project model.ID, src sourceFixture, specs ...issueSpec) seededIssues {
	e.t.Helper()
	system, err := e.app.Auth.AuthorizeSystem(e.ctx, org, []model.ID{project}, auth.IssuesWrite)
	if err != nil {
		e.t.Fatal(err)
	}
	group := model.NewID()
	var evidence []issues.Evidence
	index := model.Uint64(0)
	for _, s := range specs {
		for k := range s.n {
			at := s.newest - model.UnixNano(s.n-1-k)*1_000_000_000
			index++
			ev := issues.Evidence{OccurrenceID: model.NewID(), RecordID: model.NewID(), Origin: model.Cursor{Group: group, Index: index}, GroupingVersion: 1, Fingerprint: model.Hash{s.fp},
				EventTime: at, ArrivalTime: at + 1, Ancestry: "unknown", Freshness: "fresh", Ordinal: 1, ReleaseID: s.release}
			evidence = append(evidence, ev)
			if k == s.n-1 && s.class != "" {
				e.ingest(src, model.Record{ID: ev.RecordID, Kind: model.ErrorKind, ObservedAt: at, Resource: e.resource(src),
					Payload: model.Payload{Error: &model.ErrorOccurrence{Occurrence: ev.OccurrenceID, Class: s.class, Mechanism: "manual", Build: src.Bd, Handled: true, Frames: []model.Frame{}}}})
			}
		}
	}
	if err = e.svc.ApplyThrough(e.ctx, system, model.Cursor{Group: group, Index: index}, evidence); err != nil {
		e.t.Fatal(err)
	}
	book, err := e.app.Control.IssueBook(e.ctx, system, project)
	if err != nil {
		e.t.Fatal(err)
	}
	out := seededIssues{byFP: map[byte]model.ID{}}
	for _, gi := range book.Issues {
		for _, s := range specs {
			if gi.Fingerprint == (model.Hash{s.fp}) {
				out.byFP[s.fp] = gi.ID
			}
		}
	}
	if len(out.byFP) != len(specs) {
		e.t.Fatalf("seeded %d of %d issues", len(out.byFP), len(specs))
	}
	return out
}

// issueRig is one organization with a project, an error source, a reader and three issues:
// A (TypeError, one occurrence), B (RangeError, three occurrences) and C (newest, its error record never stored).
type issueRig struct {
	*clEnv
	org, project model.ID
	src          sourceFixture
	reader       person
	a, b, c      model.ID
	release      model.ID
	base         model.UnixNano
}

func newIssueRig(t *testing.T, titleBudget int) *issueRig {
	t.Helper()
	r := &issueRig{clEnv: newClEnv(t, titleBudget), project: model.NewID(), release: model.NewID()}
	r.org = r.org2("issue list org", r.project)
	ids := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	r.src = r.source(r.org, r.project, ids, []model.Kind{model.ErrorKind})
	r.reader = r.user(r.org, "issue-list-reader@example.test")
	r.grant(r.org, r.reader, r.project, true, auth.Read)
	r.base = model.UnixNano(time.Now().Add(-time.Hour).UnixNano())
	seeded := r.seedIssues(r.org, r.project, r.src,
		issueSpec{fp: 1, n: 1, newest: r.base, class: "TypeError", release: &r.release},
		issueSpec{fp: 2, n: 3, newest: r.base + 12_000_000_000, class: "RangeError"},
		issueSpec{fp: 3, n: 1, newest: r.base + 20_000_000_000})
	r.a, r.b, r.c = seeded.byFP[1], seeded.byFP[2], seeded.byFP[3]
	return r
}

// org2 is isoEnv.org (the embedded method is shadowed by the field named org).
func (r *issueRig) org2(name string, projects ...model.ID) model.ID {
	return r.isoEnv.org(name, projects...)
}

func TestIssueListTitlesSummariesSortAndFilters(t *testing.T) {
	r := newIssueRig(t, 0)
	status, raw := r.issueList(r.reader, r.org, []model.ID{r.project}, nil)
	l := decodeList[httpapi.IssueListItem](t, status, raw)
	if l.State != httpapi.StateReady || l.Org != r.org || len(l.Projects) != 1 || l.More || l.NextCursor != "" {
		t.Fatalf("envelope: %s", raw)
	}
	if want := []model.ID{r.c, r.b, r.a}; !slices.Equal(issueIDs(l), want) {
		t.Fatalf("default order is last_seen newest first: %s", raw)
	}
	c, b, a := l.Items[0], l.Items[1], l.Items[2]
	if c.Title != nil || c.TitleState != httpapi.StateNotAvailable || !strings.Contains(string(raw), `"title":null`) {
		t.Fatalf("an occurrence record that is not stored has no title: %+v", c)
	}
	if b.Title == nil || *b.Title != "RangeError" || b.TitleState != httpapi.StateReady || a.Title == nil || *a.Title != "TypeError" {
		t.Fatalf("titles come from the newest stored occurrence: %s", raw)
	}
	if b.Occurrences != 3 || b.FirstSeen == nil || b.LastSeen == nil || int64(*b.LastSeen)-int64(*b.FirstSeen) != 2_000_000_000 || b.Workflow != "open" || b.Compacted {
		t.Fatalf("summary of B: %+v", b)
	}
	if len(a.Releases) != 1 || a.Releases[0] != r.release || len(b.Releases) != 0 || b.Releases == nil {
		t.Fatalf("releases: %+v %+v", a, b)
	}
	if s := listSectionOf(l.Sections, "titles"); s.State != httpapi.StateIncomplete || s.Reason != httpapi.ReasonTitlesNotAvailable {
		t.Fatalf("a title that cannot be read is said so in the titles section: %+v", l.Sections)
	}
	if strings.Contains(string(raw), "frames") || strings.Contains(string(raw), "occurrence_id") {
		t.Fatalf("the list carries no occurrence detail: %s", raw)
	}

	// sort kinds
	_, raw = r.issueList(r.reader, r.org, []model.ID{r.project}, clBody{"sort": "occurrences"})
	if got := issueIDs(decodeList[httpapi.IssueListItem](t, 200, raw)); got[0] != r.b {
		t.Fatalf("occurrences sort puts the busiest first: %v", got)
	}
	_, raw = r.issueList(r.reader, r.org, []model.ID{r.project}, clBody{"sort": "first_seen"})
	if got := issueIDs(decodeList[httpapi.IssueListItem](t, 200, raw)); !slices.Equal(got, []model.ID{r.c, r.b, r.a}) {
		t.Fatalf("first_seen order: %v", got)
	}

	// release, owner, regressed and time filters
	_, raw = r.issueList(r.reader, r.org, []model.ID{r.project}, clBody{"release": r.release.String()})
	if got := issueIDs(decodeList[httpapi.IssueListItem](t, 200, raw)); !slices.Equal(got, []model.ID{r.a}) {
		t.Fatalf("release filter: %v", got)
	}
	_, raw = r.issueList(r.reader, r.org, []model.ID{r.project}, clBody{"owner": "none"})
	if got := decodeList[httpapi.IssueListItem](t, 200, raw); len(got.Items) != 3 {
		t.Fatalf("no issue has an owner yet: %s", raw)
	}
	_, raw = r.issueList(r.reader, r.org, []model.ID{r.project}, clBody{"owner": model.NewID().String()})
	if got := decodeList[httpapi.IssueListItem](t, 200, raw); len(got.Items) != 0 || got.State != httpapi.StateEmpty || got.Reason != httpapi.ReasonListNoItems {
		t.Fatalf("an owner nobody has: %s", raw)
	}
	_, raw = r.issueList(r.reader, r.org, []model.ID{r.project}, clBody{"regressed": true})
	if got := decodeList[httpapi.IssueListItem](t, 200, raw); len(got.Items) != 0 || listSectionOf(got.Sections, "regressions").Name == "" {
		t.Fatalf("nothing has regressed: %s", raw)
	}
	_, raw = r.issueList(r.reader, r.org, []model.ID{r.project}, clBody{"regressed": false})
	if got := decodeList[httpapi.IssueListItem](t, 200, raw); len(got.Items) != 3 {
		t.Fatalf("regressed:false keeps every issue that never reopened: %s", raw)
	}
	after := model.Int64(int64(r.base) + 5_000_000_000)
	_, raw = r.issueList(r.reader, r.org, []model.ID{r.project}, clBody{"last_seen_after": after})
	if got := issueIDs(decodeList[httpapi.IssueListItem](t, 200, raw)); !slices.Equal(got, []model.ID{r.c, r.b}) {
		t.Fatalf("last_seen_after: %v", got)
	}
	_, raw = r.issueList(r.reader, r.org, []model.ID{r.project}, clBody{"last_seen_before": after})
	if got := issueIDs(decodeList[httpapi.IssueListItem](t, 200, raw)); !slices.Equal(got, []model.ID{r.a}) {
		t.Fatalf("last_seen_before: %v", got)
	}

	// workflow filter after a real lifecycle action
	admin, err := r.scope(r.actor, r.org, r.project, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	current, err := r.svc.Get(r.ctx, admin, r.project, r.a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.svc.Act(r.ctx, admin, issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: current.Revision, IssueID: r.a, Kind: "ignore", Reason: "list filter"}); err != nil {
		t.Fatal(err)
	}
	_, raw = r.issueList(r.reader, r.org, []model.ID{r.project}, clBody{"workflow": []string{"ignored"}})
	got := decodeList[httpapi.IssueListItem](t, 200, raw)
	if len(got.Items) != 1 || got.Items[0].IssueID != r.a || got.Items[0].Workflow != "ignored" || got.Items[0].Revision != model.Uint64(current.Revision+1) {
		t.Fatalf("workflow filter: %s", raw)
	}
	_, raw = r.issueList(r.reader, r.org, []model.ID{r.project}, clBody{"workflow": []string{"open", "resolved"}})
	if got := issueIDs(decodeList[httpapi.IssueListItem](t, 200, raw)); !slices.Equal(got, []model.ID{r.c, r.b}) {
		t.Fatalf("workflow open+resolved: %v", got)
	}
}

func TestIssueListOwnerAndExternalSummary(t *testing.T) {
	r := newIssueRig(t, 0)
	owner := r.user(r.org, "issue-list-owner@example.test")
	key := model.ReleaseScopeKey(r.org, r.project, r.b)
	err := r.app.Control.Update(r.ctx, func(st *model.ControlState) error {
		gi := st.GroupingIssues[key]
		gi.Owner = &owner.ID
		gi.External = []model.ExternalLink{{Provider: "gitlab", State: model.ExternalLinked, Marker: "soundpost-ref-secretmarker", Project: "shop/web", IID: 7, URL: "https://git.example.test/shop/web/-/issues/7", Actor: owner.ID, At: 5}}
		st.GroupingIssues[key] = gi
		return nil
	})
	if err != nil {
		t.Fatalf("storing an owner and an external link on an issue: %v", err)
	}
	status, raw := r.issueList(r.reader, r.org, []model.ID{r.project}, clBody{"owner": owner.ID.String()})
	l := decodeList[httpapi.IssueListItem](t, status, raw)
	if len(l.Items) != 1 || l.Items[0].IssueID != r.b || l.Items[0].Owner == nil || *l.Items[0].Owner != owner.ID {
		t.Fatalf("owner filter: %s", raw)
	}
	ex := l.Items[0].External
	if len(ex) != 1 || ex[0].Provider != "gitlab" || ex[0].State != model.ExternalLinked || ex[0].IID != 7 || ex[0].URL == "" || strings.Contains(string(raw), "secretmarker") || strings.Contains(string(raw), "marker") {
		t.Fatalf("external summary is provider, state and link, never the marker: %s", raw)
	}
	_, raw = r.issueList(r.reader, r.org, []model.ID{r.project}, clBody{"owner": "none"})
	if got := issueIDs(decodeList[httpapi.IssueListItem](t, 200, raw)); slices.Contains(got, r.b) || len(got) != 2 {
		t.Fatalf("owner none: %v", got)
	}
}

func TestIssueListSearchPagingAndCursorBinding(t *testing.T) {
	r := newIssueRig(t, 0)
	one := []model.ID{r.project}

	_, raw := r.issueList(r.reader, r.org, one, clBody{"query": "RANGE"})
	if l := decodeList[httpapi.IssueListItem](t, 200, raw); len(l.Items) != 1 || l.Items[0].IssueID != r.b {
		t.Fatalf("title search is case-insensitive: %s", raw)
	}
	_, raw = r.issueList(r.reader, r.org, one, clBody{"query": r.a.String()[:10]})
	l := decodeList[httpapi.IssueListItem](t, 200, raw)
	if len(l.Items) != 1 || l.Items[0].IssueID != r.a {
		t.Fatalf("id prefix search: %s", raw)
	}
	if l.State != httpapi.StateIncomplete || l.Reason == "" {
		t.Fatalf("an issue whose title cannot be read might match by title: the search says it is incomplete: %s", raw)
	}

	// paging: limit 2 over three issues
	_, raw = r.issueList(r.reader, r.org, one, clBody{"limit": 2})
	p1 := decodeList[httpapi.IssueListItem](t, 200, raw)
	if len(p1.Items) != 2 || !p1.More || p1.NextCursor == "" {
		t.Fatalf("first page: %s", raw)
	}
	_, raw = r.issueList(r.reader, r.org, one, clBody{"limit": 2, "cursor": p1.NextCursor})
	p2 := decodeList[httpapi.IssueListItem](t, 200, raw)
	if len(p2.Items) != 1 || p2.More || p2.NextCursor != "" || p2.Items[0].IssueID != r.a {
		t.Fatalf("second page: %s", raw)
	}
	// a smaller page size does not break the cursor (the request identity excludes it)
	if status, _ := r.issueList(r.reader, r.org, one, clBody{"limit": 1, "cursor": p1.NextCursor}); status != 200 {
		t.Fatalf("page size change: %d", status)
	}

	// the cursor is bound to the request and to the caller
	for name, extra := range map[string]clBody{
		"other query":  {"cursor": p1.NextCursor, "query": "type"},
		"other sort":   {"cursor": p1.NextCursor, "sort": "occurrences"},
		"other filter": {"cursor": p1.NextCursor, "workflow": []string{"open"}},
		"garbage":      {"cursor": "AAAA"},
		"tampered":     {"cursor": p1.NextCursor[:len(p1.NextCursor)-2] + "AA"},
	} {
		status, raw := r.issueList(r.reader, r.org, one, extra)
		if status != 400 || !strings.Contains(string(raw), "cursor_invalid") {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
	}
	other := r.user(r.org, "issue-list-other@example.test")
	r.grant(r.org, other, r.project, true, auth.Read)
	status, raw := r.issueList(other, r.org, one, clBody{"limit": 2, "cursor": p1.NextCursor})
	if status != 400 || !strings.Contains(string(raw), "cursor_invalid") {
		t.Fatalf("a cursor of another caller is replayed: %d %s", status, raw)
	}
}

func TestIssueListTitleSearchIsBoundedAndResumable(t *testing.T) {
	r := newIssueRig(t, 2) // two occurrence reads per request
	one := []model.ID{r.project}
	status, raw := r.issueList(r.reader, r.org, one, clBody{"query": "zzz-no-such-title"})
	l := decodeList[httpapi.IssueListItem](t, status, raw)
	if l.State != httpapi.StateIncomplete || l.Reason != httpapi.ReasonSearchScanCapped || !l.More || l.NextCursor == "" || len(l.Items) != 0 {
		t.Fatalf("the scan cap says so: %s", raw)
	}
	status, raw = r.issueList(r.reader, r.org, one, clBody{"query": "zzz-no-such-title", "cursor": l.NextCursor})
	l = decodeList[httpapi.IssueListItem](t, status, raw)
	if l.More || len(l.Items) != 0 || l.State == httpapi.StateReady {
		t.Fatalf("the resumed search ends: %s", raw)
	}
	// a matching title past the first request's budget is found by following the cursor
	status, raw = r.issueList(r.reader, r.org, one, clBody{"query": "typeerror"})
	l = decodeList[httpapi.IssueListItem](t, status, raw)
	if len(l.Items) != 0 || l.Reason != httpapi.ReasonSearchScanCapped {
		t.Fatalf("A is third in the order, past the budget: %s", raw)
	}
	status, raw = r.issueList(r.reader, r.org, one, clBody{"query": "typeerror", "cursor": l.NextCursor})
	if l = decodeList[httpapi.IssueListItem](t, status, raw); len(l.Items) != 1 || l.Items[0].IssueID != r.a {
		t.Fatalf("the cursor continues the scan: %s", raw)
	}
}

func TestIssueListRequestBounds(t *testing.T) {
	r := newIssueRig(t, 0)
	one := []model.ID{r.project}
	many := make([]model.ID, 17)
	for i := range many {
		many[i] = model.NewID()
	}
	for name, c := range map[string]struct {
		projects []model.ID
		extra    clBody
	}{
		"limit over 200":   {one, clBody{"limit": 201}},
		"negative limit":   {one, clBody{"limit": -1}},
		"17 projects":      {many, nil},
		"no projects":      {nil, nil},
		"duplicate":        {[]model.ID{r.project, r.project}, nil},
		"unknown sort":     {one, clBody{"sort": "title"}},
		"unknown workflow": {one, clBody{"workflow": []string{"closed"}}},
		"bad owner":        {one, clBody{"owner": "somebody"}},
		"window too long":  {one, clBody{"window": map[string]any{"start": "1", "end": "9999999999999999"}}},
		"control in query": {one, clBody{"query": "a\u0000b"}},
		"query too long":   {one, clBody{"query": strings.Repeat("a", 129)}},
		"unknown field":    {one, clBody{"scope": "org_admin"}},
	} {
		if status, raw := r.issueList(r.reader, r.org, c.projects, c.extra); status != 400 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
	}
	for _, limit := range []int{1, 200} {
		if status, raw := r.issueList(r.reader, r.org, one, clBody{"limit": limit}); status != 200 {
			t.Fatalf("limit %d: %d %s", limit, status, raw)
		}
	}
	// 16 projects is the largest valid request: foreign ones are a 404, not a 400
	sixteen := many[:16]
	if status, _ := r.issueList(r.reader, r.org, sixteen, nil); status != 404 {
		t.Fatalf("16 unknown projects: %d", status)
	}
}

func TestIssueListScopeIsTheCallersOwn(t *testing.T) {
	r := newIssueRig(t, 0)
	one := []model.ID{r.project}
	foreignProject := model.NewID()
	foreignOrg := r.org2("foreign issue org", foreignProject)
	foreign := r.user(foreignOrg, "issue-list-foreign@example.test")
	r.grant(foreignOrg, foreign, foreignProject, true, auth.Read)
	stranger := r.user(r.org, "issue-list-stranger@example.test") // member with no grant
	ungranted := model.NewID()
	r.cmd(r.org, "create_project", auth.AdminPayload{ID: ungranted, Name: "other project"})

	var want string
	deny := func(name string, who person, org model.ID, projects []model.ID) {
		status, raw := r.issueList(who, org, projects, nil)
		if status != 404 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		if got := denial(t, status, raw); want == "" {
			want = got
		} else if got != want {
			t.Fatalf("%s is distinguishable from the other refusals: %s vs %s", name, got, want)
		}
	}
	deny("member without a grant", stranger, r.org, one)
	deny("another organization's reader", foreign, r.org, one)
	deny("own org, another org's project", foreign, foreignOrg, one)
	deny("a project she holds no grant on", r.reader, r.org, []model.ID{r.project, ungranted})
	deny("a project that does not exist", r.reader, r.org, []model.ID{model.NewID()})
	deny("an organization that does not exist", r.reader, model.NewID(), one)
	if status, _ := r.issueList(person{}, r.org, one, nil); status == 200 {
		t.Fatal("an anonymous caller read the list")
	}

	// a grant that is withdrawn takes the list away at once
	r.grant(r.org, r.reader, r.project, false, auth.Read)
	deny("revoked reader", r.reader, r.org, one)
}

func TestIssueListTitlesNeedTheCallersTelemetryRead(t *testing.T) {
	r := newIssueRig(t, 0)
	one := []model.ID{r.project}
	writer := r.user(r.org, "issue-list-writer@example.test")
	r.grant(r.org, writer, r.project, true, auth.IssuesWrite)
	status, raw := r.issueList(writer, r.org, one, nil)
	l := decodeList[httpapi.IssueListItem](t, status, raw)
	if len(l.Items) != 3 {
		t.Fatalf("an issues.write holder reads the issue list: %s", raw)
	}
	for _, it := range l.Items {
		if it.Title != nil || it.TitleState != httpapi.StateNotAvailable {
			t.Fatalf("a title is telemetry: without telemetry.read it is not available: %+v", it)
		}
	}
	if strings.Contains(string(raw), "RangeError") || strings.Contains(string(raw), "TypeError") {
		t.Fatalf("exception types leaked to a caller without telemetry.read: %s", raw)
	}
	// and a search by title cannot match what the caller may not read
	_, raw = r.issueList(writer, r.org, one, clBody{"query": "rangeerror"})
	if got := decodeList[httpapi.IssueListItem](t, 200, raw); len(got.Items) != 0 || got.State != httpapi.StateIncomplete {
		t.Fatalf("title search without telemetry.read: %s", raw)
	}
}

func TestIssueListTitleIsTruncatedAndSafe(t *testing.T) {
	e := newClEnv(t, 0)
	project := model.NewID()
	org := e.isoEnv.org("issue title org", project)
	src := e.source(org, project, sharedIDs{model.NewID(), model.NewID(), model.NewID()}, []model.Kind{model.ErrorKind})
	reader := e.user(org, "issue-title-reader@example.test")
	e.grant(org, reader, project, true, auth.Read)
	long := strings.Repeat("a", 200)
	seeded := e.seedIssues(org, project, src, issueSpec{fp: 9, n: 1, newest: model.UnixNano(time.Now().Add(-time.Hour).UnixNano()), class: long})
	status, raw := e.issueList(reader, org, []model.ID{project}, nil)
	l := decodeList[httpapi.IssueListItem](t, status, raw)
	if len(l.Items) != 1 || l.Items[0].IssueID != seeded.byFP[9] || l.Items[0].Title == nil {
		t.Fatalf("%s", raw)
	}
	title := *l.Items[0].Title
	if len(title) != httpapi.MaxIssueTitleBytes || title != long[:httpapi.MaxIssueTitleBytes] {
		t.Fatalf("title is cut at %d bytes: %q (%d bytes)", httpapi.MaxIssueTitleBytes, title, len(title))
	}
}
