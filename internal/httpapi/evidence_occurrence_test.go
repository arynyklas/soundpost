// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

// fakeErrors is a labelled double of the stored-error read seam: it records
// exactly what the handler hands it and answers a configured record. The real
// storage read is exercised through NewStorageErrorSource below and, with a
// real server and a real ingest, by web/e2e/error-release-artifact.spec.ts.
type fakeErrors struct {
	calls      atomic.Int32
	scope      auth.Scope
	project    model.ID
	record     model.ID
	occurrence model.ID
	at         model.UnixNano
	occ        model.ErrorOccurrence
	found      bool
	partial    bool
	err        error
}

func (f *fakeErrors) ErrorOccurrence(_ context.Context, scope auth.Scope, project, record, occurrence model.ID, at model.UnixNano) (model.ErrorOccurrence, bool, bool, error) {
	f.calls.Add(1)
	f.scope, f.project, f.record, f.occurrence, f.at = scope, project, record, occurrence, at
	return f.occ, f.found, f.partial, f.err
}

func (e *evEnv) occurrenceEnv(t *testing.T, issues httpapi.IssueEvidenceReader, errs httpapi.ErrorOccurrenceReader) {
	t.Helper()
	ev := httpapi.NewEvidence(nil, e.app.Releases, issues, httpapi.WithErrorOccurrences(errs))
	e.srv.Close()
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterEvidenceRoutes(mux, e.app.Auth, ev)
		e.app.RegisterArtifactRoutes(mux)
	}).Handler)
	t.Cleanup(e.srv.Close)
}

func decodeOccurrence(t *testing.T, raw []byte) httpapi.ErrorOccurrenceView {
	t.Helper()
	var v httpapi.ErrorOccurrenceView
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("not an occurrence view: %v\n%s", err, raw)
	}
	return v
}

func TestEvidenceOccurrenceShowsStoredChainMechanismHandledFatalAndCode(t *testing.T) {
	issues, errs := &fakeIssues{}, &fakeErrors{}
	e := newEvEnv(t, nil, issues, true)
	e.occurrenceEnv(t, issues, errs)
	p := model.NewID()
	org := e.org("evidence occurrence", p)
	admin := e.user(org, "occ-admin@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	e.grant(org, admin, p, true, auth.Read)
	noTelemetry := e.user(org, "occ-notelemetry@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: noTelemetry.ID, Enabled: true})
	reader := e.user(org, "occ-reader@example.test")
	e.grant(org, reader, p, true, auth.Read)
	stranger := e.user(e.org("evidence occurrence B"), "occ-stranger@example.test")

	fp := model.HashCanonical([]byte("occurrence fingerprint"))
	release, trace, build := model.NewID(), model.NewID(), model.NewID()
	span := model.SpanID{1, 2, 3, 4, 5, 6, 7, 8}
	listed := model.GroupingEvidence{OccurrenceID: model.NewID(), RecordID: model.NewID(), GroupingVersion: 1, Fingerprint: fp, EventTime: 1234, ArrivalTime: 2000, ReleaseID: &release, Ancestry: "known", Freshness: "fresh"}
	late := model.GroupingEvidence{OccurrenceID: model.NewID(), RecordID: model.NewID(), GroupingVersion: 1, Fingerprint: fp, EventTime: 77, ArrivalTime: 2000, Ancestry: "unknown", Freshness: "fresh"}
	issues.issue = model.GroupingIssue{ID: model.NewID(), Org: org, Project: p, GroupingVersion: 1, Fingerprint: fp, Workflow: "open", Revision: 2, Occurrences: []model.GroupingEvidence{listed}, LateHistory: []model.GroupingEvidence{late}}
	column := uint32(4)
	code, ordinal := "E_STORED", uint32(1)
	errs.found = true
	errs.occ = model.ErrorOccurrence{Occurrence: listed.OccurrenceID, Class: "StoredFailure", Mechanism: "unhandled_rejection", Handled: false, Fatal: true, Code: &code, Build: build, Release: &release, Trace: &trace, Span: &span,
		Frames: []model.Frame{{Module: "app", Function: "boom", Artifact: model.NewID().String(), Line: 3, Column: &column, InApp: true}},
		Graph: &model.ExceptionGraph{
			Nodes: []model.ExceptionNode{
				{ID: 0, Class: "StoredFailure", Frames: []model.Frame{{Module: "app", Function: "boom", Artifact: "a", Line: 3, Column: &column, InApp: true}}},
				{ID: 1, Class: "RootCause", Frames: []model.Frame{}, Suppressed: true},
			},
			Edges:   []model.ExceptionEdge{{From: 0, To: 1, Kind: "cause"}, {From: 0, To: 1, Kind: "group", Ordinal: &ordinal}},
			Reasons: []string{"node_limit"},
		}}
	body := func(occurrence model.ID) map[string]any {
		return map[string]any{"org": org.String(), "project": p.String(), "issue": issues.issue.ID.String(), "occurrence": occurrence.String()}
	}

	status, raw := e.post(admin, "/api/v1/evidence/occurrence", body(listed.OccurrenceID), nil)
	if status != 200 {
		t.Fatalf("occurrence: %d %s", status, raw)
	}
	v := decodeOccurrence(t, raw)
	d := v.Detail
	if v.State != httpapi.StateReady || d == nil || d.Class != "StoredFailure" || d.Mechanism != "unhandled_rejection" || d.Handled || !d.Fatal || d.Code == nil || *d.Code != "E_STORED" {
		t.Fatalf("stored class, mechanism, handled, fatal and code must be shown as stored: %s", raw)
	}
	if d.Build != build || d.Release == nil || *d.Release != release || d.Trace == nil || *d.Trace != trace || d.Span == nil || *d.Span != span || len(d.Frames) != 1 || d.Frames[0].Function != "boom" {
		t.Fatalf("links and frames: %s", raw)
	}
	if d.Chain == nil || len(d.Chain.Nodes) != 2 || d.Chain.Nodes[1].Class != "RootCause" || !d.Chain.Nodes[1].Suppressed || len(d.Chain.Edges) != 2 || d.Chain.Edges[0].Kind != "cause" || d.Chain.Edges[1].Kind != "group" || d.Chain.Edges[1].Ordinal == nil || *d.Chain.Edges[1].Ordinal != 1 || len(d.Chain.Reasons) != 1 {
		t.Fatalf("the exception chain, its edges and its reasons must be shown: %s", raw)
	}
	// The record is read under the caller's TELEMETRY scope for the one project, from the evidence's own record, time and occurrence.
	if errs.scope.Permission() != auth.Read || errs.project != p || errs.record != listed.RecordID || errs.occurrence != listed.OccurrenceID || errs.at != 1234 {
		t.Fatalf("reader got scope %v project %v record %v occurrence %v at %v", errs.scope.Permission(), errs.project, errs.record, errs.occurrence, errs.at)
	}
	// Late history is evidence of the same issue: its stored record is readable the same way.
	errs.occ.Occurrence = late.OccurrenceID
	if status, raw = e.post(admin, "/api/v1/evidence/occurrence", body(late.OccurrenceID), nil); status != 200 || decodeOccurrence(t, raw).State != httpapi.StateReady || errs.record != late.RecordID {
		t.Fatalf("late history occurrence: %d %s", status, raw)
	}
	errs.occ.Occurrence = listed.OccurrenceID

	// The issue view says, before anything is clicked, whether the detail is readable for THIS caller.
	issueState := func(who person) (httpapi.ViewSection, httpapi.IssueView) {
		t.Helper()
		status, raw := e.post(who, "/api/v1/evidence/issue", map[string]any{"org": org.String(), "project": p.String(), "issue": issues.issue.ID.String()}, nil)
		if status != 200 {
			t.Fatalf("issue view: %d %s", status, raw)
		}
		var iv httpapi.IssueView
		if err := json.Unmarshal(raw, &iv); err != nil {
			t.Fatal(err)
		}
		for _, s := range iv.Sections {
			if s.Name == "occurrence_detail" {
				return s, iv
			}
		}
		t.Fatalf("no occurrence_detail section: %s", raw)
		return httpapi.ViewSection{}, iv
	}
	if s, _ := issueState(admin); s.State != httpapi.StateReady || s.Reason != "" {
		t.Fatalf("an administrator with telemetry.read can read the detail: %+v", s)
	}
	if s, _ := issueState(noTelemetry); s.State != httpapi.StateNotAvailable || s.Reason != httpapi.ReasonOccurrenceNeedsTelemetry {
		t.Fatalf("an administrator without telemetry.read is told so: %+v", s)
	}

	// Administration alone never reads telemetry: no read, an explicit reason, the reader is not asked.
	before := errs.calls.Load()
	status, raw = e.post(noTelemetry, "/api/v1/evidence/occurrence", body(listed.OccurrenceID), nil)
	if v = decodeOccurrence(t, raw); status != 200 || v.State != httpapi.StateNotAvailable || v.Reason != httpapi.ReasonOccurrenceNeedsTelemetry || v.Detail != nil || errs.calls.Load() != before {
		t.Fatalf("administrator without telemetry.read: %d %s", status, raw)
	}
	// A telemetry reader who is no administrator is told the evidence needs one; nothing is read.
	status, raw = e.post(reader, "/api/v1/evidence/occurrence", body(listed.OccurrenceID), nil)
	if v = decodeOccurrence(t, raw); status != 200 || v.State != httpapi.StateNotAvailable || v.Reason != httpapi.ReasonIssueNeedsAdmin || v.Detail != nil || errs.calls.Load() != before {
		t.Fatalf("telemetry reader: %d %s", status, raw)
	}
	// Scope first: a stranger, a guessed issue and an occurrence the issue does not list are one not-found and nothing is read.
	for name, c := range map[string]struct {
		who  person
		body map[string]any
	}{
		"stranger":                {stranger, body(listed.OccurrenceID)},
		"guessed occurrence":      {admin, body(model.NewID())},
		"another issue's record":  {admin, map[string]any{"org": org.String(), "project": p.String(), "issue": model.NewID().String(), "occurrence": listed.OccurrenceID.String()}},
		"guessed project":         {admin, map[string]any{"org": org.String(), "project": model.NewID().String(), "issue": issues.issue.ID.String(), "occurrence": listed.OccurrenceID.String()}},
		"zero occurrence":         {admin, body(model.ID{})},
		"unknown field in a body": {admin, map[string]any{"org": org.String(), "project": p.String(), "issue": issues.issue.ID.String(), "occurrence": listed.OccurrenceID.String(), "permission": "org.admin"}},
	} {
		status, raw = e.post(c.who, "/api/v1/evidence/occurrence", c.body, nil)
		want := 404
		if name == "zero occurrence" || name == "unknown field in a body" {
			want = 400
		}
		if status != want || errs.calls.Load() != before {
			t.Fatalf("%s: %d %s (reader calls %d -> %d)", name, status, raw, before, errs.calls.Load())
		}
	}

	// A record that is no longer stored is an explicit state, never an empty success; a partial read is not proof of absence.
	errs.found = false
	status, raw = e.post(admin, "/api/v1/evidence/occurrence", body(listed.OccurrenceID), nil)
	if v = decodeOccurrence(t, raw); status != 200 || v.State != httpapi.StateNotAvailable || v.Reason != httpapi.ReasonOccurrenceNotStored || v.Detail != nil {
		t.Fatalf("not stored: %d %s", status, raw)
	}
	errs.partial = true
	status, raw = e.post(admin, "/api/v1/evidence/occurrence", body(listed.OccurrenceID), nil)
	if v = decodeOccurrence(t, raw); status != 200 || v.State != httpapi.StateIncomplete || v.Reason != httpapi.ReasonOccurrenceReadPartial || v.Detail != nil {
		t.Fatalf("partial read: %d %s", status, raw)
	}
	// A record that is not the occurrence asked for is corruption, never shown.
	errs.found, errs.partial = true, false
	errs.occ.Occurrence = model.NewID()
	if status, raw = e.post(admin, "/api/v1/evidence/occurrence", body(listed.OccurrenceID), nil); status == 200 || strings.Contains(string(raw), "StoredFailure") {
		t.Fatalf("a foreign record was shown: %d %s", status, raw)
	}
	// A read that fails is a typed failure, never an empty detail.
	errs.occ.Occurrence, errs.err = listed.OccurrenceID, model.Fail(model.Unavailable)
	if status, raw = e.post(admin, "/api/v1/evidence/occurrence", body(listed.OccurrenceID), nil); status < 500 {
		t.Fatalf("a failed read: %d %s", status, raw)
	}
}

func TestEvidenceOccurrenceIsNotAvailableWithoutAStoredErrorReader(t *testing.T) {
	issues := &fakeIssues{}
	e := newEvEnv(t, nil, issues, true) // no stored-error reader bound
	p := model.NewID()
	org := e.org("evidence occurrence unwired", p)
	admin := e.user(org, "occ-unwired@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	e.grant(org, admin, p, true, auth.Read)
	fp := model.HashCanonical([]byte("unwired"))
	ev := model.GroupingEvidence{OccurrenceID: model.NewID(), RecordID: model.NewID(), GroupingVersion: 1, Fingerprint: fp, EventTime: 5, ArrivalTime: 6, Ancestry: "unknown", Freshness: "fresh"}
	issues.issue = model.GroupingIssue{ID: model.NewID(), Org: org, Project: p, GroupingVersion: 1, Fingerprint: fp, Workflow: "open", Revision: 1, Occurrences: []model.GroupingEvidence{ev}}
	status, raw := e.post(admin, "/api/v1/evidence/occurrence", map[string]any{"org": org.String(), "project": p.String(), "issue": issues.issue.ID.String(), "occurrence": ev.OccurrenceID.String()}, nil)
	if v := decodeOccurrence(t, raw); status != 200 || v.State != httpapi.StateNotAvailable || v.Reason != httpapi.ReasonOccurrenceDetail || v.Detail != nil {
		t.Fatalf("unwired stored-error reader: %d %s", status, raw)
	}
}

// With and WithFrames return copies that keep every other binding: the node binds
// the stored-error reader at open and the symbolicator is configured later.
func TestEvidenceWithFramesKeepsTheOtherBindings(t *testing.T) {
	issues, errs := &fakeIssues{}, &fakeErrors{found: true}
	e := newEvEnv(t, nil, issues, true)
	base := httpapi.NewEvidence(nil, e.app.Releases, issues, httpapi.WithErrorOccurrences(errs))
	resolver := &fakeResolver{answer: mapFrames}
	copied := base.WithFrames(resolver)
	e.srv.Close()
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) { httpapi.RegisterEvidenceRoutes(mux, e.app.Auth, copied) }).Handler)
	t.Cleanup(e.srv.Close)
	p := model.NewID()
	org := e.org("evidence with frames", p)
	admin := e.user(org, "with-admin@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	e.grant(org, admin, p, true, auth.Read, auth.ArtifactRead)
	fp := model.HashCanonical([]byte("with"))
	ev := model.GroupingEvidence{OccurrenceID: model.NewID(), RecordID: model.NewID(), GroupingVersion: 1, Fingerprint: fp, EventTime: 5, ArrivalTime: 6, Ancestry: "unknown", Freshness: "fresh"}
	issues.issue = model.GroupingIssue{ID: model.NewID(), Org: org, Project: p, GroupingVersion: 1, Fingerprint: fp, Workflow: "open", Revision: 1, Occurrences: []model.GroupingEvidence{ev}}
	errs.occ = model.ErrorOccurrence{Occurrence: ev.OccurrenceID, Class: "C", Mechanism: "manual", Build: model.NewID()}
	status, raw := e.post(admin, "/api/v1/evidence/occurrence", map[string]any{"org": org.String(), "project": p.String(), "issue": issues.issue.ID.String(), "occurrence": ev.OccurrenceID.String()}, nil)
	if v := decodeOccurrence(t, raw); status != 200 || v.State != httpapi.StateReady {
		t.Fatalf("the copy lost the stored-error reader: %d %s", status, raw)
	}
	status, raw = e.post(admin, "/api/v1/evidence/frames", framesBody(org, p, model.NewID(), false, frame(10, "f")), nil)
	if v := decodeFrames(t, raw); status != 200 || v.State != httpapi.StateReady || resolver.calls.Load() != 1 {
		t.Fatalf("the copy does not use the new resolver: %d %s", status, raw)
	}
	// The receiver is unchanged: the base still has no resolver.
	e.srv.Close()
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) { httpapi.RegisterEvidenceRoutes(mux, e.app.Auth, base) }).Handler)
	t.Cleanup(e.srv.Close)
	status, raw = e.post(admin, "/api/v1/evidence/frames", framesBody(org, p, model.NewID(), false, frame(10, "f")), nil)
	if v := decodeFrames(t, raw); status != 200 || v.State != httpapi.StateNotAvailable || v.Reason != httpapi.ReasonSymbolicatorNotBuilt || resolver.calls.Load() != 1 {
		t.Fatalf("the base was changed by WithFrames: %d %s", status, raw)
	}
}

// ---- the committed storage source ----

type errRows struct {
	pages []storage.Page
	i     int
	done  bool
}

func (r *errRows) Next(context.Context) (storage.Page, error) {
	if r.i >= len(r.pages) {
		return storage.Page{}, io.EOF
	}
	r.i++
	return r.pages[r.i-1], nil
}
func (r *errRows) Watermarks() []model.Cursor { return nil }
func (r *errRows) Close() error               { r.done = true; return nil }

type errScanner struct {
	req   storage.ScanRequest
	scope auth.Scope
	pages []storage.Page
	err   error
	rows  *errRows
	calls int
}

func (s *errScanner) Scan(_ context.Context, scope auth.Scope, req storage.ScanRequest) (storage.RowIterator, error) {
	s.calls++
	s.req, s.scope = req, scope
	if s.err != nil {
		return nil, s.err
	}
	s.rows = &errRows{pages: s.pages}
	return s.rows, nil
}

func errPage(partial bool, ids []model.ID, errs ...*model.ErrorOccurrence) storage.Page {
	p := storage.Page{Partial: partial, IDs: ids}
	for _, e := range errs {
		p.Values = append(p.Values, model.Payload{Error: e})
	}
	return p
}

func TestStorageErrorSourceRequestAndFilter(t *testing.T) {
	project, record, occurrence := model.NewID(), model.NewID(), model.NewID()
	want := model.ErrorOccurrence{Occurrence: occurrence, Class: "Stored", Mechanism: "manual", Build: model.NewID()}
	sameOccurrenceOtherRecord := model.ErrorOccurrence{Occurrence: occurrence, Class: "Impostor", Mechanism: "manual"}
	otherOccurrence := model.ErrorOccurrence{Occurrence: model.NewID(), Class: "Other", Mechanism: "manual"}
	sc := &errScanner{pages: []storage.Page{errPage(true, []model.ID{model.NewID(), model.NewID(), record}, &otherOccurrence, &sameOccurrenceOtherRecord, &want)}}
	src := httpapi.NewStorageErrorSource(sc)
	occ, found, partial, err := src.ErrorOccurrence(context.Background(), auth.Scope{}, project, record, occurrence, 1_000)
	if err != nil || !found || !partial || occ.Class != "Stored" {
		t.Fatalf("got %+v found=%v partial=%v err=%v: only the record of the evidence itself may be returned", occ, found, partial, err)
	}
	r := sc.req
	if r.Signal != model.ErrorKind || len(r.Projects) != 1 || r.Projects[0] != project || r.Start != 1_000 || r.End != 1_001 || len(r.Selectors) != 1 {
		t.Fatalf("scan request = %+v", r)
	}
	m := r.Selectors[0]
	if m.Target != storage.MatchField || m.Name != "occurrence_id" || m.Op != storage.MatchEqual || m.Literal.Kind != storage.LiteralString || m.Literal.String != occurrence.String() {
		t.Fatalf("occurrence selector = %+v", m)
	}
	if !r.Fence.AllowPartial || !sc.rows.done {
		t.Fatalf("a missing shard must be reported, not fail the read (allow partial %v), and the iterator must be closed (%v)", r.Fence.AllowPartial, sc.rows.done)
	}

	// A record that is not there is found=false with the partial flag kept, never a zero record.
	sc.pages = []storage.Page{errPage(true, []model.ID{model.NewID()}, &otherOccurrence), errPage(false, nil)}
	if _, found, partial, err = src.ErrorOccurrence(context.Background(), auth.Scope{}, project, record, occurrence, 1_000); err != nil || found || !partial {
		t.Fatalf("absent record: found=%v partial=%v err=%v", found, partial, err)
	}
	// The answer is owned: scribbling over the borrowed page afterwards (the iterator reuses its buffers) cannot reach it.
	code, release, column := "E_STORED", model.NewID(), uint32(9)
	want.Code, want.Release = &code, &release
	want.Frames = []model.Frame{{Module: "m", Function: "f", Artifact: "a", Line: 1, Column: &column, InApp: true}}
	want.Graph = &model.ExceptionGraph{Nodes: []model.ExceptionNode{{ID: 0, Class: "Stored", Frames: want.Frames}}, Edges: []model.ExceptionEdge{}, Reasons: []string{"cycle"}}
	sc.pages = []storage.Page{errPage(false, []model.ID{record}, &want)}
	occ, found, _, err = src.ErrorOccurrence(context.Background(), auth.Scope{}, project, record, occurrence, 1_000)
	if err != nil || !found {
		t.Fatalf("owned record: found=%v err=%v", found, err)
	}
	want.Class, code, release, column = "scribbled", "scribbled", model.NewID(), 99
	want.Frames[0].Function = "scribbled"
	want.Graph.Nodes[0].Class, want.Graph.Reasons[0] = "scribbled", "scribbled"
	if occ.Class != "Stored" || *occ.Code != "E_STORED" || *occ.Release == release || occ.Frames[0].Function != "f" || *occ.Frames[0].Column != 9 || occ.Graph.Nodes[0].Class != "Stored" || occ.Graph.Nodes[0].Frames[0].Function != "f" || occ.Graph.Reasons[0] != "cycle" {
		t.Fatalf("the record aliases the borrowed page: %+v", occ)
	}

	// Refusals are typed and passed through; a window that cannot be formed is refused before any read.
	sc.err = model.Fail(model.NotFound)
	if _, _, _, err = src.ErrorOccurrence(context.Background(), auth.Scope{}, project, record, occurrence, 1_000); faultCode(err) != model.NotFound {
		t.Fatalf("scan refusal = %v", err)
	}
	sc.err = nil
	calls := sc.calls
	for _, at := range []model.UnixNano{-1} {
		if _, _, _, err = src.ErrorOccurrence(context.Background(), auth.Scope{}, project, record, occurrence, at); faultCode(err) != model.Unavailable || sc.calls != calls {
			t.Fatalf("window at %d: %v (scan calls %d -> %d)", at, err, calls, sc.calls)
		}
	}
	// A page whose values and IDs disagree is corruption.
	sc.pages = []storage.Page{{IDs: []model.ID{record, record}, Values: []model.Payload{{Error: &want}}}}
	if _, _, _, err = src.ErrorOccurrence(context.Background(), auth.Scope{}, project, record, occurrence, 1_000); faultCode(err) != model.Corrupt {
		t.Fatalf("mismatched page = %v", err)
	}
}
