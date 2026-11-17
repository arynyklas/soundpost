// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

// occSens is one admin with telemetry read, one issue listing one occurrence, and
// a stored-error double: post answers the occurrence request with the given
// stored record and returns the raw response body.
type occSens struct {
	t          *testing.T
	e          *evEnv
	admin      person
	issues     *fakeIssues
	errs       *fakeErrors
	org, p     model.ID
	occurrence model.ID
}

func newOccSens(t *testing.T) *occSens {
	t.Helper()
	issues, errs := &fakeIssues{}, &fakeErrors{found: true}
	e := newEvEnv(t, nil, issues, true)
	e.occurrenceEnv(t, issues, errs)
	p := model.NewID()
	org := e.org("evidence occurrence sensitivity", p)
	admin := e.user(org, "occ-sens-admin@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	e.grant(org, admin, p, true, auth.Read)
	fp := model.HashCanonical([]byte("occurrence sensitivity fingerprint"))
	listed := model.GroupingEvidence{OccurrenceID: model.NewID(), RecordID: model.NewID(), GroupingVersion: 1, Fingerprint: fp, EventTime: 1234, ArrivalTime: 2000, Ancestry: "unknown", Freshness: "fresh"}
	issues.issue = model.GroupingIssue{ID: model.NewID(), Org: org, Project: p, GroupingVersion: 1, Fingerprint: fp, Workflow: "open", Revision: 1, Occurrences: []model.GroupingEvidence{listed}}
	return &occSens{t: t, e: e, admin: admin, issues: issues, errs: errs, org: org, p: p, occurrence: listed.OccurrenceID}
}

func (s *occSens) post(stored model.ErrorOccurrence) []byte {
	s.t.Helper()
	stored.Occurrence = s.occurrence
	s.errs.occ = stored
	status, raw := s.e.post(s.admin, "/api/v1/evidence/occurrence", map[string]any{"org": s.org.String(), "project": s.p.String(), "issue": s.issues.issue.ID.String(), "occurrence": s.occurrence.String()}, nil)
	if status != 200 {
		s.t.Fatalf("occurrence: %d %s", status, raw)
	}
	return raw
}

// rawField descends one object key of a raw JSON object.
func rawField(t *testing.T, raw []byte, key string) json.RawMessage {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("not an object (looking for %q): %v\n%s", key, err, raw)
	}
	v, ok := obj[key]
	if !ok {
		t.Fatalf("no %q in %s", key, raw)
	}
	return v
}

// requireEmptyList fails unless the raw JSON value is exactly an empty array: a
// JSON null is the failure this guards against.
func requireEmptyList(t *testing.T, what string, v json.RawMessage) {
	t.Helper()
	if string(v) != "[]" {
		t.Fatalf("%s must be the empty list [] on the wire, got %s", what, v)
	}
}

func TestEvidenceSensOccurrenceDetailCarriesTemplateReplayProfileAndRunAsStored(t *testing.T) {
	s := newOccSens(t)
	template := "tmpl-stored-7"
	replay, profile, run := model.NewID(), model.NewID(), model.NewID()
	raw := s.post(model.ErrorOccurrence{Class: "StoredFailure", Mechanism: "manual", Build: model.NewID(), Template: &template, Replay: &replay, Profile: &profile, Run: &run})
	v := decodeOccurrence(t, raw)
	d := v.Detail
	if v.State != httpapi.StateReady || d == nil {
		t.Fatalf("occurrence: %s", raw)
	}
	if d.Template == nil || *d.Template != template {
		t.Fatalf("the stored template link must be shown as stored: %s", raw)
	}
	if d.Replay == nil || *d.Replay != replay {
		t.Fatalf("the stored replay link must be shown as stored: %s", raw)
	}
	if d.Profile == nil || *d.Profile != profile {
		t.Fatalf("the stored profile link must be shown as stored: %s", raw)
	}
	if d.Run == nil || *d.Run != run {
		t.Fatalf("the stored run link must be shown as stored: %s", raw)
	}
}

func TestEvidenceSensOccurrenceWireFormNeverCarriesNullLists(t *testing.T) {
	column := uint32(2)
	frames := []model.Frame{{Module: "app", Function: "boom", Artifact: "a", Line: 3, Column: &column, InApp: true}}
	base := func() model.ErrorOccurrence {
		return model.ErrorOccurrence{Class: "StoredFailure", Mechanism: "manual", Build: model.NewID(), Frames: frames}
	}
	t.Run("absent frames of the occurrence are an empty list", func(t *testing.T) {
		s := newOccSens(t)
		stored := base()
		stored.Frames = nil
		raw := s.post(stored)
		requireEmptyList(t, "detail.frames", rawField(t, rawField(t, raw, "detail"), "frames"))
	})
	graph := func() *model.ExceptionGraph {
		return &model.ExceptionGraph{
			Nodes:   []model.ExceptionNode{{ID: 0, Class: "StoredFailure", Frames: frames}},
			Edges:   []model.ExceptionEdge{{From: 0, To: 0, Kind: "cause"}},
			Reasons: []string{"node_limit"},
		}
	}
	chain := func(t *testing.T, s *occSens, g *model.ExceptionGraph) json.RawMessage {
		t.Helper()
		stored := base()
		stored.Graph = g
		return rawField(t, rawField(t, s.post(stored), "detail"), "exception_graph")
	}
	t.Run("absent chain nodes are an empty list", func(t *testing.T) {
		g := graph()
		g.Nodes = nil
		requireEmptyList(t, "exception_graph.nodes", rawField(t, chain(t, newOccSens(t), g), "nodes"))
	})
	t.Run("absent frames of a chain node are an empty list", func(t *testing.T) {
		g := graph()
		g.Nodes[0].Frames = nil
		var nodes []map[string]json.RawMessage
		if err := json.Unmarshal(rawField(t, chain(t, newOccSens(t), g), "nodes"), &nodes); err != nil || len(nodes) != 1 {
			t.Fatalf("nodes: %v %d", err, len(nodes))
		}
		requireEmptyList(t, "exception_graph.nodes[0].frames", nodes[0]["frames"])
	})
	t.Run("absent chain edges are an empty list", func(t *testing.T) {
		g := graph()
		g.Edges = nil
		requireEmptyList(t, "exception_graph.edges", rawField(t, chain(t, newOccSens(t), g), "edges"))
	})
	t.Run("absent chain reasons are an empty list", func(t *testing.T) {
		g := graph()
		g.Reasons = nil
		requireEmptyList(t, "exception_graph.reasons", rawField(t, chain(t, newOccSens(t), g), "reasons"))
	})
}

// nilRowsScanner is a scanner that answers neither rows nor an error.
type nilRowsScanner struct{}

func (nilRowsScanner) Scan(context.Context, auth.Scope, storage.ScanRequest) (storage.RowIterator, error) {
	return nil, nil
}

func TestEvidenceSensStorageSourceReturnsOnlyTheRequestedOccurrence(t *testing.T) {
	project, record, occurrence := model.NewID(), model.NewID(), model.NewID()
	want := model.ErrorOccurrence{Occurrence: occurrence, Class: "Stored", Mechanism: "manual", Build: model.NewID()}
	// The same record ID carrying a different occurrence is not the evidence asked for.
	foreign := model.ErrorOccurrence{Occurrence: model.NewID(), Class: "Foreign", Mechanism: "manual"}

	t.Run("a row of the requested record holding another occurrence is not returned", func(t *testing.T) {
		sc := &errScanner{pages: []storage.Page{errPage(false, []model.ID{record}, &foreign)}}
		occ, found, _, err := httpapi.NewStorageErrorSource(sc).ErrorOccurrence(context.Background(), auth.Scope{}, project, record, occurrence, 1_000)
		if err != nil || found {
			t.Fatalf("got %+v found=%v err=%v: another occurrence's record must never be returned", occ, found, err)
		}
	})
	t.Run("the matching row is still found after a foreign one under the same record", func(t *testing.T) {
		sc := &errScanner{pages: []storage.Page{errPage(false, []model.ID{record, record}, &foreign, &want)}}
		occ, found, _, err := httpapi.NewStorageErrorSource(sc).ErrorOccurrence(context.Background(), auth.Scope{}, project, record, occurrence, 1_000)
		if err != nil || !found || occ.Class != "Stored" || occ.Occurrence != occurrence {
			t.Fatalf("got %+v found=%v err=%v", occ, found, err)
		}
	})
	t.Run("a scan that answers no row iterator is corruption", func(t *testing.T) {
		var (
			err      error
			panicked any
		)
		func() {
			defer func() { panicked = recover() }()
			_, _, _, err = httpapi.NewStorageErrorSource(nilRowsScanner{}).ErrorOccurrence(context.Background(), auth.Scope{}, project, record, occurrence, 1_000)
		}()
		if panicked != nil {
			t.Fatalf("a nil row iterator must be a typed fault, it panicked: %v", panicked)
		}
		if faultCode(err) != model.Corrupt {
			t.Fatalf("a nil row iterator must be a corrupt fault, got %v", err)
		}
	})
}

// The scan window is the one nanosecond [at, at+1) of the evidence's own event time: a time that has no such window (negative, or the last
// representable nanosecond, whose end would wrap) is not scanned at all, and the nearest times that do have one are.
func TestEvidenceSensStorageSourceWindowsOnlyAnEventTimeThatHasOne(t *testing.T) {
	project, record, occurrence := model.NewID(), model.NewID(), model.NewID()
	for _, at := range []model.UnixNano{-1, math.MaxInt64} {
		sc := &errScanner{pages: []storage.Page{errPage(false, []model.ID{record}, &model.ErrorOccurrence{Occurrence: occurrence})}}
		_, found, _, err := httpapi.NewStorageErrorSource(sc).ErrorOccurrence(context.Background(), auth.Scope{}, project, record, occurrence, at)
		if faultCode(err) != model.Unavailable || found || sc.calls != 0 {
			t.Fatalf("event time %d: code %q found=%v scans=%d: a time without a one-nanosecond window must be unavailable and never scanned", at, faultCode(err), found, sc.calls)
		}
	}
	for _, at := range []model.UnixNano{0, math.MaxInt64 - 1} {
		sc := &errScanner{pages: []storage.Page{errPage(false, []model.ID{record}, &model.ErrorOccurrence{Occurrence: occurrence})}}
		_, found, _, err := httpapi.NewStorageErrorSource(sc).ErrorOccurrence(context.Background(), auth.Scope{}, project, record, occurrence, at)
		if err != nil || !found || sc.calls != 1 || sc.req.Start != at || sc.req.End != at+1 {
			t.Fatalf("event time %d: err=%v found=%v scans=%d window [%d,%d): the nearest times that have a window are scanned over exactly it", at, err, found, sc.calls, sc.req.Start, sc.req.End)
		}
	}
}

func TestEvidenceSensInvalidReleaseRequestDoesNotEchoCallerInput(t *testing.T) {
	e := newEvEnv(t, nil, nil, true)
	p := model.NewID()
	org := e.org("evidence release echo", p)
	admin := e.user(org, "release-echo-admin@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	compare := make([]string, 0, httpapi.MaxEvidenceCompare+1)
	for i := 0; i <= httpapi.MaxEvidenceCompare; i++ {
		compare = append(compare, model.NewID().String())
	}
	release := model.NewID()
	status, raw := e.post(admin, "/api/v1/evidence/release", map[string]any{"org": org.String(), "project": p.String(), "release": release.String(), "compare": compare}, nil)
	if status != 400 {
		t.Fatalf("an over-bound compare list: %d %s", status, raw)
	}
	var fault struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(raw, &fault); err != nil {
		t.Fatalf("not a typed fault: %v\n%s", err, raw)
	}
	if fault.Code != string(model.Invalid) || fault.Detail != "evidence_request_invalid" {
		t.Fatalf("the refusal must be the typed invalid fault evidence_request_invalid: %s", raw)
	}
	for name, input := range map[string]string{"org": org.String(), "project": p.String(), "release": release.String(), "compare": compare[0]} {
		if strings.Contains(string(raw), input) {
			t.Fatalf("the refusal echoes the caller's %s %s: %s", name, input, raw)
		}
	}
}
