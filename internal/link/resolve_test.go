// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package link_test

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/link"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
	"io"
	"path/filepath"
	"testing"
	"time"
)

// scriptedRecords answers a scan from the selector alone, so the test can see
// exactly which targets reached an index.
type scriptedRecords struct {
	known map[model.ID]bool
	scans []model.ID
	// failure modes of an otherwise-present target
	scanErr, nextErr, closeErr bool
}
type scriptedRows struct {
	row      bool
	done     bool
	nextErr  bool
	closeErr bool
}

func (s *scriptedRecords) Scan(_ context.Context, _ auth.Scope, req storage.ScanRequest) (storage.RowIterator, error) {
	id, err := model.ParseID(req.Selectors[0].Literal.String)
	if err != nil {
		return nil, err
	}
	s.scans = append(s.scans, id)
	if s.scanErr {
		return nil, errors.New("index unavailable")
	}
	return &scriptedRows{row: s.known[id], nextErr: s.nextErr, closeErr: s.closeErr}, nil
}
func (r *scriptedRows) Next(context.Context) (storage.Page, error) {
	if r.nextErr {
		return storage.Page{}, errors.New("page read failed")
	}
	if r.done || !r.row {
		return storage.Page{}, io.EOF
	}
	r.done = true
	return storage.Page{IDs: []model.ID{{}}}, nil
}
func (r *scriptedRows) Watermarks() []model.Cursor { return nil }
func (r *scriptedRows) Close() error {
	if r.closeErr {
		return errors.New("close failed")
	}
	return nil
}

func TestResolveAuthorizesBeforeAnyLookupAndHidesDifference(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := control.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	enable, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err = store.EnableSingle(enable, filepath.Join(dir, "raft-control")); err != nil {
		t.Fatal(err)
	}
	boot, _ := store.BootstrapToken()
	session, err := service.Bootstrap(ctx, boot, "link-owner@example.test", "link owner password 2026")
	if err != nil {
		t.Fatal(err)
	}
	actor, _ := service.Authenticate(ctx, session.Token)
	org, p1, p2, reader := model.NewID(), model.NewID(), model.NewID(), model.NewID()
	cmd := func(kind string, p auth.AdminPayload) {
		t.Helper()
		var revision model.Revision
		_ = store.View(ctx, func(st control.State) error { revision = st.Revision; return nil })
		p.Reason = "link regression"
		raw, _ := json.Marshal(p)
		if _, err := service.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); err != nil {
			t.Fatal(kind, err)
		}
	}
	cmd("create_org", auth.AdminPayload{Name: "link"})
	cmd("create_project", auth.AdminPayload{ID: p1, Name: "one"})
	cmd("create_project", auth.AdminPayload{ID: p2, Name: "two"})
	cmd("create_user", auth.AdminPayload{ID: reader, Email: "link-reader@example.test", Password: "link reader password"})
	cmd("membership", auth.AdminPayload{UserID: reader, Enabled: true})
	cmd("grant", auth.AdminPayload{UserID: reader, ProjectID: p1, Enabled: true, Permissions: []string{string(auth.Read)}})
	login, err := service.Login(ctx, "link-reader@example.test", "link reader password", "")
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := service.Authenticate(ctx, login.Token)
	scope, err := service.Authorize(ctx, credential, org, []model.ID{p1}, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	present, absent := model.NewID(), model.NewID()
	records := &scriptedRecords{known: map[model.ID]bool{present: true}}
	resolver, err := link.New(service, records, nil)
	if err != nil {
		t.Fatal(err)
	}
	ref := func(project model.ID, kind string, id model.ID, relation string) link.Reference {
		return link.Reference{Project: project, Kind: kind, ID: id, Relation: relation}
	}
	refs := []link.Reference{
		ref(p1, "error", present, link.RelationExplicit),
		ref(p1, "error", absent, link.RelationExplicit),
		ref(p2, "error", present, link.RelationExplicit),            // existing target, project outside the scope
		ref(model.NewID(), "error", present, link.RelationExplicit), // guessed project
		ref(p1, "error", present, "inferred_by_vibes"),              // not a closed relation
		ref(p1, "error", model.ID{}, link.RelationExplicit),         // zero id
		ref(p1, "metric", present, link.RelationExplicit),           // unsupported kind
		ref(p1, "artifact", present, link.RelationExplicit),         // no artifact reader configured
		ref(p1, "error", present, link.RelationTimeOverlap),
	}
	out, err := resolver.Resolve(ctx, scope, refs)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []bool{true, false, false, false, false, false, false, false, true} {
		if out[i].Available != want || (out[i].Reference != nil) != want {
			t.Fatalf("reference %d available=%v", i, out[i].Available)
		}
		if !want && out[i] != (link.ResolvedReference{}) {
			t.Fatalf("unavailable reference %d is distinguishable: %+v", i, out[i])
		}
	}
	if out[8].Reference.Relation != link.RelationTimeOverlap {
		t.Fatal("inference was reported as explicit")
	}
	// Only in-scope, well-formed record references reached an index.
	if len(records.scans) != 3 {
		t.Fatalf("index lookups %d, want 3 (present, absent, present again)", len(records.scans))
	}
	if _, err = resolver.Resolve(ctx, scope, make([]link.Reference, 129)); err == nil {
		t.Fatal("oversized reference batch accepted")
	}
	// A target is available only if the index read completed cleanly end to end:
	// a failed scan, page read or close is the same unavailable value, never a
	// resolved reference.
	for name, failing := range map[string]*scriptedRecords{
		"scan":  {known: map[model.ID]bool{present: true}, scanErr: true},
		"next":  {known: map[model.ID]bool{present: true}, nextErr: true},
		"close": {known: map[model.ID]bool{present: true}, closeErr: true},
	} {
		broken, err := link.New(service, failing, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := broken.Resolve(ctx, scope, refs[:1])
		if err != nil || got[0] != (link.ResolvedReference{}) {
			t.Fatalf("%s failure resolved a reference: %+v %v", name, got, err)
		}
	}
	// Revocation fails the whole call before any further lookup.
	cmd("grant", auth.AdminPayload{UserID: reader, ProjectID: p1, Enabled: false})
	before := len(records.scans)
	if _, err = resolver.Resolve(ctx, scope, refs[:1]); err == nil || len(records.scans) != before {
		t.Fatalf("stale scope resolved a link: %v", err)
	}
	if _, err = link.New(nil, records, nil); err == nil {
		t.Fatal("resolver built without a scope authority")
	}
}
