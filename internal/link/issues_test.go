// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package link_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/link"
	"github.com/arynyklas/soundpost/internal/model"
)

type fakeIssueIndex struct {
	held  map[model.ID]model.ID
	err   error
	asked [][]model.ID
}

func (f *fakeIssueIndex) IssuesOf(_ context.Context, _ auth.Scope, _ model.ID, occ []model.ID) (map[model.ID]model.ID, error) {
	f.asked = append(f.asked, append([]model.ID(nil), occ...))
	if f.err != nil {
		return nil, f.err
	}
	return f.held, nil
}

// An occurrence resolves to its issue only when the project is in scope, the scope is fresh and the error record
// itself is readable; everything else is absent from the answer and never reaches the issue index.
func TestIssuesOfResolvesOnlyReadableOccurrencesInScope(t *testing.T) {
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
	session, err := service.Bootstrap(ctx, boot, "issue-owner@example.test", "issue owner password 2026")
	if err != nil {
		t.Fatal(err)
	}
	actor, _ := service.Authenticate(ctx, session.Token)
	org, p1, p2, reader := model.NewID(), model.NewID(), model.NewID(), model.NewID()
	cmd := func(kind string, p auth.AdminPayload) {
		t.Helper()
		var revision model.Revision
		_ = store.View(ctx, func(st control.State) error { revision = st.Revision; return nil })
		p.Reason = "issue link regression"
		raw, _ := json.Marshal(p)
		if _, err := service.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); err != nil {
			t.Fatal(kind, err)
		}
	}
	cmd("create_org", auth.AdminPayload{Name: "issue link"})
	cmd("create_project", auth.AdminPayload{ID: p1, Name: "one"})
	cmd("create_project", auth.AdminPayload{ID: p2, Name: "two"})
	cmd("create_user", auth.AdminPayload{ID: reader, Email: "issue-reader@example.test", Password: "issue reader password"})
	cmd("membership", auth.AdminPayload{UserID: reader, Enabled: true})
	cmd("grant", auth.AdminPayload{UserID: reader, ProjectID: p1, Enabled: true, Permissions: []string{string(auth.Read)}})
	login, err := service.Login(ctx, "issue-reader@example.test", "issue reader password", "")
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := service.Authenticate(ctx, login.Token)
	scope, err := service.Authorize(ctx, credential, org, []model.ID{p1}, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	held, unreadable, issue, otherIssue := model.NewID(), model.NewID(), model.NewID(), model.NewID()
	records := &scriptedRecords{known: map[model.ID]bool{held: true}}
	index := &fakeIssueIndex{held: map[model.ID]model.ID{held: issue, unreadable: otherIssue}}
	resolver, err := link.New(service, records, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := resolver.IssuesOf(ctx, scope, p1, []model.ID{held}); len(got) != 0 {
		t.Fatalf("no issue index bound, resolved %v", got)
	}
	resolver.WithIssues(index)
	got := resolver.IssuesOf(ctx, scope, p1, []model.ID{held, unreadable, {}})
	if len(got) != 1 || got[held] != issue {
		t.Fatalf("resolved %v, want only %v -> %v (an occurrence whose error record is not readable has no link)", got, held, issue)
	}
	if len(index.asked) != 1 || len(index.asked[0]) != 1 || index.asked[0][0] != held {
		t.Fatalf("the issue index was asked %v, want only the readable occurrence", index.asked)
	}
	// A project outside the scope never reaches a record or the issue index.
	scans, asked := len(records.scans), len(index.asked)
	if got := resolver.IssuesOf(ctx, scope, p2, []model.ID{held}); len(got) != 0 || len(records.scans) != scans || len(index.asked) != asked {
		t.Fatalf("foreign project resolved %v (scans %d->%d, index asks %d->%d)", got, scans, len(records.scans), asked, len(index.asked))
	}
	// A failing index resolves nothing.
	index.err = errors.New("book unavailable")
	if got := resolver.IssuesOf(ctx, scope, p1, []model.ID{held}); len(got) != 0 {
		t.Fatalf("failed index resolved %v", got)
	}
	index.err = nil
	// Revocation: nothing resolves and nothing is read.
	cmd("grant", auth.AdminPayload{UserID: reader, ProjectID: p1, Enabled: false})
	scans, asked = len(records.scans), len(index.asked)
	if got := resolver.IssuesOf(ctx, scope, p1, []model.ID{held}); len(got) != 0 || len(records.scans) != scans || len(index.asked) != asked {
		t.Fatalf("stale scope resolved %v", got)
	}
}
