// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package exports

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/storage"
	"sync/atomic"
	"testing"
	"time"
)

type gate struct {
	release chan struct{}
	started chan struct{}
}

// Scan returns at once; the iterator parks inside its final Next (after every
// per-page check has passed), so authority changes land exactly where only the
// completion revalidation can catch them.
func (g *gate) Scan(context.Context, auth.Scope, storage.ScanRequest) (storage.RowIterator, error) {
	return &oneRow{g: g}, nil
}

type oneRow struct {
	g    *gate
	done bool
}

func (r *oneRow) Next(ctx context.Context) (storage.Page, error) {
	if r.done {
		r.g.started <- struct{}{}
		select {
		case <-r.g.release:
		case <-ctx.Done():
			return storage.Page{}, ctx.Err()
		}
		return storage.Page{}, io.EOF
	}
	r.done = true
	v := model.FloatBits(0x3ff0000000000000)
	return storage.Page{IDs: []model.ID{model.NewID()}, Times: []model.UnixNano{1}, ObservedTimes: []model.UnixNano{1}, Resources: []model.Resource{{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "i", Labels: model.Labels{}}}, Values: []model.Payload{{Metric: &model.MetricPoint{Name: "pending_total", Labels: model.Labels{}, SampleKind: "float", Value: &v, Unit: "1", Type: "counter"}}}, Origins: []model.Cursor{{}}, Projects: []model.ID{model.NewID()}, Sources: []model.ID{model.NewID()}, Loss: []uint64{0}}, nil
}
func (r *oneRow) Watermarks() []model.Cursor { return nil }
func (r *oneRow) Close() error               { return nil }

type bump struct {
	base auth.DeleteGenerations
	n    atomic.Uint64
}

func (b *bump) DeleteGeneration(ctx context.Context, org model.ID, p []model.ID) (uint64, error) {
	v, err := b.base.DeleteGeneration(ctx, org, p)
	return v + b.n.Load(), err
}

// A pending export that is revoked or deleted while computing must not become
// downloadable: completion revalidates, and nothing is retained.
func TestPendingExportNeverCompletesAfterRevocationOrDeletion(t *testing.T) {
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
	session, err := service.Bootstrap(ctx, boot, "pending-owner@example.test", "pending owner password 2026")
	if err != nil {
		t.Fatal(err)
	}
	actor, _ := service.Authenticate(ctx, session.Token)
	org, project, reader := model.NewID(), model.NewID(), model.NewID()
	cmd := func(kind string, p auth.AdminPayload) {
		t.Helper()
		var revision model.Revision
		_ = store.View(ctx, func(st control.State) error { revision = st.Revision; return nil })
		p.Reason = "pending export regression"
		raw, _ := json.Marshal(p)
		if _, err := service.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); err != nil {
			t.Fatal(kind, err)
		}
	}
	cmd("create_org", auth.AdminPayload{Name: "pending"})
	cmd("create_project", auth.AdminPayload{ID: project, Name: "p"})
	cmd("create_user", auth.AdminPayload{ID: reader, Email: "pending-reader@example.test", Password: "pending reader password"})
	cmd("membership", auth.AdminPayload{UserID: reader, Enabled: true})
	grant := func(enabled bool) {
		cmd("grant", auth.AdminPayload{UserID: reader, ProjectID: project, Enabled: enabled, Permissions: []string{string(auth.Read)}})
	}
	grant(true)
	login, err := service.Login(ctx, "pending-reader@example.test", "pending reader password", "")
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := service.Authenticate(ctx, login.Token)
	deletes := &bump{base: service.SourceLifecycleGenerations()}
	cache, err := auth.NewCache(service, deletes, 8, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	g := &gate{release: make(chan struct{}), started: make(chan struct{}, 8)}
	exp, err := New(service, cache, deletes, g)
	if err != nil {
		t.Fatal(err)
	}
	defer exp.Close()
	req := Request{Project: project, Signal: model.Metric, End: 10}
	phase := func(grant Grant) (Operation, [][]byte) {
		t.Helper()
		var entries []*entry
		exp.mu.Lock()
		for _, e := range exp.entries {
			if e.op.ID == grant.Operation.ID {
				entries = append(entries, e)
			}
		}
		exp.mu.Unlock()
		if len(entries) != 1 {
			t.Fatal("operation missing from service")
		}
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			e := entries[0]
			e.mu.Lock()
			op, chunks := e.op, e.chunks
			e.mu.Unlock()
			if op.Phase != "running" {
				return op, chunks
			}
		}
		t.Fatal("export stayed pending")
		return Operation{}, nil
	}
	start := func() Grant {
		t.Helper()
		scope, err := service.Authorize(ctx, credential, org, []model.ID{project}, auth.Read)
		if err != nil {
			t.Fatal(err)
		}
		grant, err := exp.Create(ctx, scope, req)
		if err != nil {
			t.Fatal(err)
		}
		<-g.started
		return grant
	}
	// Control: untouched pending export completes with data.
	released := func() { g.release = make(chan struct{}) }
	done := start()
	close(g.release)
	if op, chunks := phase(done); op.Phase != "complete" || len(chunks) != 1 {
		t.Fatalf("unrevoked export phase %q reason %q chunks %d", op.Phase, op.SafeReason, len(chunks))
	}
	// Revoked while pending.
	released()
	pending := start()
	grant(false)
	close(g.release)
	if op, chunks := phase(pending); op.Phase != "failed" || op.SafeReason != "revoked" || chunks != nil {
		t.Fatalf("revoked pending export phase %q reason %q retained=%v", op.Phase, op.SafeReason, chunks != nil)
	}
	// Deleted while pending (grant unchanged).
	grant(true)
	login, err = service.Login(ctx, "pending-reader@example.test", "pending reader password", "")
	if err != nil {
		t.Fatal(err)
	}
	credential, _ = service.Authenticate(ctx, login.Token)
	released()
	pending = start()
	deletes.n.Add(1)
	close(g.release)
	if op, chunks := phase(pending); op.Phase != "failed" || op.SafeReason != "revoked" || chunks != nil {
		t.Fatalf("deleted pending export phase %q reason %q retained=%v", op.Phase, op.SafeReason, chunks != nil)
	}
}
