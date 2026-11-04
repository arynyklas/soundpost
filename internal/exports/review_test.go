// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package exports

import (
	"errors"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"testing"
	"time"
)

func faultCode(err error) model.Code {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.Code
	}
	return ""
}

func metricRequest(project model.ID) Request {
	return Request{Project: project, Signal: model.Metric, End: 10}
}

// An authorized, complete export with no rows is a real empty download: one
// empty last chunk. Anything that is not that operation stays a plain NotFound.
func TestEmptyCompleteExportReleasesOneEmptyChunk(t *testing.T) {
	f := newFx(t)
	org, project := f.newOrg("empty")
	c, _ := f.reader(org, project, "empty-reader@example.test", auth.Read)
	exp := f.service(&script{pages: 0}, testLimits())
	scope := f.scope(c, org, project)
	grant, err := exp.Create(f.ctx, scope, metricRequest(project))
	if err != nil {
		t.Fatal(err)
	}
	if op := exp.settle(t, exp.entryFor(t, grant.Operation.ID)); op.Phase != "complete" {
		t.Fatalf("empty export phase %q reason %q", op.Phase, op.SafeReason)
	}
	chunk, err := exp.Chunk(f.ctx, scope, grant.Ticket, grant.Operation.ID, 0)
	if err != nil || len(chunk.Data) != 0 || !chunk.Last || chunk.Index != 0 {
		t.Fatalf("empty export chunk %+v err=%v", chunk, err)
	}
	if op, err := exp.Status(f.ctx, scope, grant.Operation.ID); err != nil || op.Chunks != 1 {
		t.Fatalf("empty export status %+v err=%v", op, err)
	}
	if _, err = exp.Chunk(f.ctx, scope, grant.Ticket, grant.Operation.ID, 1); faultCode(err) != model.NotFound {
		t.Fatalf("chunk past the empty export: %v", err)
	}
	if _, err = exp.Chunk(f.ctx, scope, grant.Ticket, model.NewID(), 0); faultCode(err) != model.NotFound {
		t.Fatalf("unknown operation: %v", err)
	}
	if _, err = exp.Chunk(f.ctx, scope, "forged", grant.Operation.ID, 0); faultCode(err) != model.NotFound {
		t.Fatalf("forged ticket: %v", err)
	}
}

// A scan that reports it is partial is never presented as complete.
func TestPartialScanIsNeverPresentedAsComplete(t *testing.T) {
	f := newFx(t)
	org, project := f.newOrg("partial")
	c, _ := f.reader(org, project, "partial-reader@example.test", auth.Read)
	scope := f.scope(c, org, project)
	run := func(s *script) (Operation, [][]byte) {
		t.Helper()
		exp := f.service(s, testLimits())
		grant, err := exp.Create(f.ctx, scope, metricRequest(project))
		if err != nil {
			t.Fatal(err)
		}
		e := exp.entryFor(t, grant.Operation.ID)
		exp.settle(t, e)
		op, chunks, _ := e.state()
		if op.Phase != "complete" {
			if _, err = exp.Chunk(f.ctx, scope, grant.Ticket, grant.Operation.ID, 0); faultCode(err) != model.NotFound {
				t.Fatalf("incomplete export released bytes: %v", err)
			}
		}
		return op, chunks
	}
	if op, _ := run(&script{pages: 2}); op.Phase != "complete" {
		t.Fatalf("control: a full scan must complete, got %q %q", op.Phase, op.SafeReason)
	}
	for _, at := range []int{1, 2, 3} {
		op, chunks := run(&script{pages: 3, partialAt: at})
		if op.Phase == "complete" || op.SafeReason != "partial" || chunks != nil {
			t.Fatalf("partial page %d: phase %q reason %q retained=%v", at, op.Phase, op.SafeReason, chunks != nil)
		}
	}
}

// The export budget is per principal, per organization and global, so one
// tenant filling its own budget never blocks another.
func TestExportLimitsArePerPrincipalPerOrgAndGlobal(t *testing.T) {
	f := newFx(t)
	orgX, projectX := f.newOrg("tenant X")
	orgY, projectY := f.newOrg("tenant Y")
	orgZ, projectZ := f.newOrg("tenant Z")
	a1, _ := f.reader(orgX, projectX, "a1@example.test", auth.Read)
	a2, _ := f.reader(orgX, projectX, "a2@example.test", auth.Read)
	b1, _ := f.reader(orgY, projectY, "b1@example.test", auth.Read)
	c1, _ := f.reader(orgZ, projectZ, "c1@example.test", auth.Read)
	hold := make(chan struct{})
	exp := f.service(&script{pages: 1, startGate: hold}, Limits{PerPrincipal: 2, PerOrg: 3, Global: 4, SweepInterval: time.Hour})
	create := func(c auth.Credential, org, project model.ID) error {
		t.Helper()
		_, err := exp.Create(f.ctx, f.scope(c, org, project), metricRequest(project))
		return err
	}
	for i := range 2 {
		if err := create(a1, orgX, projectX); err != nil {
			t.Fatalf("a1 export %d: %v", i, err)
		}
	}
	if err := create(a1, orgX, projectX); faultCode(err) != model.Quota {
		t.Fatalf("a1 exceeded its per-principal budget: %v", err)
	}
	if err := create(a2, orgX, projectX); err != nil {
		t.Fatalf("a1 saturating its own budget blocked a2: %v", err)
	}
	if err := create(a2, orgX, projectX); faultCode(err) != model.Quota {
		t.Fatalf("org X exceeded its per-org budget through a second principal: %v", err)
	}
	// Tenant X is fully saturated; other tenants are unaffected.
	if err := create(b1, orgY, projectY); err != nil {
		t.Fatalf("tenant Y starved by tenant X: %v", err)
	}
	if err := create(c1, orgZ, projectZ); faultCode(err) != model.Quota {
		t.Fatalf("global budget not enforced: %v", err)
	}
	// Completed exports still hold memory until they expire; expiry frees budget.
	close(hold)
	f.advance(grantTTL + time.Second)
	if err := create(a1, orgX, projectX); err != nil {
		t.Fatalf("expired exports still count against the budget: %v", err)
	}
	if err := create(c1, orgZ, projectZ); err != nil {
		t.Fatalf("global budget not released by expiry: %v", err)
	}
}

// Expired payloads are reclaimed without anyone creating another export: by the
// periodic sweep, by any operation entering the service, and by Close.
func TestExpiredExportPayloadsAreReclaimed(t *testing.T) {
	f := newFx(t)
	org, project := f.newOrg("reclaim")
	reader, _ := f.reader(org, project, "reclaim-reader@example.test", auth.Read)
	other, _ := f.reader(org, project, "reclaim-other@example.test", auth.Read)
	scope := f.scope(reader, org, project)
	finish := func(exp *Service) *entry {
		t.Helper()
		grant, err := exp.Create(f.ctx, scope, metricRequest(project))
		if err != nil {
			t.Fatal(err)
		}
		e := exp.entryFor(t, grant.Operation.ID)
		if op := exp.settle(t, e); op.Phase != "complete" {
			t.Fatalf("phase %q", op.Phase)
		}
		if _, chunks, _ := e.state(); len(chunks) == 0 {
			t.Fatal("completed export retained nothing")
		}
		return e
	}
	released := func(e *entry) bool { _, chunks, _ := e.state(); return chunks == nil }

	// 1. Timer: nothing but the clock moves.
	timed := f.service(&script{pages: 1}, Limits{PerPrincipal: 4, PerOrg: 8, Global: 32, SweepInterval: 10 * time.Millisecond})
	e := finish(timed)
	f.advance(grantTTL + time.Second)
	for deadline := time.Now().Add(5 * time.Second); timed.liveEntries() != 0 && time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
	}
	if timed.liveEntries() != 0 || !released(e) {
		t.Fatalf("expired export not reclaimed by the sweep: entries=%d payload released=%v", timed.liveEntries(), released(e))
	}

	// 2. Any operation entering the service (even another principal's lookup of
	// an unknown id) reclaims expired payloads.
	f.setClock(time.Now())
	lazy := f.service(&script{pages: 1}, testLimits())
	e = finish(lazy)
	f.advance(grantTTL + time.Second)
	if _, err := lazy.Status(f.ctx, f.scope(other, org, project), model.NewID()); faultCode(err) != model.NotFound {
		t.Fatal(err)
	}
	if lazy.liveEntries() != 0 || !released(e) {
		t.Fatalf("expired export not reclaimed on operation entry: entries=%d payload released=%v", lazy.liveEntries(), released(e))
	}

	// 3. Close frees everything, completed or not.
	f.setClock(time.Now())
	closing := f.service(&script{pages: 1}, testLimits())
	e = finish(closing)
	closing.Close()
	if closing.liveEntries() != 0 || !released(e) {
		t.Fatalf("Close left payloads behind: entries=%d payload released=%v", closing.liveEntries(), released(e))
	}
}

// A restricted-raw window closing is a pure clock event. An export, its grant
// and its pending computation must die with it, minted or not before.
func TestExportDiesAtTheRestrictedRawWindow(t *testing.T) {
	f := newFx(t)
	org, project := f.newOrg("raw window")
	reader, readerID := f.reader(org, project, "raw-window-reader@example.test", auth.RawRead)
	start := f.at()
	source := f.rawSource(org, project, readerID, 10*time.Minute, time.Hour)
	second := f.rawSource(org, project, readerID, 20*time.Minute, time.Hour) // outlives the first
	expiry := start.Add(10 * time.Minute)
	f.setClock(expiry.Add(-time.Second))
	authorize := func() (auth.Scope, error) {
		return f.svc.AuthorizeRestrictedSource(f.ctx, reader, org, project, source)
	}
	logRequest := Request{Project: project, Signal: model.Log, Source: source, End: 10}

	exp := f.service(&script{pages: 1}, testLimits())
	scope, err := authorize()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := exp.Create(f.ctx, scope, logRequest)
	if err != nil {
		t.Fatal(err)
	}
	e := exp.entryFor(t, grant.Operation.ID)
	if op := exp.settle(t, e); op.Phase != "complete" {
		t.Fatalf("phase %q reason %q", op.Phase, op.SafeReason)
	}
	if _, _, expires := e.state(); expires.After(expiry) {
		t.Fatalf("export entry outlives the raw window by %v", expires.Sub(expiry))
	}
	if chunk, err := exp.Chunk(f.ctx, scope, grant.Ticket, grant.Operation.ID, 0); err != nil || len(chunk.Data) == 0 {
		t.Fatalf("chunk one second before expiry: %v", err)
	}
	// One second past the window: control state, epoch, fingerprint and delete
	// generation are all unchanged, yet nothing minted earlier works.
	f.setClock(expiry.Add(time.Second))
	if _, err = exp.Chunk(f.ctx, scope, grant.Ticket, grant.Operation.ID, 0); faultCode(err) != model.NotFound {
		t.Fatalf("grant minted before expiry released bytes after it: %v", err)
	}
	if _, err = exp.Status(f.ctx, scope, grant.Operation.ID); faultCode(err) != model.NotFound {
		t.Fatalf("operation visible after expiry: %v", err)
	}
	if _, err = exp.Create(f.ctx, scope, logRequest); faultCode(err) != model.NotFound {
		t.Fatalf("expired scope created an export: %v", err)
	}
	if _, err = authorize(); faultCode(err) != model.NotFound {
		t.Fatalf("expired source re-authorized: %v", err)
	}

	// A computation still running when the window closes never completes.
	secondEnds := start.Add(20 * time.Minute)
	f.setClock(secondEnds.Add(-time.Second))
	hold := make(chan struct{})
	pendingExp := f.service(&script{pages: 1, startGate: hold}, testLimits())
	pendingScope, err := f.svc.AuthorizeRestrictedSource(f.ctx, reader, org, project, second)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := pendingExp.Create(f.ctx, pendingScope, Request{Project: project, Signal: model.Log, Source: second, End: 10})
	if err != nil {
		t.Fatal(err)
	}
	pe := pendingExp.entryFor(t, pending.Operation.ID)
	f.setClock(secondEnds.Add(time.Second))
	close(hold)
	if op := pendingExp.settle(t, pe); op.Phase != "failed" || op.SafeReason != "revoked" {
		t.Fatalf("export finished across the raw window: phase %q reason %q", op.Phase, op.SafeReason)
	}
	if _, chunks, _ := pe.state(); chunks != nil {
		t.Fatal("expired pending export retained rows")
	}
}

// Authority is re-checked between pages, not only at completion: a revoked
// export stops reading instead of finishing the scan.
func TestScanStopsAtTheNextPageAfterRevocation(t *testing.T) {
	f := newFx(t)
	org, project := f.newOrg("between pages")
	reader, readerID := f.reader(org, project, "between-reader@example.test", auth.Read)
	s := &script{pages: 3, parkAt: 2, parked: make(chan struct{}, 1), parkGate: make(chan struct{})}
	exp := f.service(s, testLimits())
	grant, err := exp.Create(f.ctx, f.scope(reader, org, project), metricRequest(project))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.parked:
	case <-time.After(10 * time.Second):
		t.Fatal("scan never reached its second page")
	}
	f.cmd(org, "grant", auth.AdminPayload{UserID: readerID, ProjectID: project, Enabled: false})
	close(s.parkGate)
	if op := exp.settle(t, exp.entryFor(t, grant.Operation.ID)); op.Phase != "failed" || op.SafeReason != "revoked" {
		t.Fatalf("phase %q reason %q", op.Phase, op.SafeReason)
	}
	if got := s.nexts.Load(); got != 2 {
		t.Fatalf("scan kept reading after revocation: %d page requests, want 2", got)
	}
}
