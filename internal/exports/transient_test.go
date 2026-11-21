// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package exports

import (
	"context"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

// Open item #1: an export of a busy project ended `safe_reason: revoked` after
// about 50 s with the grant intact and no administrator action. Nothing the
// export revalidates (scope, organization policy epoch, delete generation) moves
// when a project ingests (httpapi TestExportSurvivesConcurrentIngest), but every
// failure of those reads, whatever its cause, used to be reported as revocation.
// These tests pin the line between the two: only an authority that answers "no"
// ends an export as revoked; a control read that is slow or cannot be answered,
// or a scan that fails for a reason other than authority, never does.

// flaky is a delete-generation source whose next reads fail.
type flaky struct {
	base  auth.DeleteGenerations
	fails atomic.Int64
	err   error
	bump  atomic.Uint64
}

func (d *flaky) DeleteGeneration(ctx context.Context, org model.ID, p []model.ID) (uint64, error) {
	if d.fails.Add(-1) >= 0 {
		return 0, d.err
	}
	v, err := d.base.DeleteGeneration(ctx, org, p)
	return v + d.bump.Load(), err
}

// midExport is an export parked inside its second page request, every
// per-page check of the second page already behind it, the way a long export
// of a busy project is while its authority is read.
type midExport struct {
	f       *fx
	exp     *Service
	s       *script
	org     model.ID
	project model.ID
	reader  model.ID
	grant   Grant
	flaky   *flaky
}

func startMidExport(t *testing.T, f *fx, s *script) *midExport {
	t.Helper()
	org, project := f.newOrg("mid export")
	reader, readerID := f.reader(org, project, "mid-export-reader@example.test", auth.Read)
	if s.parked == nil {
		s.parked, s.parkGate, s.parkAt = make(chan struct{}, 1), make(chan struct{}), 2
	}
	m := &midExport{f: f, s: s, org: org, reader: readerID, flaky: &flaky{base: f.svc.SourceLifecycleGenerations(), err: model.Fail(model.Unavailable)}}
	cache, err := auth.NewCache(f.svc, m.flaky, 64, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if m.exp, err = NewWithLimits(f.svc, cache, m.flaky, s, testLimits()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.exp.Close)
	if m.grant, err = m.exp.Create(f.ctx, f.scope(reader, org, project), metricRequest(project)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.parked:
	case <-time.After(10 * time.Second):
		t.Fatal("scan never reached its second page")
	}
	m.project = project
	return m
}

func (m *midExport) release() { close(m.s.parkGate) }
func (m *midExport) settle(t *testing.T) Operation {
	t.Helper()
	return m.exp.settle(t, m.exp.entryFor(t, m.grant.Operation.ID))
}

// A control read that takes longer than the lease (5 s) is refused with Stale
// by the authority, because a slow read proves nothing. The authority did not
// revoke anything: the next read is fast and the grant is intact.
func TestSlowControlReadDoesNotRevokeAnExport(t *testing.T) {
	f := newFxHooked(t)
	m := startMidExport(t, f, &script{pages: 4})
	var slowed atomic.Bool
	f.hook.set(func() error {
		if slowed.CompareAndSwap(false, true) {
			f.advance(6 * time.Second)
		}
		return nil
	})
	m.release()
	if op := m.settle(t); op.Phase != "complete" || op.SafeReason != "" {
		t.Fatalf("one slow control read ended the export %q/%q", op.Phase, op.SafeReason)
	}
	if !slowed.Load() {
		t.Fatal("the slow read never happened: the test proved nothing")
	}
}

// A control group that cannot answer one read (a leader change, a fsync stall)
// says nothing about the grant.
func TestUnavailableControlReadDoesNotRevokeAnExport(t *testing.T) {
	f := newFxHooked(t)
	m := startMidExport(t, f, &script{pages: 4})
	var failed atomic.Int64
	f.hook.set(func() error {
		if failed.Add(1) == 1 {
			return model.Fail(model.Unavailable)
		}
		return nil
	})
	m.release()
	if op := m.settle(t); op.Phase != "complete" || op.SafeReason != "" {
		t.Fatalf("one unanswered control read ended the export %q/%q", op.Phase, op.SafeReason)
	}
	if failed.Load() < 2 {
		t.Fatal("the failure was never injected or never retried")
	}
}

// The same for the delete-generation read.
func TestUnavailableDeleteGenerationReadDoesNotRevokeAnExport(t *testing.T) {
	f := newFx(t)
	m := startMidExport(t, f, &script{pages: 4})
	m.flaky.fails.Store(1)
	m.release()
	if op := m.settle(t); op.Phase != "complete" || op.SafeReason != "" {
		t.Fatalf("one failed delete-generation read ended the export %q/%q", op.Phase, op.SafeReason)
	}
	if m.flaky.fails.Load() >= 0 {
		t.Fatal("the failed read was never retried: the test proved nothing")
	}
}

// A control group that stays down ends the export, honestly: unavailable is
// retryable by the user, revoked is a statement about their access.
func TestControlOutageEndsAnExportAsUnavailable(t *testing.T) {
	f := newFxHooked(t)
	m := startMidExport(t, f, &script{pages: 4})
	f.hook.set(func() error { return model.Fail(model.Unavailable) })
	m.release()
	op := m.settle(t)
	if op.Phase != "failed" || op.SafeReason != "unavailable" {
		t.Fatalf("control outage ended the export %q/%q, want failed/unavailable", op.Phase, op.SafeReason)
	}
	if got := m.s.nexts.Load(); got != 2 {
		t.Fatalf("the scan kept reading while authority was unknown: %d page requests, want 2", got)
	}
}

// A scan that fails for a reason that is not authority (a read fence that is
// behind, a node that is not ready) is not a revocation either, and the export
// that hit it is run again rather than lost.
func TestTransientScanFailureDoesNotRevokeAnExport(t *testing.T) {
	for _, code := range []model.Code{model.Stale, model.Unavailable} {
		t.Run(string(code), func(t *testing.T) {
			f := newFx(t)
			s := &script{pages: 4, fail: map[int64]error{3: model.Fail(code)}}
			m := startMidExport(t, f, s)
			m.release()
			if op := m.settle(t); op.Phase != "complete" || op.SafeReason != "" {
				t.Fatalf("a %s scan failure ended the export %q/%q", code, op.Phase, op.SafeReason)
			}
			if got := s.scans.Load(); got != 2 {
				t.Fatalf("scan restarted %d times, want exactly one restart", got-1)
			}
		})
	}
}

// A scan that never succeeds ends the export after a bounded number of runs,
// and says unavailable.
func TestPersistentScanFailureEndsAsUnavailable(t *testing.T) {
	f := newFx(t)
	fail := map[int64]error{}
	for n := int64(3); n < 100; n++ {
		fail[n] = model.Fail(model.Stale)
	}
	s := &script{pages: 4, fail: fail}
	m := startMidExport(t, f, s)
	m.release()
	op := m.settle(t)
	if op.Phase != "failed" || op.SafeReason != "unavailable" {
		t.Fatalf("persistent scan failure ended the export %q/%q, want failed/unavailable", op.Phase, op.SafeReason)
	}
	if got := s.scans.Load(); got != 1+scanRestarts {
		t.Fatalf("scan ran %d times, want %d", got, 1+scanRestarts)
	}
}

// A scan refused for authority (NotFound/Forbidden/Unauthenticated) is a
// revocation and is never run again.
func TestScanRefusedForAuthorityRevokesAndIsNotRetried(t *testing.T) {
	for _, code := range []model.Code{model.NotFound, model.Forbidden, model.Unauthenticated} {
		t.Run(string(code), func(t *testing.T) {
			f := newFx(t)
			s := &script{pages: 4, fail: map[int64]error{3: model.Fail(code)}}
			m := startMidExport(t, f, s)
			m.release()
			if op := m.settle(t); op.Phase != "failed" || op.SafeReason != "revoked" {
				t.Fatalf("a %s scan refusal ended the export %q/%q, want failed/revoked", code, op.Phase, op.SafeReason)
			}
			if got := s.scans.Load(); got != 1 {
				t.Fatalf("a refused scan was run %d times", got)
			}
		})
	}
}

// Everything that really ends an authorization still ends a running export at
// its next page, and nothing is read after it: a retry of a failed read never
// carries an earlier "valid" over a change that has since committed.
func TestRealAuthorityChangesStillRevokeARunningExport(t *testing.T) {
	cases := []struct {
		name   string
		hooked bool
		change func(t *testing.T, f *fx, m *midExport)
		reads  int // page requests before the scan stops
	}{
		{"grant removed", false, func(t *testing.T, f *fx, m *midExport) {
			f.cmd(m.org, "grant", auth.AdminPayload{UserID: m.reader, ProjectID: m.project, Enabled: false})
		}, 2},
		{"membership removed", false, func(t *testing.T, f *fx, m *midExport) {
			f.cmd(m.org, "membership", auth.AdminPayload{UserID: m.reader, Enabled: false})
		}, 2},
		{"policy epoch moved", false, func(t *testing.T, f *fx, m *midExport) {
			f.cmd(m.org, "create_project", auth.AdminPayload{ID: model.NewID(), Name: "another project"})
		}, 2},
		{"delete generation moved", false, func(t *testing.T, f *fx, m *midExport) {
			m.flaky.bump.Add(1)
		}, 2},
		{"revoked while a read was failing", true, func(t *testing.T, f *fx, m *midExport) {
			f.cmd(m.org, "grant", auth.AdminPayload{UserID: m.reader, ProjectID: m.project, Enabled: false})
			var failed atomic.Int64
			f.hook.set(func() error {
				if failed.Add(1) == 1 {
					return model.Fail(model.Unavailable)
				}
				return nil
			})
		}, 2},
		{"delete generation moved while a read was failing", false, func(t *testing.T, f *fx, m *midExport) {
			m.flaky.bump.Add(1)
			m.flaky.fails.Store(1)
		}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFxWith(t, c.hooked)
			s := &script{pages: 4}
			m := startMidExport(t, f, s)
			c.change(t, f, m)
			m.release()
			op := m.settle(t)
			if op.Phase != "failed" || op.SafeReason != "revoked" {
				t.Fatalf("phase %q reason %q, want failed/revoked", op.Phase, op.SafeReason)
			}
			if _, chunks, _ := m.exp.entryFor(t, m.grant.Operation.ID).state(); chunks != nil {
				t.Fatal("a revoked export retained rows")
			}
			if got := s.nexts.Load(); got != int64(c.reads) {
				t.Fatalf("scan kept reading after the change: %d page requests, want %d", got, c.reads)
			}
			if got := s.scans.Load(); got != 1 {
				t.Fatalf("a revoked export restarted its scan %d times", got-1)
			}
		})
	}
}

// Completion revalidates after every page has been read: a change that lands
// between the last page and the verdict still ends the export as revoked, also
// when the verdict read has to be retried.
func TestRevocationAtCompletionIsStillRevokedAfterARetry(t *testing.T) {
	f := newFxHooked(t)
	g := &gate{release: make(chan struct{}), started: make(chan struct{}, 1)}
	org, project := f.newOrg("completion")
	reader, readerID := f.reader(org, project, "completion-reader@example.test", auth.Read)
	exp := f.service(g, testLimits())
	grant, err := exp.Create(f.ctx, f.scope(reader, org, project), metricRequest(project))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-g.started:
	case <-time.After(10 * time.Second):
		t.Fatal("scan never reached its last page request")
	}
	f.cmd(org, "grant", auth.AdminPayload{UserID: readerID, ProjectID: project, Enabled: false})
	var failed atomic.Int64
	f.hook.set(func() error {
		if failed.Add(1) == 1 {
			return model.Fail(model.Unavailable)
		}
		return nil
	})
	close(g.release)
	if op := exp.settle(t, exp.entryFor(t, grant.Operation.ID)); op.Phase != "failed" || op.SafeReason != "revoked" {
		t.Fatalf("phase %q reason %q, want failed/revoked", op.Phase, op.SafeReason)
	}
}

// The safe reasons: revoked is only ever the authority's own answer.
func TestSafeReasonVocabulary(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{model.Fail(model.NotFound), "revoked"},
		{model.Fail(model.Forbidden), "revoked"},
		{model.Fail(model.Unauthenticated), "revoked"},
		{model.Fail(model.Stale), "unavailable"},
		{model.Fail(model.Unavailable), "unavailable"},
		{model.Fail(model.Corrupt), "unavailable"},
		{model.Fail(model.TooLarge), "unavailable"},
		{model.Fail(model.Conflict), "unavailable"},
		{model.Fail(model.Cancelled), "timeout"},
		{model.Fail(model.Timeout), "timeout"},
		{context.DeadlineExceeded, "timeout"},
		{context.Canceled, "timeout"},
		{io.ErrUnexpectedEOF, "unavailable"},
	}
	for _, c := range cases {
		if got := reasonFor(c.err); got != c.want {
			t.Errorf("reasonFor(%v) = %q, want %q", c.err, got, c.want)
		}
		if got := denied(c.err); got != (c.want == "revoked") {
			t.Errorf("denied(%v) = %v", c.err, got)
		}
	}
}
