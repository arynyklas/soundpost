// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replays

import (
	"context"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"testing"
	"time"
)

func (f *fx) revisions() (revision, authority model.Revision) {
	if err := f.store.View(f.ctx, func(st control.State) error {
		revision, authority = st.Revision, st.AuthorityRevision
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return
}

// plainStore is a ReferenceStore that offers only View and Update, the way a test double does:
// the index step falls back to Update, which always moves the control AuthorityRevision.
type plainStore struct{ s *control.Store }

func (p plainStore) View(ctx context.Context, fn func(model.ControlState) error) error {
	return p.s.View(ctx, fn)
}
func (p plainStore) Update(ctx context.Context, fn func(*model.ControlState) error) error {
	return p.s.Update(ctx, fn)
}

// The replay index entry is not authority state. Recording a checkpoint spends a control revision
// but must leave AuthorityRevision alone: a deletion Begin whose view predates only replay
// traffic is still accepted. A store that cannot say so (a double with no UpdateReplayIndex)
// moves it, the fail-safe direction.
func TestReplayIndexWriteDoesNotMoveTheAuthorityRevision(t *testing.T) {
	f := newFx(t)
	r := newRecorder(f.wall())
	g := f.grant(f.main)
	until := f.wall() + model.UnixNano(24*time.Hour)
	_, before := f.revisions()
	if before == 0 {
		t.Fatal("fixture invalid: the control state has no authority transition yet")
	}
	cp := r.cp()
	rev0, _ := f.revisions()
	if err := f.svc.Record(f.ctx, g, f.main.project, cp, until); err != nil {
		t.Fatal(err)
	}
	rev1, after := f.revisions()
	if rev1 != rev0+1 {
		t.Fatalf("fixture invalid: recording a new checkpoint spent revision %d -> %d, want one write", rev0, rev1)
	}
	if after != before {
		t.Fatalf("a replay index write moved AuthorityRevision %d -> %d", before, after)
	}

	plain, err := New(f.scan, f.auth, plainStore{f.store})
	if err != nil {
		t.Fatal(err)
	}
	plain.now = f.now
	cp2 := r.cp()
	if err = plain.Record(f.ctx, g, f.main.project, cp2, until); err != nil {
		t.Fatal(err)
	}
	rev2, moved := f.revisions()
	if rev2 != rev1+1 || moved != rev2 {
		t.Fatalf("a store without UpdateReplayIndex did not fall back to a bumping Update: revision %d -> %d, authority %d", rev1, rev2, moved)
	}
}
