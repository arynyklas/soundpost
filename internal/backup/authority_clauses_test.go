// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"soundpost/internal/model"
)

// checkAuthorityCoversControl is the only thing that stops a backup from being
// bound to a rolled-back or forked authority. Every clause is refused on its own.
func TestAuthorityCoversControlRefusesEachClause(t *testing.T) {
	installation := model.NewID()
	head := model.Hash{1}
	cur := CurrentDeletion{Installation: installation, Root: model.Hash{9}, Head: AuthorityHead{Sequence: 1, Generation: 3}, Chain: []model.Hash{head}}
	state := func(phase string, receipt *model.DeletionAuthority) model.ControlState {
		op := model.DeletionOperation{Phase: phase, Authority: receipt}
		op.Predicate.Operation = model.NewID()
		return model.ControlState{Installation: installation, Deletions: map[string]model.DeletionOperation{op.Predicate.Operation.String(): op}}
	}
	receipt := func(h model.Hash, generation uint64) *model.DeletionAuthority {
		return &model.DeletionAuthority{Head: h, Generation: model.Uint64(generation), At: 1}
	}
	foreign := cur
	foreign.Installation = model.NewID()
	for _, tc := range []struct {
		name string
		st   model.ControlState
		cur  CurrentDeletion
		want model.Code
	}{
		{"a completed deletion whose receipt is in the chain", state(model.DeletePhaseComplete, receipt(head, 3)), cur, ""},
		{"a completed deletion without an authority receipt", state(model.DeletePhaseComplete, nil), cur, ""},
		{"a deletion still fencing names no receipt to check", state(model.DeletePhaseFencing, receipt(model.Hash{2}, 9)), cur, ""},
		{"an authority of another installation", state(model.DeletePhaseComplete, receipt(head, 3)), foreign, model.Conflict},
		{"a receipt that names a head the journal does not contain", state(model.DeletePhaseComplete, receipt(model.Hash{2}, 3)), cur, model.Corrupt},
		{"a receipt from a later generation than the journal's head", state(model.DeletePhaseComplete, receipt(head, 4)), cur, model.Corrupt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := faultCode(checkAuthorityCoversControl(tc.st, tc.cur)); got != tc.want {
				t.Fatalf("checkAuthorityCoversControl = %q, want %q", got, tc.want)
			}
		})
	}
}

// A record may never move the generation backwards, even when it repeats the
// same tombstones. CheckpointDeletion refuses to write one; a writer that holds
// the signing key can still try, and the journal must then be unreadable.
func TestAuthorityRefusesARecordWhoseGenerationGoesBackwards(t *testing.T) {
	f := newAuthFixture(t)
	f.initialize()
	ctx := context.Background()
	t1 := tombstone(model.NewID(), model.NewID(), 10, 20)
	if _, err := f.a.CheckpointDeletion(ctx, generation(f.installation, 5, t1)); err != nil {
		t.Fatal(err)
	}
	cur, err := f.a.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.a.advance(ctx, cur, generation(f.installation, 4, t1)); err == nil {
		t.Fatal("a record whose generation went backwards was accepted as the new head")
	}
	if _, err = f.a.Current(ctx); err == nil {
		t.Fatal("a journal whose generation goes backwards is readable")
	}
}

// The signed record already says which sequence it is; the file name is a second,
// independent statement of it. A genuine, correctly chained record stored under a
// name that is not its sequence (moved, or listed out of place) is not the head.
func TestAuthorityRefusesAGenuineRecordUnderTheWrongName(t *testing.T) {
	f := newAuthFixture(t)
	f.initialize()
	ctx := context.Background()
	org, project := model.NewID(), model.NewID()
	var tombs []model.DeletePredicate
	for i := range 3 {
		tombs = append(tombs, tombstone(org, project, int64(10*i), int64(10*i+5)))
		if _, err := f.a.CheckpointDeletion(ctx, generation(f.installation, uint64(i+1), tombs...)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.a.Current(ctx); err != nil {
		t.Fatal(err)
	}
	heads := filepath.Join(f.dir, "authority", "head")
	if err := os.Rename(filepath.Join(heads, filepath.Base(headName(3))), filepath.Join(heads, filepath.Base(headName(99)))); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.Current(ctx); err == nil {
		t.Fatal("a valid record stored under a name that is not its sequence was read as the head")
	}
}
