// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// ViewShared decodes the committed state once per revision for every reader (decoding it per read
// made a pass of the background workers cost O(projects squared)). These tests pin what that
// sharing must not cost: a reader never sees a mix of two revisions, nothing a reader does to what
// it was given reaches the next reader, and the decode is not kept past a commit.

func TestViewSharedDecodesOncePerCommittedRevision(t *testing.T) {
	f := newFenceFx(t)
	read := func() uint64 {
		t.Helper()
		var rev model.Revision
		if err := f.store.ViewShared(f.ctx, func(ro model.ReadOnlyControl) error { rev = ro.Revision(); return nil }); err != nil {
			t.Fatal(err)
		}
		return uint64(rev)
	}
	before := f.store.SharedDecodesForTest()
	first := read()
	for range 50 {
		if got := read(); got != first {
			t.Fatalf("revision moved from %d to %d without a commit", first, got)
		}
	}
	if got := f.store.SharedDecodesForTest() - before; got != 1 {
		t.Fatalf("51 shared reads of one revision decoded the state %d times, want 1", got)
	}
	// A read that mutates gets a decode of its own and leaves the shared one alone.
	if err := f.store.View(f.ctx, func(st control.State) error { st.Users = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	read()
	if got := f.store.SharedDecodesForTest() - before; got != 1 {
		t.Fatalf("View changed the shared decode count to %d", got)
	}

	if err := f.store.Update(f.ctx, func(st *control.State) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if f.store.SharedDecodeHeldForTest() {
		t.Fatal("the decode of the revision that was just replaced is still held after the commit")
	}
	if second := read(); second <= first {
		t.Fatalf("a read after a commit sees revision %d, want more than %d", second, first)
	}
	for range 10 {
		read()
	}
	if got := f.store.SharedDecodesForTest() - before; got != 2 {
		t.Fatalf("after one commit the state was decoded %d times, want 2", got)
	}
}

// A reader on an older snapshot must not replace a newer decode with its own.
func TestViewSharedKeepsTheNewestDecode(t *testing.T) {
	f := newFenceFx(t)
	// Transaction ids far above anything the fixture's commits reached.
	const base = 1_000_000
	newer, older := &control.State{Revision: 9}, &control.State{Revision: 8}
	if !f.store.PublishSharedDecodeForTest(base, newer) {
		t.Fatal("the first decode was not kept")
	}
	if f.store.PublishSharedDecodeForTest(base-1, older) {
		t.Fatal("a decode of an older transaction replaced a newer one")
	}
	if !f.store.PublishSharedDecodeForTest(base+1, &control.State{Revision: 10}) {
		t.Fatal("a decode of a newer transaction was not kept")
	}
}

// Writers commit while readers run: a reader sees the state of one commit. Commit i adds user i
// and nothing else, so in a state of revision base+n exactly the users 0..n-1 exist; a reader that
// took the revision from one decode and the users from another would break that. Under -race this
// also fails if a shared decode were edited in place.
func TestViewSharedReaderSeesOneWholeRevisionBesideWriters(t *testing.T) {
	f := newFenceFx(t)
	var base model.Revision
	if err := f.store.ViewShared(f.ctx, func(ro model.ReadOnlyControl) error { base = ro.Revision(); return nil }); err != nil {
		t.Fatal(err)
	}
	const commits = 25
	userOf := func(i int) model.ID { return model.ID{0xd0, byte(i)} }
	var stop atomic.Bool
	var wg sync.WaitGroup
	var failure atomic.Value
	fail := func(format string, args ...any) { failure.CompareAndSwap(nil, fmt.Sprintf(format, args...)) }
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var last model.Revision
			for !stop.Load() {
				err := f.store.ViewShared(f.ctx, func(ro model.ReadOnlyControl) error {
					rev := ro.Revision()
					n := int(rev - base)
					for i := range commits {
						exists, _ := ro.UserState(userOf(i).String())
						if exists != (i < n) {
							fail("revision %d: user %d exists=%v, want %v", rev, i, exists, i < n)
							break
						}
					}
					if rev < last {
						fail("a reader saw revision %d after %d", rev, last)
					}
					last = rev
					return nil
				})
				if err != nil {
					fail("ViewShared: %v", err)
					return
				}
			}
		}()
	}
	for i := range commits {
		u := userOf(i)
		if err := f.store.Update(f.ctx, func(st *control.State) error {
			st.Users[u.String()] = model.ControlUser{ID: u, Email: fmt.Sprintf("u%d@example.test", i)}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
	if msg := failure.Load(); msg != nil {
		t.Fatal(msg)
	}
}

// What a reader does to the predicates ActiveDeletions returned is not visible to the next read
// of the same revision, which is the same decode.
func TestViewSharedResultsAreCopiesOfTheCommittedState(t *testing.T) {
	f := newFenceFx(t)
	if _, _, err := f.del(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}}); err != nil {
		t.Fatal(err)
	}
	want, err := f.store.ActiveDeletions(f.ctx, f.org, nil)
	if err != nil || len(want) != 1 || len(want[0].Projects) != 1 {
		t.Fatalf("fixture: ActiveDeletions = %+v, %v; want the one project deletion", want, err)
	}
	want[0] = clonePredicate(want[0])
	for round := range 3 {
		got, err := f.store.ActiveDeletions(f.ctx, f.org, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("round %d: ActiveDeletions = %+v, want %+v", round, got, want)
		}
		got[0].Projects[0] = model.ID{0xff}
		got[0].Org = model.ID{0xff}
		got[0].Signals = append(got[0].Signals[:0], model.Log)
	}
}

func clonePredicate(p model.DeletePredicate) model.DeletePredicate {
	p.Projects = append([]model.ID(nil), p.Projects...)
	p.Signals = append([]model.Kind(nil), p.Signals...)
	p.Entities = append([]model.ID(nil), p.Entities...)
	return p
}

// The reads the workers make every pass share one decode: any number of revalidations and system
// authorizations of an unchanged state decode it once, and a commit makes the next one decode again.
func TestRunnerReadsShareOneDecodePerRevision(t *testing.T) {
	f := newFenceFx(t)
	ctx := context.Background()
	runner, err := f.svc.AuthorizeSystem(ctx, f.org, []model.ID{f.project}, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	before := f.store.SharedDecodesForTest()
	for range 20 {
		if err := f.svc.Revalidate(ctx, runner); err != nil {
			t.Fatalf("Revalidate: %v", err)
		}
		if _, err := f.svc.AuthorizeSystem(ctx, f.org, []model.ID{f.project}, auth.Read); err != nil {
			t.Fatalf("AuthorizeSystem: %v", err)
		}
		if _, err := f.store.ActiveDeletions(ctx, f.org, []model.ID{f.project}); err != nil {
			t.Fatalf("ActiveDeletions: %v", err)
		}
	}
	if got := f.store.SharedDecodesForTest() - before; got > 1 {
		t.Fatalf("60 reads of one revision decoded the state %d times, want at most 1", got)
	}
	// A commit that retires the project must be seen by the next read: no stale decode.
	if err := f.store.Update(f.ctx, func(st *control.State) error {
		if st.RetiredProjects == nil {
			st.RetiredProjects = map[string]model.ID{}
		}
		st.RetiredProjects[f.org.String()+":"+f.project.String()] = model.ID{0xaa}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Revalidate(ctx, runner); err == nil {
		t.Fatal("a scope over a project that was just retired was still valid: the shared decode was stale")
	}
}
