// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// TestJobUpdatesDoNotInvalidateTheSharedDecode is the red test of the next hotspot of the live 2,000
// records/s run (L2w20Admission7/r5): the job worker commits ~35 job updates a second, and each one
// rewrote the control blob, which marked the shared decode of the state stale, so the next
// admission, the next ActiveDeletions read and the next job read each decoded the whole blob again
// (32 % of the server's CPU). A job update changes the JobBooks member and nothing a core reader
// reads: the decode that was held stays the decode, and the job read, which does want the new
// book, takes it from the blob itself.
func TestJobUpdatesDoNotInvalidateTheSharedDecode(t *testing.T) {
	f := newJobFxOn(t, newFenceFxPatch(t))
	job := f.job(1)
	f.must(1, f.upd(job, 0, 1))
	if _, err := reserveSeries(f.fenceFx, "prime"); err != nil {
		t.Fatal(err)
	}
	read := func() {
		t.Helper()
		if err := f.store.ViewShared(f.ctx, func(ro model.ReadOnlyControl) error { _ = ro.Revision(); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	read()
	decodes := f.store.SharedDecodesForTest()
	for i := uint64(1); i <= 20; i++ {
		f.must(byte(i+1), f.upd(job, i, byte(i+1)))
		read()
		snap, ok := f.book(job)
		if !ok || uint64(snap.Version) != i+1 {
			t.Fatalf("after update %d the job book is at version %d (found %v), want %d", i, snap.Version, ok, i+1)
		}
	}
	if got := f.store.SharedDecodesForTest() - decodes; got != 0 {
		t.Errorf("20 job updates, each followed by a shared read and a job read, made %d whole-state decodes, want 0", got)
	}
}

// A write that changes anything else than the job books still drops the decode: a reader after it
// sees the new state.
func TestAWriteOtherThanAJobUpdateStillInvalidatesTheSharedDecode(t *testing.T) {
	f := newJobFxOn(t, newFenceFxPatch(t))
	read := func() {
		t.Helper()
		if err := f.store.ViewShared(f.ctx, func(ro model.ReadOnlyControl) error { _ = ro.Revision(); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	read()
	decodes := f.store.SharedDecodesForTest()
	for i := range 3 {
		f.admin("create_org", model.NewID(), auth.AdminPayload{Name: fmt.Sprintf("o%d", i), Reason: "fixture"})
		read()
	}
	if got := f.store.SharedDecodesForTest() - decodes; got < 3 {
		t.Errorf("3 organizations created, each followed by a shared read, made %d decodes, want one each", got)
	}
}
