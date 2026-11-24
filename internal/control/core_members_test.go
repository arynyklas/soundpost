// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// The background workers read the control state all the time (the rule scheduler reads one rule book per
// rule per tick, the outbox its records, the retention worker the deletion generations) while rule
// commits and outbox writes change the blob under them. A read that decodes the whole state again after every
// such commit costs O(size of the state) each, and the storage read path asks once per page chunk of
// every query. These tests count what the reads decode.

// newRuleFxPatch is newRuleFx on a group that has opened the state patch gate, whose books are in the ledger
// (layout 2: the revision lives outside the blob, and a commit rewrites only the members it changed).
func newRuleFxPatch(t *testing.T) *ruleFx {
	t.Helper()
	f := &ruleFx{fenceFx: newFenceFxPatch(t), rule: model.NewID()}
	if err := f.store.BindRuleEvaluation(); err != nil {
		t.Fatal(err)
	}
	return f
}

// decodeCounts is what the control store has decoded so far: whole states and members of the shared
// decode, and whole blobs by any reader.
type decodeCounts struct{ whole, members, blobs uint64 }

func (f *fenceFx) decodeCounts() decodeCounts {
	return decodeCounts{f.store.SharedDecodesForTest(), f.store.SharedMemberDecodesForTest(), f.store.BlobDecodesForTest()}
}

func (c decodeCounts) since(then decodeCounts) decodeCounts {
	return decodeCounts{c.whole - then.whole, c.members - then.members, c.blobs - then.blobs}
}

// Reads of one rule book, after each of a run of rule commits, share what the first of them decodes: the
// book is in one member of the blob, and that member is the only thing a commit of the rule changes for it.
func TestRuleBookReadsDoNotDecodeTheState(t *testing.T) {
	f := newRuleFxPatch(t)
	lease := f.lease()
	scope := f.adminScope()
	commit := func(i int) {
		t.Helper()
		if _, err := f.eval(lease, f.evaluation(1, uint64(60*i), uint64(i-1), control.RuleModeLive, fmt.Sprintf(`{"n":%d}`, i), recordingIntent(byte(i)))); err != nil {
			t.Fatalf("evaluation %d: %v", i, err)
		}
	}
	read := func(revision uint64) {
		t.Helper()
		book, found, err := f.store.RuleBook(f.ctx, scope, f.project, f.rule)
		if err != nil || !found {
			t.Fatalf("rule book: found=%v err=%v", found, err)
		}
		if got := uint64(book.Versions[0].StateRevision); got != revision {
			t.Fatalf("the read after commit %d sees the rule at revision %d", revision, got)
		}
	}
	commit(1)
	read(1)
	for i := 2; i <= 8; i++ {
		commit(i)
		before := f.decodeCounts()
		for range 6 {
			read(uint64(i))
		}
		got := f.decodeCounts().since(before)
		if got.blobs != 0 {
			t.Errorf("commit %d: 6 reads of one rule book decoded the whole blob %d times, want never", i, got.blobs)
		}
		if got.whole != 0 {
			t.Errorf("commit %d: 6 reads of one rule book made %d whole-state decodes, want none", i, got.whole)
		}
		if got.members > 1 {
			t.Errorf("commit %d: 6 reads of one rule book decoded %d members, want the rule books at most", i, got.members)
		}
	}
}

// A query reads the deletions of its organization once per page chunk, and what a rule commit changes
// (the rule books, the outbox) is no part of what that read needs: it decodes nothing after the commit.
func TestQueryReadsDoNotDecodeWhatARuleCommitChanged(t *testing.T) {
	f := newRuleFxPatch(t)
	lease := f.lease()
	read := func() {
		t.Helper()
		if _, err := f.store.ActiveDeletions(f.ctx, f.org, []model.ID{f.project}); err != nil {
			t.Fatal(err)
		}
	}
	read()
	for i := 1; i <= 6; i++ {
		if _, err := f.eval(lease, f.evaluation(1, uint64(60*i), uint64(i-1), control.RuleModeLive, fmt.Sprintf(`{"n":%d}`, i), recordingIntent(byte(i)), conditionIntent(byte(100+i), true))); err != nil {
			t.Fatalf("evaluation %d: %v", i, err)
		}
		before := f.decodeCounts()
		for range 4 {
			read()
		}
		if got := f.decodeCounts().since(before); got.whole != 0 || got.members != 0 || got.blobs != 0 {
			t.Errorf("rule commit %d: 4 queries' reads decoded %d whole states, %d members, %d blobs, want none", i, got.whole, got.members, got.blobs)
		}
	}
}

// The control store's own readers of one book or one member (the policy states of the outbox, the rule
// catalogue, the declared evidence gaps, the delete generation, the readiness probe) read what they need of the
// shared decode: none of them decodes the whole blob for a State of its own.
func TestControlReadersOfOneMemberDoNotDecodeTheBlob(t *testing.T) {
	f := newRuleFxPatch(t)
	scope := f.adminScope()
	policy := model.NewID()
	reads := map[string]func() error{
		"PolicyRecord": func() error {
			_, _, err := f.store.PolicyRecord(f.ctx, scope, f.project, policy, "subject")
			return err
		},
		"RuleDefinitions": func() error { _, err := f.store.RuleDefinitions(f.ctx, scope, f.project); return err },
		"RuleDefinition": func() error {
			_, _, err := f.store.RuleDefinition(f.ctx, scope, f.project, f.rule)
			return err
		},
		"EvidenceGaps":     func() error { _, err := f.store.EvidenceGaps(f.ctx, f.org, f.project); return err },
		"DeleteGeneration": func() error { _, err := f.store.DeleteGeneration(f.ctx, f.org); return err },
		"ReadinessFacts":   func() error { _, _, err := f.store.ReadinessFacts(f.ctx); return err },
		"Revision":         func() error { _, err := f.store.Revision(f.ctx); return err },
	}
	for name, read := range reads {
		if err := read(); err != nil { // what the first read decodes is shared by the rest
			t.Fatalf("%s: %v", name, err)
		}
		before := f.decodeCounts()
		for range 5 {
			if err := read(); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		if got := f.decodeCounts().since(before); got.blobs != 0 || got.whole != 0 {
			t.Errorf("%s: 5 reads decoded the whole blob %d times and the whole shared state %d times, want never", name, got.blobs, got.whole)
		}
	}
}

// The revision a caller names in a command (ExpectedRevision) is read without decoding the state, and is the
// revision a View of the same moment sees, whatever the commit that moved it was.
func TestRevisionIsTheRevisionOfView(t *testing.T) {
	f := newRuleFxPatch(t)
	lease := f.lease()
	check := func(when string) {
		t.Helper()
		got, err := f.store.Revision(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		var want model.Revision
		if err = f.store.View(f.ctx, func(st control.State) error { want = st.Revision; return nil }); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%s: Revision says %d, View says %d", when, got, want)
		}
		if via, err := control.RevisionOf(f.ctx, f.store); err != nil || via != want {
			t.Fatalf("%s: RevisionOf says %d (%v), View says %d", when, via, err, want)
		}
	}
	check("at the start")
	for i := 1; i <= 3; i++ {
		if _, err := f.eval(lease, f.evaluation(1, uint64(60*i), uint64(i-1), control.RuleModeLive, fmt.Sprintf(`{"n":%d}`, i))); err != nil {
			t.Fatal(err)
		}
		check(fmt.Sprintf("after rule commit %d", i))
	}
	before := f.decodeCounts()
	for range 5 {
		if _, err := f.store.Revision(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.decodeCounts().since(before); got != (decodeCounts{}) {
		t.Fatalf("5 reads of the revision decoded %+v, want nothing", got)
	}
}
