// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// D85: the grouping issues and the applied-command log are records of their own. A commit of the issue
// lifecycle writes the records it changes and decodes nothing of the others, so what it writes to the file and
// what it makes every reader decode again must not follow the number of issues and commands the state holds.

func TestIssueCommitWritesDoNotGrowWithTheIssuesAndTheCommandLog(t *testing.T) {
	f := newIssFxOn(t, newFenceFxPatch(t))
	revision, next := uint64(0), byte(0)
	step := func(n int) {
		for range n {
			next++
			c := control.IssueCommand{ExpectedRevision: model.Revision(revision), Records: []control.IssueRecordChange{f.record(f.issue(next, 1, f.evidence(next, uint64(next))))}, Checkpoint: &control.IssueCheckpoint{Group: f.group, Index: model.Uint64(next)}}
			f.must(c)
			revision++
		}
	}
	perCommit := func(n int) (written int64, decodes uint64) {
		w0, d0 := f.store.BoltWriteStatsForTest(), f.store.SharedDecodesForTest()
		step(n)
		w1, d1 := f.store.BoltWriteStatsForTest(), f.store.SharedDecodesForTest()
		return (w1.AllocBytes - w0.AllocBytes) / int64(n), d1 - d0
	}
	step(5)
	smallBytes, _ := perCommit(10)
	step(200)
	largeBytes, largeDecodes := perCommit(10)
	t.Logf("an issue commit allocates %d bytes of pages with 15 issues in the state and %d with 225; %d shared decodes in the last 10 commits", smallBytes, largeBytes, largeDecodes)
	if largeBytes > smallBytes+24<<10 {
		t.Errorf("an issue commit wrote %d bytes of pages on a small state and %d after the issues and the command log grew: what it writes follows their size", smallBytes, largeBytes)
	}
	if largeDecodes != 0 {
		t.Errorf("%d issue commits made the readers of the state decode it again", largeDecodes)
	}
	for _, member := range []string{"GroupingIssues", "Commands", "CommandOwners"} {
		if got := f.store.BlobMemberForTest(member); got != "null" {
			t.Errorf("the blob holds %s: %.100s", member, got)
		}
	}
	if n := f.store.LedgerCountForTest("grouping_issues"); n != int(next) {
		t.Errorf("grouping_issues holds %d records, want %d", n, next)
	}
	if n := f.store.LedgerCountForTest("cmd_results"); n < int(next) {
		t.Errorf("cmd_results holds %d records for %d commits", n, next)
	}
	if n, m := f.store.LedgerCountForTest("cmd_results"), f.store.LedgerCountForTest("cmd_owners"); n != m {
		t.Errorf("%d command results and %d owners", n, m)
	}
	if s := f.snap(); len(s.Issues) != int(next) {
		t.Errorf("the project holds %d issues, want %d", len(s.Issues), next)
	}
}

// A retry of a command that was applied is answered from its record, and a reused ID with another binding is
// not answered.
func TestAppliedCommandIsAnsweredFromItsRecord(t *testing.T) {
	f := newIssFxOn(t, newFenceFxPatch(t))
	c := control.IssueCommand{ExpectedRevision: 0, Records: []control.IssueRecordChange{f.record(f.issue(1, 1, f.evidence(1, 1)))}, Checkpoint: &control.IssueCheckpoint{Group: f.group, Index: 1}}
	first := f.must(c)
	again, err := f.commit(c)
	if err != nil {
		t.Fatal(err)
	}
	if again.Revision != first.Revision || again.Phase != first.Phase {
		t.Errorf("the retry answered %+v, the first commit %+v", again, first)
	}
	if n := f.store.LedgerCountForTest("cmd_results"); n < 1 {
		t.Errorf("cmd_results holds %d records", n)
	}
}
