// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// D84: the job and issue books are records of their own and the writers of them commit the records they
// change, without decoding or encoding the control state under the lock every writer shares. What one job
// update costs must therefore not follow the size of the state.

// bloat makes the control state larger by n organizations: members the books do not have, which every
// whole-state transition decodes and encodes.
func bloat(f *fenceFx, n int) {
	for i := range n {
		f.admin("create_org", model.NewID(), auth.AdminPayload{Name: fmt.Sprintf("bloat-%04d", i), Reason: "fixture"})
	}
}

// lockHold runs fn and answers how long the lock every control writer shares was held per time it was taken.
func lockHold(f *fenceFx, fn func()) (perHold time.Duration, holds uint64) {
	h0, d0 := f.store.UpdateLockStatsForTest()
	fn()
	h1, d1 := f.store.UpdateLockStatsForTest()
	if h1 == h0 {
		return 0, 0
	}
	return (d1 - d0) / time.Duration(h1-h0), h1 - h0
}

func TestJobUpdateCostDoesNotGrowWithTheState(t *testing.T) {
	f := newJobFxOn(t, newFenceFxPatch(t))
	job := f.job(1)
	version, tag := uint64(0), byte(0)
	step := func(n int) {
		for range n {
			f.must(tag+1, f.upd(job, version, tag+1))
			version++
			tag++
		}
	}
	step(5)
	const updates = 40
	small, _ := lockHold(f.fenceFx, func() { step(updates) })
	blob := len(f.store.BlobMemberForTest("Orgs"))
	bloat(f.fenceFx, 1200)
	if grown := len(f.store.BlobMemberForTest("Orgs")); grown < blob+300_000 {
		t.Fatalf("the state did not grow enough to tell the cost apart: Orgs %d -> %d bytes", blob, grown)
	}
	commits := f.store.SparseCommitsForTest()
	large, holds := lockHold(f.fenceFx, func() { step(updates) })
	if got := f.store.SparseCommitsForTest() - commits; got != updates || holds != updates {
		t.Errorf("%d of %d job updates were committed as records, the lock was taken %d times", got, updates, holds)
	}
	t.Logf("a job update holds the lock %v, %v after the state grew by %d bytes", small, large, len(f.store.BlobMemberForTest("Orgs"))-blob)
	if large > 2*small+2*time.Millisecond {
		t.Errorf("a job update held the lock %v on a small state and %v on a larger one: its cost follows the size of the state", small, large)
	}
	snap, ok := f.book(job)
	if !ok || uint64(snap.Version) != version {
		t.Fatalf("the job is at version %d (found %v), want %d", snap.Version, ok, version)
	}
}

// A job book lives in its bucket: the blob holds none, a reader finds the record the update wrote, and the
// record is the one the logical state carries.
func TestJobBookIsARecordOfItsOwn(t *testing.T) {
	f := newJobFxOn(t, newFenceFxPatch(t))
	job := f.job(1)
	f.must(1, f.upd(job, 0, 1))
	f.must(2, f.upd(job, 1, 2))
	key := f.org.String() + ":" + f.project.String() + ":" + job.String()
	record := f.store.LedgerRecordForTest("job_books", key)
	if record == nil {
		t.Fatal("the job book is not a record of job_books")
	}
	if got := f.store.BlobMemberForTest("JobBooks"); got != "null" {
		t.Errorf("the blob holds the job books: %.100s", got)
	}
	if got, want := string(f.books()[key]), string(record); got != want {
		t.Errorf("the logical state carries\n%s\nthe bucket holds\n%s", got, want)
	}
	if f.store.LedgerCountForTest("job_books") != 1 {
		t.Errorf("the bucket holds %d records, want 1", f.store.LedgerCountForTest("job_books"))
	}
	if f.store.SparseCommitsForTest() < 2 {
		t.Errorf("%d of 2 updates were committed as records", f.store.SparseCommitsForTest())
	}
}

func newIssFxOn(t *testing.T, fence *fenceFx) *issFx {
	t.Helper()
	f := &issFx{fenceFx: fence, group: model.ID{0xe1}, rel: model.ID{0xc0, 1}}
	if err := f.store.BindReleases(); err != nil {
		t.Fatal(err)
	}
	f.admin("grant", f.org, auth.AdminPayload{UserID: f.user, ProjectID: f.project, Enabled: true, Permissions: []string{string(auth.Read), string(issuesWrite)}, Reason: "fixture"})
	var err error
	if f.writer, err = f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{f.project}, issuesWrite); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestIssueCommitDecodesNothingUnderTheLock(t *testing.T) {
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
	step(3)
	const commits = 10
	small, _ := lockHold(f.fenceFx, func() { step(commits) })
	blob := len(f.store.BlobMemberForTest("Orgs"))
	bloat(f.fenceFx, 1200)
	if grown := len(f.store.BlobMemberForTest("Orgs")); grown < blob+300_000 {
		t.Fatalf("the state did not grow enough to tell the cost apart: Orgs %d -> %d bytes", blob, grown)
	}
	sparse, decodes := f.store.SparseCommitsForTest(), f.store.SharedDecodesForTest()
	large, _ := lockHold(f.fenceFx, func() { step(commits) })
	if got := f.store.SparseCommitsForTest() - sparse; got != commits {
		t.Errorf("%d of %d issue commits were committed as records", got, commits)
	}
	t.Logf("an issue commit holds the lock %v, %v after the state grew; %d whole-state decodes for %d commits, %d of them under the lock", small, large, f.store.SharedDecodesForTest()-decodes, commits, f.store.SparseLockedDecodesForTest())
	if got := f.store.SparseLockedDecodesForTest(); got != 0 {
		t.Errorf("%d issue commits decoded the whole state while they held the lock every control writer shares", got)
	}
	key := f.org.String() + ":" + f.project.String()
	if f.store.LedgerRecordForTest("issue_books", key) == nil {
		t.Error("the issue book is not a record of issue_books")
	}
	if got := f.store.BlobMemberForTest("IssueBooks"); got != "null" {
		t.Errorf("the blob holds the issue books: %.100s", got)
	}
	var book control.IssueBook
	if err := json.Unmarshal(f.store.LedgerRecordForTest("issue_books", key), &book); err != nil || uint64(book.Revision) != revision {
		t.Errorf("the issue book is at revision %d (%v), want %d", book.Revision, err, revision)
	}
	if s := f.snap(); len(s.Issues) != int(next) {
		t.Errorf("the project holds %d issues, want %d", len(s.Issues), next)
	}
}
