// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// D108, the red tests of the 5,000 records/s control lane: the records the sparse items of a round write (a job's record with
// the last 1,024 commands it applied, a grouping issue with its whole evidence ledger) were proposed whole, 3 KB per round in
// minute 1 and 165 KB in minute 20 of the gate run, and a round that carried a settlement command waited behind them (79 ms, then
// 121 ms). What a job update or an issue commit puts in a control command has to be a function of what the update changed, not of
// the record it changed. SOUNDPOST_TEST_COMPACT_OFF leaves the compact gate closed, the form measured red.

const recordBytesBudget = 4000 // bytes of control commands per update: the job state (about 300), the command's own records (about 700), the delta, a step

// patchBytesOf runs fn and answers the bytes of the state patches proposed meanwhile.
func patchBytesOf(f *fenceFx, fn func()) uint64 {
	_, before := f.store.StatePatchStatsForTest()
	fn()
	_, after := f.store.StatePatchStatsForTest()
	return after - before
}

func TestJobUpdatePatchBytesDoNotGrowWithTheRecord(t *testing.T) {
	f := newJobFxOn(t, newFenceFxCompact(t))
	job := f.job(1)
	version, tag := uint64(0), 0
	step := func(n int) {
		for range n {
			tag++
			f.must(byte(tag), f.upd(job, version, byte(tag)))
			version++
		}
	}
	step(2)
	const measured = 8
	early := patchBytesOf(f.fenceFx, func() { step(measured) }) / measured
	step(230) // the record grows by one applied command per update (the last 1,024 are kept): some 60 KB here
	late := patchBytesOf(f.fenceFx, func() { step(measured) }) / measured
	t.Logf("bytes per job update: %d on a young record, %d after %d updates (record %d bytes)", early, late, version, len(f.store.LedgerRecordForTest("job_books", f.org.String()+":"+f.project.String()+":"+job.String())))
	if late > recordBytesBudget {
		t.Errorf("a job update costs %d bytes of control commands on a record of %d updates, budget %d", late, version, recordBytesBudget)
	}
	if late > early*5/4+400 {
		t.Errorf("the bytes of a job update grew from %d to %d with the record", early, late)
	}
	if snap, ok := f.book(job); !ok || uint64(snap.Version) != version {
		t.Fatalf("the job is at version %d (found %v), want %d", snap.Version, ok, version)
	}
}

func TestIssueCommitPatchBytesDoNotGrowWithTheRecord(t *testing.T) {
	f := newIssFxOn(t, newFenceFxCompact(t))
	revision, occurrences := uint64(0), uint64(0)
	var evidence []model.GroupingEvidence
	step := func(n int) {
		for range n {
			occurrences++
			evidence = append(evidence, f.evidence(1, occurrences))
			issue := f.issue(1, occurrences, append([]model.GroupingEvidence(nil), evidence...)...)
			f.must(control.IssueCommand{ExpectedRevision: model.Revision(revision), Records: []control.IssueRecordChange{f.record(issue)}, Checkpoint: &control.IssueCheckpoint{Group: f.group, Index: model.Uint64(occurrences)}})
			revision++
		}
	}
	step(2)
	const measured = 8
	early := patchBytesOf(f.fenceFx, func() { step(measured) }) / measured
	step(150) // the evidence ledger of the issue: some 70 KB
	late := patchBytesOf(f.fenceFx, func() { step(measured) }) / measured
	t.Logf("bytes per issue commit: %d on a young issue, %d after %d occurrences", early, late, occurrences)
	if late > recordBytesBudget {
		t.Errorf("an issue commit costs %d bytes of control commands on an issue of %d occurrences, budget %d", late, occurrences, recordBytesBudget)
	}
	if late > early*5/4+400 {
		t.Errorf("the bytes of an issue commit grew from %d to %d with the record", early, late)
	}
	if s := f.snap(); len(s.Issues) != 1 || len(s.Issues[0].Occurrences) != int(occurrences) {
		t.Fatalf("the issue holds %d occurrences, want %d", len(s.Issues[0].Occurrences), occurrences)
	}
}
