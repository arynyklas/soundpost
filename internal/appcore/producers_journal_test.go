// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"errors"
	"math"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

type journalClock struct{ v atomic.Int64 }

func (c *journalClock) Now() model.UnixNano   { return model.UnixNano(c.v.Load()) }
func (c *journalClock) set(at model.UnixNano) { c.v.Store(int64(at)) }

// journalRig is an issue rig whose error batches all land in one data group,
// with the producer stalled (nothing processes them) and a journal-expiry
// producer on a clock the test moves.
type journalRig struct {
	*issueRig
	clock *journalClock
}

func newJournalRig(t *testing.T) *journalRig {
	t.Helper()
	return &journalRig{issueRig: newIssueRig(t), clock: &journalClock{}}
}

// stalled ingests one error batch per ID, in one data group, and returns the
// expiring entries of the project (one per batch) in journal order.
func (r *journalRig) ingestAll(ids []model.ID) []storage.ExpiringEntry {
	r.t.Helper()
	for i, id := range ids {
		r.ingestBatch(r.record("TypeError", model.UnixNano(5+i), false, true, id))
	}
	return r.entries()
}

func (r *journalRig) entries() []storage.ExpiringEntry {
	r.t.Helper()
	all, err := r.app.Storage.ExpiringErrorEvidence(r.ctx, model.UnixNano(math.MaxInt64))
	if err != nil {
		r.t.Fatal(err)
	}
	var out []storage.ExpiringEntry
	for _, e := range all {
		if e.Org == r.org && e.Project == r.project {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Cursor.Index < out[j].Cursor.Index })
	return out
}

func (r *journalRig) expiry(lead time.Duration) *appcore.Workers {
	r.t.Helper()
	w, err := r.app.NewWorkers(r.config(func(c *appcore.WorkerConfig) {
		c.Producers = []appcore.Producer{r.app.JournalExpiryProducerWith(appcore.JournalExpiryConfig{Lead: lead, ReserveBytes: 1, Clock: r.clock})}
	}))
	if err != nil {
		r.t.Fatal(err)
	}
	return w
}

func (r *journalRig) health() (complete bool, gaps int) {
	r.t.Helper()
	svc, err := r.app.NewIssueActions(r.workerNode.clock)
	if err != nil {
		r.t.Fatal(err)
	}
	h, err := svc.Health(r.ctx, r.system(auth.IssuesWrite), r.project)
	if err != nil {
		r.t.Fatal(err)
	}
	return h.Complete, len(h.Gaps)
}

// Unprocessed error evidence about to expire from the journal is declared as a
// gap BEFORE it can be lost: the checkpoint advances over exactly that interval
// in the same control transaction, the project's health reads incomplete, and the
// evidence the producer could still process is not touched.
func TestJournalExpiryDeclaresAGapBeforeUnprocessedEvidenceExpires(t *testing.T) {
	r := newJournalRig(t)
	entries := r.ingestAll(r.idsInOneSlot(3))
	if len(entries) != 3 {
		t.Fatalf("setup: %d expiring entries", len(entries))
	}
	group := entries[0].Cursor.Group
	deadline := entries[2].Deadline
	w := r.expiry(24 * time.Hour)

	// More than the reach before the deadline: nothing to declare, nothing changes.
	r.clock.set(entries[0].Deadline - model.UnixNano(60*time.Hour))
	if rep := r.tick(w); rep.Produced != 0 {
		t.Fatalf("evidence far from expiry was declared: %+v", rep)
	}
	// Inside the reach but outside the lead (the plan sees it, no trigger): still nothing.
	r.clock.set(deadline - model.UnixNano(36*time.Hour))
	w = r.expiry(24 * time.Hour)
	if rep := r.tick(w); rep.Produced != 0 {
		t.Fatalf("evidence outside the lead was declared: %+v", rep)
	}
	if snap := r.snapshot(); len(snap.Gaps) != 0 || len(snap.Checkpoints) != 0 {
		t.Fatalf("something committed before the lead: %+v", snap)
	}
	if complete, _ := r.health(); !complete {
		t.Fatal("health incomplete before any gap")
	}

	// Inside the lead: one gap over the whole unprocessed run, with its checkpoint.
	r.clock.set(deadline - model.UnixNano(12*time.Hour))
	w = r.expiry(24 * time.Hour)
	if rep := r.tick(w); rep.Produced != 1 {
		t.Fatalf("expected one gap: %+v", rep)
	}
	snap := r.snapshot()
	if len(snap.Gaps) != 1 {
		t.Fatalf("gaps: %+v", snap.Gaps)
	}
	g := snap.Gaps[0]
	if g.Group != group || g.After != 0 || g.Through != entries[2].Cursor.Index || g.Count != 3 || g.Reason != "unprocessed_expiry" || len(g.Signals) != 1 || g.Signals[0] != model.ErrorKind ||
		g.Org != r.org || g.Project != r.project || g.DeclaredBy != "" || g.Start <= 0 || g.End < g.Start {
		t.Fatalf("the gap: %+v (entries %+v)", g, entries)
	}
	if got := snap.Checkpoints[group]; got != entries[2].Cursor.Index {
		t.Fatalf("the checkpoint must advance over the gap with it: %d want %d", got, entries[2].Cursor.Index)
	}
	if complete, gaps := r.health(); complete || gaps != 1 {
		t.Fatalf("health after the gap: complete=%v gaps=%d", complete, gaps)
	}
	var audited bool
	if err := r.app.Control.View(r.ctx, func(st model.ControlState) error {
		for _, a := range st.Audits {
			if a.Action == "issues.evidence_gap" && a.ID == g.ID && a.Principal == auth.SystemPrincipal(r.org) {
				audited = true
			}
		}
		return nil
	}); err != nil || !audited {
		t.Fatalf("the gap is not audited under the system principal (err %v)", err)
	}

	// Idempotent: another pass declares nothing, and the issue producer, which
	// resumes after the checkpoint, creates no issue out of the declared interval.
	if rep := r.tick(w); rep.Produced != 0 {
		t.Fatalf("a second pass declared again: %+v", rep)
	}
	r.tick(r.workers())
	if got := r.snapshot(); len(got.Issues) != 0 || len(got.Gaps) != 1 {
		t.Fatalf("the declared interval was processed or re-declared: issues=%d gaps=%d", len(got.Issues), len(got.Gaps))
	}
}

// The gap starts exactly at the group's committed checkpoint and covers only the
// contiguous unprocessed run that is expiring: evidence the producer already
// processed is not claimed lost, and a later cursor that still has time is left
// to be processed.
func TestJournalExpiryGapCoversOnlyTheExpiringUnprocessedRun(t *testing.T) {
	r := newJournalRig(t)
	ids := r.idsInOneSlot(4)
	// The first batch is processed normally: it is below the checkpoint.
	r.ingestBatch(r.record("TypeError", 5, false, true, ids[0]))
	r.tick(r.workers())
	first := onlyCheckpoint(t, r.snapshot())
	if len(r.snapshot().Issues) != 1 {
		t.Fatalf("setup: %+v", r.snapshot().Issues)
	}
	// Three more arrive while the producer is stalled.
	for i := 1; i < 4; i++ {
		r.ingestBatch(r.record("TypeError", model.UnixNano(5+i), false, true, ids[i]))
	}
	entries := r.entries()
	if len(entries) != 4 || entries[0].Cursor.Index != first {
		t.Fatalf("setup entries: %+v", entries)
	}
	// Lead 1ns: now sits just before the second batch's deadline, so only the
	// second batch is in the reach; the third and fourth (a few microseconds
	// later) still have time.
	now := entries[1].Deadline - 1
	if entries[2].Deadline <= now+2 {
		t.Skip("the batches' receipt deadlines are too close to separate")
	}
	r.clock.set(now)
	w := r.expiry(time.Nanosecond)
	if rep := r.tick(w); rep.Produced != 1 {
		t.Fatalf("expected one gap: %+v", rep)
	}
	snap := r.snapshot()
	if len(snap.Gaps) != 1 {
		t.Fatalf("gaps: %+v", snap.Gaps)
	}
	g := snap.Gaps[0]
	if g.After != first || g.Through != entries[1].Cursor.Index || g.Count != 1 {
		t.Fatalf("the gap must start at the checkpoint %d and cover only the second batch: %+v (entries %+v)", first, g, entries)
	}
	if got := onlyCheckpoint(t, snap); got != entries[1].Cursor.Index {
		t.Fatalf("checkpoint %d, want %d", got, entries[1].Cursor.Index)
	}
	// The cursors that still had time are processed normally afterwards.
	r.tick(r.workers())
	after := r.snapshot()
	var counted int
	for _, gi := range after.Issues {
		counted += len(gi.Occurrences)
	}
	if counted != 3 {
		t.Fatalf("the first and the two later batches must be counted (3), got %d", counted)
	}
}

// If the gap cannot commit, the journal is HELD: its growth is bounded by the
// reserve and further error evidence is rejected (retryable, a typed fault)
// instead of being discarded; a gap that does commit releases the hold.
func TestJournalExpiryHoldsTheJournalWhenTheGapCannotCommit(t *testing.T) {
	r := newJournalRig(t)
	entries := r.ingestAll(r.idsInOneSlot(2))
	// Exhaust the book's gap capacity with unrelated gaps (the real limit), so the
	// gap the scheduler needs cannot commit.
	svc, err := r.app.NewIssueActions(r.workerNode.clock)
	if err != nil {
		t.Fatal(err)
	}
	write := r.system(auth.IssuesWrite)
	for i := range 128 {
		g := model.EvidenceGap{ID: model.NewID(), Org: r.org, Project: r.project, Group: model.NewID(), After: 0, Through: 1, Count: 1, Start: 1, End: 1, Signals: []model.Kind{model.ErrorKind}, Reason: "unprocessed_expiry", RecordedAt: 1}
		if err = svc.RecordGap(r.ctx, write, g); err != nil {
			t.Fatalf("filling gap %d: %v", i, err)
		}
	}
	r.clock.set(entries[1].Deadline - model.UnixNano(time.Hour))
	w := r.expiry(24 * time.Hour)
	rep := w.Tick(r.ctx)
	if rep.Produced != 0 || len(rep.Errors) == 0 {
		t.Fatalf("a gap that cannot commit must fail the stage: %+v", rep)
	}
	holds := r.app.Storage.JournalHolds()
	if len(holds) != 1 || holds[0].Org != r.org || holds[0].Project != r.project || holds[0].Reserve != 1 {
		t.Fatalf("the journal must be held: %+v", holds)
	}
	// Nothing advanced: the checkpoint stays where it was.
	if got := r.snapshot().Checkpoints[entries[0].Cursor.Group]; got != 0 {
		t.Fatalf("a failed gap moved the checkpoint to %d", got)
	}
	// The reserve is spent: error evidence is rejected, typed and retryable.
	_, err = r.admit(r.batchOf(r.record("TypeError", 99, false, true, model.NewID())))
	var f *model.Fault
	if !errors.As(err, &f) || f.Code != model.Unavailable || !f.Retryable || f.SafeDetail != storage.JournalReserveDetail {
		t.Fatalf("admission into a held journal: %v", err)
	}
	// Another project's journal is not held.
	if len(r.app.Storage.JournalHolds()) != 1 {
		t.Fatalf("holds: %+v", r.app.Storage.JournalHolds())
	}
}

// A hold ends when the evidence it protected is declared (or processed): the
// next pass that finds nothing unprocessed to expire releases it.
func TestJournalExpiryReleasesTheHoldOnceTheGapCommits(t *testing.T) {
	r := newJournalRig(t)
	entries := r.ingestAll(r.idsInOneSlot(2))
	r.app.Storage.HoldJournal(r.org, r.project, 1)
	if _, err := r.admit(r.batchOf(r.record("TypeError", 98, false, true, model.NewID()))); err == nil {
		t.Fatal("setup: the held journal accepted evidence past its reserve")
	}
	r.clock.set(entries[1].Deadline - model.UnixNano(time.Hour))
	w := r.expiry(24 * time.Hour)
	if rep := r.tick(w); rep.Produced != 1 {
		t.Fatalf("expected the gap: %+v", rep)
	}
	if holds := r.app.Storage.JournalHolds(); len(holds) != 0 {
		t.Fatalf("the hold outlived the gap: %+v", holds)
	}
	if _, err := r.admit(r.batchOf(r.record("TypeError", 97, false, true, model.NewID()))); err != nil {
		t.Fatalf("a released journal must admit evidence again: %v", err)
	}
}

// batchOf builds one admissible batch of the rig's source (the same shape
// ingestBatch admits).
func (r *issueRig) batchOf(records ...model.Record) model.Batch {
	r.t.Helper()
	b := model.Batch{Version: 1, Project: r.project, Source: r.source, Producer: r.producer, ID: model.NewID(), PolicyRevision: 1, Records: records}
	var err error
	if b.RouteSlot, err = model.OwnerSlot(r.org, r.project, r.source, r.producer, records[0]); err != nil {
		r.t.Fatal(err)
	}
	return b
}
