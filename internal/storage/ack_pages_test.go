// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// ackPagesBatch is settleBatch with a random producer and a series drawn from a pool: the rows of the batch
// land in the random-keyed buckets of the data engine. All records of a batch must route to one slot, so a
// request carries the one record its first series routes (the gate sends ~3.6 records of one slot).
func ackPagesBatch(t *testing.T, store *control.Store, a *auth.Service, c auth.SourceCredential, d model.SourceDescriptor, at model.UnixNano, names []string) (auth.Scope, model.NormalizedBatch) {
	t.Helper()
	scope, e := a.SourceScope(context.Background(), c, false)
	if e != nil {
		t.Fatal(e)
	}
	src, e := a.SourceAuthority(context.Background(), c, true)
	if e != nil {
		t.Fatal(e)
	}
	res := model.Resource{Service: src.Policy.Resources.Services[0], Environment: src.Policy.Resources.Environments[0], Build: src.Policy.Resources.Builds[0], Instance: src.Policy.Resources.Instances[0]}
	records := make([]model.Record, len(names))
	for i, name := range names {
		records[i] = model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: at, Resource: res, Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: ptrBits(0x3ff0000000000000), Type: "counter", Unit: "1"}}}
	}
	b := model.Batch{Version: 1, Project: d.Project, Source: d.Source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: records}
	slot, _ := model.OwnerSlot(d.Org, b.Project, b.Source, b.Producer, b.Records[0])
	b.RouteSlot = slot
	raw := mustJSON(t, b)
	policyBytes := mustJSON(t, src.Policy)
	n := model.NormalizedBatch{Batch: b, Org: d.Org, Hash: model.HashCanonical(raw), Canonical: raw, PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyHash: model.HashCanonical(policyBytes).String(), AdmissionAt: 10, Deadlines: []model.SignalDeadline{{Kind: model.Metric, RetainUntil: 100}}}
	n.Reservation, e = store.ReserveAdmission(context.Background(), scope, n)
	if e != nil {
		t.Fatal(e)
	}
	return scope, n
}

// ackPageNodesBound is the most page nodes (bolt writes: a node of a few contiguous pages is one) one
// acknowledged request may dirty in apply.db when the appends of a commit are about a dozen, however long
// the history. On the single-host gate the writer of apply.db was held 97 % of the time at 470 acks/s by
// 27.7 page nodes per ack (L2w20Admission14) and the virtual disk does about 30,000 random 4 KiB writes per
// second: the random-keyed buckets (batches, receipts, metrics, scan pages and commits) cost one scattered
// leaf per row, the rows of a commit do not share one.
const ackPageNodesBound = 14

// ackPagesSlotOf is the slot that owns a metric series of the fixture's project (the producer and the source
// do not enter it).
func ackPagesSlotOf(t *testing.T, d model.SourceDescriptor, name string) uint16 {
	t.Helper()
	slot, err := model.OwnerSlot(d.Org, d.Project, d.Source, model.ID{}, model.Record{Kind: model.Metric, Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}}}})
	if err != nil {
		t.Fatal(err)
	}
	return slot
}

// appendInCommits appends the batches width at a time and makes every group of width ONE bolt commit of
// apply.db: the commit is held while the applies of the group queue (updateGrouped), then it is released
// with all of them. The batches of a group must route to different slots, because the appends of one slot
// are ordered one behind the other and never share a commit. It returns the number of commits and of
// applies that went through updateGrouped.
//
// Left alone, the width of a commit is a race, and the page nodes per ack are a function of it: a commit
// dirties about 26 page nodes with one append in it and 32 with twelve (its registry, root, run buckets,
// freelist and meta pages are the same whatever it carries, L2w20Admission18). The engine commits as soon as
// no commit is running, and on a file system whose fsync is free (the tmpfs of a test) a commit takes a
// fraction of a millisecond, so the applies that happen to arrive while one runs form the next: 1.1 to 1.3
// appends per commit on an idle 8-CPU machine, about 3 on another run, and 10 on the single-host gate, whose
// fdatasync takes 10 ms (L2w20Admission14). The same history costs 26 page nodes per ack at one append per
// commit, 9 at three, 4.6 at six and 2.7 at twelve; the test measured whichever of those the scheduler
// gave it, 8 to 24.
func appendInCommits(t *testing.T, e *Engine, batches []preparedAppend, width int) (commits, applies uint64) {
	t.Helper()
	g := &e.db.grouped
	rounds0, calls0 := g.rounds.Load(), g.calls.Load()
	for from := 0; from < len(batches); from += width {
		group := batches[from:min(from+width, len(batches))]
		g.mu.Lock()
		g.running = true // no commit starts: the applies queue in g.pending
		g.mu.Unlock()
		errs := make([]error, len(group))
		var wg sync.WaitGroup
		for i := range group {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = e.Append(context.Background(), group[i].scope, group[i].batch)
			}()
		}
		queued := 0
		for deadline := time.Now().Add(10 * time.Second); queued < len(group) && time.Now().Before(deadline); {
			time.Sleep(50 * time.Microsecond)
			g.mu.Lock()
			queued = len(g.pending)
			g.mu.Unlock()
		}
		g.commitNext(e.db) // releases the hold: commits what queued as one transaction
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("append %d of the group at %d: %v", i, from, err)
			}
		}
		if queued != len(group) {
			t.Fatalf("%d of the %d appends of the group at %d reached the commit: two of them route to one slot?", queued, len(group), from)
		}
	}
	return g.rounds.Load() - rounds0, g.calls.Load() - calls0
}

// pageNodesPerAck appends the batches width to a commit (appendInCommits), runs the merges those commits
// made due and returns the page nodes bolt wrote to apply.db per ack. The merger of the engine is stopped
// for it: it wakes every 200 ms and merges everything due, while the commits of a window take a fraction of
// that, so the merges the commits made due fell into their window, into the next one or into neither,
// depending on the phase of the tick (3.7 to 5 page nodes per ack of a window of 250 appends at one append
// per commit when they all fell in it, none when they did not). The pass the merger would make
// (mergeIndexRuns) is made here once the commits are in: a window pays for the merges its own commits make due.
func pageNodesPerAck(t *testing.T, e *Engine, batches []preparedAppend, width int) float64 {
	t.Helper()
	e.stopIndexMerger()
	if len(batches)%width != 0 {
		t.Fatalf("%d appends do not make whole commits of %d", len(batches), width)
	}
	before := e.db.Stats()
	commits, applies := appendInCommits(t, e, batches, width)
	if commits != uint64(len(batches)/width) || applies != uint64(len(batches)) {
		t.Fatalf("%d appends in groups of %d made %d commits of %d applies: the commits of the measurement are not the ones it describes", len(batches), width, commits, applies)
	}
	if cancelled, err := e.mergeIndexRuns(nil); cancelled || err != nil {
		t.Fatalf("merging the runs the commits made due: cancelled=%v %v", cancelled, err)
	}
	after := e.db.Stats()
	d := after.Sub(&before)
	return float64(d.TxStats.GetWrite()) / float64(len(batches))
}

// TestAckPageNodesAreBoundedAndIndependentOfHistory drives single-record appends over 900 series (the source
// quota of the fixture), a dozen to a commit, through a history of 1,500 acknowledged requests and counts
// the page nodes bolt writes to apply.db per ack in a window at the start and one at the end of the history:
// both must be within the bound, and the later one must not exceed the earlier by more than a tree level.
//
// What the number must not depend on is the schedule of the run, so the test fixes what the schedule used
// to decide: the appends of a commit (appendInCommits: a dozen, the 10 of the gate, as the bound says) and
// the merges its window pays for (pageNodesPerAck).
func TestAckPageNodesAreBoundedAndIndependentOfHistory(t *testing.T) {
	store, service, cred, desc := fixture(t)
	e, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BindAdmissionOwner(e); err != nil {
		t.Fatal(err)
	}
	e.stopIndexMerger() // pageNodesPerAck runs its pass itself
	const total, window, width, universe = 1500, 240, 12, 900
	bySlot := map[uint16][]string{}
	for i := range universe {
		name := fmt.Sprintf("ack_pages_series_%d", i)
		slot := ackPagesSlotOf(t, desc, name)
		bySlot[slot] = append(bySlot[slot], name)
	}
	slots := make([]uint16, 0, len(bySlot))
	for slot := range bySlot {
		slots = append(slots, slot)
	}
	sort.Slice(slots, func(i, j int) bool { return slots[i] < slots[j] })
	if len(slots) < width {
		t.Fatalf("the %d series route to %d slots, a commit needs %d", universe, len(slots), width)
	}
	// The group of a commit takes the next width slots in turn, and a series of each that the random walk
	// picks, so the history spreads over the slots and over the series as a stream of producers does.
	rng := rand.New(rand.NewPCG(7, 7))
	batches := make([]preparedAppend, total)
	for i := range batches {
		names := bySlot[slots[i%len(slots)]]
		batches[i].scope, batches[i].batch = ackPagesBatch(t, store, service, cred, desc, model.UnixNano(1+i), []string{names[rng.IntN(len(names))]})
	}
	early := pageNodesPerAck(t, e, batches[:window], width)
	pageNodesPerAck(t, e, batches[window:total-window], width)
	late := pageNodesPerAck(t, e, batches[total-window:], width)
	t.Logf("apply.db page nodes per ack with %d in a commit: first %d acks %.1f, last %d acks (history %d) %.1f", width, window, early, window, total-window, late)
	if early > ackPageNodesBound || late > ackPageNodesBound {
		t.Errorf("an acknowledged append dirties %.1f (first %d) and %.1f (last %d) page nodes of apply.db, bound %d", early, window, late, window, ackPageNodesBound)
	}
	if late > early*1.25+2 {
		t.Errorf("page nodes per ack grew with the history: %.1f for the first %d acks, %.1f for the last %d", early, window, late, window)
	}
}
