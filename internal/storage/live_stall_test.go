// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// The engine mutex was held across every authority read of a live subscription: Subscribe after its fence, the
// top of every Next, the deletion read of a page and both validations of a release barrier. Each of them waits
// on the control state (a ReadIndex round that needs a quorum, seconds when the quorum is slow), so one slow
// read stopped every append and every other reader of the node for as long. Whatever read stalls, appends and
// other readers complete at once, and the stalled call still ends with its normal answer when the authority
// answers.

// liveStallBound is only a hang guard, never a speed limit. The authority read waits until the test releases
// it, so an append or another reader that completes while the stall is still held proves no lock is held
// across the read, however slow the machine is. A lock held across it fails by hitting this deadline with
// the stall still held.
const liveStallBound = 5 * time.Minute

// liveStallKey marks the contexts whose authority reads are stalled.
type liveStallKey struct{}

// stallPoint names the authority read that stalls: the one after skip reads of its kind (validations of the
// scope, or reads of the control view's deletions) have been answered at once, counted over the reads made with
// a marked context.
type stallPoint struct {
	view bool
	skip int64
}

// liveStallAuthority is the seam of a control ReadIndex that does not answer. It is the engine's validator and
// its deletion view at once: the read of a marked context that stallPoint names waits until release is closed (or
// the context ends). entered is signalled when a read starts to wait.
type liveStallAuthority struct {
	inner    Revalidator
	validate atomic.Int64
	view     atomic.Int64
	deny     atomic.Bool // the validations released from a stall answer that the scope was revoked
	release  chan struct{}
	entered  chan struct{}
	once     sync.Once
}

func newLiveStallAuthority(inner Revalidator) *liveStallAuthority {
	v := &liveStallAuthority{inner: inner, release: make(chan struct{}), entered: make(chan struct{}, 1)}
	v.validate.Store(math.MaxInt64)
	v.view.Store(math.MaxInt64)
	return v
}

// installLiveStall makes the engine of x read its authority through the seam. Nothing stalls until stallAt.
func installLiveStall(t *testing.T, x *eraseEnv) *liveStallAuthority {
	t.Helper()
	v := newLiveStallAuthority(x.a)
	if err := x.e.BindDeletions(v); err != nil {
		t.Fatal(err)
	}
	x.e.mu.Lock()
	x.e.validator = v
	x.e.mu.Unlock()
	t.Cleanup(v.free)
	return v
}

func (v *liveStallAuthority) stallAt(p stallPoint) {
	if p.view {
		v.view.Store(p.skip)
	} else {
		v.validate.Store(p.skip)
	}
}

// free lets every stalled read answer, now and from then on.
func (v *liveStallAuthority) free() { v.once.Do(func() { close(v.release) }) }

// wait stalls the read when it is the one the counter names, and reports whether it did.
func (v *liveStallAuthority) wait(ctx context.Context, skip *atomic.Int64) (bool, error) {
	if ctx.Value(liveStallKey{}) == nil || skip.Add(-1) >= 0 {
		return false, nil
	}
	select {
	case v.entered <- struct{}{}:
	default:
	}
	select {
	case <-v.release:
		return true, nil
	case <-ctx.Done():
		return true, model.Fail(model.Cancelled)
	}
}

func (v *liveStallAuthority) Revalidate(ctx context.Context, s auth.Scope) error {
	stalled, err := v.wait(ctx, &v.validate)
	if err != nil {
		return err
	}
	if stalled && v.deny.Load() {
		return model.Fail(model.Unauthenticated)
	}
	return v.inner.Revalidate(ctx, s)
}

func (v *liveStallAuthority) ActiveDeletions(ctx context.Context, _ model.ID, _ []model.ID) ([]model.DeletePredicate, error) {
	_, err := v.wait(ctx, &v.view)
	return nil, err
}

// stalledContext is a context whose authority reads go through the stall.
func stalledContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), liveStallKey{}, true))
	t.Cleanup(cancel)
	return ctx
}

// liveStallRow admits one metric row of a series of its own, to be appended later.
func (x *eraseEnv) liveStallRow(tag string) (model.NormalizedBatch, auth.Scope, model.ID) {
	x.t.Helper()
	rec := x.metric("live_stall_"+tag+"_"+model.NewID().String(), 1000)
	n, scope := x.admit(model.NewID(), metricRetention, rec)
	return n, scope, rec.ID
}

func (x *eraseEnv) liveStallAppend(tag string) model.ID {
	x.t.Helper()
	n, scope, id := x.liveStallRow(tag)
	if _, err := x.e.Append(context.Background(), scope, n); err != nil {
		x.t.Fatal("append: ", err)
	}
	return id
}

// liveStallSee counts the rows of a page and fails on anything but rows: a gap, a revocation, a row twice.
func liveStallSee(change ChangePage, seen map[model.ID]int) error {
	if change.Gap != nil || change.Revoked {
		return fmt.Errorf("a gap (%+v) or a revocation (%v) was handed over", change.Gap, change.Revoked)
	}
	for _, id := range change.Page.IDs {
		seen[id]++
		if seen[id] > 1 {
			return fmt.Errorf("row %s was handed over twice", id)
		}
	}
	return nil
}

// liveStallTake takes pages until every wanted row was seen.
func liveStallTake(it ChangeIterator, seen map[model.ID]int, want map[model.ID]bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*liveStallBound)
	defer cancel()
	for {
		missing := 0
		for id := range want {
			if seen[id] == 0 {
				missing++
			}
		}
		if missing == 0 {
			return nil
		}
		change, err := it.Next(ctx)
		if err != nil {
			return fmt.Errorf("%d rows still to come: %w", missing, err)
		}
		if err = liveStallSee(change, seen); err != nil {
			return err
		}
	}
}

type liveStallResult struct {
	it     ChangeIterator
	change ChangePage
	err    error
}

// awaitEntered waits until the stalled read waits; a call that ended first never stalled.
func awaitEntered(t *testing.T, v *liveStallAuthority, done <-chan liveStallResult) {
	t.Helper()
	select {
	case <-v.entered:
	case r := <-done:
		t.Fatalf("the stalled read never waited: %+v", r)
	case <-time.After(liveStallBound):
		t.Fatal("the stalled read never started")
	}
}

func TestLiveStalledAuthorityReadDoesNotHoldTheEngineLock(t *testing.T) {
	for _, tc := range []struct {
		name      string
		at        stallPoint
		subscribe bool // the stalled call is Subscribe; else the Next of a subscription
		queued    bool // a commit is queued for the Next: it reads and certifies its page
		overrun   bool // the queue overran: the Next has a gap to certify
	}{
		{name: "subscribe_after_fence", subscribe: true, at: stallPoint{skip: 1}},
		{name: "subscribe_after_fence_deletions", subscribe: true, at: stallPoint{view: true, skip: 1}},
		{name: "next_waiting_for_a_commit", at: stallPoint{}},
		{name: "next_top_with_a_page", queued: true, at: stallPoint{skip: 1}},
		{name: "page_deletions", queued: true, at: stallPoint{view: true, skip: 2}},
		{name: "release_barrier_before_fence", queued: true, at: stallPoint{skip: 2}},
		{name: "release_barrier_before_fence_deletions", queued: true, at: stallPoint{view: true, skip: 3}},
		{name: "release_barrier_after_fence", queued: true, at: stallPoint{skip: 3}},
		{name: "release_barrier_after_fence_deletions", queued: true, at: stallPoint{view: true, skip: 4}},
		{name: "gap_barrier_after_fence", overrun: true, at: stallPoint{skip: 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newEraseEnv(t)
			v := installLiveStall(t, x)
			req := SubscribeRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric}
			stalled := stalledContext(t)
			seen := map[model.ID]int{}
			want := map[model.ID]bool{}
			var it ChangeIterator
			if !tc.subscribe {
				var err error
				if it, err = x.e.Subscribe(context.Background(), x.read, req); err != nil {
					t.Fatal(err)
				}
				defer it.Close()
				switch {
				case tc.queued:
					want[x.liveStallAppend("first")] = true
				case tc.overrun:
					for i := range liveCapacity + 2 {
						x.liveStallAppend(fmt.Sprintf("burst%d", i))
					}
				}
			}
			appendN, appendScope, appendID := x.liveStallRow("during_append")
			otherN, otherScope, otherID := x.liveStallRow("during_other")
			want[appendID], want[otherID] = true, true

			v.stallAt(tc.at)
			done := make(chan liveStallResult, 1)
			if tc.subscribe {
				go func() {
					got, err := x.e.Subscribe(stalled, x.read, req)
					done <- liveStallResult{it: got, err: err}
				}()
			} else {
				go func() {
					change, err := it.Next(stalled)
					done <- liveStallResult{change: change, err: err}
				}()
			}
			awaitEntered(t, v, done)

			// While it waits: an append, a whole scan and a whole new subscription of other readers complete.
			appended := make(chan error, 1)
			go func() { _, err := x.e.Append(context.Background(), appendScope, appendN); appended <- err }()
			scanned := make(chan error, 1)
			go func() {
				it, err := x.e.Scan(context.Background(), x.read, ScanRequest{Projects: req.Projects, Signal: model.Metric, End: 1 << 40})
				if err != nil {
					scanned <- err
					return
				}
				defer it.Close()
				for {
					if _, err = it.Next(context.Background()); err != nil {
						if err == io.EOF {
							err = nil
						}
						scanned <- err
						return
					}
				}
			}()
			subscribed := make(chan error, 1)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*liveStallBound)
				defer cancel()
				other, err := x.e.Subscribe(ctx, x.read, req)
				if err != nil {
					subscribed <- err
					return
				}
				defer other.Close()
				if _, err = x.e.Append(ctx, otherScope, otherN); err != nil {
					subscribed <- err
					return
				}
				otherSeen := map[model.ID]int{}
				subscribed <- liveStallTake(other, otherSeen, map[model.ID]bool{otherID: true})
			}()
			deadline := time.Now().Add(liveStallBound)
			for _, c := range []struct {
				what string
				ch   chan error
			}{{"append", appended}, {"another reader's scan", scanned}, {"another reader's subscription", subscribed}} {
				select {
				case err := <-c.ch:
					if err != nil {
						t.Errorf("%s while an authority read waits: %v", c.what, err)
					}
				case <-time.After(time.Until(deadline)):
					t.Errorf("%s did not complete within %v while an authority read of a live subscription waits: the engine lock is held across the control read", c.what, liveStallBound)
				}
			}
			select {
			case r := <-done:
				t.Fatalf("the stalled call ended before its authority answered: %+v", r)
			default:
			}

			v.free()
			var r liveStallResult
			select {
			case r = <-done:
			case <-time.After(liveStallBound):
				t.Fatal("the stalled call did not end after the authority answered")
			}
			if r.err != nil {
				t.Fatalf("the stalled call after the authority answered: %v", r.err)
			}
			if tc.subscribe {
				if r.it == nil {
					t.Fatal("Subscribe returned no iterator")
				}
				defer r.it.Close()
				// A fresh subscription starts at what is applied when it registers: the commits that landed
				// while its authority read waited are not owed to it, and it opens clean for what follows.
				after := x.liveStallAppend("after")
				if err := liveStallTake(r.it, map[model.ID]int{}, map[model.ID]bool{after: true}); err != nil {
					t.Fatalf("the subscription that waited for its authority: %v", err)
				}
				return
			}
			if tc.overrun {
				if r.change.Gap == nil || r.change.Gap.Reason != "slow_consumer" || r.change.Page.Len() != 0 {
					t.Fatalf("the first change of an overrun subscription: %+v", r.change)
				}
			} else if err := liveStallSee(r.change, seen); err != nil {
				t.Fatal(err)
			} else if r.change.Page.Len() == 0 {
				t.Fatalf("the stalled Next handed no rows: %+v", r.change)
			}
			if err := liveStallTake(it, seen, want); err != nil {
				t.Fatalf("what committed while the authority read waited: %v", err)
			}
		})
	}
}

// An iterator cancelled while its authority read waits is closed at once (the lock is free for the cancellation),
// and the Next that waited judges it again under the lock when the authority answers: it fails with the
// cancellation and releases nothing, whichever read it waited in.
func TestLiveCancelledDuringItsAuthorityReadFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   stallPoint
	}{
		{name: "top", at: stallPoint{skip: 1}},
		{name: "page_deletions", at: stallPoint{view: true, skip: 2}},
		{name: "release_barrier_before_fence", at: stallPoint{skip: 2}},
		{name: "release_barrier_after_fence", at: stallPoint{skip: 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newEraseEnv(t)
			v := installLiveStall(t, x)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			it, err := x.e.Subscribe(ctx, x.read, SubscribeRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric})
			if err != nil {
				t.Fatal(err)
			}
			defer it.Close()
			x.liveStallAppend("queued")
			v.stallAt(tc.at)
			done := make(chan liveStallResult, 1)
			stalled := stalledContext(t)
			go func() {
				change, err := it.Next(stalled)
				done <- liveStallResult{change: change, err: err}
			}()
			awaitEntered(t, v, done)
			cancel()
			closed := make(chan struct{})
			go func() {
				defer close(closed)
				for x.e.Stats().ActiveIterators != 0 {
					time.Sleep(5 * time.Millisecond)
				}
			}()
			select {
			case <-closed:
			case <-time.After(liveStallBound):
				t.Error("the cancelled iterator stayed open while its authority read waits")
			}
			v.free()
			select {
			case r := <-done:
				var f *model.Fault
				if !errors.As(r.err, &f) || f.Code != model.Cancelled || r.change.Page.Len() != 0 || r.change.Gap != nil || r.change.Revoked {
					t.Fatalf("Next of a subscription cancelled during its authority read: %+v, %v; want the cancellation and nothing else", r.change, r.err)
				}
			case <-time.After(liveStallBound):
				t.Fatal("Next did not end after the authority answered")
			}
			<-closed
			if got := x.e.Stats().BorrowedPages; got != 0 {
				t.Fatalf("%d pages borrowed after the cancelled Next", got)
			}
		})
	}
}

// A revocation that the authority reports when its stalled read is answered ends the stream with the revoke
// page and no row, in every read a Next waits in.
func TestLiveRevocationFoundByAStalledAuthorityReadReleasesNothing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		queued bool
		at     stallPoint
	}{
		{name: "top", at: stallPoint{}},
		{name: "top_with_a_page", queued: true, at: stallPoint{skip: 1}},
		{name: "release_barrier_before_fence", queued: true, at: stallPoint{skip: 2}},
		{name: "release_barrier_after_fence", queued: true, at: stallPoint{skip: 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newEraseEnv(t)
			v := installLiveStall(t, x)
			v.deny.Store(true)
			it, err := x.e.Subscribe(context.Background(), x.read, SubscribeRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric})
			if err != nil {
				t.Fatal(err)
			}
			defer it.Close()
			if tc.queued {
				x.liveStallAppend("queued")
			}
			v.stallAt(tc.at)
			done := make(chan liveStallResult, 1)
			stalled := stalledContext(t)
			go func() {
				change, err := it.Next(stalled)
				done <- liveStallResult{change: change, err: err}
			}()
			awaitEntered(t, v, done)
			v.free()
			select {
			case r := <-done:
				if r.err != nil || !r.change.Revoked || r.change.Page.Len() != 0 || r.change.Gap != nil {
					t.Fatalf("a revocation answered by a stalled read: %+v, %v; want the revoke page and no row", r.change, r.err)
				}
			case <-time.After(liveStallBound):
				t.Fatal("Next did not end after the authority answered")
			}
			if _, err = it.Next(context.Background()); err != io.EOF {
				t.Fatalf("a revoked stream stays open: %v", err)
			}
		})
	}
}

// A restore that begins while an authority read waits raises the gate: nothing is served until its deletion
// ledger is applied. The answer of the read that waited is not used under a gate that rose meanwhile: the Next
// fails as unavailable (not as a revocation) and hands nothing, in every read it waits in.
func TestLiveRestoreGateRaisedWhileAnAuthorityReadWaitsReleasesNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   stallPoint
	}{
		{name: "top", at: stallPoint{skip: 1}},
		{name: "page_deletions", at: stallPoint{view: true, skip: 2}},
		{name: "release_barrier_before_fence", at: stallPoint{skip: 2}},
		{name: "release_barrier_after_fence", at: stallPoint{skip: 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newEraseEnv(t)
			v := installLiveStall(t, x)
			it, err := x.e.Subscribe(context.Background(), x.read, SubscribeRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric})
			if err != nil {
				t.Fatal(err)
			}
			defer it.Close()
			x.liveStallAppend("queued")
			v.stallAt(tc.at)
			done := make(chan liveStallResult, 1)
			stalled := stalledContext(t)
			go func() {
				change, err := it.Next(stalled)
				done <- liveStallResult{change: change, err: err}
			}()
			awaitEntered(t, v, done)
			x.e.tomb.gate.Store(true)
			t.Cleanup(func() { x.e.tomb.gate.Store(false) })
			v.free()
			select {
			case r := <-done:
				var f *model.Fault
				if !errors.As(r.err, &f) || f.Code != model.Unavailable || r.change.Page.Len() != 0 || r.change.Gap != nil || r.change.Revoked {
					t.Fatalf("Next under a restore gate that rose while its authority read waited: %+v, %v; want unavailable and nothing else", r.change, r.err)
				}
			case <-time.After(liveStallBound):
				t.Fatal("Next did not end after the authority answered")
			}
		})
	}
}

// The commit a Next holds the page of is rewritten while one of its authority reads waits (the lock is free, so
// the erasure runs): the page it read before holds rows that no longer exist. None of them is handed over, and
// the rows the rewrite kept are handed once. The windows are the read of the page's deletions and the two
// validations of the release barrier, which the page read precedes; the rewrite is an expiry (no deletion
// predicate names it, only the rewrite counter of the commit records shows it) and a range deletion.
var liveStallWindows = []struct {
	name string
	at   stallPoint
}{
	{name: "page_deletions", at: stallPoint{view: true, skip: 2}},
	{name: "release_barrier_before_fence", at: stallPoint{skip: 2}},
	{name: "release_barrier_after_fence", at: stallPoint{skip: 3}},
}

func TestLiveExpiryWhileAnAuthorityReadWaitsHandsNoErasedRow(t *testing.T) {
	for _, w := range liveStallWindows {
		t.Run(w.name, func(t *testing.T) {
			r := rechunkRig(t, false)
			v := installLiveStall(t, r.eraseEnv)
			producer := model.NewID()
			slot := r.slotOf(producer)
			rows, _ := r.commitOn(producer, slot, 3)
			v.stallAt(w.at)
			done := make(chan liveStallResult, 1)
			stalled := stalledContext(t)
			go func() {
				change, err := r.it.Next(stalled)
				done <- liveStallResult{change: change, err: err}
			}()
			awaitEntered(t, v, done)
			expired := make(chan error, 1)
			go func() {
				report, err := r.e.EraseExpired(context.Background(), metricDeadline, nil)
				if err == nil && report.Records != uint64(len(rows)) {
					err = fmt.Errorf("expired %d rows, want %d", report.Records, len(rows))
				}
				expired <- err
			}()
			select {
			case err := <-expired:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(liveStallBound):
				t.Fatal("the expiry erasure did not complete while an authority read of a live subscription waits: the engine lock is held across the control read")
			}
			survivor := r.rowsOn(producer, slot, 1)
			r.appendRecords(producer, metricRetention, survivor...)
			v.free()
			select {
			case res := <-done:
				if res.err != nil || res.change.Gap != nil || res.change.Revoked {
					t.Fatalf("Next after the rewrite: %+v, %v", res.change, res.err)
				}
				if got := res.change.Page.IDs; len(got) != 1 || got[0] != survivor[0].ID {
					t.Fatalf("Next handed %v after every row of its page expired, want only the row committed after (%v)", got, survivor[0].ID)
				}
			case <-time.After(liveStallBound):
				t.Fatal("Next did not end after the authority answered")
			}
		})
	}
}

func TestLiveWalkSurvivesARewriteWhileAnAuthorityReadWaits(t *testing.T) {
	for _, catchUp := range []bool{false, true} {
		for _, w := range liveStallWindows {
			t.Run(fmt.Sprintf("catchup_%v/%s", catchUp, w.name), func(t *testing.T) {
				r := rechunkRig(t, catchUp)
				v := installLiveStall(t, r.eraseEnv)
				producer := model.NewID()
				slot := r.slotOf(producer)
				big, _ := r.commitOn(producer, slot, 300) // pages of 128, 128 and 44 rows
				v.stallAt(w.at)
				done := make(chan liveStallResult, 1)
				stalled := stalledContext(t)
				go func() {
					change, err := r.it.Next(stalled)
					done <- liveStallResult{change: change, err: err}
				}()
				awaitEntered(t, v, done)
				// The first 12 rows go while the first page is being certified: the 288 kept rows are cut anew.
				erased := make(chan error, 1)
				go func() { erased <- r.eraseHead(context.Background(), big, 12) }()
				select {
				case err := <-erased:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(liveStallBound):
					t.Fatal("the erasure did not complete while an authority read of a live subscription waits: the engine lock is held across the control read")
				}
				v.free()
				var got []model.ID
				select {
				case res := <-done:
					if res.err != nil || res.change.Gap != nil || res.change.Revoked {
						t.Fatalf("Next after the rewrite: %+v, %v", res.change, res.err)
					}
					got = append(got, res.change.Page.IDs...)
				case <-time.After(liveStallBound):
					t.Fatal("Next did not end after the authority answered")
				}
				got = r.drainUntilIdle(got, 288)
				r.quiet()
				r.requireRows(got, idsOf(big[12:]))
			})
		}
	}
}
