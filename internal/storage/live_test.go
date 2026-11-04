// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"io"
	"reflect"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"sync"
	"testing"
	"time"
)

func TestCommittedSubscriptionGapAndRevocation(t *testing.T) {
	store, a, c, d := fixture(t)
	write, b := normalized(t, store, a, c, d)
	read := scanScope(t, store, a, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	it, err := e.Subscribe(context.Background(), read, SubscribeRequest{Projects: []model.ID{d.Project}, Signal: model.Metric})
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	receipt, err := e.Append(context.Background(), write, b)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	change, err := it.Next(ctx)
	if err != nil || change.Page.Len() != 1 || change.Cursors[0] != receipt.Cursor {
		t.Fatal("committed row absent", err)
	}
	// Real successive committed records overrun the finite apply channel.
	for i := range liveCapacity + 2 {
		row := b.Records[0]
		row.ID = model.NewID()
		row.ObservedAt = model.UnixNano(i + 2)
		appendTyped(t, e, store, a, c, d, row)
	}
	change, err = it.Next(ctx)
	if err != nil || change.Gap == nil || change.Gap.Reason != "slow_consumer" {
		t.Fatal("silent overrun", err)
	}
	if err = store.Update(context.Background(), func(st *control.State) error {
		o := st.Orgs[d.Org.String()]
		o.Epoch++
		st.Orgs[d.Org.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	change, err = it.Next(ctx)
	if err != nil || !change.Revoked || change.Page.Len() != 0 {
		t.Fatal("revocation leaked chunk", err)
	}
	if _, err = it.Next(ctx); err != io.EOF {
		t.Fatal("revoked stream remains open", err)
	}
}

// liveEnv bundles the real actual-Raft engine and the real authority used by
// the revoke/resume tests below.
type liveEnv struct {
	store *control.Store
	a     *auth.Service
	c     auth.SourceCredential
	d     model.SourceDescriptor
	e     *Engine
}

// deliveries counts how many times a consumer was handed each row, whether by a
// live page or by recovering a reported cursor window with a scan.
type deliveries map[model.ID]int

func (d deliveries) add(ids ...model.ID) {
	for _, id := range ids {
		d[id]++
	}
}
func (d deliveries) requireExactlyOnce(t *testing.T, want []model.ID) {
	t.Helper()
	for _, id := range want {
		if d[id] != 1 {
			t.Errorf("committed row %s was handed to the consumer %d times, want exactly once", id, d[id])
		}
	}
	if len(d) != len(want) {
		t.Errorf("consumer saw %d distinct rows, want %d", len(d), len(want))
	}
}
func cursorIndex(cursors []model.Cursor, group model.ID) model.Uint64 {
	for _, c := range cursors {
		if c.Group == group {
			return c.Index
		}
	}
	return 0
}
func advanceCursors(base []model.Cursor, cursor model.Cursor) []model.Cursor {
	out := append([]model.Cursor(nil), base...)
	for i := range out {
		if out[i].Group == cursor.Group && cursor.Index > out[i].Index {
			out[i] = cursor
		}
	}
	return out
}

// within reports whether a committed row's origin lies in (after, through].
func within(after, through []model.Cursor, origin model.Cursor) bool {
	high := cursorIndex(through, origin.Group)
	return origin.Index > cursorIndex(after, origin.Group) && origin.Index <= high
}
func (env liveEnv) revoke(t *testing.T) {
	t.Helper()
	if err := env.store.Update(context.Background(), func(st *control.State) error {
		o := st.Orgs[env.d.Org.String()]
		o.Epoch++
		st.Orgs[env.d.Org.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
func (env liveEnv) rows(t *testing.T, scope auth.Scope) map[model.ID]model.Cursor {
	t.Helper()
	it, err := env.e.Scan(context.Background(), scope, ScanRequest{Projects: []model.ID{env.d.Project}, Signal: model.Metric, End: 1 << 40})
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	out := map[model.ID]model.Cursor{}
	for {
		p, err := it.Next(context.Background())
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		for i := range p.IDs {
			out[p.IDs[i]] = p.Origins[i]
		}
	}
}
func (env liveEnv) appendRow(t *testing.T, base model.Record, at int) (model.ID, model.Receipt) {
	t.Helper()
	row := base
	row.ID = model.NewID()
	row.ObservedAt = model.UnixNano(at)
	return row.ID, appendTyped(t, env.e, env.store, env.a, env.c, env.d, row)
}

// resume reconnects with a fresh credential from the cursors a revoked stream
// advertised, recovers the catch-up window it reports by scanning exactly that
// window, then requires a row committed after reconnect to arrive live once.
func (env liveEnv) resume(t *testing.T, ctx context.Context, advertised []model.Cursor, got deliveries, base model.Record, at int) model.ID {
	t.Helper()
	scope := scanScope(t, env.store, env.a, env.d)
	it, err := env.e.Subscribe(ctx, scope, SubscribeRequest{Projects: []model.ID{env.d.Project}, Signal: model.Metric, After: advertised})
	if err != nil {
		t.Fatalf("resume from advertised cursors: %v", err)
	}
	defer it.Close()
	probe, _ := env.appendRow(t, base, at)
	change, err := it.Next(ctx)
	if err != nil || change.Gap == nil || change.Gap.Reason != "catch_up_required" || change.Page.Len() != 0 {
		t.Fatalf("committed rows after the advertised cursors were skipped on resume: gap=%+v rows=%d err=%v", change.Gap, change.Page.Len(), err)
	}
	if !reflect.DeepEqual(change.Gap.After, advertised) {
		t.Fatalf("catch-up window starts at %v, want the advertised %v", change.Gap.After, advertised)
	}
	env.recoverGap(t, scope, got, change.Gap)
	change, err = it.Next(ctx)
	if err != nil || change.Page.Len() != 1 || change.Page.IDs[0] != probe || change.Gap != nil {
		t.Fatalf("row committed after resume was not delivered live exactly once: %+v %v", change, err)
	}
	got.add(change.Page.IDs...)
	return probe
}

// recoverGap is what a consumer does with a reported window: scan exactly
// (After, Through] and take responsibility for those rows.
func (env liveEnv) recoverGap(t *testing.T, scope auth.Scope, got deliveries, gap *ChangeGap) {
	t.Helper()
	for id, origin := range env.rows(t, scope) {
		if within(gap.After, gap.Through, origin) {
			got.add(id)
		}
	}
}

// revokingValidator delegates to the real authority and, once armed, performs a
// real revocation (organization epoch bump) just before the n-th validation
// that follows, so a revocation can land inside a chosen Next call.
type revokingValidator struct {
	inner  Revalidator
	mu     sync.Mutex
	calls  int
	fireAt int
	fired  bool
	fire   func()
}

func (v *revokingValidator) Revalidate(ctx context.Context, scope auth.Scope) error {
	v.mu.Lock()
	v.calls++
	hit := v.fireAt != 0 && v.calls == v.fireAt
	v.fired = v.fired || hit
	v.mu.Unlock()
	if hit {
		v.fire()
	}
	return v.inner.Revalidate(ctx, scope)
}
func (v *revokingValidator) count() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls
}
func (v *revokingValidator) arm(after int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.fireAt = v.calls + after
}
func (v *revokingValidator) hasFired() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.fired
}

// A subscriber that overran the ring and is then revoked must still be told the
// explicit slow_consumer gap, and the cursors it carries away must let it resume
// without losing or repeating any committed row.
func TestRevokeAfterOverrunReportsGapAndResumesExactlyOnce(t *testing.T) {
	store, a, c, d := fixture(t)
	write, b := normalized(t, store, a, c, d)
	read := scanScope(t, store, a, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	env := liveEnv{store, a, c, d, e}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	it, err := e.Subscribe(ctx, read, SubscribeRequest{Projects: []model.ID{d.Project}, Signal: model.Metric})
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	subscribed := it.Watermarks()
	got, want := deliveries{}, []model.ID{b.Records[0].ID}
	first, err := e.Append(ctx, write, b)
	if err != nil {
		t.Fatal(err)
	}
	change, err := it.Next(ctx)
	if err != nil || change.Page.Len() != 1 || change.Cursors[0] != first.Cursor {
		t.Fatal("first committed row absent", err)
	}
	got.add(change.Page.IDs...)
	deliveredFirst := advanceCursors(subscribed, first.Cursor)
	var last model.Receipt
	for i := range liveCapacity + 2 {
		var id model.ID
		id, last = env.appendRow(t, b.Records[0], i+2)
		want = append(want, id)
	}
	env.revoke(t)

	// Drain the stream exactly as a consumer would: recover every reported gap
	// window, remember the last advertised cut, stop at EOF.
	var gaps []*ChangeGap
	var revoke ChangePage
	for pages := 0; ; pages++ {
		change, err = it.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil || pages > 2 || change.Page.Len() != 0 {
			t.Fatalf("unexpected page after revocation: %+v %v", change, err)
		}
		if change.Gap != nil {
			if revoke.Revoked {
				t.Fatal("gap reported after the stream was revoked")
			}
			gaps = append(gaps, change.Gap)
			env.recoverGap(t, scanScope(t, store, a, d), got, change.Gap)
		}
		if change.Revoked {
			revoke = change
		}
	}
	if len(gaps) != 1 || gaps[0].Reason != "slow_consumer" {
		t.Errorf("revocation swallowed the pending slow_consumer gap: %d gaps reported", len(gaps))
	} else if !reflect.DeepEqual(gaps[0].After, deliveredFirst) || cursorIndex(gaps[0].Through, first.Cursor.Group) <= first.Cursor.Index {
		t.Errorf("gap does not cover the undelivered window: after@%d through@%d delivered@%d", cursorIndex(gaps[0].After, first.Cursor.Group), cursorIndex(gaps[0].Through, first.Cursor.Group), first.Cursor.Index)
	}
	if !revoke.Revoked {
		t.Fatal("stream ended without a revoke page")
	}
	// The advertised cut is the delivered prefix plus the window the gap handed
	// over; it must never run ahead of that.
	cut := deliveredFirst
	if len(gaps) == 1 {
		cut = gaps[0].Through
	}
	if !reflect.DeepEqual(revoke.Cursors, cut) {
		t.Errorf("revoke advertised cut @%d, want the delivered cut @%d (last committed @%d)", cursorIndex(revoke.Cursors, first.Cursor.Group), cursorIndex(cut, first.Cursor.Group), last.Cursor.Index)
	}
	want = append(want, env.resume(t, ctx, revoke.Cursors, got, b.Records[0], liveCapacity+10))
	got.requireExactlyOnce(t, want)
}

// Rows committed but not yet handed to the consumer when it is revoked must not
// be advertised as delivered: resuming from the revoke cursors must replay them.
func TestRevokeWithQueuedUndeliveredRowsAdvertisesOnlyDeliveredCut(t *testing.T) {
	store, a, c, d := fixture(t)
	write, b := normalized(t, store, a, c, d)
	read := scanScope(t, store, a, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	env := liveEnv{store, a, c, d, e}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	it, err := e.Subscribe(ctx, read, SubscribeRequest{Projects: []model.ID{d.Project}, Signal: model.Metric})
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	subscribed := it.Watermarks()
	got, want := deliveries{}, []model.ID{b.Records[0].ID}
	first, err := e.Append(ctx, write, b)
	if err != nil {
		t.Fatal(err)
	}
	change, err := it.Next(ctx)
	if err != nil || change.Page.Len() != 1 || change.Cursors[0] != first.Cursor {
		t.Fatal("first committed row absent", err)
	}
	got.add(change.Page.IDs...)
	deliveredFirst := advanceCursors(subscribed, first.Cursor)
	var last model.Receipt
	for i := range 3 {
		var id model.ID
		id, last = env.appendRow(t, b.Records[0], i+2)
		want = append(want, id)
	}
	env.revoke(t)

	change, err = it.Next(ctx)
	if err != nil || !change.Revoked || change.Page.Len() != 0 || change.Gap != nil {
		t.Fatalf("revocation leaked a chunk or invented a gap without an overrun: %+v %v", change, err)
	}
	if cursorIndex(change.Cursors, last.Cursor.Group) >= last.Cursor.Index {
		t.Errorf("revoke advertised cut @%d covering committed rows the consumer never received (last committed @%d)", cursorIndex(change.Cursors, last.Cursor.Group), last.Cursor.Index)
	}
	if !reflect.DeepEqual(change.Cursors, deliveredFirst) {
		t.Errorf("revoke advertised cut @%d, want exactly the delivered cut @%d", cursorIndex(change.Cursors, last.Cursor.Group), cursorIndex(deliveredFirst, last.Cursor.Group))
	}
	if _, err = it.Next(ctx); err != io.EOF {
		t.Fatal("revoked stream remains open", err)
	}
	want = append(want, env.resume(t, ctx, change.Cursors, got, b.Records[0], 10))
	got.requireExactlyOnce(t, want)
}

// A revocation that lands after Next's first check passed, inside the release
// barrier, takes the failLocked exit instead of the top-of-Next exit. It must
// give the same guarantees: no rows, a pending gap still reported, and only the
// delivered cut advertised.
func TestRevocationInsideReleaseBarrierAdvertisesOnlyDeliveredCut(t *testing.T) {
	for _, overrun := range []bool{false, true} {
		name := "queued row"
		if overrun {
			name = "pending gap"
		}
		t.Run(name, func(t *testing.T) {
			store, a, c, d := fixture(t)
			write, b := normalized(t, store, a, c, d)
			read := scanScope(t, store, a, d)
			v := &revokingValidator{inner: a}
			e, err := openTestEngine(t, t.TempDir(), v, store)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			env := liveEnv{store, a, c, d, e}
			v.fire = func() { env.revoke(t) }
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			it, err := e.Subscribe(ctx, read, SubscribeRequest{Projects: []model.ID{d.Project}, Signal: model.Metric})
			if err != nil {
				t.Fatal(err)
			}
			defer it.Close()
			subscribed := it.Watermarks()
			got, want := deliveries{}, []model.ID{b.Records[0].ID}
			first, err := e.Append(ctx, write, b)
			if err != nil {
				t.Fatal(err)
			}
			// A healthy delivering Next calibrates the injection point: its final
			// validation is the re-check after the release barrier.
			before := v.count()
			change, err := it.Next(ctx)
			if err != nil || change.Page.Len() != 1 || change.Cursors[0] != first.Cursor {
				t.Fatal("first committed row absent", err)
			}
			got.add(change.Page.IDs...)
			delivered := advanceCursors(subscribed, first.Cursor)
			var revoke ChangePage
			if !overrun {
				calls := v.count() - before
				if calls < 2 {
					t.Fatalf("a delivering Next validated %d times; no release-barrier re-check to target", calls)
				}
				id, _ := env.appendRow(t, b.Records[0], 2)
				want = append(want, id)
				v.arm(calls)
				change, err = it.Next(ctx)
				if err != nil || !change.Revoked || change.Page.Len() != 0 || change.Gap != nil {
					t.Fatalf("revocation inside the release barrier leaked a chunk or invented a gap: %+v %v", change, err)
				}
				revoke = change
			} else {
				burst := func(from int) {
					for i := range liveCapacity + 2 {
						id, _ := env.appendRow(t, b.Records[0], from+i)
						want = append(want, id)
					}
				}
				burst(2)
				before = v.count()
				change, err = it.Next(ctx)
				if err != nil || change.Revoked || change.Gap == nil || change.Gap.Reason != "slow_consumer" {
					t.Fatalf("overrun gap absent on a healthy stream: %+v %v", change, err)
				}
				calls := v.count() - before
				if calls < 2 {
					t.Fatalf("a gap-delivering Next validated %d times; no release-barrier re-check to target", calls)
				}
				env.recoverGap(t, scanScope(t, store, a, d), got, change.Gap)
				burst(200)
				v.arm(calls)
				change, err = it.Next(ctx)
				if err != nil || change.Revoked || change.Page.Len() != 0 || change.Gap == nil || change.Gap.Reason != "slow_consumer" {
					t.Fatalf("revocation inside the gap's release barrier swallowed the pending gap: %+v %v", change, err)
				}
				env.recoverGap(t, scanScope(t, store, a, d), got, change.Gap)
				delivered = change.Gap.Through
				change, err = it.Next(ctx)
				if err != nil || !change.Revoked || change.Page.Len() != 0 || change.Gap != nil {
					t.Fatalf("revoke page after the reported gap leaked data or repeated the gap: %+v %v", change, err)
				}
				revoke = change
			}
			if !v.hasFired() {
				t.Fatal("revocation was never injected into the targeted Next")
			}
			if !reflect.DeepEqual(revoke.Cursors, delivered) {
				t.Errorf("revoke advertised cut @%d, want the delivered cut @%d", cursorIndex(revoke.Cursors, first.Cursor.Group), cursorIndex(delivered, first.Cursor.Group))
			}
			if _, err = it.Next(ctx); err != io.EOF {
				t.Fatal("revoked stream remains open", err)
			}
			want = append(want, env.resume(t, ctx, revoke.Cursors, got, b.Records[0], 1000))
			got.requireExactlyOnce(t, want)
		})
	}
}

// A consumer resuming from a stale cursor is owed every row committed after it.
// When the live ring overruns before the consumer takes the pending catch-up
// gap, the replacement gap must still begin at that stale cursor. If it began
// at the watermark the subscription started from, the rows between the stale
// cursor and that watermark would never be reported or delivered.
func TestStaleAfterCatchUpSurvivesOverrunBeforeFirstNext(t *testing.T) {
	store, a, c, d := fixture(t)
	_, b := normalized(t, store, a, c, d)
	read := scanScope(t, store, a, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	env := liveEnv{store, a, c, d, e}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req := SubscribeRequest{Projects: []model.ID{d.Project}, Signal: model.Metric}
	origin, err := e.Subscribe(ctx, read, req)
	if err != nil {
		t.Fatal(err)
	}
	base := origin.Watermarks()
	_ = origin.Close()

	// The consumer saw the first two rows, then lost its stream; three more
	// rows commit before it resumes, so its cursor is stale at resume time.
	const seen = 2
	var committed []model.ID
	var receipts []model.Receipt
	for i := range 5 {
		id, receipt := env.appendRow(t, b.Records[0], i+1)
		committed, receipts = append(committed, id), append(receipts, receipt)
	}
	stale := advanceCursors(base, receipts[seen-1].Cursor)
	req.After = stale
	it, err := e.Subscribe(ctx, read, req)
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()

	// The consumer is slow: it does not take the pending catch-up gap before
	// enough commits arrive to overrun the finite live ring.
	want := append([]model.ID(nil), committed[seen:]...)
	for i := range liveCapacity + 2 {
		id, _ := env.appendRow(t, b.Records[0], 100+i)
		want = append(want, id)
	}

	got := deliveries{}
	change, err := it.Next(ctx)
	if err != nil || change.Gap == nil || change.Page.Len() != 0 {
		t.Fatalf("overrun before the first Next was not reported as a gap: %+v %v", change, err)
	}
	for _, after := range change.Gap.After {
		if after.Index > cursorIndex(stale, after.Group) {
			t.Errorf("%s gap begins at @%d, after the consumer's stale cursor @%d: committed rows in (@%d, @%d] are never reported", change.Gap.Reason, after.Index, cursorIndex(stale, after.Group), cursorIndex(stale, after.Group), after.Index)
		}
	}
	env.recoverGap(t, scanScope(t, store, a, d), got, change.Gap)

	// Commits that landed after the gap's cut (the ring overruns on the 65th
	// event, so the 66th is queued behind it) arrive live, one page each, and
	// must not repeat rows the gap window already handed over.
	live, _ := env.appendRow(t, b.Records[0], 1000)
	want = append(want, live)
	for done := false; !done; {
		change, err = it.Next(ctx)
		if err != nil || change.Gap != nil || change.Page.Len() != 1 {
			t.Fatalf("committed row after the gap was not delivered live: %+v %v", change, err)
		}
		got.add(change.Page.IDs...)
		done = change.Page.IDs[0] == live
	}
	got.requireExactlyOnce(t, want)
}
func TestSubscriptionCancelledWithoutCommitReleases(t *testing.T) {
	store, a, _, d := fixture(t)
	read := scanScope(t, store, a, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx, cancel := context.WithCancel(context.Background())
	it, err := e.Subscribe(ctx, read, SubscribeRequest{Projects: []model.ID{d.Project}, Signal: model.Metric})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err = it.Next(ctx); err == nil {
		t.Fatal("cancel ignored")
	}
	if e.Stats().ActiveIterators != 0 {
		t.Fatal("subscription retained")
	}
}
func TestUncommittedAppendNeverPublishes(t *testing.T) {
	store, a, c, d := fixture(t)
	write, b := normalized(t, store, a, c, d)
	read := scanScope(t, store, a, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	it, err := e.Subscribe(context.Background(), read, SubscribeRequest{Projects: []model.ID{d.Project}, Signal: model.Metric})
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	e.fault = func(at string) error {
		if at == "before_apply" {
			return io.ErrShortWrite
		}
		return nil
	}
	if _, err = e.Append(context.Background(), write, b); err == nil {
		t.Fatal("unapplied entry ACKed")
	}
	page, err := it.Next(context.Background())
	if err == nil || page.Page.Len() != 0 {
		t.Fatal("uncommitted row became visible")
	}
}
