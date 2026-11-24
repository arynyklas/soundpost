// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// TestConcurrentAdmissionsShareTheirCommits is the red test of the throughput floor of admission (07.06
// #11): every reservation was its own replicated control command, one at a time (a journal fsync and the
// two fsyncs of the database apply, about 2.5 ms on the gate's virtual disk), so the installation
// admitted at most one batch per commit however many writers waited. Writers that wait for a commit have
// to be committed together: sixteen writers admitting concurrently must cost a fraction of one command
// per admission, and every admission must be in the books afterwards.
func TestConcurrentAdmissionsShareTheirCommits(t *testing.T) {
	f := newFenceFxPatch(t)
	if _, err := reserveSeries(f, "group_warmup"); err != nil {
		t.Fatal(err)
	}
	before, _ := f.store.StatePatchStatsForTest()
	const workers, each = 16, 24
	var wg sync.WaitGroup
	got := make([][]model.AdmissionReservation, workers)
	errs := make(chan error, workers*each)
	start := time.Now()
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				r, err := reserveSeries(f, fmt.Sprintf("group_%02d_%03d", w, i))
				if err != nil {
					errs <- err
					return
				}
				got[w] = append(got[w], r)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	close(errs)
	for err := range errs {
		t.Fatal("admit:", err)
	}
	after, _ := f.store.StatePatchStatsForTest()
	commands, total := after-before, workers*each
	t.Logf("%d concurrent admissions in %v took %d control commands", total, elapsed, commands)
	if commands > uint64(total/3) {
		t.Errorf("%d admissions took %d control commands: the writers that waited for a commit were not committed together", total, commands)
	}
	if err := f.store.ViewAdmission(f.ctx, func(_ control.State, books auth.AdmissionReader) error {
		for _, rs := range got {
			for _, r := range rs {
				stored, ok, err := books.Reservation(r.ID.String())
				if err != nil || !ok || stored.Hash != r.Hash || stored.State != "reserved" {
					return fmt.Errorf("reservation %s is not in the books as reserved: %+v %v %v", r.ID, stored, ok, err)
				}
			}
		}
		return nil
	}); err != nil {
		t.Error(err)
	}
}

// TestViewUnderWithoutBooksDoesNotAssembleTheLedger is the red test of the cost of the background loops of a
// live server: every pass of the workers and the fences read the state with View, which assembles the whole
// admission ledger into it (at the single-host gate's cardinality a few hundred thousand records, most of a
// second of CPU for each read), although none of them looks at a reservation or a quota record. A read under a
// context that says so does not pay for the books; a read without it still gets them.
func TestViewUnderWithoutBooksDoesNotAssembleTheLedger(t *testing.T) {
	f := newFenceFxPatch(t)
	const admitted = 300
	for i := range admitted {
		if _, err := reserveSeries(f, fmt.Sprintf("books_%03d", i)); err != nil {
			t.Fatal(err)
		}
	}
	read := func(ctx context.Context) (reservations, quotas int, alloc uint64) {
		t.Helper()
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		if err := f.store.View(ctx, func(st control.State) error {
			reservations, quotas = len(st.Reservations), len(st.Quotas)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		runtime.ReadMemStats(&after)
		return reservations, quotas, after.TotalAlloc - before.TotalAlloc
	}
	reservations, quotas, whole := read(f.ctx)
	if reservations < admitted || quotas == 0 {
		t.Fatalf("View without the marker holds %d reservations and %d quota keys: the books are not assembled", reservations, quotas)
	}
	reservations, quotas, light := read(control.WithoutBooks(f.ctx))
	t.Logf("View: %d B with the books, %d B under WithoutBooks", whole, light)
	if reservations != 0 || quotas != 0 {
		t.Errorf("View under WithoutBooks holds %d reservations and %d quota keys, want none", reservations, quotas)
	}
	if light*4 > whole {
		t.Errorf("View under WithoutBooks allocated %d B against %d B with the books: the ledger is still read", light, whole)
	}
}

// TestSharedReadsDoNotDecodeAgainAfterAnAdmissionRound is the red test of the append path of the data engine
// (07.06#11): every batch it appends asks control for the active deletions (Store.ActiveDeletions, ViewShared),
// and ViewShared kept its decode of the state for one bolt transaction only, so the read that followed any
// control commit decoded the whole state again (1.8 MB at the gate's estate, 10 ms or more of CPU, with the
// engine's append lock held): the live server appended 25 batches a second. An admission round steps the
// revision and writes ledger records and leaves the rest of the state as it is, so the decode of the
// state before it is still the state.
func TestSharedReadsDoNotDecodeAgainAfterAnAdmissionRound(t *testing.T) {
	f := newFenceFxPatch(t)
	read := func() {
		t.Helper()
		if err := f.store.ViewShared(f.ctx, func(ro model.ReadOnlyControl) error { _ = ro.Revision(); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	read()
	decodes := f.store.SharedDecodesForTest()
	for i := range 20 {
		if _, err := reserveSeries(f, fmt.Sprintf("shared_%02d", i)); err != nil {
			t.Fatal(err)
		}
		read()
	}
	if got := f.store.SharedDecodesForTest() - decodes; got > 1 {
		t.Errorf("20 admissions, each followed by a shared read, made %d whole-state decodes, want at most 1", got)
	}
}

// A reader whose transaction began before another reader published its decode still gets that decode while no
// write changed the blob in between: under the live load (6,000 requests in flight, a control commit every
// 10 ms) the readers that began a moment before the freshest decode each decoded 1.8 MB on their own, 19 % of
// the server's CPU (perf of L2w20Admission6/p1).
func TestAnOlderReaderUsesTheNewerSharedDecode(t *testing.T) {
	f := newFenceFxPatch(t)
	if _, err := reserveSeries(f, "older_reader"); err != nil {
		t.Fatal(err)
	}
	decoded, err := f.store.NewerDecodeServesAnOlderReaderForTest()
	if err != nil {
		t.Fatal(err)
	}
	if decoded != 0 {
		t.Fatalf("a reader older than the shared decode, with no write to the blob between, made %d whole-state decodes, want 0", decoded)
	}
}

// TestReadinessFactsDoNotAssembleTheLedger is the red test of /readyz on a server that has admitted batches: the
// probe's reads of the control state (the schema marker, the pending source fences) went through View, which
// assembles the whole admission ledger, and the probe gives them one second. After 4 minutes of the single-host
// load (a few hundred thousand unsettled reservations) the read no longer fit, and the server answered
// state_unavailable to every probe (L2w20Admission8/rs6t), the restart that never became ready. The facts the probe
// needs are in the state without the books.
func TestReadinessFactsDoNotAssembleTheLedger(t *testing.T) {
	f := newFenceFxPatch(t)
	for i := range 300 {
		if _, err := reserveSeries(f, fmt.Sprintf("ready_%03d", i)); err != nil {
			t.Fatal(err)
		}
	}
	measure := func(read func() error) uint64 {
		t.Helper()
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		if err := read(); err != nil {
			t.Fatal(err)
		}
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}
	whole := measure(func() error { return f.store.View(f.ctx, func(control.State) error { return nil }) })
	var marker uint8
	var fencing uint64
	facts := measure(func() (err error) { marker, fencing, err = f.store.ReadinessFacts(f.ctx); return })
	t.Logf("View: %d B, ReadinessFacts: %d B", whole, facts)
	if marker == 0 || fencing != 0 {
		t.Errorf("ReadinessFacts: marker %d, fencing %d", marker, fencing)
	}
	if facts*8 > whole {
		t.Errorf("ReadinessFacts allocated %d B against %d B of a View with the books: the ledger is still read", facts, whole)
	}
}
