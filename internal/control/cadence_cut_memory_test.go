// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/replica"
)

// 11.05-W1. The 11.05 report measured peak RSS 74 MB without the cadence and 98 MB with it on a
// 4300-command storm and attributed the 24 MB to the cut building the snapshot envelope and
// rewriting the journal in memory. This measures what one cut itself allocates and holds, on a
// journal that has grown to many times the state: a cut that materialised the journal (or a copy of
// it per voter) would allocate and peak at the size of the journal; one that works from the state
// and the retry table allocates and peaks at a small multiple of the state.

// cutProbe is the memory a cut used: the bytes it allocated, and how far the live heap rose above
// where it started, sampled every half millisecond while it ran.
type cutProbe struct {
	allocated uint64
	peakAbove uint64
	took      time.Duration
}

func probeCut(t *testing.T, cut func()) cutProbe {
	t.Helper()
	// A collector that runs at 2% growth keeps HeapAlloc near what is live, so the sampled peak is
	// what the cut holds and not the garbage it leaves for the next collection.
	defer debug.SetGCPercent(debug.SetGCPercent(2))
	runtime.GC()
	runtime.GC()
	var base, end runtime.MemStats
	runtime.ReadMemStats(&base)
	var mu sync.Mutex
	peak := base.HeapAlloc
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		var ms runtime.MemStats
		for {
			runtime.ReadMemStats(&ms)
			mu.Lock()
			peak = max(peak, ms.HeapAlloc)
			mu.Unlock()
			select {
			case <-stop:
				return
			case <-time.After(500 * time.Microsecond):
			}
		}
	}()
	began := time.Now()
	cut()
	took := time.Since(began)
	close(stop)
	<-done
	runtime.ReadMemStats(&end)
	mu.Lock()
	defer mu.Unlock()
	return cutProbe{allocated: end.TotalAlloc - base.TotalAlloc, peakAbove: peak - base.HeapAlloc, took: took}
}

// A cut's memory does not grow with the journal: the same state is cut with a journal of 20
// commands and again with a journal five times as long, and the second cut allocates and holds
// about what the first did (the retry table grows by a fixed-size record per command).
func TestControlCutTransientMemoryDoesNotGrowWithTheJournal(t *testing.T) {
	dir := t.TempDir()
	s, _ := openTimed(t, dir, replica.Cadence{Commands: ^uint64(0)}) // the cadence is on and never fires: the test cuts
	t.Cleanup(func() { s.Close() })
	raft := filepath.Join(dir, "raft-control")
	g := s.ReplicaGroup()
	next := 0
	cutAt := func(commands int) (probe cutProbe, journal int64) {
		for range commands {
			commitShape(t, s, next, bigCommit)
			next++
		}
		journal = journalSize(t, raft)
		probe = probeCut(t, func() {
			ctx := context.Background()
			if _, err := g.CreateSnapshot(ctx, g.Status().ApplicationCursor); err != nil {
				t.Fatal(err)
			}
			if _, err := g.Snapshots().DropSuperseded(); err != nil {
				t.Fatal(err)
			}
			if _, err := g.CompactJournal(ctx); err != nil {
				t.Fatal(err)
			}
		})
		if after := journalSize(t, raft); after*4 > journal {
			t.Fatalf("fixture invalid: the cut left %d of %d bytes of journal", after, journal)
		}
		return probe, journal
	}
	small, smallJournal := cutAt(20)
	big, bigJournal := cutAt(100)
	var state []byte
	if err := s.View(context.Background(), func(st State) error {
		var err error
		state, err = json.Marshal(st)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	report := func(label string, p cutProbe, journal int64) {
		t.Logf("MEASURE cut (%s): state %d bytes, journal %d bytes; took %v, allocated %d bytes (%.1f x the state, %.2f x the journal), live heap rose by at most %d bytes (%.1f x the state, %.2f x the journal)",
			label, len(state), journal, p.took.Round(time.Millisecond), p.allocated, float64(p.allocated)/float64(len(state)), float64(p.allocated)/float64(journal), p.peakAbove, float64(p.peakAbove)/float64(len(state)), float64(p.peakAbove)/float64(journal))
	}
	report("journal of 20 commands", small, smallJournal)
	report("journal of 100 commands", big, bigJournal)
	if bigJournal < 4*smallJournal {
		t.Fatalf("fixture invalid: journals of %d and %d bytes", smallJournal, bigJournal)
	}
	// 1.5 x and a quarter of a megabyte: the retry table's 80 more records, and the sampler's noise.
	if limit := small.allocated*3/2 + 256<<10; big.allocated > limit {
		t.Errorf("a cut with a journal %d times as long allocated %d bytes, more than %d (the short journal's cut allocated %d)", bigJournal/smallJournal, big.allocated, limit, small.allocated)
	}
	if limit := small.peakAbove*3/2 + 1<<20; big.peakAbove > limit {
		t.Errorf("a cut with a journal %d times as long raised the live heap by %d bytes, more than %d (the short journal's cut: %d)", bigJournal/smallJournal, big.peakAbove, limit, small.peakAbove)
	}
	// What a cut that works from the journal would allocate is at least the journal's bytes more
	// for every journal byte more, so the allocation the extra 80 commands added must stay under
	// half of what they added to the journal. Both builds: measured 0.135 plain, 0.21 under -race.
	if grown, added := big.allocated-min(big.allocated, small.allocated), uint64(bigJournal-smallJournal); grown*2 > added {
		t.Errorf("the cut allocated %d bytes more for %d bytes more journal: it works from the journal, not from the state", grown, added)
	}
	// The whole allocation of the long journal's cut against half its journal. The state-sized
	// part of a cut (the envelope is marshalled, verified twice and rewritten) is a constant here:
	// 60 times the state plain, 68 under -race, and it is not the journal. The race build is
	// excluded from this one comparison only, for a measured cause: sync.Pool drops one Put in
	// four under -race (sync/pool.go), and encoding/json takes a pooled decoder or encoder state
	// for every value it decodes or encodes (jsontext/pools.go), so the many small values of the
	// retry table allocate that state again. Allocation profile of the cut (-memprofilerate=1,
	// deltas around each cut; evidence l1w12-evidence/prof): model.ID.UnmarshalJSON 1.8 MB under
	// -race, 0.05 MB plain, before IDs, hashes and cursors were decoded without it; what remains
	// is 10.3 MB against 8.3 MB plain at the same journal, which is over journal/2 only because of
	// this fixture's 19 MB journal. The marginal check above and the live-heap and 1.5 x checks
	// keep their bounds in the race build.
	if !raceBuild && big.allocated*2 > uint64(bigJournal) {
		t.Errorf("the cut allocated %d bytes for a journal of %d: it works from the journal, not from the state", big.allocated, bigJournal)
	}
}
