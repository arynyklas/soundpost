// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"fmt"
	"math/rand/v2"
	"os"
	"runtime"
	"runtime/pprof"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// laneBatches reserves and finalizes batches of six series drawn from a pool (the gate's shape: a reserve and a finalize per
// batch, each series counted under three quota tiers) from workers goroutines.
func laneBatches(t *testing.T, f *fenceFx, workers, each, pool int, seed uint64) {
	t.Helper()
	scope := sourceScopeOf(f)
	group := model.NewID()
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(seed, uint64(w)))
			for i := range each {
				names := make([]string, 6)
				for k := range names {
					names[k] = fmt.Sprintf("lane_series_%06d", rng.IntN(pool))
				}
				r, err := reserveBatchOf(f, names)
				if err != nil {
					errs <- err
					return
				}
				if err = f.store.FinalizeAdmission(f.ctx, scope, model.FinalizeAdmission{ReservationID: r.ID, Cursor: model.Cursor{Group: group, Index: model.Uint64(1 + int(seed)*1000000 + w*each + i)}}); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal("admit:", err)
	}
}

// TestLaneMeasure prints what a batch costs the lane (SOUNDPOST_LANE_MEASURE=1; a CPU profile of the measured window goes to the
// file named by SOUNDPOST_LANE_PROFILE).
func TestLaneMeasure(t *testing.T) {
	if os.Getenv("SOUNDPOST_LANE_MEASURE") == "" {
		t.Skip("measurement only")
	}
	f := newFenceFxCompact(t)
	if err := f.store.BindAdmissionOwner(&reconcileOwner{}); err != nil {
		t.Fatal(err)
	}
	const workers, pool = 48, 900 // the fixture source's quota is 1,000 series
	laneBatches(t, f, workers, 20, pool, 1)
	if p := os.Getenv("SOUNDPOST_LANE_PROFILE"); p != "" {
		out, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		defer out.Close()
		if err = pprof.StartCPUProfile(out); err != nil {
			t.Fatal(err)
		}
		defer pprof.StopCPUProfile()
	}
	rounds0, bytes0 := f.store.StatePatchStatsForTest()
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	const each = 150
	start := time.Now()
	laneBatches(t, f, workers, each, pool, 100)
	elapsed := time.Since(start)
	runtime.ReadMemStats(&m1)
	rounds1, bytes1 := f.store.StatePatchStatsForTest()
	n := float64(workers * each)
	t.Logf("per batch (2 items): %v wall, %.0f B alloc, %.0f mallocs, %.2f patches, %.0f patch bytes", elapsed/time.Duration(workers*each), float64(m1.TotalAlloc-m0.TotalAlloc)/n, float64(m1.Mallocs-m0.Mallocs)/n, float64(rounds1-rounds0)/n, float64(bytes1-bytes0)/n)
}
