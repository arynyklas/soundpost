// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"fmt"
	"math/rand/v2"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// TestMeasureAdmissionLatencyThroughAGateHistory is a measurement (L2w20Admission29): the latency of every admission of the gate's
// shape (100 sources of 1,000 series, a batch of 20 series, 32 writers) through 60,000 admissions, by window: the median, the 99.9th
// percentile and the longest, and how many took more than a quarter of a second.
func TestMeasureAdmissionLatencyThroughAGateHistory(t *testing.T) {
	f := newFenceFxPatch(t)
	if err := f.store.BindAdmissionOwner(&reconcileOwner{}); err != nil {
		t.Fatal(err)
	}
	shape := gateShape{sources: 100, seriesPerSource: 1000, seriesPerBatch: 20, workers: 32}
	estate := f.addGateEstate(shape.sources)
	const window, windows = 5000, 12
	rng := rand.New(rand.NewPCG(1, 2))
	group := model.NewID()
	for w := range windows {
		lat := make([]time.Duration, window)
		type job struct {
			source int
			names  []string
		}
		jobs := make([]job, window)
		for i := range jobs {
			picked := map[int]bool{}
			names := make([]string, 0, shape.seriesPerBatch)
			for len(names) < shape.seriesPerBatch {
				s := rng.IntN(shape.seriesPerSource)
				if !picked[s] {
					picked[s] = true
					names = append(names, fmt.Sprintf("gate_series_%04d", s))
				}
			}
			jobs[i] = job{source: rng.IntN(len(estate)), names: names}
		}
		next := make(chan int, window)
		for i := range window {
			next <- i
		}
		close(next)
		var wg sync.WaitGroup
		errs := make(chan error, shape.workers)
		begin := time.Now()
		for range shape.workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range next {
					b := time.Now()
					if err := admitBatch(f, estate[jobs[i].source], jobs[i].names, model.Cursor{Group: group, Index: model.Uint64(w*window + i + 1)}); err != nil {
						errs <- err
						return
					}
					lat[i] = time.Since(b)
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal("admit:", err)
		}
		took := time.Since(begin)
		sorted := append([]time.Duration(nil), lat...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		slow := 0
		for _, d := range sorted {
			if d > 250*time.Millisecond {
				slow++
			}
		}
		t.Logf("admissions %6d-%6d in %v: p50 %v p99 %v p99.9 %v max %v, %d over 250 ms", w*window, (w+1)*window, took.Round(time.Millisecond), sorted[window/2], sorted[window*99/100], sorted[window*999/1000], sorted[window-1], slow)
	}
}
