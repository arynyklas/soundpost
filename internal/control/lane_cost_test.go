// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// laneWindow admits n batches of the gate's shape through workers writers and answers what the rounds that carried them cost.
func laneWindow(t *testing.T, f *fenceFx, estate []gateSource, group model.ID, first, n, workers, seriesPerBatch int, rng *rand.Rand) control.LaneCost {
	t.Helper()
	type job struct {
		source int
		names  []string
	}
	jobs := make([]job, n)
	for i := range jobs {
		picked := map[int]bool{}
		names := make([]string, 0, seriesPerBatch)
		for len(names) < seriesPerBatch {
			s := rng.IntN(2000)
			if !picked[s] {
				picked[s] = true
				names = append(names, fmt.Sprintf("lane_series_%05d", s))
			}
		}
		jobs[i] = job{source: rng.IntN(len(estate)), names: names}
	}
	next := make(chan int, n)
	for i := range n {
		next <- i
	}
	close(next)
	before := f.store.LaneCostForTest()
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				if err := admitBatch(f, estate[jobs[i].source], jobs[i].names, model.Cursor{Group: group, Index: model.Uint64(first + i + 1)}); err != nil {
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
	after := f.store.LaneCostForTest()
	return control.LaneCost{
		Rounds: after.Rounds - before.Rounds, Items: after.Items - before.Items, PatchBytes: after.PatchBytes - before.PatchBytes,
		Build: after.Build - before.Build, Propose: after.Propose - before.Propose, Lock: after.Lock - before.Lock,
	}
}

// TestMeasureLaneCostByRoundSize is a measurement: the time a lane item costs (judging it in the round, proposing the round) and the
// patch bytes it carries, at round sizes from a few items to a hundred, on a ledger that has taken history.
func TestMeasureLaneCostByRoundSize(t *testing.T) {
	f := newFenceFxPatch(t)
	if err := f.store.BindAdmissionOwner(&reconcileOwner{}); err != nil {
		t.Fatal(err)
	}
	estate := f.addGateEstate(50)
	rng := rand.New(rand.NewPCG(3, 4))
	group := model.NewID()
	first := 0
	for _, workers := range []int{4, 4, 16, 64, 128, 16, 4} {
		const n = 2000
		c := laneWindow(t, f, estate, group, first, n, workers, 12, rng)
		first += n
		if c.Items == 0 {
			t.Fatal("no round carried an item")
		}
		items := float64(c.Items)
		t.Logf("workers %3d: %5.1f items/round, build %5.0f us/item (%6.2f ms/round), propose %5.0f us/item (%6.2f ms/round), %5.0f B/item", workers,
			items/float64(c.Rounds), float64(c.Build/time.Microsecond)/items, float64(c.Build)/float64(c.Rounds)/1e6,
			float64(c.Propose/time.Microsecond)/items, float64(c.Propose)/float64(c.Rounds)/1e6, float64(c.PatchBytes)/items)
	}
}
