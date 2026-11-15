// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"sync"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// [11.04-W5, hazard 1] bolt registers a reader and only then updates Stats().OpenTxN, so a scrub
// that trusted the stat could zero pages a reader that is just beginning may still walk. The
// engine counts its readers itself before bolt sees them: a reader caught in that window defers
// the scrub, and the rerun finishes it.
func TestScrubDefersToAReaderBoltHasNotCountedYet(t *testing.T) {
	x := newEraseEnv(t)
	x.appendMixed(eraseCanary, bothDeadlines)
	x.e.scrub = scrubConfig{attempts: 1}
	entered, release := make(chan struct{}), make(chan struct{})
	gap := func() { close(entered); <-release }
	x.e.db.viewGap.Store(&gap)
	finished := make(chan error, 1)
	go func() { finished <- x.e.db.View(func(*bolt.Tx) error { return nil }) }()
	<-entered
	if n := x.e.db.Stats().OpenTxN; n != 0 {
		t.Fatalf("fixture invalid: bolt already counts %d readers", n)
	}
	preds := []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}
	first, err := x.e.EraseDeleted(context.Background(), preds, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !first.ScrubPending {
		t.Fatalf("the scrub ran past a reader that was about to begin: %+v", first)
	}
	if applyFileHits(t, x.e, eraseCanary) == 0 {
		t.Fatal("pages a beginning reader may read were zeroed")
	}
	close(release)
	if err = <-finished; err != nil {
		t.Fatal(err)
	}
	second, err := x.e.EraseDeleted(context.Background(), preds, nil)
	if err != nil || second.ScrubPending || second.PagesScrubbed == 0 {
		t.Fatalf("rerun %+v %v", second, err)
	}
	if n := applyFileHits(t, x.e, eraseCanary); n != 0 {
		t.Fatalf("%d copies remain after the rerun", n)
	}
	checkDatabase(t, x.e)
}

// [11.04-W5, hazard 2] A test installs and removes the engine's fault hook while group goroutines
// are already calling trip: under -race the hook must be read and written without a data race.
func TestFaultHookCanBeReplacedWhileGoroutinesTripIt(t *testing.T) {
	x := newEraseEnv(t)
	stop, done := make(chan struct{}), sync.WaitGroup{}
	for range 4 {
		done.Add(1)
		go func() {
			defer done.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = x.e.trip("point")
				}
			}
		}()
	}
	for range 2000 {
		x.e.setFault(func(string) error { return nil })
		x.e.setFault(nil)
	}
	close(stop)
	done.Wait()
}
