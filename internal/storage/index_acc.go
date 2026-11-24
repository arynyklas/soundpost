// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// runsRegistry is the bucket whose presence marks a database in the runs layout: the query indexes
// (scan_time, scan_postings) are the union of their base bucket and sorted run buckets (index_runs.go),
// and one bolt commit writes the index keys of all the appends it carries as ONE new run, in key
// order, instead of one random insert per key (L2w20Admission5: 32 of the 55 bolt nodes an acknowledged
// append dirtied were scan_postings inserts). A file starts in the single-bucket layout, which the
// previous release reads; it moves to this layout when the installation is contracted (the previous
// release is no member and cannot become one: D70/D72), because the previous release refuses a
// database whose scan_index_version is not 1 (initStorage).
const runsRegistry = "scan_runs"

// scanIndexVersion is the value of meta/scan_index_version: 1 the single-bucket layout, 2 the runs layout of
// the query indexes only (written by builds before the row store: opened as is and moved to 3, because from then
// on rows are in runs that such a build would not read), 3 the runs layout with the row store (rows.go).
const (
	scanIndexClassic = 1
	scanIndexRuns    = 2
	scanIndexRows    = 3
	// scanIndexPayload is the rows layout with the owned payload log (paylog.go): bolt may hold payload references. A build that does
	// not know the log refuses the file (it accepts only 1 to 3).
	scanIndexPayload = 4
)

// indexAccumulator collects the index pairs of the appends of one write transaction, and the rows
// (pairs of the index rowsIndex, with their position by key so that a row the commit holds is found).
type indexAccumulator struct {
	pairs  map[string][]indexPair
	rowIdx map[string]int
	rows   *rowStore // the row store of the transaction (rowsOf), dropped when the run of its rows is written
}

var indexAccumulators sync.Map // *bolt.Tx -> *indexAccumulator

func accumulatorOf(tx *bolt.Tx) *indexAccumulator {
	v, ok := indexAccumulators.Load(tx)
	if !ok {
		return nil
	}
	return v.(*indexAccumulator)
}

func (a *indexAccumulator) add(name string, pairs []indexPair) {
	a.pairs[name] = append(a.pairs[name], pairs...)
}

// flush writes what is collected as one run per index and empties the accumulator. The rows of the commit
// (rows.go) are one run of their own index, collected beside the query indexes.
func (a *indexAccumulator) flush(tx *bolt.Tx) error {
	for _, name := range []string{"scan_time", "scan_postings", rowsIndex} {
		pairs := a.pairs[name]
		if len(pairs) == 0 {
			continue
		}
		if err := writeIndexRun(tx, name, pairs); err != nil {
			return err
		}
		clear(pairs)
		a.pairs[name] = pairs[:0]
		if name == rowsIndex {
			clear(a.rowIdx)
			a.rows = nil // its list of runs is out of date
		}
	}
	return nil
}

// withIndexRun runs fn, which may apply several appends in tx, and writes their index keys as one
// run before the transaction commits. In the single-bucket layout it is fn.
func withIndexRun(tx *bolt.Tx, fn func() error) error {
	if tx.Bucket([]byte(runsRegistry)) == nil {
		return fn()
	}
	a := &indexAccumulator{pairs: map[string][]indexPair{}, rowIdx: map[string]int{}}
	indexAccumulators.Store(tx, a)
	defer indexAccumulators.Delete(tx)
	if err := fn(); err != nil {
		return err
	}
	return a.flush(tx)
}

// flushIndexRun writes the keys collected so far (an entry that reads or deletes index entries must
// find those of the entries before it in the commit).
func flushIndexRun(tx *bolt.Tx) error {
	if a := accumulatorOf(tx); a != nil {
		return a.flush(tx)
	}
	return nil
}

// indexRunTx is fn as a transaction function that writes the index keys of the appends it applies as
// one run (withIndexRun).
func indexRunTx(fn func(*bolt.Tx) error) func(*bolt.Tx) error {
	return func(tx *bolt.Tx) error { return withIndexRun(tx, func() error { return fn(tx) }) }
}

// orderedCursor is the part of a cursor the scans use: a bolt cursor of the single bucket, or the
// merged cursor of the runs layout.
type orderedCursor interface {
	Seek(seek []byte) (key, value []byte)
	Next() (key, value []byte)
}

// openOrderedCursor opens the cursor of the query index name: the union of its base bucket and runs
// in the runs layout, the bucket itself otherwise.
func openOrderedCursor(tx *bolt.Tx, name string) (orderedCursor, error) {
	if tx.Bucket([]byte(runsRegistry)) == nil {
		bucket := tx.Bucket([]byte(name))
		if bucket == nil {
			return nil, model.Fail(model.Corrupt)
		}
		return bucket.Cursor(), nil
	}
	set, err := openIndexSet(tx, name)
	if err != nil {
		return nil, err
	}
	return set.Cursor(), nil
}

// contractedAuthority is the optional question of a ReplicatedAuthority (control.Store): whether the
// installation is contracted, i.e. no member runs the previous release and none can join.
type contractedAuthority interface {
	IndexesContracted(context.Context) (bool, error)
}

// layoutContracted asks the authority whether the installation is contracted; an authority that cannot
// say counts as not contracted (the file keeps the layout the previous release reads). A variable so
// that a test can play an expanded installation.
var layoutContracted = func(ctx context.Context, a ReplicatedAuthority) (bool, error) {
	if c, ok := a.(contractedAuthority); ok {
		return c.IndexesContracted(ctx)
	}
	return false, nil
}

// adoptRunsLayout moves a single-bucket file to the runs layout in one transaction: the existing
// index buckets become the base of the runs, nothing is rewritten. It is idempotent and safe while
// appends run (every write transaction looks for the registry when it starts).
func (e *Engine) adoptRunsLayout() error {
	err := e.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("meta"))
		v := meta.Get([]byte("scan_index_version"))
		if len(v) != 1 || v[0] != scanIndexClassic && v[0] != scanIndexRuns && v[0] != scanIndexRows && v[0] != scanIndexPayload {
			return model.Fail(model.Corrupt)
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(runsRegistry)); err != nil {
			return err
		}
		if v[0] == scanIndexPayload {
			return nil // a file that has the log keeps it
		}
		return meta.Put([]byte("scan_index_version"), []byte{scanIndexRows})
	})
	if err == nil {
		e.runsLayout.Store(true)
	}
	return err
}

// adoptPayloadLayout lets the engine write payload references: the file's scan_index_version moves to scanIndexPayload in one
// transaction. It needs the rows layout (the installation is contracted: no previous release is a member, and none can join); the
// values already in the file stay where they are, and both forms are read from then on.
func (e *Engine) adoptPayloadLayout() error {
	err := e.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("meta"))
		if v := meta.Get([]byte("scan_index_version")); len(v) != 1 || v[0] != scanIndexRows && v[0] != scanIndexPayload {
			return model.Fail(model.Corrupt)
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(payloadScrubBucket)); err != nil {
			return err
		}
		return meta.Put([]byte("scan_index_version"), []byte{scanIndexPayload})
	})
	if err == nil {
		e.payloadOn.Store(true)
	}
	return err
}

// adoptRunsLayoutIfContracted adopts the runs layout when the installation the engine serves is
// contracted. Without an authority (before EnableReplication) it does nothing.
func (e *Engine) adoptRunsLayoutIfContracted(ctx context.Context) error {
	if e.runsLayout.Load() || e.closing.Load() {
		return nil
	}
	a := e.layoutAuthority.Load()
	if a == nil {
		return nil
	}
	contracted, err := layoutContracted(ctx, *a)
	if err != nil || !contracted {
		return err
	}
	return e.adoptRunsLayout()
}

// payloadLayoutEnabled lets the engine adopt the payload layout once the installation is contracted; a variable so that a test can
// keep a file in the layout before it.
var payloadLayoutEnabled = true

// adoptPayloadLayoutIfContracted adopts the payload layout when the installation the engine serves is contracted (the same fact that
// moved the file to the rows layout).
func (e *Engine) adoptPayloadLayoutIfContracted(ctx context.Context) error {
	if !payloadLayoutEnabled || e.payloadOn.Load() || e.closing.Load() || !e.runsLayout.Load() {
		return nil
	}
	a := e.layoutAuthority.Load()
	if a == nil {
		return nil
	}
	contracted, err := layoutContracted(ctx, *a)
	if err != nil || !contracted {
		return err
	}
	return e.adoptPayloadLayout()
}

// indexMerger is the background goroutine of the query-index layout: it adopts the runs layout when the
// installation is contracted, and merges the runs of the query indexes into larger runs
// (compactIndexRuns), each merge in transactions of about 2 MiB so that none of them holds the write
// lock of the acknowledged appends for long. A run of 64 MiB or more is final (compactOptions.MaxRunBytes),
// which bounds how often a key is rewritten.
type indexMerger struct {
	stop chan struct{}
	done chan struct{}
}

// startIndexMerger starts the goroutine.
func (e *Engine) startIndexMerger() {
	m := &e.indexMerger
	if m.stop != nil {
		return
	}
	m.stop, m.done = make(chan struct{}), make(chan struct{})
	go func(stop <-chan struct{}, done chan<- struct{}) {
		defer close(done)
		tick := time.NewTicker(200 * time.Millisecond)
		defer tick.Stop()
		for n := 0; ; n++ {
			select {
			case <-stop:
				return
			case <-tick.C:
			}
			if !e.runsLayout.Load() {
				if n%5 == 0 {
					_ = e.adoptRunsLayoutIfContracted(context.Background())
				}
				continue
			}
			if !e.payloadOn.Load() && n%5 == 0 {
				_ = e.adoptPayloadLayoutIfContracted(context.Background())
			}
			if e.payloadOn.Load() && n%5 == 0 && e.payloadScrubOwed() { // records no value names (published hot pages, replaced commands) are zeroed when no reader overlaps
				_, _ = e.scrubPayload(context.Background(), scrubConfig{attempts: 1}.withDefaults())
			}
			appended := e.payload.appended()
			cancelled, merr := e.mergeIndexRuns(stop)
			if merr != nil && e.payload.appended() != appended {
				e.payloadDirty.Store(true) // a chunk that failed after it logged blocks leaves records no commit names (payload_sweep.go)
			}
			if cancelled {
				return
			}
			if e.payloadOn.Load() {
				appended = e.payload.appended()
				cancelled, merr = e.migrateInlinePayload(stop)
				if merr != nil && e.payload.appended() != appended {
					e.payloadDirty.Store(true)
				}
				if cancelled {
					return
				}
			}
		}
	}(m.stop, m.done)
}

// mergeIndexRuns is one pass of the merger: it merges the runs of every index that has runs due (each
// index until it has none) and reports whether stop closed first. A failed merge ends the pass of its index
// only, and the first error is returned. A nil stop never cancels.
func (e *Engine) mergeIndexRuns(stop <-chan struct{}) (cancelled bool, first error) {
	for _, name := range []string{"scan_time", "scan_postings", rowsIndex} {
		cancelled, err := e.mergeIndexRunsOf(name, stop)
		if err != nil && first == nil {
			first = err
		}
		if cancelled {
			return true, first
		}
	}
	if e.payloadOn.Load() { // the blocks of the final runs that were written before the layout, or by a merge that stored them in the run
		cancelled, err := e.externalizeRuns(stop)
		if err != nil && first == nil {
			first = err
		}
		return cancelled, first
	}
	return false, first
}

// mergeIndexRunsOf merges the runs of the index name until it has none due, and reports whether stop closed first.
func (e *Engine) mergeIndexRunsOf(name string, stop <-chan struct{}) (cancelled bool, first error) {
	for {
		select {
		case <-stop:
			return true, first
		default:
		}
		opt := compactOptions{Cancel: stop, MaxRunBytes: finalRunBytes, Update: e.db.Update}
		if e.payloadOn.Load() {
			opt.Payload = e.payload
		}
		did, err := compactIndexRuns(e.db.DB, name, opt)
		if err != nil && first == nil {
			first = err
		}
		if err != nil || !did {
			return false, first
		}
	}
}

// stopIndexMerger stops the merger and waits for it; the merge in progress leaves a building run
// that the next open removes.
func (e *Engine) stopIndexMerger() {
	m := &e.indexMerger
	if m.stop == nil {
		return
	}
	close(m.stop)
	<-m.done
	m.stop, m.done = nil, nil
}
