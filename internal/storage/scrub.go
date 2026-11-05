// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"errors"
	"os"
	"time"

	bolt "go.etcd.io/bbolt"
	"soundpost/internal/model"
)

// bbolt is copy-on-write and never zeroes a page it frees, so an erasure that only deletes keys
// leaves the deleted bytes in free pages of apply.db: reachable through no bucket, present in the
// raw file. Physical erasure therefore ends with a scrub that overwrites every free page with
// zeros.
//
// Safety argument. Inside a bbolt write transaction (the single writer, so nothing allocates or
// frees concurrently) a page the freelist reports as free is referenced by no committed tree: the
// latest meta does not reach it, and no transaction that began earlier can, provided no read
// transaction is open (an open reader pins the pages freed after it began as "pending" and may
// still walk them; the freelist cannot tell the two apart from outside, so any open reader defers
// the chunk). A transaction that begins later reads the latest meta and cannot reach the page
// either. Zeroing such a page changes nothing bbolt can observe. A crash at any point leaves at
// worst some free pages zeroed and others not: the database is valid, and the durable owed-scrub
// marker below makes the next pass redo it.
//
// The scrub runs in bounded chunks, each in its own write transaction, so intake is held off for
// one chunk at a time. Pages a later writer allocates after the scrub looked are rewritten whole by
// that writer (bbolt writes every page it allocates from a zeroed buffer), so only pages that were
// free when the pass ran can still hold erased bytes.
const (
	scrubErasedSeqKey = "scrub_erased_seq" // bumped by every transaction that erased bytes
	scrubDoneSeqKey   = "scrub_done_seq"   // erased sequence a completed scrub covered

	defaultScrubChunkPages = 8192 // 32 MiB at 4 KiB pages per write transaction
	defaultScrubAttempts   = 40
	defaultScrubBackoff    = 25 * time.Millisecond
	scrubZeroRunPages      = 256
)

// scrubConfig overrides the defaults (zero fields use them); tests shrink the chunk and the wait.
type scrubConfig struct {
	chunkPages int
	attempts   int // tries per chunk while a read transaction is open
	backoff    time.Duration
}

func (c scrubConfig) withDefaults() scrubConfig {
	if c.chunkPages <= 0 {
		c.chunkPages = defaultScrubChunkPages
	}
	if c.attempts <= 0 {
		c.attempts = defaultScrubAttempts
	}
	if c.backoff <= 0 {
		c.backoff = defaultScrubBackoff
	}
	return c
}

var errScrubBusy = errors.New("read transaction open")

// markScrubPendingTx records, in the transaction that erased bytes, that the free pages those
// bytes now sit in are still to be zeroed.
func (e *Engine) markScrubPendingTx(tx *bolt.Tx) error {
	meta := tx.Bucket([]byte("meta"))
	return putUint(meta, []byte(scrubErasedSeqKey), getUint(meta, []byte(scrubErasedSeqKey))+1)
}

func (e *Engine) scrubSequences() (erased, done uint64, err error) {
	err = e.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("meta"))
		erased, done = getUint(meta, []byte(scrubErasedSeqKey)), getUint(meta, []byte(scrubDoneSeqKey))
		return nil
	})
	return
}

// scrubFreePages zeroes every free page of apply.db if a scrub is owed. It reports how many pages
// it zeroed and whether a scrub is still owed afterwards (a reader stayed open; an erasure
// committed while it ran). An error means the pass could not even try or crashed part-way: the
// owed marker stays, nothing is claimed.
func (e *Engine) scrubFreePages(ctx context.Context) (zeroed uint64, pending bool, err error) {
	erased, done, err := e.scrubSequences()
	if err != nil {
		return 0, false, unavailableDB(err)
	}
	if done >= erased {
		return 0, false, nil
	}
	if err = e.trip("erase_scrub"); err != nil {
		return 0, true, err
	}
	cfg := e.scrub.withDefaults()
	file, err := os.OpenFile(e.db.Path(), os.O_WRONLY, 0)
	if err != nil {
		return 0, true, err
	}
	defer file.Close()
	pageSize := uint64(e.db.Info().PageSize)
	var high uint64
	if err = e.db.View(func(tx *bolt.Tx) error { high = uint64(tx.Size()) / pageSize; return nil }); err != nil {
		return 0, true, unavailableDB(err)
	}
	for first := uint64(2); first < high; first += uint64(cfg.chunkPages) {
		if err = ctx.Err(); err != nil {
			return zeroed, true, model.Fail(model.Cancelled)
		}
		last := min(first+uint64(cfg.chunkPages), high)
		n, busy, err := e.scrubChunk(ctx, file, first, last, pageSize, cfg)
		zeroed += n
		if err != nil {
			return zeroed, true, err
		}
		if busy {
			return zeroed, true, nil
		}
	}
	// Only an erasure that committed before this pass began is covered by it.
	if err = e.db.Update(func(tx *bolt.Tx) error {
		return putUint(tx.Bucket([]byte("meta")), []byte(scrubDoneSeqKey), erased)
	}); err != nil {
		return zeroed, true, unavailableDB(err)
	}
	erasedNow, doneNow, err := e.scrubSequences()
	if err != nil {
		return zeroed, true, unavailableDB(err)
	}
	return zeroed, doneNow < erasedNow, nil
}

// scrubChunk zeroes the free pages with id in [first,last) inside one write transaction. busy is
// true when a read transaction stayed open through every attempt: nothing was zeroed.
func (e *Engine) scrubChunk(ctx context.Context, file *os.File, first, last, pageSize uint64, cfg scrubConfig) (zeroed uint64, busy bool, err error) {
	zero := make([]byte, pageSize*scrubZeroRunPages)
	for attempt := 0; ; attempt++ {
		zeroed = 0
		err = e.db.Update(func(tx *bolt.Tx) error {
			if e.db.Stats().OpenTxN > 0 {
				return errScrubBusy
			}
			for id := first; id < last; {
				info, err := tx.Page(int(id))
				if err != nil {
					return err
				}
				if info == nil { // beyond this transaction's high-water mark
					break
				}
				if info.Type != "free" {
					id++
					continue
				}
				start := id
				for id < last {
					if info, err = tx.Page(int(id)); err != nil {
						return err
					}
					if info == nil || info.Type != "free" {
						break
					}
					id++
				}
				for run := start; run < id; {
					n := min(id-run, scrubZeroRunPages)
					if _, err := file.WriteAt(zero[:n*pageSize], int64(run*pageSize)); err != nil {
						return err
					}
					run += n
				}
				zeroed += id - start
			}
			if zeroed > 0 {
				if err := file.Sync(); err != nil {
					return err
				}
			}
			return e.trip("scrub_chunk")
		})
		switch {
		case err == nil:
			return zeroed, false, nil
		case errors.Is(err, errScrubBusy):
			if attempt+1 >= cfg.attempts {
				return 0, true, nil
			}
			select {
			case <-ctx.Done():
				return 0, false, model.Fail(model.Cancelled)
			case <-time.After(cfg.backoff):
			}
		default:
			return 0, false, unavailableDB(err)
		}
	}
}

// unavailableDB maps a closed or failed database to the engine's unavailable fault and passes
// faults (including crash hooks) through unchanged.
func unavailableDB(err error) error {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return err
	}
	return model.Fail(model.Unavailable)
}
