// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// These tests pin the safety conditions of ScrubErased/scrubChunk from the outside: what a reader
// that stays open does to a scrub, that every free page of a file larger than several chunks is
// zeroed (chunk bounds, the high-water mark), and that a cancelled scrub zeroes nothing.

// mutantReader opens a read transaction on control.db and keeps it open until release is called (or
// until a watchdog does, so a failing assertion never leaves the scrub waiting on it forever).
func (f *installFx) mutantReader() (release func()) {
	f.t.Helper()
	held, done, stop := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	closeStop := func() { once.Do(func() { close(stop) }) }
	watchdog := time.AfterFunc(10*time.Second, closeStop)
	go func() {
		defer close(done)
		_ = f.s.db.View(func(tx *bolt.Tx) error {
			close(held)
			<-stop
			return nil
		})
	}()
	<-held
	if f.s.db.Stats().OpenTxN < 1 {
		f.t.Fatal("fixture invalid: the open read transaction is not counted")
	}
	return func() { watchdog.Stop(); closeStop(); <-done }
}

// A scrub never zeroes a page a reader may still reference: while a read transaction is open it
// defers for its whole bound (scrubAttempts waits of scrubBackoff), then fails closed with
// Unavailable, leaves the file as it found it and keeps the debt owed. Once the reader is gone the
// next scrub finishes.
func TestMutantAScrubDefersToAnOpenReaderThenFailsClosed(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(true)
	if !f.dbHolds() || !f.owesState() {
		t.Fatal("fixture invalid: the erased payload is not owed a scrub")
	}
	release := f.mutantReader()
	start := time.Now()
	err := f.s.ScrubErased(f.ctx)
	waited := time.Since(start)
	release()
	if mutantCode(err) != model.Unavailable {
		t.Fatalf("a scrub over an open reader answered %v, want unavailable (the debt is still owed)", err)
	}
	if floor := time.Duration(scrubAttempts-1) * scrubBackoff * 9 / 10; waited < floor {
		t.Fatalf("the scrub gave up after %s, before its deferral bound (%d waits of %s)", waited, scrubAttempts-1, scrubBackoff)
	}
	if !f.dbHolds() || !f.owesState() || !f.local().owed {
		t.Fatalf("a scrub that could not run changed the file or the debt: holds=%v owes=%v marker=%+v", f.dbHolds(), f.owesState(), f.local())
	}
	if err = f.s.ScrubErased(f.ctx); err != nil {
		t.Fatalf("the scrub after the reader closed: %v", err)
	}
	if f.dbHolds() || f.owesState() {
		t.Fatalf("the scrub after the reader closed left the payload or the debt: holds=%v owes=%v", f.dbHolds(), f.owesState())
	}
}

// A reader that closes within the bound only delays the scrub: it waits, then runs.
func TestMutantAScrubWaitsOutAReaderThatClosesInTime(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(true)
	release := f.mutantReader()
	const hold = 200 * time.Millisecond
	time.AfterFunc(hold, release)
	start := time.Now()
	if err := f.s.ScrubErased(f.ctx); err != nil {
		t.Fatalf("a scrub that had to wait for a reader failed: %v", err)
	}
	if waited := time.Since(start); waited < hold*9/10 {
		t.Fatalf("the scrub finished after %s with a reader open for %s", waited, hold)
	}
	if f.dbHolds() || f.owesState() {
		t.Fatalf("the scrub left the payload or the debt: holds=%v owes=%v", f.dbHolds(), f.owesState())
	}
}

// A scrub whose context is already cancelled zeroes nothing and leaves the debt owed.
func TestMutantACancelledScrubZeroesNothingAndStaysOwed(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(true)
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if err := f.s.ScrubErased(ctx); mutantCode(err) != model.Cancelled {
		t.Fatalf("a cancelled scrub answered %v, want cancelled", err)
	}
	if !f.dbHolds() || !f.owesState() || !f.local().owed {
		t.Fatalf("a cancelled scrub changed the file or the debt: holds=%v owes=%v marker=%+v", f.dbHolds(), f.owesState(), f.local())
	}
}

// mutantFreePages are the pages the freelist reports free (the ones freed by a commit that a reader
// still held included) from page 2 to the file's high-water mark, which is returned in pages.
func (f *installFx) mutantFreePages() (free []uint64, high uint64) {
	f.t.Helper()
	if err := f.s.probeDB(func(tx *bolt.Tx, pageSize uint64) error {
		high = uint64(tx.Size()) / pageSize
		for id := uint64(2); id < high; id++ {
			info, err := tx.Page(int(id))
			if err != nil {
				return err
			}
			if info != nil && info.Type == "free" {
				free = append(free, id)
			}
		}
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return free, high
}

// mutantPage is page id of a raw copy of the file.
func mutantPage(raw []byte, id, pageSize uint64) []byte { return raw[id*pageSize : (id+1)*pageSize] }

// mutantCanaryValue is a value of the given size that holds the canary every 512 bytes, so every
// page of the run it lands in holds at least one whole copy.
func mutantCanaryValue(size int) []byte {
	value := make([]byte, size)
	for off := 0; off+len(mutantChunkCanary) <= len(value); off += 512 {
		copy(value[off:], mutantChunkCanary)
	}
	return value
}

// mutantWrite runs one write transaction on the control bucket of f.
func (f *installFx) mutantWrite(write func(*bolt.Bucket) error) {
	f.t.Helper()
	if err := f.s.db.Update(func(tx *bolt.Tx) error { return write(tx.Bucket([]byte("control"))) }); err != nil {
		f.t.Fatal(err)
	}
}

const mutantChunkCanary = "CANARYCHUNK0f3a9d61c2b84e7a-the-erased-payload"

// A file of more than two chunks (scrubChunkPages pages each) keeps erased payload in free pages
// on both sides of every chunk boundary. The scrub zeroes all of them (the last page of one chunk,
// the first of the next), leaves no copy of the payload anywhere in the file and a database bbolt
// can still check. (It does not assert that every free page is zero afterwards: the commits of the
// scrub itself write their freelist into free pages.)
func TestMutantAScrubOfSeveralChunksZeroesEveryFreePage(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(true)
	pageSize := f.pageSize()
	key := []byte("mutant_filler")
	f.mutantWrite(func(b *bolt.Bucket) error {
		return b.Put(key, mutantCanaryValue((2*scrubChunkPages+1500)*int(pageSize)))
	})
	f.mutantWrite(func(b *bolt.Bucket) error { return b.Delete(key) })
	free, high := f.mutantFreePages()
	raw := f.rawFile()
	if high <= 2+2*scrubChunkPages {
		t.Fatalf("fixture invalid: the file has %d pages, fewer than three chunks", high)
	}
	wasFree := map[uint64]bool{}
	for _, id := range free {
		wasFree[id] = true
	}
	for _, edge := range []uint64{2 + scrubChunkPages - 1, 2 + scrubChunkPages, 2 + 2*scrubChunkPages - 1, 2 + 2*scrubChunkPages} {
		if !wasFree[edge] || !bytes.Contains(mutantPage(raw, edge, pageSize), []byte(mutantChunkCanary)) {
			t.Fatalf("fixture invalid: page %d, next to a chunk boundary, is not a free page holding the erased payload", edge)
		}
	}

	if err := f.s.ScrubErased(f.ctx); err != nil {
		t.Fatalf("ScrubErased: %v", err)
	}

	if at := bytes.Index(f.rawFile(), []byte(mutantChunkCanary)); at >= 0 {
		page := uint64(at) / pageSize
		t.Errorf("the scrub left the erased payload in page %d (chunk %d) of %d pages", page, (page-2)/scrubChunkPages, high)
	}
	if f.owesState() || f.local().owed {
		t.Errorf("the scrub left the debt owed: %v %+v", f.s.ResidualStores(), f.local())
	}
	if err := f.s.probeDB(func(tx *bolt.Tx, _ uint64) error { // Check is safe on a writable transaction only
		for err := range tx.Check() {
			t.Errorf("bbolt check after the scrub: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.localState(); err != nil {
		t.Fatalf("the state cannot be read after the scrub: %v", err)
	}
}

// The last page of the file is a free page like any other: the scrub reaches the file's high-water
// mark. Each value here is larger than every run freed before it, so it extends the file; the last
// one, deleted, leaves its tail in the last pages (the settle commit after the scrub takes the lowest
// free pages, never these).
func TestMutantAScrubReachesTheLastPageOfTheFile(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(true)
	pageSize := f.pageSize()
	key := []byte("mutant_tail")
	for _, pages := range []int{40, 80, 160, 320} {
		f.mutantWrite(func(b *bolt.Bucket) error { return b.Put(key, mutantCanaryValue(pages*int(pageSize)+1000)) })
	}
	f.mutantWrite(func(b *bolt.Bucket) error { return b.Delete(key) })
	free, high := f.mutantFreePages()
	if last := high - 1; !slices.Contains(free, last) || !bytes.Contains(mutantPage(f.rawFile(), last, pageSize), []byte(mutantChunkCanary)) {
		t.Fatalf("fixture invalid: the last page (%d of %d) is not a free page holding the erased payload", last, high)
	}
	if err := f.s.ScrubErased(f.ctx); err != nil {
		t.Fatalf("ScrubErased: %v", err)
	}
	if at := bytes.Index(f.rawFile(), []byte(mutantChunkCanary)); at >= 0 {
		t.Errorf("the scrub left the erased payload in page %d of %d", uint64(at)/pageSize, high)
	}
}

// A scrub that owes only this file's debt commits nothing replicated and needs no consensus: a node
// whose group is stopped (it can read no index and propose nothing) still zeroes its own free pages
// and settles its own marker, and the scrub reports success.
func TestMutantALocalOnlyScrubNeedsNoConsensus(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(true) // the log owes nothing by itself: only this file's marker does
	if len(owedScrubs(f.state().Audits)) != 0 || !f.owesState() || !f.dbHolds() {
		t.Fatal("fixture invalid: the debt is not the local one alone, or the payload is not in the file")
	}
	if err := f.s.ReplicaGroup().Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Update(f.ctx, func(*State) error { return errNothingToSettle }); errors.Is(err, errNothingToSettle) {
		t.Fatal("fixture invalid: the stopped group still takes an update")
	}
	if err := f.s.ScrubErased(f.ctx); err != nil {
		t.Fatalf("a scrub that owes only the local debt failed without a group: %v", err)
	}
	if f.dbHolds() || f.owesState() || f.local().owed {
		t.Fatalf("the scrub left the payload or the debt: holds=%v owes=%v marker=%+v", f.dbHolds(), f.owesState(), f.local())
	}
}

// mutantFirstFreePagesFx is a fixture whose pages 2 and 3, the first pages after the meta pages, are
// free: the erasure's commit has just moved the state out of them. Which state size does that
// depends on bbolt's allocator, so the fixture searches for it and stops the test, loudly, when none
// does (it never settles for a layout that cannot tell the mutant from the original). The freelist
// must not be a two-page run: the scrub's own commit would write it over pages 2 and 3.
func mutantFirstFreePagesFx(t *testing.T) *installFx {
	t.Helper()
	for books := 1; books <= 40; books++ {
		f := newInstallFxOf(t, books)
		f.erasedByTheLeader(false) // the log owes a scrub, so does this file
		// Settle this file's own debt alone (the scrub's commit would take the first free pages): only
		// the log's debt, which needs consensus, is left.
		if err := f.s.settleLocalScrub(f.local().generation); err != nil {
			t.Fatal(err)
		}
		free, _ := f.mutantFreePages()
		freelist := -1
		if err := f.s.probeDB(func(tx *bolt.Tx, pageSize uint64) error {
			for id := 2; id < int(uint64(tx.Size())/pageSize); id++ {
				if info, err := tx.Page(id); err != nil {
					return err
				} else if info != nil && info.Type == "freelist" {
					freelist = info.OverflowCount
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(free, 2) && slices.Contains(free, 3) && freelist != 1 && len(owedScrubs(f.state().Audits)) != 0 {
			return f
		}
	}
	t.Fatal("fixture invalid: no state size leaves pages 2 and 3 free (bbolt's allocator moved?)")
	return nil
}

// A scrub zeroes the free pages from page 2 on BEFORE it settles anything: a node whose consensus
// group is stopped (the settle of the log's debt cannot commit) has still zeroed every free page,
// the first two included, and reports the debt as owed. With nothing committed after the chunk but
// its own freelist, a page-2 or page-3 payload that the scrub skipped is still in the file.
func TestMutantAScrubThatCannotSettleHasZeroedTheFirstFreePages(t *testing.T) {
	f := mutantFirstFreePagesFx(t)
	pageSize := f.pageSize()
	file, err := os.OpenFile(f.s.db.Path(), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	stale := bytes.Repeat([]byte(mutantChunkCanary), int(pageSize)/len(mutantChunkCanary)+1)[:pageSize]
	for _, id := range []uint64{2, 3} { // erased payload left behind in the free pages the erasure just made
		if _, err = file.WriteAt(stale, int64(id*pageSize)); err != nil {
			t.Fatal(err)
		}
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint64{2, 3} {
		if !bytes.Contains(mutantPage(f.rawFile(), id, pageSize), []byte(mutantChunkCanary)) {
			t.Fatalf("fixture invalid: page %d does not hold the planted payload", id)
		}
	}
	if err = f.s.ReplicaGroup().Close(); err != nil {
		t.Fatal(err)
	}

	if err = f.s.ScrubErased(f.ctx); mutantCode(err) != model.Unavailable {
		t.Fatalf("a scrub whose settle cannot commit answered %v, want unavailable", err)
	}

	raw := f.rawFile()
	for _, id := range []uint64{2, 3} {
		if bytes.Contains(mutantPage(raw, id, pageSize), []byte(mutantChunkCanary)) {
			t.Errorf("the scrub left the erased payload in page %d, one of the first free pages of the file", id)
		}
	}
	if len(owedScrubs(f.state().Audits)) == 0 {
		t.Error("a scrub that could not commit its settle cleared the log's debt")
	}
}
