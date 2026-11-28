// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// loadGate stalls the first page load of a scan (scanPageLoadHook) until released; later loads pass.
type loadGate struct {
	entered chan struct{}
	release chan struct{}
	loads   atomic.Int64
	done    atomic.Bool
}

func (g *loadGate) open() {
	if g.done.CompareAndSwap(false, true) {
		close(g.release)
	}
}

func holdFirstPageLoad(t *testing.T) *loadGate {
	t.Helper()
	g := &loadGate{entered: make(chan struct{}, 1), release: make(chan struct{})}
	hook := func() {
		if g.loads.Add(1) != 1 {
			return
		}
		g.entered <- struct{}{}
		<-g.release
	}
	scanPageLoadHook.Store(&hook)
	t.Cleanup(func() {
		scanPageLoadHook.Store(nil)
		g.open()
	})
	return g
}

// drainRows reads a scan to its end and returns the rows delivered.
func drainRows(x *eraseEnv, req ScanRequest) (int, error) {
	it, err := x.e.Scan(context.Background(), x.read, req)
	if err != nil {
		return 0, err
	}
	defer it.Close()
	rows := 0
	for {
		page, err := it.Next(context.Background())
		if err == io.EOF {
			return rows, nil
		}
		if err != nil {
			return rows, err
		}
		rows += page.Len()
	}
}

type drained struct {
	rows int
	err  error
}

func drainAsync(x *eraseEnv, req ScanRequest) chan drained {
	out := make(chan drained, 1)
	go func() {
		rows, err := drainRows(x, req)
		out <- drained{rows, err}
	}()
	return out
}

func awaitLoad(t *testing.T, g *loadGate, first chan drained) {
	t.Helper()
	select {
	case <-g.entered:
	case r := <-first:
		t.Fatalf("the first scan ended without loading a page: %+v", r)
	case <-time.After(10 * time.Second):
		t.Fatal("the first scan never loaded a page")
	}
}

func awaitDrained(t *testing.T, what string, ch chan drained, want int, bound time.Duration) {
	t.Helper()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("%s: %v", what, r.err)
		}
		if r.rows != want {
			t.Fatalf("%s delivered %d rows, want %d", what, r.rows, want)
		}
	case <-time.After(bound):
		t.Fatalf("%s did not complete within %v", what, bound)
	}
}

// The chunk build of a scan (the index seeks, the page reads and the decode) held the engine mutex, so one
// scan that waited on the disk or spent its time decoding stopped every other scan and every append of the
// node: at the Queries gate the mutex was held 86.5 % of the time with 21 scans waiting. A scan's decode
// runs under a bolt read transaction and not under e.mu.
func TestScanDecodeDoesNotHoldTheEngineLock(t *testing.T) {
	const bound = 10 * time.Second
	x := newEraseEnv(t)
	seedScanRows(x, 1, 3)
	req := ScanRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric, End: 1 << 40}
	g := holdFirstPageLoad(t)
	first := drainAsync(x, req)
	awaitLoad(t, g, first)

	t.Run("another scan overlaps", func(t *testing.T) {
		awaitDrained(t, "a second scan while the first one decodes", drainAsync(x, req), 3, bound)
	})
	t.Run("an append is not blocked", func(t *testing.T) {
		n, scope := x.admit(model.NewID(), metricRetention, x.metric("decode_append", 500))
		done := make(chan error, 1)
		go func() { _, err := x.e.Append(context.Background(), scope, n); done <- err }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(bound):
			t.Fatalf("an append did not complete within %v while a scan decodes: the engine lock is held across the chunk build", bound)
		}
	})
	t.Run("the engine answers stats", func(t *testing.T) {
		done := make(chan StorageStats, 1)
		go func() { done <- x.e.Stats() }()
		select {
		case s := <-done:
			if s.ActiveIterators < 1 {
				t.Fatalf("ActiveIterators %d while a scan is open", s.ActiveIterators)
			}
		case <-time.After(bound):
			t.Fatalf("Stats did not answer within %v while a scan decodes", bound)
		}
	})
	g.open()
	select {
	case r := <-first:
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.rows < 3 {
			t.Fatalf("the stalled scan delivered %d rows, want at least the 3 seeded", r.rows)
		}
	case <-time.After(bound):
		t.Fatal("the stalled scan did not end after its load was released")
	}
}

// An iterator closed while its chunk decodes is closed at once, and the Next that was decoding judges it
// under the lock when it comes back: it fails and releases no page.
func TestIteratorClosedDuringItsDecodeReleasesNothing(t *testing.T) {
	const bound = 10 * time.Second
	x := newEraseEnv(t)
	seedScanRows(x, 1, 3)
	g := holdFirstPageLoad(t)
	it, err := x.e.Scan(context.Background(), x.read, ScanRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric, End: 1 << 40})
	if err != nil {
		t.Fatal(err)
	}
	next := make(chan error, 1)
	go func() {
		page, err := it.Next(context.Background())
		if err == nil && page.Len() > 0 {
			err = errors.New("a page was released to a closed iterator")
		}
		next <- err
	}()
	select {
	case <-g.entered:
	case <-time.After(bound):
		t.Fatal("the scan never loaded a page")
	}
	closed := make(chan struct{})
	go func() { _ = it.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(bound):
		t.Fatal("Close did not return while the scan decodes")
	}
	g.open()
	select {
	case err := <-next:
		if err == nil {
			t.Fatal("Next of an iterator closed during its decode succeeded")
		}
	case <-time.After(bound):
		t.Fatal("Next did not end after its load was released")
	}
	if got := x.e.Stats().BorrowedPages; got != 0 {
		t.Fatalf("%d pages borrowed after the closed Next", got)
	}
	if got := x.e.Stats().ActiveIterators; got != 0 {
		t.Fatalf("%d iterators active after the close", got)
	}
}

// The segment a chunk's snapshot names can be replaced and removed while the chunk decodes (a compaction
// retires its files at once: the lock no longer keeps the reader out). The reader meets the vanished file,
// looks the page up again in a new snapshot and serves the rows from the page's new place.
func TestScanSurvivesACompactionDuringItsDecode(t *testing.T) {
	const bound = 10 * time.Second
	x := newEraseEnv(t)
	seedScanRows(x, 1, 3)
	if err := x.e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	g := holdFirstPageLoad(t)
	first := drainAsync(x, ScanRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric, End: 1 << 40})
	awaitLoad(t, g, first)
	compacted := make(chan error, 1)
	go func() { compacted <- x.e.Compact(context.Background()) }()
	select {
	case err := <-compacted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(bound):
		t.Fatalf("Compact did not complete within %v while a scan decodes", bound)
	}
	g.open()
	awaitDrained(t, "the scan whose segment was compacted away", first, 3, bound)
}
