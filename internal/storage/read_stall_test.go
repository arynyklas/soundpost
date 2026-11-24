// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// stallKey marks the contexts whose authority reads are stalled.
type stallKey struct{}

// stallingValidator is the authority seam of a control ReadIndex that does not answer: the control read
// of a context marked with stallKey waits until release is closed (or the context ends), after skip
// such reads have been answered at once. entered is signalled when a read starts to wait.
type stallingValidator struct {
	inner   Revalidator
	skip    atomic.Int64
	release chan struct{}
	entered chan struct{}
}

func (v *stallingValidator) Revalidate(ctx context.Context, s auth.Scope) error {
	if ctx.Value(stallKey{}) != nil && v.skip.Add(-1) < 0 {
		select {
		case v.entered <- struct{}{}:
		default:
		}
		select {
		case <-v.release:
		case <-ctx.Done():
			return model.Fail(model.Cancelled)
		}
	}
	return v.inner.Revalidate(ctx, s)
}

// The engine mutex was held across the authority read of a scan (Scan after its fence, the start of a
// chunk, the release barrier of a page and of EOF): a control ReadIndex that waits for a quorum for
// seconds stopped every append of the node and every other reader for as long. Whatever read stalls,
// appends and other scans complete at once, and the stalled read still ends with its normal answer
// when the authority answers.
func TestStalledAuthorityReadDoesNotHoldTheEngineLock(t *testing.T) {
	const bound = 10 * time.Second
	for _, tc := range []struct {
		name        string
		skip        int64 // authority reads of the stalled call answered before the one that stalls
		stalledScan bool  // Scan itself stalls (its authority read after the fence); else Next does
		drainFirst  bool  // a page is read before the stalled Next (the Next after the last page is the EOF barrier)
	}{
		{name: "scan_after_fence", skip: 1, stalledScan: true},
		{name: "chunk_start", skip: 0},
		{name: "page_barrier", skip: 1},
		{name: "eof_entry", skip: 0, drainFirst: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newEraseEnv(t)
			seedScanRows(x, 1, 3)
			v := &stallingValidator{inner: x.a, release: make(chan struct{}), entered: make(chan struct{}, 1)}
			v.skip.Store(tc.skip)
			x.e.mu.Lock()
			x.e.validator = v
			x.e.mu.Unlock()
			req := ScanRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric, End: 1 << 40}
			stalled := context.WithValue(context.Background(), stallKey{}, true)
			released := false
			release := func() {
				if !released {
					released = true
					close(v.release)
				}
			}
			defer release()

			type result struct {
				rows int
				err  error
			}
			done := make(chan result, 1)
			if tc.stalledScan {
				go func() {
					it, err := x.e.Scan(stalled, x.read, req)
					if err != nil {
						done <- result{err: err}
						return
					}
					defer it.Close()
					rows := 0
					for {
						page, err := it.Next(context.Background())
						if err == io.EOF {
							done <- result{rows: rows}
							return
						}
						if err != nil {
							done <- result{err: err}
							return
						}
						rows += page.Len()
					}
				}()
			} else {
				it, err := x.e.Scan(context.Background(), x.read, req)
				if err != nil {
					t.Fatal(err)
				}
				defer it.Close()
				rows := 0
				if tc.drainFirst {
					page, err := it.Next(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					rows += page.Len()
				}
				go func() {
					for {
						page, err := it.Next(stalled)
						if err == io.EOF {
							done <- result{rows: rows}
							return
						}
						if err != nil {
							done <- result{err: err}
							return
						}
						rows += page.Len()
					}
				}()
			}
			select {
			case <-v.entered:
			case r := <-done:
				t.Fatalf("the stalled read never waited: %+v", r)
			case <-time.After(bound):
				t.Fatal("the stalled read never started")
			}

			// While it waits: an append and a whole scan by another reader complete.
			n, scope := x.admit(model.NewID(), metricRetention, x.metric(fmt.Sprintf("stall_append_%s", tc.name), 500))
			appended := make(chan error, 1)
			go func() { _, err := x.e.Append(context.Background(), scope, n); appended <- err }()
			other := make(chan error, 1)
			go func() {
				it, err := x.e.Scan(context.Background(), x.read, req)
				if err != nil {
					other <- err
					return
				}
				defer it.Close()
				for {
					if _, err = it.Next(context.Background()); err != nil {
						if err == io.EOF {
							err = nil
						}
						other <- err
						return
					}
				}
			}()
			for _, c := range []struct {
				what string
				ch   chan error
			}{{"append", appended}, {"another reader's scan", other}} {
				select {
				case err := <-c.ch:
					if err != nil {
						t.Errorf("%s while an authority read waits: %v", c.what, err)
					}
				case <-time.After(bound):
					t.Errorf("%s did not complete within %v while another reader's authority read waits: the engine lock is held across the control read", c.what, bound)
				}
			}
			select {
			case r := <-done:
				t.Fatalf("the stalled call ended before its authority answered: %+v", r)
			default:
			}

			release()
			select {
			case r := <-done:
				if r.err != nil {
					t.Fatalf("stalled scan after the authority answered: %v", r.err)
				}
				if r.rows < 3 {
					t.Fatalf("stalled scan delivered %d rows, want at least the 3 seeded", r.rows)
				}
			case <-time.After(bound):
				t.Fatal("stalled scan did not end after the authority answered")
			}
		})
	}
}

// An iterator cancelled while its authority read waits is closed at once (the lock is free for the
// cancellation), and the Next that waited judges it again under the lock when the authority answers:
// it fails with the cancellation and releases nothing.
func TestIteratorCancelledDuringItsAuthorityReadFailsClosed(t *testing.T) {
	const bound = 10 * time.Second
	x := newEraseEnv(t)
	seedScanRows(x, 1, 3)
	v := &stallingValidator{inner: x.a, release: make(chan struct{}), entered: make(chan struct{}, 1)}
	x.e.mu.Lock()
	x.e.validator = v
	x.e.mu.Unlock()
	scanCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	it, err := x.e.Scan(scanCtx, x.read, ScanRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric, End: 1 << 40})
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	released := false
	release := func() {
		if !released {
			released = true
			close(v.release)
		}
	}
	defer release()
	next := make(chan error, 1)
	go func() {
		page, err := it.Next(context.WithValue(context.Background(), stallKey{}, true))
		if err == nil && page.Len() > 0 {
			err = fmt.Errorf("a page of %d rows was released to a cancelled scan", page.Len())
		}
		next <- err
	}()
	select {
	case <-v.entered:
	case <-time.After(bound):
		t.Fatal("the authority read never waited")
	}
	cancel()
	deadline := time.Now().Add(bound)
	for x.e.Stats().ActiveIterators != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the cancelled iterator stayed open while its authority read waits")
		}
		time.Sleep(5 * time.Millisecond)
	}
	release()
	select {
	case err := <-next:
		var f *model.Fault
		if !errors.As(err, &f) || f.Code != model.Cancelled {
			t.Fatalf("Next of a scan cancelled during its authority read: %v, want Cancelled", err)
		}
	case <-time.After(bound):
		t.Fatal("Next did not end after the authority answered")
	}
	if got := x.e.Stats().BorrowedPages; got != 0 {
		t.Fatalf("%d pages borrowed after the cancelled Next", got)
	}
}

// A page that a flush moves from the row to a segment is read, and verified, at its new place by the
// next scan, not served from the decode of the page where it lay: the content hash does not change
// when the page moves, its location does.
func TestScanPageCacheDoesNotServeAPageThatMoved(t *testing.T) {
	x := newEraseEnv(t)
	seedScanRows(x, 1, 3)
	if rows, _ := scanAll(t, x); rows != 3 {
		t.Fatalf("first scan delivered %d rows, want 3", rows)
	}
	if err := x.e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := x.e.Stats().PagesRead
	if rows, _ := scanAll(t, x); rows != 3 {
		t.Fatalf("scan after the flush delivered %d rows, want 3", rows)
	}
	if read := x.e.Stats().PagesRead - before; read != 1 {
		t.Fatalf("the scan after a flush read %d pages, want the 1 page at its new place", read)
	}
}
