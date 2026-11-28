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

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// countingValidator counts the authority reads a scan makes: each Revalidate is a control read (a
// ReadIndex round and, when the control revision moved, a decode of the whole control state).
type countingValidator struct {
	inner Revalidator
	calls *atomic.Int64
}

func (v countingValidator) Revalidate(ctx context.Context, s auth.Scope) error {
	v.calls.Add(1)
	return v.inner.Revalidate(ctx, s)
}

// seedScanRows appends batches of per records each, so that a scan of them is a chain of full pages:
// a page closes before the batch that would not fit (pageRows). By default the batches are one
// series over consecutive times; interleaved gives each batch its own series over the same times.
func seedScanRows(x *eraseEnv, batches, per int, interleaved ...bool) {
	x.t.Helper()
	at := 50
	for batch := range batches {
		recs := make([]model.Record, per)
		for i := range recs {
			if len(interleaved) > 0 && interleaved[0] {
				recs[i] = x.metric(fmt.Sprintf("scan_cost_series_%d", batch), model.UnixNano(50+i))
				continue
			}
			recs[i] = x.metric("scan_cost_series", model.UnixNano(at))
			at++
		}
		x.appendRecords(model.NewID(), metricRetention, recs...)
	}
}

// scanAll drains one scan of every metric row and returns the rows and pages it delivered.
func scanAll(t testing.TB, x *eraseEnv) (rows, pages int) {
	t.Helper()
	it, err := x.e.Scan(context.Background(), x.read, ScanRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric, End: 1 << 40})
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	for {
		page, err := it.Next(context.Background())
		if err == io.EOF {
			return rows, pages
		}
		if err != nil {
			t.Fatal(err)
		}
		rows += page.Len()
		pages++
	}
}

// The release barrier runs once per page and names the replica group of every mark of the cut; the
// identifier of a group is a SHA-256 of the engine identity and the slot, so deriving it per
// (mark, slot) pair, 64 times 64 times for every page, was a fifth of a scan's CPU. The identity is
// fixed for the life of a replicated engine: the table is built once. This counts the derivations
// the barrier and the before-cursor check make.
func TestReleaseFenceDoesNotDeriveGroupIdentifiers(t *testing.T) {
	x := newEraseEnv(t)
	seedScanRows(x, 1, 3)
	marks, _, err := x.e.replicaReadFence(context.Background(), nil, false)
	if err != nil || len(marks) != 64 {
		t.Fatalf("read fence: %d marks, %v", len(marks), err)
	}
	var derived atomic.Int64
	hook := func() { derived.Add(1) }
	groupDerivedHook.Store(&hook)
	defer groupDerivedHook.Store(nil)
	const rounds = 10
	for range rounds {
		x.e.mu.Lock()
		err = x.e.replicaReleaseFenceLocked(context.Background(), marks)
		x.e.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range marks {
			if err = x.e.replicaBeforeCursor(context.Background(), m); err != nil {
				t.Fatal(err)
			}
		}
	}
	// The slack covers the engine's own background work, which names a group now and then; the
	// per-pair derivation was 64*65/2 per fence and again per before-cursor sweep (2 x 2080 x rounds).
	if got := derived.Load(); got > 64 {
		t.Fatalf("%d group identifiers derived by %d fences and %d before-cursor checks, want none (a table built once)", got, rounds, rounds*len(marks))
	}
	// A mark of a group that is not the engine's is still refused.
	x.e.mu.Lock()
	err = x.e.replicaReleaseFenceLocked(context.Background(), []model.Cursor{{Group: model.NewID(), Index: 1}})
	x.e.mu.Unlock()
	if !isStale(err) {
		t.Fatalf("release fence of a foreign group: %v, want Stale", err)
	}
	if err = x.e.replicaBeforeCursor(context.Background(), model.Cursor{Group: model.NewID(), Index: 1}); !isStale(err) {
		t.Fatalf("before-cursor of a foreign group: %v, want Stale", err)
	}
}

func isStale(err error) bool {
	var f *model.Fault
	return errors.As(err, &f) && f.Code == model.Stale
}

// Each page is certified by the release barrier, whose own authorization, judged after the quorum,
// supersedes every earlier one: Next reads the authority once to start a chunk (that read also
// returns the deletion predicates the chunk filters with) and once at the barrier, not before the
// chunk loop a second time and a third time through a separate deletion read.
func TestScanReadsAuthorityOncePerChunkAndOncePerBarrier(t *testing.T) {
	x := newEraseEnv(t)
	seedScanRows(x, 4, 100)
	var calls atomic.Int64
	x.e.mu.Lock()
	x.e.validator = countingValidator{inner: x.a, calls: &calls}
	x.e.mu.Unlock()
	it, err := x.e.Scan(context.Background(), x.read, ScanRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric, End: 1 << 40})
	if err != nil {
		t.Fatal(err)
	}
	calls.Store(0)
	rows, pages := 0, 0
	for {
		page, err := it.Next(context.Background())
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		rows += page.Len()
		pages++
	}
	it.Close()
	if rows != 400 || pages < 3 {
		t.Fatalf("scan delivered %d rows in %d pages, want 400 rows in at least 3 pages", rows, pages)
	}
	// A page costs a chunk start and a barrier; the last Next (no more rows) is a barrier and the
	// check that precedes it.
	if got, limit := calls.Load(), int64(2*(pages+1)); got > limit {
		t.Fatalf("%d authority reads for %d pages, want at most %d", got, pages, limit)
	}
}

// The rows of batches that overlap in time alternate in the time index. A walk that kept only the
// page of the row before read, hashed and decoded a page again at every alternation (786 reads for
// the 8 pages of one scan); a page is decoded once per chunk, and every row still comes out once, in
// index order, whatever the interleaving.
func TestInterleavedBatchesDecodeEachPageOncePerChunk(t *testing.T) {
	x := newEraseEnv(t)
	const batches, per = 4, 100
	want := map[model.ID]bool{}
	for batch := range batches {
		recs := make([]model.Record, per)
		for i := range recs {
			recs[i] = x.metric(fmt.Sprintf("interleaved_series_%d", batch), model.UnixNano(50+i))
			want[recs[i].ID] = true
		}
		x.appendRecords(model.NewID(), metricRetention, recs...)
	}
	before := x.e.Stats().PagesRead
	it, err := x.e.Scan(context.Background(), x.read, ScanRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric, End: 1 << 40})
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	pages := 0
	var last model.UnixNano
	for {
		page, err := it.Next(context.Background())
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		pages++
		for i := range page.IDs {
			if !want[page.IDs[i]] {
				t.Fatalf("row %s delivered twice or never written", page.IDs[i])
			}
			delete(want, page.IDs[i])
			if page.Times[i] < last {
				t.Fatalf("row at %d after one at %d: the scan left index order", page.Times[i], last)
			}
			last = page.Times[i]
		}
	}
	if len(want) != 0 {
		t.Fatalf("%d rows never delivered", len(want))
	}
	// A chunk decodes each of the pages it reaches once (at most the batches), not once per row.
	if read := x.e.Stats().PagesRead - before; read > uint64(batches*pages) {
		t.Fatalf("%d page reads for %d released pages of %d batches: a page is decoded again at every alternation of the index", read, pages, batches)
	}
}

// BenchmarkScanRelease measures a scan that is mostly release barriers: pages of 100 rows, every
// page certified by the quorum barrier over 64 groups and the authorization behind it. "ordered" is
// one series (consecutive times, so the rows of a page are consecutive in the time index);
// "interleaved" is a series per batch over the same times (the rows of the batches alternate in
// the index). "fence" is the barrier alone, "scan" the whole read. derivations/page counts
// group-identifier derivations (a SHA-256 each), authority-reads/page the Revalidate calls,
// pages-read/op the pages the engine decoded.
func BenchmarkScanRelease(b *testing.B) {
	for _, layout := range []struct {
		name        string
		interleaved bool
	}{{"ordered", false}, {"interleaved", true}} {
		b.Run(layout.name, func(b *testing.B) {
			runAsTest(b, func(t *testing.T) {
				x := newEraseEnv(t)
				seedScanRows(x, 8, 100, layout.interleaved)
				marks, _, err := x.e.replicaReadFence(context.Background(), nil, false)
				if err != nil {
					t.Fatal(err)
				}
				var derived, calls atomic.Int64
				hook := func() { derived.Add(1) }
				groupDerivedHook.Store(&hook)
				defer groupDerivedHook.Store(nil)
				x.e.mu.Lock()
				x.e.validator = countingValidator{inner: x.a, calls: &calls}
				x.e.mu.Unlock()
				b.Run("fence", func(b *testing.B) {
					derived.Store(0)
					b.ReportAllocs()
					b.ResetTimer()
					for range b.N {
						x.e.mu.Lock()
						err := x.e.replicaReleaseFenceLocked(context.Background(), marks)
						x.e.mu.Unlock()
						if err != nil {
							b.Fatal(err)
						}
					}
					b.ReportMetric(float64(derived.Load())/float64(b.N), "derivations/op")
				})
				b.Run("scan", func(b *testing.B) {
					derived.Store(0)
					calls.Store(0)
					pages := 0
					readBefore := x.e.Stats().PagesRead
					b.ReportAllocs()
					b.ResetTimer()
					for range b.N {
						rows, p := scanAll(b, x)
						if rows != 800 {
							b.Fatalf("scan delivered %d rows, want 800", rows)
						}
						pages += p
					}
					b.ReportMetric(float64(derived.Load())/float64(pages), "derivations/page")
					b.ReportMetric(float64(calls.Load())/float64(pages), "authority-reads/page")
					b.ReportMetric(float64(pages)/float64(b.N), "pages/op")
					b.ReportMetric(float64(x.e.Stats().PagesRead-readBefore)/float64(b.N), "pages-read/op")
				})
			})
		})
	}
}

// A backfill puts rows of the whole window into every batch, so the time index alternates between the
// pages at every row. The chunk bound counted the stored rows of the page a row comes from instead of
// the rows the chunk holds, so every chunk held one row (a 24 h scan of one project at the Queries
// gate: 19,500 chunks, each an authority read, a barrier, an index seek and a page decode). A chunk
// holds up to pageRows rows whichever pages they come from, and a page decoded for one chunk is not
// decoded again for the next one while it is unchanged.
func TestTimeSpreadPagesFillChunksAndAreDecodedOnce(t *testing.T) {
	x := newEraseEnv(t)
	const batches, per = 8, 100
	seedScanRows(x, batches, per, true)
	before := x.e.Stats().PagesRead
	rows, chunks := scanAll(t, x)
	if rows != batches*per {
		t.Fatalf("scan delivered %d rows, want %d", rows, batches*per)
	}
	if want := (rows + pageRows - 1) / pageRows; chunks > want+1 {
		t.Fatalf("%d rows came in %d chunks, want at most %d (pageRows %d)", rows, chunks, want+1, pageRows)
	}
	if read := x.e.Stats().PagesRead - before; read > batches {
		t.Fatalf("%d page decodes for %d pages scanned once: a page is decoded again for a later chunk", read, batches)
	}
}

// A cached page is never served once its stored bytes changed: a page that physical erasure
// rewrites between two chunks is read again, and the rows that survive come out exactly once.
func TestChunkCacheDoesNotServeARewrittenPage(t *testing.T) {
	x := newEraseEnv(t)
	const batches, per = 4, 100
	seedScanRows(x, batches, per, true)
	ctx := context.Background()
	it, err := x.e.Scan(ctx, x.read, ScanRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric, End: 1 << 40})
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	first, err := it.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[model.ID]bool{}
	for _, id := range first.IDs {
		seen[id] = true
	}
	// The rows of the first chunk are delivered; the pages are rewritten without the rows of the later times.
	pred := x.rangePredicate(110, 1<<40, model.Metric)
	if _, err = x.e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err != nil {
		t.Fatal(err)
	}
	rest := 0
	for {
		page, err := it.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("scan after the pages were rewritten: %v", err)
		}
		for i, id := range page.IDs {
			if seen[id] {
				t.Fatalf("row %s delivered twice", id)
			}
			if page.Times[i] >= 110 {
				t.Fatalf("row at %d delivered after its erasure", page.Times[i])
			}
			seen[id] = true
			rest++
		}
	}
	if want := batches * 60; len(seen) != want {
		t.Fatalf("scan delivered %d rows (%d after the rewrite), want the %d rows below the erased range", len(seen), rest, want)
	}
}

// The pages one scan decoded serve the next scan of the same window: ten queries a second over the
// same 24 h do not decode the pages ten times a second.
func TestSecondScanOfTheSamePagesDecodesNothing(t *testing.T) {
	x := newEraseEnv(t)
	const batches, per = 8, 100
	seedScanRows(x, batches, per, true)
	if rows, _ := scanAll(t, x); rows != batches*per {
		t.Fatalf("first scan delivered %d rows", rows)
	}
	before := x.e.Stats().PagesRead
	if rows, _ := scanAll(t, x); rows != batches*per {
		t.Fatalf("second scan delivered %d rows", rows)
	}
	if read := x.e.Stats().PagesRead - before; read != 0 {
		t.Fatalf("the second scan of unchanged pages decoded %d pages, want none", read)
	}
}

// A decoded page that erasure deletes does not stay in memory: the cache drops it with the page, so
// no decoded copy of erased bytes outlives the erasure.
func TestErasedPagesLeaveTheDecodedPageCache(t *testing.T) {
	x := newEraseEnv(t)
	const batches, per = 4, 100
	seedScanRows(x, batches, per, true)
	scanAll(t, x)
	held := func() int {
		x.e.scanPages.mu.Lock()
		defer x.e.scanPages.mu.Unlock()
		return len(x.e.scanPages.byID)
	}
	if got := held(); got != batches {
		t.Fatalf("the cache holds %d pages after a scan of %d, want all of them", got, batches)
	}
	pred := x.rangePredicate(0, 1<<40, model.Metric)
	if _, err := x.e.EraseDeleted(context.Background(), []model.DeletePredicate{pred}, nil); err != nil {
		t.Fatal(err)
	}
	if got := held(); got != 0 {
		t.Fatalf("the cache holds %d pages of an erased range", got)
	}
	if rows, _ := scanAll(t, x); rows != 0 {
		t.Fatalf("a scan after the erasure delivered %d rows", rows)
	}
}
