// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"testing"
)

// The rows of batches that overlap in time alternate between their pages in the time index, so every
// chunk meets every page of the window, and each first sight of a page in a chunk looked its reference
// up in the row store (a block decode) and parsed it (a JSON decode of the whole reference): 47 s of 449
// CPU seconds of a ten-query mix at the Queries gate. A page that the cache holds, decoded from a
// reference no commit has changed since, is served without either.
func TestSecondScanLooksUpNoPageReference(t *testing.T) {
	x := newEraseEnv(t)
	seedScanRows(x, 4, 8, true)
	rows, chunks := scanAll(t, x)
	if rows != 32 || chunks != 1 {
		t.Fatalf("first scan: %d rows in %d chunks, want 32 in 1", rows, chunks)
	}
	if got := x.e.scanPages.refLookups.Load(); got != 4 {
		t.Fatalf("first scan looked %d page references up, want the 4 pages once", got)
	}
	before := x.e.scanPages.refLookups.Load()
	if rows, _ = scanAll(t, x); rows != 32 {
		t.Fatalf("second scan: %d rows, want 32", rows)
	}
	if got := x.e.scanPages.refLookups.Load() - before; got != 0 {
		t.Fatalf("second scan looked %d page references up, want none: every page is cached from an unchanged reference", got)
	}
}

// A commit that changes a page's reference (a flush moves it from the row to a segment) makes the next
// scan look it up again, and read it at its new place; the scan after that is served from the cache.
func TestPageReferencesAreLookedUpAgainWhenTheyMove(t *testing.T) {
	x := newEraseEnv(t)
	seedScanRows(x, 4, 8, true)
	scanAll(t, x)
	if err := x.e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	lookups, read := x.e.scanPages.refLookups.Load(), x.e.Stats().PagesRead
	if rows, _ := scanAll(t, x); rows != 32 {
		t.Fatalf("scan after the flush: %d rows, want 32", rows)
	}
	if got := x.e.scanPages.refLookups.Load() - lookups; got != 4 {
		t.Fatalf("scan after the flush looked %d page references up, want the 4 pages", got)
	}
	if got := x.e.Stats().PagesRead - read; got != 4 {
		t.Fatalf("scan after the flush read %d pages, want the 4 pages at their new place", got)
	}
	lookups = x.e.scanPages.refLookups.Load()
	scanAll(t, x)
	if got := x.e.scanPages.refLookups.Load() - lookups; got != 0 {
		t.Fatalf("the scan after that looked %d page references up, want none", got)
	}
}
