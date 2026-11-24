// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"math"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// readsOutsideTransactions counts the reads of the payload log made while the engine has a read transaction open, and keeps the stack of
// the first one.
type readsOutsideTransactions struct {
	e      *Engine
	reads  atomic.Int64
	inside atomic.Int64
	once   sync.Once
	stack  string
}

func watchPayloadReads(t *testing.T, e *Engine) *readsOutsideTransactions {
	t.Helper()
	w := &readsOutsideTransactions{e: e}
	hook := func() {
		w.reads.Add(1)
		if e.db.openReaders() > 0 {
			w.inside.Add(1)
			w.once.Do(func() { w.stack = string(debug.Stack()) })
		}
	}
	payloadReadHook.Store(&hook)
	t.Cleanup(func() { payloadReadHook.Store(nil) })
	return w
}

// A reader that follows a payload reference inside its read transaction holds the transaction open for the length of the disk read, and
// bolt reuses no page freed after the oldest open read transaction began: at the single-host gate every command reader that waited for the
// disk made apply.db grow (0.33 -> 2.66 GB in 20 s) and the writes fresh pages, and the acknowledgements failed from the 40th minute
// (L2w20Admission36, G8). The readers of the stored commands (the settlement of the open window, the derivation of a window for a cut,
// the window files of a snapshot, the journal-expiry plan, the candidates of an erasure) read the log outside any read transaction, whatever
// is in the page cache.
func TestCommandReadersNeverReadThePayloadLogInsideAReadTransaction(t *testing.T) {
	check := func(t *testing.T, w *readsOutsideTransactions, what string) {
		t.Helper()
		if w.reads.Load() == 0 {
			t.Fatalf("%s read no record of the payload log: the test measures nothing", what)
		}
		if n := w.inside.Load(); n != 0 {
			t.Fatalf("%s read %d of %d records of the payload log inside a read transaction; the first:\n%s", what, n, w.reads.Load(), w.stack)
		}
	}
	t.Run("settlement and cut", func(t *testing.T) {
		holdBackgroundVerification(t)
		defer SetSnapshotWindow(SetSnapshotWindow(8))
		defer SetSettlePartSpan(SetSettlePartSpan(2))
		w := newWindowEnv(t)
		if err := w.e.adoptRunsLayout(); err != nil {
			t.Fatal(err)
		}
		if err := w.e.adoptPayloadLayout(); err != nil {
			t.Fatal(err)
		}
		w.addNamed(11) // window 0 sealed, window 1 open with one complete part
		ctx := context.Background()
		watch := watchPayloadReads(t, w.e)
		if _, err := w.e.SettleCandidates(ctx); err != nil {
			t.Fatal(err)
		}
		check(t, watch, "the settlement pass")
		// The window table of the first pass is persisted: what the second reads is the part the two new commands complete.
		w.addNamed(2)
		before := watch.reads.Load()
		if _, err := w.e.SettleCandidates(ctx); err != nil {
			t.Fatal(err)
		}
		if watch.reads.Load() == before {
			t.Fatal("the settlement of the open window read no record of the payload log: the test measures nothing")
		}
		check(t, watch, "the settlement of the open window")
		w.addNamed(4)
		w.e.dropWindowCaches() // the cut derives the windows from the commands
		before = watch.reads.Load()
		if _, err := w.e.CreateSnapshots(ctx); err != nil {
			t.Fatal(err)
		}
		if watch.reads.Load() == before {
			t.Fatal("the cut read no record of the payload log: the test measures nothing")
		}
		check(t, watch, "the settlement pass and the cut")
	})
	t.Run("expiry plan and erasure scan", func(t *testing.T) {
		holdBackgroundVerification(t)
		x := newEraseEnv(t)
		x.adoptPayload()
		first, _ := x.appendError(100)
		for range 3 {
			x.appendMixed("plan", bothDeadlines)
		}
		watch := watchPayloadReads(t, x.e)
		x.expiring(math.MaxInt64)
		check(t, watch, "the journal-expiry plan")
		before := watch.reads.Load()
		guard := func(context.Context, EraseCandidate) (bool, error) { return true, nil }
		sel := eraseSelector{
			record: func(_, _ model.ID, r model.Record, _ model.Receipt) (bool, model.UnixNano) {
				return r.ID == first.ID, 0
			},
			blob: func(model.BlobManifest) (bool, model.UnixNano) { return false, 0 },
		}
		if _, _, _, err := x.e.eraseCandidates(context.Background(), sel, guard); err != nil {
			t.Fatal(err)
		}
		if watch.reads.Load() == before {
			t.Fatal("the erasure scan read no record of the payload log: the test measures nothing")
		}
		check(t, watch, "the journal-expiry plan and the erasure scan")
	})
}
