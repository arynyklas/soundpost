// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// pollEvery makes the passes of a test look at their context every `every` units of work, each unit taking delay, and restores the
// production interval and delay when the test ends.
func pollEvery(t *testing.T, every uint32, delay time.Duration) {
	t.Helper()
	oldEvery, oldDelay := cancelPollEvery, verifyUnitDelay
	cancelPollEvery, verifyUnitDelay = every, delay
	t.Cleanup(func() { cancelPollEvery, verifyUnitDelay = oldEvery, oldDelay })
}

// A SIGTERM right after a start waited 67 s, and more than 3 minutes, for the first full pass of the background verification: the pass's
// read transaction walked every command, every index entry and every window of the node and looked at nothing (L2w20Admission30). Every
// loop of it looks at the context every cancelPollEvery units of work now; the polls below are what the shutdown waits for.
func TestEveryLoopOfAVerificationPassStopsAtItsFirstLook(t *testing.T) {
	holdBackgroundVerification(t)
	w := newWindowEnv(t)
	w.add(9) // two sealed windows of the 4 commands the tests cut a slot's history into, and an open one
	if _, err := w.e.CreateSnapshots(context.Background()); err != nil {
		t.Fatal(err)
	}
	pollEvery(t, 1, 0)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, c := range []struct {
		name string
		run  func(tx *bolt.Tx, poll *cancelPoll) error
	}{
		{"replica namespaces, every command of every slot", func(tx *bolt.Tx, poll *cancelPoll) error {
			return validateReplicaNamespacesTx(tx, poll, nil, nil)
		}},
		{"replica namespaces above the verified point", func(tx *bolt.Tx, poll *cancelPoll) error {
			return validateReplicaNamespacesTx(tx, poll, w.e.verifiedFrom, nil, true)
		}},
		{"every entry of the query indexes and every page", validateIndexIntegrityPolled},
		{"window records, every command of every window", validateWindowRecordsTx},
		{"index entries of every command above the verified point", func(tx *bolt.Tx, poll *cancelPoll) error {
			var entries atomic.Uint64
			return w.e.validateIndexTail(tx, poll, &entries)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			poll := &cancelPoll{ctx: cancelled}
			err := w.e.db.View(func(tx *bolt.Tx) error { return c.run(tx, poll) })
			if !isCancelled(err) {
				t.Fatalf("the validation of a cancelled pass returned %v", err)
			}
			if poll.n != 1 {
				t.Fatalf("the validation did %d units of work after its pass was cancelled, want 1 (the first look)", poll.n)
			}
			// The same validation with a live context completes, and does more than one unit: the loop that is polled is the loop that runs.
			live := &cancelPoll{ctx: context.Background()}
			if err = w.e.db.View(func(tx *bolt.Tx) error { return c.run(tx, live) }); err != nil {
				t.Fatalf("the validation of a live pass: %v", err)
			}
			if live.n < 2 {
				t.Fatalf("the validation of a live pass did %d units of work, the fixture is too small to show a loop", live.n)
			}
		})
	}
	t.Run("hash of a segment", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "segment")
		if err := os.WriteFile(path, bytes.Repeat([]byte{7}, 3*hashFileBlock), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := hashFileCtx(cancelled, path); !isCancelled(err) {
			t.Fatalf("the hash of a segment for a cancelled pass: %v", err)
		}
		if _, err := hashFileCtx(context.Background(), path); err != nil {
			t.Fatal(err)
		}
	})
}

// A pass that was stopped found nothing wrong: the engine is not failed closed, and the next pass records the point.
func TestCancelledFullPassFailsNothing(t *testing.T) {
	holdBackgroundVerification(t)
	x := newEraseEnv(t)
	x.appendN(6, 100)
	pollEvery(t, 1, 0)
	ctx, cancel := context.WithCancel(context.Background())
	x.e.setFault(func(at string) error {
		if at == "verify_full_view" {
			cancel() // the pass is stopped while it is inside its read transaction
		}
		return nil
	})
	if err := x.e.VerifyFull(ctx); !isCancelled(err) {
		t.Fatalf("a full pass stopped inside its read transaction returned %v", err)
	}
	if err := x.e.VerifyFailure(); err != nil {
		t.Fatalf("a stopped pass failed the engine: %v", err)
	}
	x.e.setFault(nil)
	x.appendN(1, 200) // the engine still serves
	if err := x.e.VerifyFull(context.Background()); err != nil {
		t.Fatalf("the next full pass: %v", err)
	}
	if got, want := recordedTotal(t, x), totalApplied(x.e); got != want {
		t.Fatalf("the next pass recorded %d commands, applied %d", got, want)
	}
}

// The red test of the shutdown that waited for the pass: Close stops the background verification and waits for it. The pass is made
// slow (every unit of work takes verifyUnitDelay, as the minutes of a node the gate leaves are), and a stop asked while it runs inside
// its read transaction is answered within a small part of what the whole pass takes.
func TestShutdownDuringAFullPassReturnsWithinOneStretchOfWork(t *testing.T) {
	holdBackgroundVerification(t)
	w := newWindowEnv(t)
	w.add(20)
	if _, err := w.e.CreateSnapshots(context.Background()); err != nil {
		t.Fatal(err)
	}
	gate := verifyGate
	// The pass without a stop: what the shutdown used to wait for.
	pollEvery(t, 4, 30*time.Millisecond)
	began := time.Now()
	if err := w.e.VerifyFull(context.Background()); err != nil {
		t.Fatal(err)
	}
	whole := time.Since(began)
	if whole < 3*time.Second {
		t.Fatalf("fixture invalid: the slowed full pass takes %v, too short to show a wait", whole)
	}
	entered := make(chan struct{})
	var once sync.Once
	w.e.setFault(func(at string) error {
		if at == "verify_full_view" {
			once.Do(func() { close(entered) })
		}
		return nil
	})
	close(gate) // the background loop's first pass begins
	select {
	case <-entered:
	case <-time.After(20 * time.Second):
		t.Fatal("the background pass never reached its read transaction")
	}
	time.Sleep(whole / 4) // well inside the transaction
	began = time.Now()
	w.e.stopBackgroundVerify()
	stopped := time.Since(began)
	t.Logf("the full pass takes %v; the stop waited %v for it", whole, stopped)
	if stopped > whole/4 || stopped > time.Second {
		t.Fatalf("the stop waited %v for a full pass of %v: it is not answered within a bounded stretch of work", stopped, whole)
	}
	if err := w.e.VerifyFailure(); err != nil {
		t.Fatalf("a stopped pass failed the engine: %v", err)
	}
}
