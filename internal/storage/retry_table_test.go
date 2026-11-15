// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// setSlotRetryMax changes how many applied commands a slot's replication group keeps in its retry
// table for the engines opened until the returned function runs.
func setSlotRetryMax(n int) func() {
	previous := slotRetryMax
	slotRetryMax = n
	return func() { slotRetryMax = previous }
}

// retryShape reads the retry table the selected snapshot of slot serializes into its envelope: how
// many commands it keeps, and how many of them still carry a payload.
func retryShape(t *testing.T, e *Engine, slot uint16) (records, withPayload int, envelopeBytes int64) {
	t.Helper()
	current, ok := e.repl.groups[slot].Snapshots().Current()
	if !ok {
		t.Fatalf("slot %d has no selected snapshot", slot)
	}
	path := filepath.Join(current.Dir(), "envelope.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Completed []struct {
			Entry struct {
				Payload []byte `json:"payload"`
			} `json:"entry"`
		} `json:"completed"`
	}
	if err = json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	for _, c := range envelope.Completed {
		if len(c.Entry.Payload) > 0 {
			withPayload++
		}
	}
	return len(envelope.Completed), withPayload, int64(len(raw))
}

// A slot's retry table keeps a fixed-size record for the newest slotRetryMax commands, never a
// payload, so what a cut serializes and what the compacted journal begins with is bounded by that
// number and not by how much history the slot holds.
func TestSlotRetryTableIsBoundedAndKeepsNoPayload(t *testing.T) {
	const keep = 6
	defer setSlotRetryMax(keep)()
	// One window for the whole history: the window table grows with history/window, which is not what
	// this test bounds.
	defer SetSnapshotWindow(SetSnapshotWindow(4096))
	ctx := context.Background()
	store, service, credential, descriptor := fixture(t)
	dir := t.TempDir()
	e, err := openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BindAdmissionOwner(e); err != nil {
		t.Fatal(err)
	}
	producer := model.NewID()
	var slot uint16
	at := model.UnixNano(1)
	add := func(count int) {
		for range count {
			scope, b := measureNormalized(t, store, service, credential, descriptor, producer, at)
			at++
			slot = b.RouteSlot
			if _, err := e.Append(ctx, scope, b); err != nil {
				t.Fatal(err)
			}
		}
	}
	type shape struct {
		records, withPayload int
		envelope, journal    int64
	}
	measure := func() shape {
		if _, err := e.CreateSnapshots(ctx); err != nil {
			t.Fatal(err)
		}
		if err := e.CompactJournals(ctx); err != nil {
			t.Fatal(err)
		}
		var s shape
		s.records, s.withPayload, s.envelope = retryShape(t, e, slot)
		s.journal = fileSize(filepath.Join(dir, "raft", "slot-"+strconv.Itoa(int(slot)), "ready.wal"))
		return s
	}
	add(24)
	small := measure()
	add(60)
	large := measure()
	for label, s := range map[string]shape{"24 commands": small, "84 commands": large} {
		if s.records != keep {
			t.Fatalf("%s: the retry table serialized %d records, want the newest %d", label, s.records, keep)
		}
		if s.withPayload != 0 {
			t.Fatalf("%s: %d of the table's records still carry a payload", label, s.withPayload)
		}
	}
	if large.envelope > small.envelope+small.envelope/10 || large.journal > small.journal+small.journal/10 {
		t.Fatalf("history grew 3.5x but the envelope went %d -> %d bytes and the compacted journal %d -> %d bytes: the retry table is not bounded",
			small.envelope, large.envelope, small.journal, large.journal)
	}
}

// The replication layer keeps its own copy of every committed command in the retained log, the
// journal that mirrors it and the backup pin archives, and an erasure redacts those by command. A
// command the bounded retry table has already forgotten still has such copies, so the redaction
// locates them by application index.
func TestRedactionReachesACommandTheRetryTableForgot(t *testing.T) {
	defer setSlotRetryMax(2)()
	x := newCheckpointEnv(t)
	ctx := context.Background()
	producer := model.NewID()
	hit := x.appendMixedAs(producer, eraseCanary, bothDeadlines)
	var rest []erased
	for range 5 {
		rest = append(rest, x.appendMixedAs(producer, otherCanary, bothDeadlines))
	}
	if got, want := hit.batch.RouteSlot, rest[0].batch.RouteSlot; got != want {
		t.Fatalf("fixture invalid: the batches route to slots %d and %d", got, want)
	}
	slot := hit.batch.RouteSlot
	x.cut() // a cut serializes the retry table, which must hold only the newest two commands
	if records, withPayload, _ := retryShape(t, x.e, slot); records != 2 || withPayload != 0 {
		t.Fatalf("fixture invalid: the retry table holds %d records, %d of them with a payload; want the newest 2, none with a payload", records, withPayload)
	}
	pred := x.rangePredicate(0, 10, model.Metric)
	barrierAll(t, x.e, pred)
	if hits := x.raftHits(eraseCanary); !inHits(hits, "ready.wal") {
		t.Fatalf("fixture invalid: %s is not in the journal before the erasure: %v", eraseCanary, hits)
	}
	if report, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err != nil || report.Records < 6 {
		t.Fatalf("erase %+v %v", report, err)
	}
	for _, c := range []string{eraseCanary, otherCanary} {
		if hits := x.raftHits(c); inHits(hits, "ready.wal") {
			t.Fatalf("the journal still holds %s right after the erasure, although the retry table forgot its command: %v", c, hits)
		}
	}
	x.maintain(pred)
	x.requireNoCopy("after the maintenance sequence", eraseCanary, otherCanary)
	x.requireReceipt("after the maintenance sequence", hit)
}

// A backup pin archives the journal entries it keeps; once the journal was compacted past them the
// archive is the only replication-layer copy of a command the retry table forgot, and the erasure
// has to find it there.
func TestRedactionReachesAPinArchivedCommandTheRetryTableForgot(t *testing.T) {
	defer setSlotRetryMax(2)()
	x := newCheckpointEnv(t)
	ctx := context.Background()
	producer := model.NewID()
	hit := x.appendMixedAs(producer, eraseCanary, bothDeadlines)
	for range 5 {
		x.appendMixedAs(producer, otherCanary, bothDeadlines)
	}
	slot := hit.batch.RouteSlot
	pin, err := x.e.repl.groups[slot].PinJournal(0)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Release()
	x.cut()
	if err = x.e.CompactJournals(ctx); err != nil { // the pinned range now lives only in the archive
		t.Fatal(err)
	}
	pred := x.rangePredicate(0, 10, model.Metric)
	barrierAll(t, x.e, pred)
	if hits := x.raftHits(eraseCanary); len(hits) == 0 {
		t.Fatalf("fixture invalid: the pin archive does not hold %s", eraseCanary)
	}
	if report, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err != nil || report.Records < 6 {
		t.Fatalf("erase %+v %v", report, err)
	}
	x.maintain(pred)
	x.requireNoCopy("after the maintenance sequence", eraseCanary, otherCanary)
}
