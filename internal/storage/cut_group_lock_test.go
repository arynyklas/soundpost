// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// addBulk admits and appends n batches of records records, each of a metric whose name is pad bytes long, to the slot
// of the env's producer: the stored command of a batch of the single-host load (12 records, ~10 KB), from the fixture
// normalizedAs uses.
func (w *windowEnv) addBulk(n, records, pad int) {
	w.t.Helper()
	name := "requests_" + strings.Repeat("p", pad)
	for range n {
		scope, err := w.service.SourceScope(context.Background(), w.cred, false)
		if err != nil {
			w.t.Fatal(err)
		}
		src, err := w.service.SourceAuthority(context.Background(), w.cred, true)
		if err != nil {
			w.t.Fatal(err)
		}
		b := model.Batch{Version: 1, Project: w.desc.Project, Source: w.desc.Source, Producer: w.producer, ID: model.NewID(), PolicyRevision: 1}
		for i := range records {
			b.Records = append(b.Records, model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: w.next + model.UnixNano(i), Resource: model.Resource{Service: src.Policy.Resources.Services[0], Environment: src.Policy.Resources.Environments[0], Build: src.Policy.Resources.Builds[0], Instance: src.Policy.Resources.Instances[0]}, Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: ptrBits(0x3ff0000000000000), Type: "counter", Unit: "1"}}})
		}
		w.next += model.UnixNano(records)
		slot, _ := model.OwnerSlot(w.desc.Org, b.Project, b.Source, b.Producer, b.Records[0])
		b.RouteSlot = slot
		w.slot = slot
		raw := mustJSON(w.t, b)
		policyBytes := mustJSON(w.t, src.Policy)
		nb := model.NormalizedBatch{Batch: b, Org: w.desc.Org, Hash: model.HashCanonical(raw), Canonical: raw, PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyHash: model.HashCanonical(policyBytes).String(), AdmissionAt: 10, Deadlines: []model.SignalDeadline{{Kind: model.Metric, RetainUntil: 1 << 40}}}
		if nb.Reservation, err = w.store.ReserveAdmission(context.Background(), scope, nb); err != nil {
			w.t.Fatalf("reserve: %v", err)
		}
		if _, err = w.e.Append(context.Background(), scope, nb); err != nil {
			w.t.Fatalf("append: %v", err)
		}
	}
}

// onlyExplicitCuts keeps the data groups' own cadence from cutting while a test fills a slot: the bound is one no test reaches.
func onlyExplicitCuts(t *testing.T) {
	t.Helper()
	old := DefaultSlotCadence
	DefaultSlotCadence = replica.Cadence{Commands: 1 << 40}
	t.Cleanup(func() { DefaultSlotCadence = old })
}

const (
	cutLockWindow   = 256 // commands of the open window of a cut (production: 4096; filling a slot takes ~10 ms a command)
	cutLockRecords  = 12  // records of a batch at the single-host load
	cutLockPad      = 700 // bytes of metric name per record: a command of ~8 KB
	cutLockCommands = cutLockWindow - 1
)

// A snapshot cut of a data group held the ready stage (ioMu) and the group lock for the whole of the machine's
// derivation: the window table (a decode of every command of the open window, 4096 commands of 10 KB at the
// single-host load), the deletion ledger and the staging of the window files. A group that holds them runs no cycle
// (no proposal, no apply, no heartbeat leaves) and takes no tick or step, so a leader that cuts is silent for as long
// as the derivation takes: 0.3-0.8 s at the 5k records/s gate, where the followers' election timers run out
// (admit-report round 4, "What remains" 4). What the applied index fixes is its number, the table of retried commands and
// the members; the derivation reads commands at or below that index, which no command applied later changes, and is
// done after the locks are released.
func TestSnapshotCutHoldsTheGroupLocksOnlyToCaptureTheIndex(t *testing.T) {
	defer SetSnapshotWindow(SetSnapshotWindow(cutLockWindow))
	onlyExplicitCuts(t)
	w := newWindowEnv(t)
	fillBegan := time.Now()
	w.addBulk(cutLockCommands, cutLockRecords, cutLockPad) // one command short of a sealed window: the cut derives the whole open window
	t.Logf("filled %d commands in %v", cutLockCommands, time.Since(fillBegan))
	g := w.e.repl.groups[w.slot]
	g.PhaseMaxima()
	cut := func() time.Duration {
		began := time.Now()
		if _, err := g.CreateSnapshot(context.Background(), g.Status().ApplicationCursor); err != nil {
			t.Fatal(err)
		}
		return time.Since(began)
	}
	cold := cut()
	_, coldLock, _, _ := g.PhaseMaxima()
	w.addBulk(cutLockWindow/2, cutLockRecords, cutLockPad) // seals the window and opens the next with half of it
	warm := cut()
	_, warmLock, _, _ := g.PhaseMaxima()
	t.Logf("cut of a slot at %d commands of ~%d KB: whole %v, group locks held %v; %d commands more: whole %v, locks held %v", cutLockCommands, cutLockRecords*cutLockPad/1024, cold, time.Duration(coldLock), cutLockWindow/2, warm, time.Duration(warmLock))
	const bound = 50 * time.Millisecond
	if time.Duration(coldLock) > bound || time.Duration(warmLock) > bound {
		t.Fatalf("a cut held the group locks for %v (first) and %v (next), want at most %v: they are for the index, not for the derivation", time.Duration(coldLock), time.Duration(warmLock), bound)
	}
}
