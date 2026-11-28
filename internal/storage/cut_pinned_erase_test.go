// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// deriveCut derives what a pinned cut hands the snapshot store: the compact state of its envelope and the bytes of its window files.
func deriveCut(t *testing.T, c *pinnedSlotCut) (state []byte, application uint64, files []byte) {
	t.Helper()
	state, err := c.CompactSnapshot()
	if err != nil {
		t.Fatal("derive the cut's state:", err)
	}
	var v2 slotSnapshotV2
	if err = json.Unmarshal(state, &v2); err != nil {
		t.Fatal(err)
	}
	pinned, release, err := c.PinFiles()
	if err != nil {
		t.Fatal("derive the cut's files:", err)
	}
	defer release()
	for _, f := range pinned {
		if f.Reuse {
			t.Fatalf("file %s is reused from a snapshot, and no cut was taken in this test", f.Name)
		}
		raw, err := os.ReadFile(f.Path)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, raw...)
	}
	return state, uint64(v2.Application), files
}

// A snapshot cut of a data group is pinned at an applied index and derived after the group has released its locks (admit report,
// round 5), so an erasure (the one writer that rewrites stored commands) and a snapshot install can land between the pin and the
// derivation. The cut then has to be the state at the pinned index, not a later one, and has to hold no byte the erasure removed
// (m4 review of round 5, coverage gap 2). The fixture is checked first: a cut derived before the erasure does hold the canary and
// the kept series, by the same search.
func TestAnErasureAndASnapshotInstallBetweenThePinAndTheDerivationOfACutLeaveNoErasedBytes(t *testing.T) {
	const lateCanary = "LATECANARY5b1c93a07e4d2f68"
	x := newCheckpointEnv(t)
	ctx := context.Background()
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	slot := hit.batch.RouteSlot
	m := &slotMachine{engine: x.e, slot: slot}
	keptName := []byte(hit.keepM.Payload.Metric.Name)
	x.coldCanary(eraseCanary)
	pred := x.rangePredicate(0, 10, model.Metric)
	barrierAll(t, x.e, pred) // the saga's fence

	before, err := m.pinSlotCut()
	if err != nil {
		t.Fatal(err)
	}
	state, _, files := deriveCut(t, before)
	if !deepContains(state, []byte(eraseCanary), 5) && !deepContains(files, []byte(eraseCanary), 5) {
		t.Fatal("fixture invalid: a cut derived before the erasure does not hold the canary, so the search proves nothing")
	}
	if !deepContains(state, keptName, 5) && !deepContains(files, keptName, 5) {
		t.Fatal("fixture invalid: a cut derived before the erasure does not hold the kept series")
	}

	pin, err := m.pinSlotCut()
	if err != nil {
		t.Fatal(err)
	}
	// Between the pin and the derivation: the erasure rewrites the stored commands, the group goes on applying (a batch whose
	// canary the cut must not hold: it is above the pinned index), and a snapshot of the erased history is installed.
	report, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil)
	if err != nil || report.Records < 1 {
		t.Fatalf("erase %+v %v", report, err)
	}
	var late model.Record // outside the deleted range (t=50), routed to the slot of the cut
	for salt := range 1 << 16 {
		r := x.metric(fmt.Sprintf("late%s_%d", lateCanary, salt), 50)
		if s, err := model.OwnerSlot(x.d.Org, x.d.Project, x.d.Source, hit.batch.Producer, r); err == nil && s == slot {
			late = r
			break
		}
	}
	x.appendRecords(hit.batch.Producer, bothDeadlines, late, hit.keepL)
	installed, err := m.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var physical uint64
	if err = x.e.db.View(func(tx *bolt.Tx) error { physical = getCounter(tx, slot, "physical"); return nil }); err != nil {
		t.Fatal(err)
	}
	if err = m.Restore(installed, physical); err != nil {
		t.Fatal("install:", err)
	}
	x.e.mu.Lock()
	now := x.e.indexes[slot]
	x.e.mu.Unlock()
	if now <= pin.application {
		t.Fatalf("fixture invalid: the slot is at %d, not past the pinned index %d", now, pin.application)
	}

	state, application, files := deriveCut(t, pin)
	if application != pin.application {
		t.Fatalf("the cut was derived at index %d, pinned at %d (the slot is at %d)", application, pin.application, now)
	}
	for _, c := range []string{eraseCanary, otherCanary} {
		if deepContains(state, []byte(c), 5) || deepContains(files, []byte(c), 5) {
			t.Fatalf("the cut holds %s, which the erasure removed before it was derived", c)
		}
	}
	if deepContains(state, []byte(lateCanary), 5) || deepContains(files, []byte(lateCanary), 5) {
		t.Fatal("the cut holds a batch applied after its pinned index")
	}
	if !deepContains(state, keptName, 5) && !deepContains(files, keptName, 5) {
		t.Fatal("the cut lost the series the erasure keeps")
	}
}
