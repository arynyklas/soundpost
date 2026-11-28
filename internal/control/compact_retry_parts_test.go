// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"fmt"
	"io"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// D87 (L2w20Admission17): the control group's retry table (every acknowledged command, up to 100,000 entries) was
// serialized into the envelope of every snapshot it cut. A contracted installation cuts compact snapshots; its
// envelope now names retry parts instead of carrying the table, and a cut takes the parts of the previous cut by link.
func TestAContractedControlCutKeepsTheRetryTableOutOfTheEnvelope(t *testing.T) {
	f := newFenceFxPatch(t)
	if err := f.store.BindAdmissionOwner(&reconcileOwner{}); err != nil {
		t.Fatal(err)
	}
	f.addEstate(40)
	group := f.store.ReplicaGroup()
	cursorGroup := model.NewID()
	next := 0
	admit := func(n int) {
		t.Helper()
		for range n {
			if err := admitAndFinalize(f, fmt.Sprintf("retry_parts_series_%03d", next), model.Cursor{Group: cursorGroup, Index: model.Uint64(next + 1)}); err != nil {
				t.Fatal(err)
			}
			next++
		}
	}
	cut := func() replica.Snapshot {
		t.Helper()
		at, err := group.ReadIndex(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := group.CreateSnapshot(f.ctx, at)
		if err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	envelopeOf := func(s replica.Snapshot) (size int, inline int, parts []string) {
		t.Helper()
		in, err := s.File("envelope.json")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(in)
		in.Close()
		if err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			Completed  []json.RawMessage `json:"completed"`
			RetryParts []string          `json:"retry_parts"`
		}
		if err = json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal(err)
		}
		return len(raw), len(envelope.Completed), envelope.RetryParts
	}
	admit(30)
	first := cut()
	size, inline, parts := envelopeOf(first)
	if size > 32<<10 || inline != 0 || len(parts) == 0 {
		t.Fatalf("the envelope of a contracted control cut carries %d retry entries inline and names %d parts (%d bytes)", inline, len(parts), size)
	}
	if _, err := group.CompactJournal(f.ctx); err != nil {
		t.Fatal(err)
	}
	admit(10)
	second := cut()
	if _, _, again := envelopeOf(second); len(again) < len(parts) {
		t.Fatalf("the second cut names %d parts after %d", len(again), len(parts))
	}
	if written := group.Phases().CutRetryBytes; written == 0 || written > 1<<20 {
		t.Fatalf("the second cut serialized %d bytes of retry table", written)
	}
	if _, err := group.CompactJournal(f.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := group.Snapshots().DropSuperseded(); err != nil {
		t.Fatal(err)
	}
	if _, err := group.Snapshots().Verify(); err != nil {
		t.Fatalf("the snapshot with retry parts does not verify: %v", err)
	}
}
