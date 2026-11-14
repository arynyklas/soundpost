// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// MIN-2: after a restart the next publication still reports the cuts that are on disk.
func TestSnapshotCoverageSurvivesRestart(t *testing.T) {
	x := newEraseEnv(t)
	x.appendN(3, 100)
	cut, err := x.e.CreateSnapshots(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	x.closeEngine()
	if _, err = x.open(); err != nil {
		t.Fatal(err)
	}
	x.appendN(1, 400) // a hot page for the flush to publish
	if err = x.e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	x.e.mu.Lock()
	coverage := x.e.catalog.Manifest.SnapshotCoverage
	x.e.mu.Unlock()
	if len(coverage) != 64 {
		t.Fatalf("manifest coverage after restart has %d groups, want 64", len(coverage))
	}
	for slot, c := range coverage {
		if c.Group != x.e.group(uint16(slot)) || c.Index != cut.Slots[slot].Manifest.Cursor.Index {
			t.Fatalf("slot %d: coverage %v, cut was at %d", slot, c, cut.Slots[slot].Manifest.Cursor.Index)
		}
	}
}

// MIN-5: Close does not wait forever behind a long publication, and a publication that sees Close
// starting stops.
func TestCloseDeadlineAndPublicationStop(t *testing.T) {
	old := closeDeadline
	closeDeadline = 150 * time.Millisecond
	t.Cleanup(func() { closeDeadline = old })
	x := newEraseEnv(t)
	x.appendN(2, 100)
	x.e.mu.Lock() // stands for a publication that holds the engine
	began := time.Now()
	err := x.e.Close()
	took := time.Since(began)
	x.e.mu.Unlock()
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.Timeout || took > 5*time.Second {
		t.Fatalf("Close behind a held engine: %v after %v", err, took)
	}
	if err = x.e.Flush(context.Background()); err == nil {
		t.Fatal("a publication started after Close began")
	}
	if err = x.e.Close(); err != nil {
		t.Fatalf("a second Close must finish once the engine is free: %v", err)
	}
}
