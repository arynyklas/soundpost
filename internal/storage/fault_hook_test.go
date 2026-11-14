//go:build soundpost_faults

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

// [07.07-W1] The exported hook reaches the replica journal's fsync step through the real
// engine: while it fails "wal_sync" the append is refused (never acknowledged), the hook is
// the only difference from the healthy engine, and removing it restores the default.
func TestSetFaultHookFailsTheJournalSyncThroughTheEngine(t *testing.T) {
	store, a, c, d := fixture(t)
	scope, b := normalized(t, store, a, c, d)
	engine, e := openTestEngine(t, t.TempDir(), a, store)
	if e != nil {
		t.Fatal(e)
	}
	defer engine.Close()
	var synced atomic.Int32
	engine.SetFaultHook(func(point string) error {
		if point == "wal_sync" {
			synced.Add(1)
			return errors.New("injected sync failure")
		}
		return nil
	})
	if _, e = engine.Append(context.Background(), scope, b); e == nil {
		t.Fatal("an append was acknowledged while the journal sync failed")
	}
	if synced.Load() == 0 {
		t.Fatal("the hook was not consulted at wal_sync")
	}
	engine.SetFaultHook(nil)
	if engine.injected.Load() != nil {
		t.Fatal("SetFaultHook(nil) left a hook installed")
	}
}
