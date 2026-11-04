// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/replica"
	"testing"
)

// The control group's journal can only be cut at a verified snapshot that
// carries its tombstone-class state, and a restart then keeps every committed
// revision without replaying the history.
func TestControlSnapshotTruncatesJournalAndRestartKeepsState(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	open := func() *control.Store {
		store, err := control.Open(directory)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = auth.NewService(auth.AuthDependencies{Control: store}); err != nil {
			store.Close()
			t.Fatal(err)
		}
		if err = store.EnableSingle(ctx, filepath.Join(directory, "raft-control")); err != nil {
			store.Close()
			t.Fatal(err)
		}
		return store
	}
	store := open()
	for i := range 6 {
		key := string(rune('a' + i))
		if err := store.Update(ctx, func(st *control.State) error {
			if st.Quotas == nil {
				st.Quotas = map[string]model.QuotaState{}
			}
			st.Quotas["fixture:"+key] = model.QuotaState{Bytes: model.Uint64(i + 1), MaxBytes: 1 << 20, MaxSeries: 10}
			return nil
		}); err != nil {
			store.Close()
			t.Fatal(err)
		}
	}
	group := store.ReplicaGroup()
	if _, err := group.CompactJournal(ctx); !errors.Is(err, replica.ErrNoSnapshot) {
		store.Close()
		t.Fatalf("truncation without a snapshot: %v", err)
	}
	cut, err := group.ReadIndex(ctx)
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	snapshot, err := group.CreateSnapshot(ctx, cut)
	if err != nil {
		store.Close()
		t.Fatalf("control group cannot cut a snapshot: %v", err)
	}
	in, err := snapshot.File("ledger.json")
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(in)
	in.Close()
	var ledger replica.Ledger
	if json.Unmarshal(raw, &ledger) != nil || ledger.Entries == nil {
		store.Close()
		t.Fatal("control snapshot has no deletion ledger")
	}
	var stream bytes.Buffer
	if _, err = snapshot.WriteTo(&stream); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if _, err = group.CompactJournal(ctx); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if first, _ := group.JournalRange(); first <= 2 {
		store.Close()
		t.Fatalf("control journal not truncated: first=%d", first)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store = open()
	defer store.Close()
	if err = store.View(ctx, func(st control.State) error {
		if len(st.Quotas) != 6 || st.Quotas["fixture:f"].Bytes != 6 {
			t.Fatalf("committed control state lost across truncation: %d keys", len(st.Quotas))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = store.Update(ctx, func(st *control.State) error { st.Quotas["fixture:g"] = model.QuotaState{MaxBytes: 1}; return nil }); err != nil {
		t.Fatal(err)
	}
}
