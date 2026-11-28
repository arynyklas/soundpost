// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Protocol 7 (the ledger layout of control) gates only the patches of a contracted installation; an
// installation the previous release can still read keeps the books in the blob and needs the 5 that
// release declares. A binary that declared 7 at its first start on such a directory would commit one
// more command in slot 0 (the slot-0 watermark of every query answer moves: the upgrade-rollback smoke
// of the produced binaries read query_changed), so it declares 7 only once the installation is
// contracted, and a voter that declared 5 keeps proposing nothing until then.
func TestAnExpandedInstallationDeclaresOnlyTheProtocolOfThePreviousRelease(t *testing.T) {
	var contracted atomic.Bool
	old := layoutContracted
	layoutContracted = func(context.Context, ReplicatedAuthority) (bool, error) { return contracted.Load(), nil }
	t.Cleanup(func() { layoutContracted = old })
	f := newWithdrawFixture(t)
	ctx := context.Background()
	e := f.v.engines[1]
	declared := func() uint64 {
		id, identity, _ := e.selfMember()
		var got uint64
		_ = e.db.View(func(tx *bolt.Tx) error {
			got = capabilityOf(tx.Bucket([]byte("replica_data")), id, identity)
			return nil
		})
		return got
	}
	applied := func() uint64 {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.indexes[eraseAckSlot]
	}
	f.v.leadSlotZero(t, 1)
	if err := e.declareErasure(ctx); err != nil {
		t.Fatal(err)
	}
	if got := declared(); got != legacyStatePatchProtocol {
		t.Fatalf("an expanded installation: the voter declared %d, want %d (the previous release's)", got, legacyStatePatchProtocol)
	}
	// Nothing more is committed while the installation stays expanded, however often the loop asks.
	before := applied()
	for range 3 {
		time.Sleep(1100 * time.Millisecond)
		if err := e.declareErasure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if after := applied(); after != before || declared() != legacyStatePatchProtocol {
		t.Fatalf("an expanded installation committed %d slot-0 commands more and declared %d", after-before, declared())
	}
	// The operator contracts: the next pass declares the ledger layout.
	contracted.Store(true)
	if !eventually(30*time.Second, func() bool { _ = e.declareErasure(ctx); return declared() == declaredProtocol }) {
		t.Fatalf("a contracted installation: the voter declared %d, want %d", declared(), declaredProtocol)
	}
}
