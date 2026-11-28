// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build soundpost_diag

package storage

import (
	"context"
	"maps"
	"testing"

	"github.com/arynyklas/soundpost/internal/diagstat"
)

// A diagnostic build reports the protocol each member declared (capabilityOf), so that a drill can assert protocol
// declaredProtocol for every member of the installation before it trusts a gate that waits for "declared by all". A
// member that has declared nothing reads 0, not a missing entry.
func TestTheDiagnosticEndpointNamesTheProtocolEachMemberDeclared(t *testing.T) {
	old := layoutContracted
	layoutContracted = func(context.Context, ReplicatedAuthority) (bool, error) { return true, nil }
	t.Cleanup(func() { layoutContracted = old })
	f := newWithdrawFixtureUndeclared(t)
	none := map[string]uint64{"1": 0, "2": 0, "3": 0}
	for node, e := range f.v.engines {
		if got := e.diagDeclaredProtocols(e.repl); !maps.Equal(got, none) {
			t.Fatalf("node %d before any declaration reports %v, want %v", node, got, none)
		}
	}
	f.v.declareProtocol(t)
	all := map[string]uint64{"1": declaredProtocol, "2": declaredProtocol, "3": declaredProtocol}
	for node, e := range f.v.engines {
		if got := e.diagDeclaredProtocols(e.repl); !maps.Equal(got, all) {
			t.Fatalf("node %d after the declarations reports %v, want %v", node, got, all)
		}
	}
	// The endpoint carries it: the engine registered its counters when it opened (the last one to open answers).
	storage, _ := diagstat.Snapshot()["storage"].(map[string]any)
	got, ok := storage["declared_protocols"].(map[string]uint64)
	if !ok || !maps.Equal(got, all) {
		t.Fatalf("the diagnostic snapshot of the storage engine carries declared_protocols %v (%T), want %v", storage["declared_protocols"], storage["declared_protocols"], all)
	}
}
