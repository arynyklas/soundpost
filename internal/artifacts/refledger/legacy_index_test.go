// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package refledger

import (
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// A project written by an earlier build (one whole-project index under artifact_refs_index:<p>
// and its anchor) still loads, and its first write splits the index into shards and removes the
// legacy keys. A tampered legacy index is refused by that write, not migrated.
func TestLegacyWholeProjectIndexIsReadAndMigratedByTheFirstWrite(t *testing.T) {
	f := newFx(t)
	var ledgers []*Ledger
	for i := range 40 {
		ledgers = append(ledgers, f.ledger(Entry{Kind: KindError, Cursor: cursor(uint64(i + 1)), RetainUntil: 100}))
	}
	f.store(ledgers...)
	// Rewrite the stored state into the legacy layout.
	idx := map[string]IndexEntry{}
	for _, l := range ledgers {
		got, err := f.load(l)
		if err != nil || got == nil {
			t.Fatalf("setup: %v", err)
		}
		idx[l.Root.String()] = IndexEntry{Seq: got.Seq, Head: got.Head}
	}
	for _, l := range ledgers {
		delete(f.org.Settings, ShardIndexKey(f.project, l.Root))
		delete(f.org.Settings, ShardAnchorKey(f.project, l.Root))
	}
	rawIndex, _ := json.Marshal(idx)
	rawAnchor, _ := json.Marshal(anchor{Version: Version, Roots: len(idx), Index: model.HashCanonical(rawIndex)})
	f.org.Settings[LegacyIndexKey(f.project)] = rawIndex
	f.org.Settings[LegacyAnchorKey(f.project)] = rawAnchor
	for _, l := range ledgers {
		if got, err := f.load(l); err != nil || got == nil {
			t.Fatalf("a legacy project does not load: %v", err)
		}
	}
	added := f.ledger(Entry{Kind: KindBuild, Cursor: cursor(77), RetainUntil: 200})
	f.store(added)
	for _, key := range []string{LegacyIndexKey(f.project), LegacyAnchorKey(f.project)} {
		if _, ok := f.org.Settings[key]; ok {
			t.Fatalf("the first write left the legacy key %s", key)
		}
	}
	for _, l := range append(ledgers, added) {
		if got, err := f.load(l); err != nil || got == nil {
			t.Fatalf("a migrated ledger does not load: %v", err)
		}
	}
	// Removing a ledger with its shard entry is still caught after the migration.
	delete(f.org.Settings, LedgerKey(f.project, ledgers[0].Root))
	var shard map[string]IndexEntry
	if err := json.Unmarshal(f.org.Settings[ShardIndexKey(f.project, ledgers[0].Root)], &shard); err != nil {
		t.Fatal(err)
	}
	delete(shard, ledgers[0].Root.String())
	raw, _ := json.Marshal(shard)
	f.org.Settings[ShardIndexKey(f.project, ledgers[0].Root)] = raw
	if got, err := f.load(ledgers[0]); code(err) != model.Corrupt {
		t.Fatalf("a removal after the migration was not detected: %v, %v", got, err)
	}

	g := newFx(t)
	a := g.ledger(Entry{Kind: KindError, Cursor: cursor(1), RetainUntil: 100})
	g.store(a)
	delete(g.org.Settings, ShardIndexKey(g.project, a.Root))
	delete(g.org.Settings, ShardAnchorKey(g.project, a.Root))
	g.org.Settings[LegacyIndexKey(g.project)] = json.RawMessage(`{}`)
	g.org.Settings[LegacyAnchorKey(g.project)] = json.RawMessage(`{"Version":1,"Roots":1,"Index":"00"}`)
	if err := Store(&g.org, g.project, g.ledger(Entry{Kind: KindError, Cursor: cursor(2), RetainUntil: 1})); code(err) != model.Corrupt {
		t.Fatalf("a write over a tampered legacy index: %v", err)
	}
}
