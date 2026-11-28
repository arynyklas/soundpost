// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package refledger

import (
	"bytes"
	"encoding/json"
	"runtime"
	"testing"
)

// scaleProject stores n ledgers for one project (one Store call) and returns the settings.
func scaleProject(t *testing.T, n int) (*fx, []*Ledger) {
	t.Helper()
	f := newFx(t)
	ledgers := make([]*Ledger, n)
	for i := range ledgers {
		ledgers[i] = f.ledger(Entry{Kind: KindError, Cursor: cursor(uint64(i%200 + 1)), RetainUntil: 100})
		ledgers[i].Retired = true // a fenced map: what accumulates, never removed
	}
	f.store(ledgers...)
	return f, ledgers
}

// One more ledger costs one shard of the project's index, not the project's whole index: the
// bytes the write changes in the organization's Settings stay a small constant while the project
// holds thousands of ledgers (review 10.09-F2: 1 ledger write = +1 MiB at 5k ledgers, +9 MiB at
// 45k, because the whole index and its anchor were rewritten).
func TestStoreRewritesOneIndexShardNotTheWholeProject(t *testing.T) {
	const n = 5000
	f, _ := scaleProject(t, n)
	before := map[string]json.RawMessage{}
	for k, v := range f.org.Settings {
		before[k] = bytes.Clone(v)
	}
	f.store(f.ledger(Entry{Kind: KindError, Cursor: cursor(1), RetainUntil: 100}))
	changed := 0
	for k, v := range f.org.Settings {
		if !bytes.Equal(before[k], v) {
			changed += len(k) + len(v)
		}
	}
	if changed > 24<<10 {
		t.Fatalf("one ledger write changed %d bytes of Settings in a project of %d ledgers; want one ledger and one index shard (< 24 KiB)", changed, n)
	}
}

// A read verifies one shard: the memory a Load allocates does not grow with the project.
func TestLoadParsesOneIndexShardNotTheWholeProject(t *testing.T) {
	const n = 5000
	f, ledgers := scaleProject(t, n)
	const loads = 50
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	for i := range loads {
		if got, err := Load(f.org.Settings, f.project, ledgers[i*7].Root); err != nil || got == nil {
			t.Fatalf("load %d: %v", i, err)
		}
	}
	runtime.ReadMemStats(&m1)
	if per := (m1.TotalAlloc - m0.TotalAlloc) / loads; per > 96<<10 {
		t.Fatalf("a Load allocated %d bytes in a project of %d ledgers; want one shard (< 96 KiB)", per, n)
	}
}
