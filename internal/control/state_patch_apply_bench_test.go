// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// BenchmarkStatePatchCommandAtProductionSize is the cost of one control command on a store holding
// the production-sized state (23 MB encoded, productionPatchStore): the proposer's read, transition
// and diff, the leader's validation and the apply, all of which run in this one voter. allocs/op
// and B/op are the process-wide figures of one command. The classes are the ones the console and the
// workers commit most: a session, one setting of one organization, one audit row (the delta
// command of the elevated read when the audit gate is open).
func BenchmarkStatePatchCommandAtProductionSize(b *testing.B) {
	if raceBuild {
		b.Skip("production-sized state: measured without the race detector")
	}
	s, _ := productionPatchStore(b, prodProfiles[0].p)
	s.SetStatePatchGate(func() bool { return true })
	s.SetAuditDeltaGate(func() bool { return true })
	ctx := b.Context()
	b.Run("session", func(b *testing.B) {
		b.ReportAllocs()
		for i := range b.N {
			if err := s.Update(ctx, func(st *State) error {
				if st.Sessions == nil {
					st.Sessions = map[string]model.ControlSession{}
				}
				st.Sessions["bench-session"] = model.ControlSession{User: model.ID{3}, CSRF: strconv.Itoa(i), Expires: 1 << 40}
				return nil
			}); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("setting", func(b *testing.B) {
		b.ReportAllocs()
		for i := range b.N {
			if err := s.Update(ctx, func(st *State) error {
				st.Orgs["org-3"].Settings["job:project-5:0"] = json.RawMessage(`{"enabled":false,"schedule":"0 * * * *","version":` + strconv.Itoa(i) + `}`)
				return nil
			}); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("audit-delta", func(b *testing.B) {
		b.ReportAllocs()
		for i := range b.N {
			if err := s.AppendAudit(ctx, func(model.ReadOnlyControl) error { return nil }, model.ControlAudit{ID: model.ID{7, byte(i)}, Principal: model.ID{1}, Action: "export.chunk", Reason: "elevated response released", Time: int64(i), Outcome: model.AuditAllowed}); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// TestApplyAtProductionSizeDoesNotDecodeTheState pins what the byte-level apply (state_raw.go) bought
// at the production-sized state (23 MB encoded): a patch command, an audit delta and a stale rejection
// are applied to the bytes of the state (no decode of the state for them), and a command allocates a
// bounded multiple of the state, where decoding and encoding it again on every voter had cost about
// 46 times (a patch) and 19 times (a delta) the state's size in one voter that proposes, validates and
// applies (BenchmarkStatePatchCommandAtProductionSize before the change: 1.09 GB and 0.46 GB at 23.5 MB).
// The proposer's own read and encode of the state for the transition function remain in these figures.
func TestApplyAtProductionSizeDoesNotDecodeTheState(t *testing.T) {
	if raceBuild || testing.Short() {
		t.Skip("production-sized state: runs without the race detector and outside -short")
	}
	s, encoded := productionPatchStore(t, prodProfiles[0].p)
	s.SetStatePatchGate(func() bool { return true })
	s.SetAuditDeltaGate(func() bool { return true })
	ctx := t.Context()
	measure := func(name string, multiple uint64, run func() error) {
		t.Helper()
		splicedBefore, decodedBefore := s.ApplyPathStatsForTest()
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		if err := run(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		took := time.Since(start)
		runtime.ReadMemStats(&after)
		spliced, decoded := s.ApplyPathStatsForTest()
		alloc := after.TotalAlloc - before.TotalAlloc
		t.Logf("%-12s %6.0f ms  %5.1f MB allocated = %.1f x the state", name, float64(took.Microseconds())/1000, float64(alloc)/1e6, float64(alloc)/float64(encoded))
		if spliced != splicedBefore+1 || decoded != decodedBefore {
			t.Fatalf("%s: %d commands applied to the bytes and %d by decoding the state, want 1 and 0", name, spliced-splicedBefore, decoded-decodedBefore)
		}
		if alloc > multiple*uint64(encoded) {
			t.Fatalf("%s allocated %d bytes, more than %d x the state (%d bytes)", name, alloc, multiple, encoded)
		}
	}
	measure("session", 20, func() error {
		return s.Update(ctx, func(st *State) error {
			if st.Sessions == nil {
				st.Sessions = map[string]model.ControlSession{}
			}
			st.Sessions["cost-session"] = model.ControlSession{User: model.ID{3}, CSRF: "c", Expires: 1 << 40}
			return nil
		})
	})
	measure("setting", 20, func() error {
		return s.Update(ctx, func(st *State) error {
			st.Orgs["org-3"].Settings["job:project-5:0"] = json.RawMessage(`{"enabled":false,"schedule":"0 * * * *","version":4}`)
			return nil
		})
	})
	measure("object-record", 20, func() error {
		return s.Update(ctx, func(st *State) error {
			o := st.Orgs["org-3"]
			o.TrackChange("team:cost")
			st.Orgs["org-3"] = o
			return nil
		})
	})
	measure("audit-delta", 10, func() error {
		return s.AppendAudit(ctx, func(model.ReadOnlyControl) error { return nil }, model.ControlAudit{ID: model.ID{7}, Principal: model.ID{1}, Action: "export.chunk", Reason: "elevated response released", Time: 1, Outcome: model.AuditAllowed})
	})
}
