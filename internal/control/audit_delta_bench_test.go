// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// D49 measurements. BenchmarkAppendAudit runs the real store and group (EnableSingle): one audit
// row per iteration, committed by the whole-state path (the gate closed: what CommitElevatedRead
// did before) or by the delta command, on an empty state and on a medium one (prodBenchState,
// kept below the replica's 16 MiB entry limit, which a production-sized whole-state command
// exceeds: see BenchmarkWholeStateCommandSizeProduction). payload_B/op is the bytes of the proposed
// command. BenchmarkAuditApplyCore* is what every voter does per delta at a production-sized state.

var mediumProfile = prodProfile{orgs: 10, projectsPerOrg: 32, membersPerOrg: 50, commands: 20000}

func benchAuditStore(b *testing.B, profile *prodProfile) *Store {
	b.Helper()
	dir := b.TempDir()
	s, err := Open(dir)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { s.Close() })
	if err = s.EnableSingle(b.Context(), filepath.Join(dir, "raft-control")); err != nil {
		b.Fatal(err)
	}
	if profile != nil {
		pad := prodBenchState(*profile)
		if err = s.Update(b.Context(), func(st *State) error {
			if st.Orgs == nil {
				st.Orgs = map[string]model.ControlOrg{}
			}
			if st.Commands == nil {
				st.Commands = map[string]model.ControlResult{}
			}
			for k, v := range pad.Orgs {
				st.Orgs[k] = v
			}
			for k, v := range pad.Commands {
				st.Commands[k] = v
			}
			return nil
		}); err != nil {
			b.Fatal(err)
		}
	}
	return s
}

func BenchmarkAppendAudit(b *testing.B) {
	for _, size := range []struct {
		name    string
		profile *prodProfile
	}{{"empty", nil}, {"medium", &mediumProfile}} {
		for _, mode := range []string{"whole", "delta"} {
			b.Run(size.name+"/"+mode, func(b *testing.B) {
				s := benchAuditStore(b, size.profile)
				s.SetAuditDeltaGate(func() bool { return mode == "delta" })
				check := func(model.ReadOnlyControl) error { return nil }
				row := model.ControlAudit{ID: model.NewID(), Principal: model.ID{1}, Action: "export.chunk", Reason: "elevated response released", Time: 1, Org: model.ID{2}.String(), PolicyEpoch: 1, Targets: []model.ID{{3}, {4}, {5}}, RequestID: model.ID{6}, Outcome: model.AuditAllowed}
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					if err := s.AppendAudit(b.Context(), check, row); err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()
				st, err := s.localState()
				if err != nil {
					b.Fatal(err)
				}
				whole, _ := json.Marshal(controlReplacement{Expected: st.Revision - 1, State: st, Keys: map[string][]byte{}})
				if mode == "delta" {
					_, bytes := s.AuditDeltaStatsForTest()
					b.ReportMetric(float64(bytes)/float64(b.N), "payload_B/op")
				} else {
					b.ReportMetric(float64(len(whole)), "payload_B/op")
				}
				b.ReportMetric(float64(len(whole)), "state_payload_B")
			})
		}
	}
}

// productionStateRaw is the bolt encoding of a production-sized state.
func productionStateRaw(b *testing.B, profile prodProfile) []byte {
	b.Helper()
	raw, err := json.Marshal(prodBenchState(profile))
	if err != nil {
		b.Fatal(err)
	}
	return raw
}

// BenchmarkAuditApplyCoreProduction is the work a voter does for one delta at a production-sized
// state: decode the committed state, append the row, encode it again (the bolt write is not
// included). It is the same decode and encode every whole-state command costs a voter, minus the
// decode of the payload.
func BenchmarkAuditApplyCoreProduction(b *testing.B) {
	for _, c := range prodProfiles {
		b.Run(c.name, func(b *testing.B) {
			raw := productionStateRaw(b, c.p)
			d := auditDelta{Installation: model.ID{1}, Expected: 1000, At: 5, Audits: []model.ControlAudit{{ID: model.ID{9}, Principal: model.ID{1}, Action: "export.chunk", Outcome: model.AuditAllowed}}}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				var st State
				if err := json.Unmarshal(raw, &st); err != nil {
					b.Fatal(err)
				}
				applyAuditDelta(&st, d)
				if _, err := json.Marshal(&st); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkWholeStateCommandProduction is what the proposer of a whole-state command does per audited
// chunk at a production-sized state: decode the committed state and marshal the command payload;
// state_payload_B is the payload's size (the replica refuses entries over 16 MiB).
func BenchmarkWholeStateCommandProduction(b *testing.B) {
	for _, c := range prodProfiles {
		b.Run(c.name, func(b *testing.B) {
			raw := productionStateRaw(b, c.p)
			b.ReportAllocs()
			b.ResetTimer()
			var size int
			for range b.N {
				var st State
				if err := json.Unmarshal(raw, &st); err != nil {
					b.Fatal(err)
				}
				st.Audits = append(st.Audits, model.ControlAudit{ID: model.ID{9}, Principal: model.ID{1}, Action: "export.chunk", Org: model.ID{2}.String(), Targets: []model.ID{{3}, {4}, {5}}, Outcome: model.AuditAllowed})
				payload, err := json.Marshal(controlReplacement{Expected: st.Revision, State: st, Keys: map[string][]byte{}})
				if err != nil {
					b.Fatal(err)
				}
				size = len(payload)
			}
			b.ReportMetric(float64(size), "state_payload_B")
		})
	}
}

// BenchmarkDeltaProposerProduction is the proposer's work per audited chunk at a production-sized
// state with the delta: one shared decode of the committed state (the cache keeps it until the next
// commit changes it) and the marshal of a delta of a few hundred bytes.
func BenchmarkDeltaProposerProduction(b *testing.B) {
	for _, c := range prodProfiles {
		b.Run(c.name, func(b *testing.B) {
			raw := productionStateRaw(b, c.p)
			row := model.ControlAudit{ID: model.ID{9}, Principal: model.ID{1}, Action: "export.chunk", Org: model.ID{2}.String(), Targets: []model.ID{{3}, {4}, {5}}, Outcome: model.AuditAllowed}
			b.ReportAllocs()
			b.ResetTimer()
			var size int
			for range b.N {
				var st State
				if err := json.Unmarshal(raw, &st); err != nil {
					b.Fatal(err)
				}
				payload, err := json.Marshal(auditDeltaCommand{AuditDelta: auditDelta{Installation: st.Installation, Expected: st.Revision, At: 5, Audits: []model.ControlAudit{row}}})
				if err != nil {
					b.Fatal(err)
				}
				size = len(payload)
			}
			b.ReportMetric(float64(size), "payload_B")
		})
	}
}
