// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func benchState() *State {
	st := &State{Installation: model.ID{1}, Revision: 1000, Orgs: map[string]model.ControlOrg{}, Commands: map[string]model.ControlResult{}}
	for i := range 20 {
		o := model.ControlOrg{ID: model.ID{2}, Members: map[string]bool{}, Projects: map[string]string{}, Settings: map[string]json.RawMessage{}}
		for j := range 50 {
			o.Members[strconv.Itoa(j)] = true
			o.Settings[model.ReplayIndexKeyPrefix+strconv.Itoa(j)] = json.RawMessage(`{"seq":1,"checkpoints":[1,2,3]}`)
			o.Settings["source_policy:"+strconv.Itoa(j)] = json.RawMessage(`{"enabled":true}`)
		}
		st.Orgs[strconv.Itoa(i)] = o
	}
	for i := range 2000 {
		st.Commands[strconv.Itoa(i)] = model.ControlResult{Revision: model.Revision(i), Cursor: model.Cursor{Group: model.ID{1}, Index: 1}}
	}
	return st
}

// BenchmarkReplayIndexMask is the cost UpdateReplayIndex adds per call (two of these); the
// BenchmarkStateMarshal baseline is the one encoding every update already does.
func BenchmarkReplayIndexMask(b *testing.B) {
	st := benchState()
	for range b.N {
		if _, err := stateWithoutReplayIndex(st); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStateMarshal(b *testing.B) {
	st := benchState()
	for range b.N {
		if _, err := json.Marshal(st); err != nil {
			b.Fatal(err)
		}
	}
}

// prodProfile sizes a benchmark control state. Provenance of each number:
//   - jobs per project: maxJobsPerProject (job_update.go, 64 jobs per project) is the code
//     bound used; the projects-per-org counts are NOT bounded by any constant or document in
//     the repository (docs/operations/deletion.md only bounds one erasure request at 128
//     projects), so 32 and 64 are assumptions; the ceiling is capped at 64 so its ~850k
//     settings keys stay benchable in memory.
//   - indexSettingsPerProject: one replay_index: and one replay_pins: key per project
//     (internal/replays/retention.go groupPrefix/pinPrefix), plus maxJobsPerProject job-book
//     style settings keys that the mask must copy untouched (settings that are NOT masked are
//     the work the mask does).
//   - members per org: assumption (no bound in the repository).
//   - commands: the replicated retry table of State.Commands has no eviction in the repository;
//     65536 is an assumption for a long-lived installation, 262144 the ceiling profile.
//   - orgs: assumption (no bound in the repository); 100 production, 200 ceiling.
type prodProfile struct {
	orgs, projectsPerOrg, membersPerOrg, commands int
}

func prodBenchState(p prodProfile) *State {
	st := &State{Installation: model.ID{1}, Revision: 1000, Orgs: make(map[string]model.ControlOrg, p.orgs), Commands: make(map[string]model.ControlResult, p.commands)}
	for i := range p.orgs {
		o := model.ControlOrg{ID: model.ID{2}, Members: map[string]bool{}, Projects: map[string]string{}, Settings: map[string]json.RawMessage{}}
		for j := range p.membersPerOrg {
			o.Members["member-"+strconv.Itoa(j)] = true
		}
		for j := range p.projectsPerOrg {
			pid := "project-" + strconv.Itoa(j)
			o.Projects[pid] = "Project " + pid
			o.Settings[model.ReplayIndexKeyPrefix+pid] = json.RawMessage(`{"seq":1,"checkpoints":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]}`)
			o.Settings[model.ReplayPinKeyPrefix+pid] = json.RawMessage(`{"pins":["a","b","c","d"]}`)
			for k := range maxJobsPerProject {
				o.Settings["job:"+pid+":"+strconv.Itoa(k)] = json.RawMessage(`{"enabled":true,"schedule":"*/5 * * * *","version":3}`)
			}
		}
		st.Orgs["org-"+strconv.Itoa(i)] = o
	}
	for i := range p.commands {
		st.Commands["cmd-"+strconv.Itoa(i)] = model.ControlResult{Revision: model.Revision(i), Cursor: model.Cursor{Group: model.ID{1}, Index: 1}}
	}
	return st
}

var prodProfiles = []struct {
	name string
	p    prodProfile
}{
	{"production", prodProfile{orgs: 100, projectsPerOrg: 32, membersPerOrg: 50, commands: 65536}},
	{"ceiling", prodProfile{orgs: 200, projectsPerOrg: 64, membersPerOrg: 200, commands: 262144}},
}

// BenchmarkReplayIndexMaskProduction and BenchmarkStateMarshalProduction run the two costs of
// the benchmarks above on the production-sized profiles; the mask's increment over a marshal is
// the number the incremental-mask decision rests on.
func BenchmarkReplayIndexMaskProduction(b *testing.B) {
	for _, c := range prodProfiles {
		b.Run(c.name, func(b *testing.B) {
			st := prodBenchState(c.p)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := stateWithoutReplayIndex(st); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkStateMarshalProduction(b *testing.B) {
	for _, c := range prodProfiles {
		b.Run(c.name, func(b *testing.B) {
			st := prodBenchState(c.p)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := json.Marshal(st); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
