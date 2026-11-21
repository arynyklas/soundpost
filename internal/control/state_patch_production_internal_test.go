// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// productionPatchStore is a real store and group (a one-voter group) whose committed state is the
// production-sized state of authority_mask_bench_test.go (100 organizations of 32 projects, 65 536
// applied commands: about 23 MB encoded, past the replica's 16 MiB entry limit). Such a state cannot
// be built through commands (the first of them would have to carry it), so it is the seed the store
// is opened from, as a restored backup's state is.
func productionPatchStore(t testing.TB, p prodProfile) (s *Store, encoded int) {
	t.Helper()
	ctx := t.Context()
	first := t.TempDir()
	s0, err := Open(first)
	if err != nil {
		t.Fatal(err)
	}
	if err = s0.EnableSingle(ctx, filepath.Join(first, "raft-control")); err != nil {
		t.Fatal(err)
	}
	raw, _, err := s0.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	if err = s0.Close(); err != nil {
		t.Fatal(err)
	}
	var seed controlSnapshot
	if err = json.Unmarshal(raw, &seed); err != nil {
		t.Fatal(err)
	}
	pad := prodBenchState(p)
	seed.State.Orgs, seed.State.Commands = pad.Orgs, pad.Commands
	if raw, err = json.Marshal(seed); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if s, err = OpenSeed(dir, raw); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err = s.EnableSingle(ctx, filepath.Join(dir, "raft-control")); err != nil {
		t.Fatal(err)
	}
	state, err := json.Marshal(seed.State)
	if err != nil {
		t.Fatal(err)
	}
	return s, len(state)
}

// Every class of control command runs at production size. The replica refuses a payload over 16 MiB
// (Entry.valid), and a whole-state command is as large as the state, so before the state patch no
// command could be proposed at all on a state this size; a patch is as large as the change, and the
// largest change a legitimate command makes (the expiry of the applied-command log: tens of
// thousands of records at once) is a few MB.
func TestStatePatchRunsEveryCommandClassAtProductionSize(t *testing.T) {
	if raceBuild || testing.Short() {
		t.Skip("production-sized state: runs without the race detector and outside -short")
	}
	s, encoded := productionPatchStore(t, prodProfiles[0].p)
	t.Logf("state: %d bytes encoded (the replica's entry limit is %d)", encoded, 16<<20)
	if encoded <= 16<<20 {
		t.Fatalf("the production-sized state is %d bytes, not past the entry limit: the test proves nothing", encoded)
	}
	ctx := t.Context()
	touch := func(st *State) error { st.BootstrapHash += "x"; return nil }

	// Without the gate a command is the whole state, which the replica refuses.
	s.SetStatePatchGate(nil)
	err := s.Update(ctx, touch)
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.Invalid {
		t.Fatalf("a whole-state command at %d bytes answered %v, want the replica's refusal (invalid)", encoded, err)
	}

	s.SetStatePatchGate(func() bool { return true })
	newOrg := func(name string, settings int) model.ControlOrg {
		o := model.ControlOrg{ID: model.ID{2}, Name: name, Members: map[string]bool{"member-0": true}, Projects: map[string]string{"project-0": "p"}, Settings: map[string]json.RawMessage{}}
		for i := range settings {
			o.Settings[fmt.Sprintf("job:project-0:%d", i)] = json.RawMessage(`{"enabled":true,"schedule":"*/5 * * * *","version":9}`)
		}
		return o
	}
	classes := []struct {
		name string
		run  func() error
		held func(State) bool
	}{
		{"login: a session", func() error {
			return s.Update(ctx, func(st *State) error {
				if st.Sessions == nil {
					st.Sessions = map[string]model.ControlSession{}
				}
				st.Sessions["session-class"] = model.ControlSession{User: model.ID{3}, CSRF: "c", Expires: 1 << 40}
				return nil
			})
		}, func(st State) bool { return st.Sessions["session-class"].CSRF == "c" }},
		{"settings: one job of one project", func() error {
			return s.Update(ctx, func(st *State) error {
				st.Orgs["org-3"].Settings["job:project-5:0"] = json.RawMessage(`{"enabled":false,"schedule":"0 * * * *","version":4}`)
				return nil
			})
		}, func(st State) bool {
			return string(st.Orgs["org-3"].Settings["job:project-5:0"]) == `{"enabled":false,"schedule":"0 * * * *","version":4}`
		}},
		{"evaluation: one record and its command result", func() error {
			return s.Update(ctx, func(st *State) error {
				if st.IncidentBooks == nil {
					st.IncidentBooks = map[string]json.RawMessage{}
				}
				st.IncidentBooks["o:p:i-class"] = json.RawMessage(`{"state":"open"}`)
				st.Commands["cmd-class"] = model.ControlResult{Revision: 9, Cursor: model.Cursor{Group: model.ID{1}, Index: 1}}
				return nil
			})
		}, func(st State) bool {
			return string(st.IncidentBooks["o:p:i-class"]) == `{"state":"open"}` && st.Commands["cmd-class"].Revision == 9
		}},
		{"audit: an elevated read's row (whole-state path)", func() error {
			return s.AppendAudit(ctx, func(model.ReadOnlyControl) error { return nil }, model.ControlAudit{ID: model.ID{7}, Principal: model.ID{1}, Action: "export.chunk", Reason: "elevated response released", Time: 1, Outcome: model.AuditAllowed})
		}, func(st State) bool { return len(st.Audits) == 1 && st.Audits[0].ID == (model.ID{7}) }},
		{"a rule pass: 5 000 records at once", func() error {
			return s.Update(ctx, func(st *State) error {
				for i := range 5000 {
					st.IncidentBooks[fmt.Sprintf("o:p:rule-%d", i)] = json.RawMessage(fmt.Sprintf(`{"n":%d,"state":"firing"}`, i))
				}
				return nil
			})
		}, func(st State) bool { return len(st.IncidentBooks) >= 5001 }},
		{"organization: one record replaced whole", func() error {
			return s.Update(ctx, func(st *State) error {
				st.Orgs["org-9"] = newOrg("replaced", 2112)
				return nil
			})
		}, func(st State) bool {
			return st.Orgs["org-9"].Name == "replaced" && len(st.Orgs["org-9"].Settings) == 2112
		}},
		{"log expiry: the oldest 64 500 applied commands", func() error {
			_, err := s.ExpireControlLog(ctx, ControlLogPolicy{Now: time.Now(), AuditDays: 365, CommandWindow: 24 * time.Hour, CommandMax: 1000})
			return err
		}, func(st State) bool { return len(st.Commands) <= 1100 }},
	}
	var worst uint64
	for _, c := range classes {
		beforeN, beforeBytes := s.StatePatchStatsForTest()
		start := time.Now()
		if err := c.run(); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		took := time.Since(start)
		n, bytes := s.StatePatchStatsForTest()
		if n != beforeN+1 {
			t.Fatalf("%s: %d patch commands proposed, want 1", c.name, n-beforeN)
		}
		size := bytes - beforeBytes
		t.Logf("%-52s payload %9d bytes  %6.0f ms", c.name, size, float64(took.Microseconds())/1000)
		if size > 8<<20 {
			t.Fatalf("%s: the command is %d bytes: half the entry limit is the most a class may need", c.name, size)
		}
		worst = max(worst, size)
		st, err := s.localState()
		if err != nil {
			t.Fatal(err)
		}
		if !c.held(st) {
			t.Fatalf("%s: the command committed but its effect is not in the state", c.name)
		}
	}
	t.Logf("largest command: %d bytes of %d (the entry limit); a whole-state command is %d", worst, 16<<20, encoded)
}
