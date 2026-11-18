// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

func (f *fenceFx) replayKeys(project model.ID) []string {
	f.t.Helper()
	var keys []string
	if err := f.store.View(f.ctx, func(st control.State) error {
		for k := range st.Orgs[f.org.String()].Settings {
			if strings.HasPrefix(k, model.ReplayIndexKeyPrefix+project.String()+":") || k == model.ReplayPinKeyPrefix+project.String() {
				keys = append(keys, k)
			}
		}
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return keys
}

func (f *fenceFx) seedReplayIndex(projects ...model.ID) {
	f.t.Helper()
	if err := f.store.UpdateReplayIndex(f.ctx, func(st *control.State) error {
		o := st.Orgs[f.org.String()]
		if o.Settings == nil {
			o.Settings = map[string]json.RawMessage{}
		}
		for _, p := range projects {
			o.Settings[model.ReplayIndexKeyPrefix+p.String()+":"+model.NewID().String()] = json.RawMessage(`{"seq":1}`)
			o.Settings[model.ReplayIndexKeyPrefix+p.String()+":"+model.NewID().String()] = json.RawMessage(`{"seq":2}`)
			o.Settings[model.ReplayPinKeyPrefix+p.String()] = json.RawMessage(`{"pin":1}`)
		}
		st.Orgs[f.org.String()] = o
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
}

// A retirement erases the replay index of the projects it covers in the transition that retires
// them: the groups name replay and session identifiers and checkpoint digests of data the deletion
// erases, and the replay service sweeps an index only inside a later write of the same project, which
// a retired project never has (independent review of 10.06, F-10.06-1: index keys 1 -> 1 after a
// completed retire_project). A sibling project's index is untouched.
func TestRetireProjectForgetsItsReplayIndexAndOnlyIts(t *testing.T) {
	f := newFenceFx(t)
	f.seedReplayIndex(f.project, f.otherProject)
	if n := len(f.replayKeys(f.otherProject)); n != 3 {
		t.Fatalf("setup: %d keys for the project to retire", n)
	}
	if _, _, err := f.del(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.otherProject}}); err != nil {
		t.Fatal(err)
	}
	if left := f.replayKeys(f.otherProject); len(left) != 0 {
		t.Fatalf("the retired project keeps replay index keys: %v", left)
	}
	if n := len(f.replayKeys(f.project)); n != 3 {
		t.Fatalf("the sibling project's replay index changed: %d keys, want 3", n)
	}
}

func TestRetireOrgForgetsTheReplayIndexOfEveryProject(t *testing.T) {
	f := newFenceFx(t)
	f.seedReplayIndex(f.project, f.otherProject)
	if _, _, err := f.del(control.DeleteScope{Mode: model.DeleteRetireOrg}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []model.ID{f.project, f.otherProject} {
		if left := f.replayKeys(p); len(left) != 0 {
			t.Fatalf("a retired organization keeps replay index keys of %s: %v", p, left)
		}
	}
}
