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
