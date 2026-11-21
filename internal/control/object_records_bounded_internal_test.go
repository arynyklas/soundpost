// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// The per-object records of an organization are Settings keys (obj_epoch:<object>, obj_floor, obj_seen). What they
// cost the control path is bounded by model.MaxObjEpochs per organization: a tracked change is a patch of three keys
// whatever the number of records, the change that reaches the bound deletes at most that many keys in one patch, the
// bytes spliced into the state equal what decoding and encoding it again leaves, and the records add at most
// about a hundred bytes per object to the state a snapshot carries.
func TestObjectRecordsKeepPatchesAndTheSpliceBounded(t *testing.T) {
	filler := func() map[string]json.RawMessage {
		m := map[string]json.RawMessage{}
		for i := range 300 {
			m[fmt.Sprintf("artifact_refs:p:%04d", i)] = json.RawMessage(`{"refs":[1,2,3]}`)
		}
		return m
	}
	transition := func(n int) (payloadLen int, ops int, stateGrowth int, equal bool) {
		o := model.ControlOrg{ID: model.ID{1}, Name: "o", Epoch: 1, Settings: filler()}
		bare, _ := json.Marshal(State{Installation: model.ID{5}, Revision: 7, Orgs: map[string]model.ControlOrg{"o": o}})
		o.StartObjectRecords()
		for i := range n {
			o.TrackChange(fmt.Sprintf("obj-%d", i))
		}
		old := State{Installation: model.ID{5}, Revision: 7, Orgs: map[string]model.ControlOrg{"o": o}}
		oldRaw := mustMarshal(t, old)
		next := State{Installation: model.ID{5}, Revision: 8}
		o2 := o
		o2.Settings = maps.Clone(o.Settings)
		o2.TrackChange("team:t")
		next.Orgs = map[string]model.ControlOrg{"o": o2}
		payload, err := patchCommand(oldRaw, old.Revision, &next, map[string][]byte{})
		if err != nil {
			t.Fatal(err)
		}
		var cmd statePatchCommand
		if err = json.Unmarshal(payload, &cmd); err != nil {
			t.Fatal(err)
		}
		newRaw := mustMarshal(t, next)
		want, ok := decodeEncodePatch(oldRaw, cmd.StatePatch.Ops)
		if !ok {
			t.Fatal("decode/encode refuses the patch")
		}
		if !bytes.Equal(want, newRaw) {
			t.Fatal("applying the patch to the old state does not leave the new state")
		}
		got, _, spliced := patchRaw(oldRaw, scanStateRoot(oldRaw), cmd.StatePatch.Ops)
		return len(payload), len(cmd.StatePatch.Ops), len(oldRaw) - len(bare), !spliced || bytes.Equal(got, want)
	}
	for _, n := range []int{0, 1, 1000, model.MaxObjEpochs - 2} {
		payload, ops, growth, equal := transition(n)
		t.Logf("%4d object records: a tracked change is a patch of %d ops, %d bytes; the records add %d bytes to the state", n, ops, payload, growth)
		if !equal {
			t.Fatalf("%d records: the splice leaves other bytes than decode/encode", n)
		}
		if ops > 8 || payload > 2000 {
			t.Fatalf("%d records: a tracked change is %d ops / %d bytes, not a constant", n, ops, payload)
		}
		if growth > model.MaxObjEpochs*120 {
			t.Fatalf("%d records add %d bytes to the state, more than 120 per object", n, growth)
		}
	}
	// The change that reaches the bound drops every record in one patch: at most one delete per record.
	payload, ops, growth, equal := transition(model.MaxObjEpochs)
	t.Logf("%4d object records: the change that reaches the bound is a patch of %d ops, %d bytes (records before: %d bytes of state)", model.MaxObjEpochs, ops, payload, growth)
	if !equal {
		t.Fatal("at the bound: the splice leaves other bytes than decode/encode")
	}
	if ops > model.MaxObjEpochs+8 || payload > model.MaxObjEpochs*160 {
		t.Fatalf("at the bound: %d ops / %d bytes, more than one delete per record", ops, payload)
	}
}
