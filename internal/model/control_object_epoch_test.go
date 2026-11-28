// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model_test

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// record is the value of an object record in the organization's Settings (0: absent).
func record(o model.ControlOrg, key string) (v uint64) {
	_ = json.Unmarshal(o.Settings[key], &v)
	return v
}

func freshOrg(epoch uint64) model.ControlOrg {
	o := model.ControlOrg{Epoch: epoch}
	o.StartObjectRecords()
	return o
}

func TestControlOrgObjectChangedAfter(t *testing.T) {
	o := freshOrg(1)
	if o.ObjectChangedAfter("a", 1) || !o.ObjectChangedAfter("a", 2) {
		t.Fatal("a fresh organization: epoch 1 is current, epoch 2 is in the future")
	}
	o.TrackChange("a") // epoch 2
	o.TrackChange("b") // epoch 3
	for _, c := range []struct {
		key  string
		read uint64
		want bool
	}{
		{"a", 1, true}, {"a", 2, false}, {"a", 3, false},
		{"b", 1, true}, {"b", 2, true}, {"b", 3, false},
		{"c", 1, false}, {"c", 2, false}, {"c", 3, false}, // never changed after the floor (1)
		{"a", 4, true}, // beyond the current epoch
	} {
		if got := o.ObjectChangedAfter(c.key, c.read); got != c.want {
			t.Errorf("ObjectChangedAfter(%q, %d) = %v, want %v (settings %v)", c.key, c.read, got, c.want, o.Settings)
		}
	}
	// An epoch bump that tracks nothing (the previous release, a restore, a retirement) makes every object
	// count as changed at the new epoch.
	o.Epoch++ // 4
	for _, key := range []string{"a", "b", "c"} {
		if !o.ObjectChangedAfter(key, 3) || o.ObjectChangedAfter(key, 4) {
			t.Errorf("after an untracked bump %q: conflict at 3 = %v, at 4 = %v", key, o.ObjectChangedAfter(key, 3), o.ObjectChangedAfter(key, 4))
		}
	}
	// A legacy organization (no object records at all) behaves the same.
	legacy := model.ControlOrg{Epoch: 7}
	if !legacy.ObjectChangedAfter("x", 6) || legacy.ObjectChangedAfter("x", 7) {
		t.Fatal("legacy organization is not the whole-epoch compare")
	}
	// A record that is not a number cannot be trusted: its object counts as changed at the current epoch.
	broken := freshOrg(1)
	broken.TrackChange("a")
	broken.Settings[model.ObjEpochKeyPrefix+"a"] = json.RawMessage(`"x"`)
	if !broken.ObjectChangedAfter("a", broken.Epoch-1) {
		t.Fatal("an unreadable record did not count as a change")
	}
}

func TestControlOrgTrackChange(t *testing.T) {
	o := freshOrg(1)
	o.TrackChange("a")
	o.TrackChange("b")
	if o.Epoch != 3 || record(o, model.ObjSeenKey) != 3 || record(o, model.ObjFloorKey) != 1 || record(o, model.ObjEpochKeyPrefix+"a") != 2 || record(o, model.ObjEpochKeyPrefix+"b") != 3 {
		t.Fatalf("two tracked changes: epoch %d, %v", o.Epoch, o.Settings)
	}
	// An untracked bump raises the effective floor to the epoch; the next tracked change persists it and prunes.
	o.Epoch++ // 4
	o.TrackChange("c")
	if o.Epoch != 5 || record(o, model.ObjFloorKey) != 4 || record(o, model.ObjSeenKey) != 5 || record(o, model.ObjEpochKeyPrefix+"c") != 5 || len(o.Settings) != 3 {
		t.Fatalf("after an untracked bump: epoch %d, %v", o.Epoch, o.Settings)
	}
	// Entries at or below the floor are dropped, so the records are bounded by the changes since the floor.
	for range 50 {
		o.TrackChange("same")
	}
	if len(o.Settings) > 4 {
		t.Fatalf("records grew: %v", o.Settings)
	}
}

// The records are Settings keys under one reserved prefix, and an organization carries no member the
// previous release's strict decoder does not know: that is why a state, a patch or a snapshot that holds
// them applies on that release (proved on its real binary by tools/smoke TestMixedBinaryVoters).
func TestObjectRecordsAreSettingsKeysNoOtherCodeReads(t *testing.T) {
	o := model.ControlOrg{ID: model.ID{1}, Name: "o", Epoch: 1, Settings: map[string]json.RawMessage{"destination:x": json.RawMessage(`{}`)}}
	o.StartObjectRecords()
	o.TrackChange("team:t")
	var keys []string
	for k := range o.Settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{"destination:x", model.ObjEpochKeyPrefix + "team:t", model.ObjFloorKey, model.ObjSeenKey}
	sort.Strings(want)
	if strings.Join(keys, "|") != strings.Join(want, "|") {
		t.Fatalf("settings keys %v, want %v", keys, want)
	}
	raw, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	// The previous release's ControlOrg, member for member (ab3469c internal/model/control.go).
	var previous struct {
		ID       model.ID
		Name     string
		Epoch    uint64
		Members  map[string]bool
		Admins   map[string]bool
		Projects map[string]string
		Grants   map[string][]string
		Secrets  map[string]string
		Settings map[string]json.RawMessage
		Teams    map[string]model.ControlTeam
	}
	if err := model.StrictJSON(raw, &previous); err != nil {
		t.Fatalf("the previous release's strict decoder refuses an organization with object records: %v", err)
	}
	for _, prefix := range []string{"team:", "source_policy:", "sso:", "destination:", "retention:", model.ArtifactLedgerKeyPrefix, model.ArtifactLedgerIndexKeyPrefix, model.ReplayIndexKeyPrefix, model.ReplayPinKeyPrefix} {
		for _, k := range []string{model.ObjFloorKey, model.ObjSeenKey, model.ObjEpochKeyPrefix + "team:t"} {
			if strings.HasPrefix(k, prefix) {
				t.Errorf("object record key %q falls under the prefix %q another reader walks", k, prefix)
			}
		}
	}
}

// Code that does not know the records can leave them alone (the previous release bumps the epoch and touches no
// Settings key it does not own) but is never relied on to keep them: whatever is missing or altered can only make a
// save conflict. A vanished floor or seen mark reads as "every object changed at the current epoch", and so does any
// record of the object that is not a number.
func TestMissingOrAlteredObjectRecordsOnlyMakeSavesConflict(t *testing.T) {
	current := func() model.ControlOrg {
		o := freshOrg(1)
		o.TrackChange("a")
		o.TrackChange("b")
		return o
	}
	base := current()
	if base.ObjectChangedAfter("c", base.Epoch-1) {
		t.Fatal("control: an untouched object conflicts although the records are current")
	}
	for name, mutate := range map[string]func(o *model.ControlOrg){
		"floor deleted":  func(o *model.ControlOrg) { delete(o.Settings, model.ObjFloorKey) },
		"seen deleted":   func(o *model.ControlOrg) { delete(o.Settings, model.ObjSeenKey) },
		"floor altered":  func(o *model.ControlOrg) { o.Settings[model.ObjFloorKey] = json.RawMessage(`"x"`) },
		"seen altered":   func(o *model.ControlOrg) { o.Settings[model.ObjSeenKey] = json.RawMessage(`null`) },
		"record altered": func(o *model.ControlOrg) { o.Settings[model.ObjEpochKeyPrefix+"c"] = json.RawMessage(`{}`) },
	} {
		o := current()
		mutate(&o)
		if !o.ObjectChangedAfter("c", o.Epoch-1) {
			t.Errorf("%s: an untouched object did not count as changed at the current epoch", name)
		}
		if o.ObjectChangedAfter("c", o.Epoch) {
			t.Errorf("%s: a save based on the current epoch conflicts", name)
		}
	}
	// A record deleted by code that moved the epoch (every previous-release write does) is covered by the stale mark.
	o := current()
	delete(o.Settings, model.ObjEpochKeyPrefix+"b")
	o.Epoch++
	if !o.ObjectChangedAfter("b", o.Epoch-1) || o.ObjectChangedAfter("b", o.Epoch) {
		t.Fatal("a record deleted together with an epoch bump is not covered by the stale mark")
	}
}
