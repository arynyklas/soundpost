// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replays

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// A project whose pins are still one map under replay_pins:<project> (written by an earlier
// build) reads from it, and its first index write moves every pin to its own key and removes the
// map, keeping every deadline. A pin map that does not parse is Corrupt for every replay of the
// project, before and after (the write refuses to migrate it).
func TestLegacyPinMapIsReadAndMigratedByTheFirstWrite(t *testing.T) {
	org, project := model.NewID(), model.NewID()
	st := &model.ControlState{Orgs: map[string]model.ControlOrg{org.String(): contractedOrg()}}
	now := time.Unix(1_800_000_000, 0)
	var replays []model.ID
	for range 20 {
		replays = append(replays, recordNew(t, st, org, project, now))
	}
	settings := st.Orgs[org.String()].Settings
	legacy := map[string]pin{}
	want := map[model.ID]pin{}
	for _, r := range replays {
		var p pin
		if err := json.Unmarshal(settings[pinKey(project, r)], &p); err != nil {
			t.Fatal(err)
		}
		legacy[r.String()], want[r] = p, p
		delete(settings, pinKey(project, r))
	}
	raw, _ := json.Marshal(legacy)
	settings[legacyPinKey(project)] = raw
	for _, r := range replays {
		if p, ok, err := readPin(settings, project, r); err != nil || !ok || p != want[r] {
			t.Fatalf("legacy pin of %s: %+v %v %v, want %+v", r, p, ok, err, want[r])
		}
		if g, _, err := loadGroup(settings, project, r); err != nil || g == nil {
			t.Fatalf("legacy group of %s: %v", r, err)
		}
	}
	added := recordNew(t, st, org, project, now)
	if _, ok := settings[legacyPinKey(project)]; ok {
		t.Fatal("the first write left the legacy pin map")
	}
	for _, r := range append(replays, added) {
		if _, ok := settings[pinKey(project, r)]; !ok {
			t.Fatalf("replay %s has no pin of its own after the migration", r)
		}
	}
	for _, r := range replays {
		if p, ok, err := readPin(settings, project, r); err != nil || !ok || p != want[r] {
			t.Fatalf("migrated pin of %s: %+v %v %v, want %+v", r, p, ok, err, want[r])
		}
	}

	settings[legacyPinKey(project)] = json.RawMessage(`"unreadable"`)
	if _, _, err := readPin(settings, project, replays[0]); err == nil {
		t.Fatal("an unreadable legacy pin map was read")
	}
	if _, err := applyIndex(st, org, project, scaleChunk(model.NewID(), model.NewID()), model.Hash{1}, model.UnixNano(now.UnixNano()), now); err == nil {
		t.Fatal("a write migrated an unreadable legacy pin map")
	}
}

// Expired pins are swept in bounded work per write, together with their groups.
func TestSweepDropsExpiredPinsWithTheirGroups(t *testing.T) {
	org, project := model.NewID(), model.NewID()
	st := &model.ControlState{Orgs: map[string]model.ControlOrg{org.String(): contractedOrg()}}
	now := time.Unix(1_800_000_000, 0)
	old := recordNew(t, st, org, project, now)
	later := now.Add(9 * 24 * time.Hour) // past the 7 d deadline and the 24 h grace
	for range 20 {
		recordNew(t, st, org, project, later)
	}
	settings := st.Orgs[org.String()].Settings
	if _, ok := settings[pinKey(project, old)]; ok {
		t.Fatal("the expired pin was not swept")
	}
	if _, ok := settings[groupKey(project, old)]; ok {
		t.Fatal("the expired group was not swept with its pin")
	}
}
