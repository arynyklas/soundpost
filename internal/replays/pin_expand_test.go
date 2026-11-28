// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replays

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// The previous release (5475ef6) reads the pins of a project from ONE value, replay_pins:<project>, and a replay
// whose group has no entry in it (or whose entry does not match the group) is Corrupt.
func previousReleaseLoads(settings map[string]json.RawMessage, project, replay model.ID) (*group, error) {
	var pins map[string]pin
	if raw, ok := settings[legacyPinKey(project)]; ok {
		if model.StrictJSON(raw, &pins) != nil || pins == nil {
			return nil, model.Fail(model.Corrupt)
		}
	}
	p, pinned := pins[replay.String()]
	raw, stored := settings[groupKey(project, replay)]
	if !stored && !pinned {
		return nil, nil
	}
	if stored != pinned {
		return nil, model.Fail(model.Corrupt)
	}
	var g group
	if model.StrictJSON(raw, &g) != nil || g.Head != g.digest() || g.Seq != p.Seq || g.Head != p.Head {
		return nil, model.Fail(model.Corrupt)
	}
	return &g, nil
}

// previousReleaseRecords is the previous release's index write: the group and the project's pin map, nothing else.
func previousReleaseRecords(t *testing.T, settings map[string]json.RawMessage, project, replay, session model.ID, sequence uint64, retain model.UnixNano) {
	t.Helper()
	g := group{Version: groupVersion, Project: project, Replay: replay, Session: session}
	if raw, ok := settings[groupKey(project, replay)]; ok {
		if err := json.Unmarshal(raw, &g); err != nil {
			t.Fatal(err)
		}
	}
	i, found := slices.BinarySearchFunc(g.Checkpoints, sequence, func(e checkpointEntry, v uint64) int {
		switch {
		case e.Sequence < v:
			return -1
		case e.Sequence > v:
			return 1
		}
		return 0
	})
	if !found {
		g.Checkpoints = slices.Insert(g.Checkpoints, i, checkpointEntry{Sequence: sequence, Hash: model.Hash{byte(sequence)}})
	}
	g.Seq++
	g.Head = g.digest()
	raw, _ := json.Marshal(g)
	settings[groupKey(project, replay)] = raw
	pins := map[string]pin{}
	if rawPins, ok := settings[legacyPinKey(project)]; ok {
		if err := json.Unmarshal(rawPins, &pins); err != nil {
			t.Fatal(err)
		}
	}
	pins[replay.String()] = pin{Seq: g.Seq, Head: g.Head, RetainUntil: max(pins[replay.String()].RetainUntil, retain)}
	rawPins, _ := json.Marshal(pins)
	settings[legacyPinKey(project)] = rawPins
}

// bothLoad requires every replay to load in the previous release and in this one, with the same group.
func bothLoad(t *testing.T, settings map[string]json.RawMessage, project model.ID, replays ...model.ID) {
	t.Helper()
	for _, r := range replays {
		old, oerr := previousReleaseLoads(settings, project, r)
		now, _, nerr := loadGroup(settings, project, r)
		if oerr != nil || nerr != nil || old == nil || now == nil || old.Head != now.Head || old.Seq != now.Seq {
			t.Fatalf("replay %s: previous release %v (%v), this release %v (%v)", r, old, oerr, now, nerr)
		}
	}
}

func expandedState() (*model.ControlState, model.ID, model.ID) {
	org, project := model.NewID(), model.NewID()
	return &model.ControlState{Orgs: map[string]model.ControlOrg{org.String(): expandedOrg()}}, org, project
}

// Before the contraction a replay write keeps the previous release's pin map current (D70).
func TestExpandedPinWritesStayReadableByThePreviousRelease(t *testing.T) {
	st, org, project := expandedState()
	now := time.Unix(1_800_000_000, 0)
	var replays []model.ID
	for range 30 {
		replays = append(replays, recordNew(t, st, org, project, now))
		bothLoad(t, st.Orgs[org.String()].Settings, project, replays...)
	}
	// A second checkpoint of an existing replay moves its group and both pins.
	settings := st.Orgs[org.String()].Settings
	var g group
	if err := json.Unmarshal(settings[groupKey(project, replays[0])], &g); err != nil {
		t.Fatal(err)
	}
	chunk := model.ReplayChunk{Replay: replays[0], Session: g.Session, Sequence: 5, CheckpointSequence: 5}
	if changed, err := applyIndex(st, org, project, chunk, model.Hash{5}, model.UnixNano(now.Add(8*24*time.Hour).UnixNano()), now); err != nil || !changed {
		t.Fatalf("second checkpoint: %v %v", changed, err)
	}
	bothLoad(t, st.Orgs[org.String()].Settings, project, replays...)
}

// The previous release may write after a rollback. This release reads what it wrote (its own pin is behind) and
// its next write puts everything right again.
func TestExpandedPinReadsFollowAWriteOfThePreviousRelease(t *testing.T) {
	st, org, project := expandedState()
	now := time.Unix(1_800_000_000, 0)
	var replays []model.ID
	for range 10 {
		replays = append(replays, recordNew(t, st, org, project, now))
	}
	settings := st.Orgs[org.String()].Settings
	var g group
	if err := json.Unmarshal(settings[groupKey(project, replays[2])], &g); err != nil {
		t.Fatal(err)
	}
	later := model.UnixNano(now.Add(30 * 24 * time.Hour).UnixNano())
	previousReleaseRecords(t, settings, project, replays[2], g.Session, 9, later)
	created, session := model.NewID(), model.NewID()
	previousReleaseRecords(t, settings, project, created, session, 1, later)
	bothLoad(t, settings, project, append(replays, created)...)
	if p, ok, err := readPin(settings, project, replays[2]); err != nil || !ok || p.RetainUntil != later {
		t.Fatalf("the deadline the previous release extended is not seen: %+v %v %v", p, ok, err)
	}
	replays = append(replays, created, recordNew(t, st, org, project, now))
	bothLoad(t, st.Orgs[org.String()].Settings, project, replays...)
}

// A replay the previous release swept leaves its own pin behind here; reading it is not corrupt, and the
// contraction drops it.
func TestExpandedPinOfAReplaySweptByThePreviousReleaseIsNotCorrupt(t *testing.T) {
	st, org, project := expandedState()
	now := time.Unix(1_800_000_000, 0)
	keep, gone := recordNew(t, st, org, project, now), recordNew(t, st, org, project, now)
	settings := st.Orgs[org.String()].Settings
	delete(settings, groupKey(project, gone))
	var pins map[string]pin
	if err := json.Unmarshal(settings[legacyPinKey(project)], &pins); err != nil {
		t.Fatal(err)
	}
	delete(pins, gone.String())
	raw, _ := json.Marshal(pins)
	settings[legacyPinKey(project)] = raw
	if g, _, err := loadGroup(settings, project, gone); err != nil || g != nil {
		t.Fatalf("a swept replay: %v %v", g, err)
	}
	bothLoad(t, settings, project, keep)
	o := st.Orgs[org.String()]
	if _, err := ContractPins(&o); err != nil {
		t.Fatal(err)
	}
	if _, ok := o.Settings[pinKey(project, gone)]; ok {
		t.Fatal("the dangling pin survived the contraction")
	}
}

// A deadline the previous release extended keeps the replay out of this release's sweep.
func TestExpandedSweepHonoursAnExtensionTheOlderReleaseWrote(t *testing.T) {
	st, org, project := expandedState()
	now := time.Unix(1_800_000_000, 0)
	old := recordNew(t, st, org, project, now)
	settings := st.Orgs[org.String()].Settings
	var g group
	if err := json.Unmarshal(settings[groupKey(project, old)], &g); err != nil {
		t.Fatal(err)
	}
	later := now.Add(9 * 24 * time.Hour)
	previousReleaseRecords(t, settings, project, old, g.Session, 3, model.UnixNano(later.Add(24*time.Hour).UnixNano()))
	for range 20 {
		recordNew(t, st, org, project, later)
	}
	if _, ok := st.Orgs[org.String()].Settings[groupKey(project, old)]; !ok {
		t.Fatal("a replay whose deadline the previous release extended was swept")
	}
	for range 20 {
		recordNew(t, st, org, project, later.Add(3*24*time.Hour))
	}
	if _, ok := st.Orgs[org.String()].Settings[groupKey(project, old)]; ok {
		t.Fatal("an expired replay was not swept in the expanded phase")
	}
	if _, err := previousReleaseLoads(st.Orgs[org.String()].Settings, project, old); err != nil {
		t.Fatalf("the previous release after the sweep: %v", err)
	}
}

// Contraction: per-replay pins carry everything, including what the previous release wrote last; the map is gone;
// the operation is idempotent; the next replay write is bounded by its own keys.
func TestContractPinsKeepsNewestAndMakesWritesBounded(t *testing.T) {
	st, org, project := expandedState()
	now := time.Unix(1_800_000_000, 0)
	var replays []model.ID
	for range 2000 {
		replays = append(replays, recordNew(t, st, org, project, now))
	}
	settings := st.Orgs[org.String()].Settings
	var g group
	if err := json.Unmarshal(settings[groupKey(project, replays[5])], &g); err != nil {
		t.Fatal(err)
	}
	later := model.UnixNano(now.Add(40 * 24 * time.Hour).UnixNano())
	previousReleaseRecords(t, settings, project, replays[5], g.Session, 7, later)
	o := st.Orgs[org.String()]
	changed, err := ContractPins(&o)
	if err != nil || !changed {
		t.Fatalf("contract pins: %v %v", changed, err)
	}
	o.Settings[model.IndexesContractedKey] = json.RawMessage(`true`)
	st.Orgs[org.String()] = o
	if _, ok := o.Settings[legacyPinKey(project)]; ok {
		t.Fatal("the pin map survived the contraction")
	}
	for _, r := range replays {
		if g, _, err := loadGroup(o.Settings, project, r); err != nil || g == nil {
			t.Fatalf("after the contraction: %v %v", g, err)
		}
	}
	if p, _, _ := readPin(o.Settings, project, replays[5]); p.RetainUntil != later || p.Seq != 2 {
		t.Fatalf("what the previous release wrote last was lost: %+v", p)
	}
	if again, err := ContractPins(&o); err != nil || again {
		t.Fatalf("a second contraction: %v %v", again, err)
	}
	before := map[string]json.RawMessage{}
	for k, v := range o.Settings {
		before[k] = bytes.Clone(v)
	}
	recordNew(t, st, org, project, now)
	changedBytes := 0
	for k, v := range st.Orgs[org.String()].Settings {
		if !bytes.Equal(before[k], v) {
			changedBytes += len(k) + len(v)
		}
	}
	if changedBytes > 8<<10 {
		t.Fatalf("one replay write changed %d bytes after the contraction in a project of %d replays", changedBytes, len(replays))
	}
	if _, ok := st.Orgs[org.String()].Settings[legacyPinKey(project)]; ok {
		t.Fatal("a write after the contraction wrote the pin map")
	}
}

// An unreadable pin map refuses the contraction and changes nothing.
func TestContractPinsRefusesAnUnreadableMap(t *testing.T) {
	st, org, project := expandedState()
	recordNew(t, st, org, project, time.Unix(1_800_000_000, 0))
	o := st.Orgs[org.String()]
	o.Settings[legacyPinKey(project)] = json.RawMessage(`"unreadable"`)
	n := len(o.Settings)
	if _, err := ContractPins(&o); err == nil || len(o.Settings) != n {
		t.Fatalf("an unreadable pin map was contracted: %v", err)
	}
}
