// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

func objRecord(o model.ControlOrg, key string) (v uint64) {
	_ = json.Unmarshal(o.Settings[key], &v)
	return v
}

// create_org starts the object epochs at 1, each tracked change records its own object, and the records stay bounded: entries
// the floor covers are dropped.
func TestObjectEpochStateAndPruning(t *testing.T) {
	e := objEnv{newCacheFixture(t)}
	org := func() (o model.ControlOrg) {
		_ = e.store.View(e.ctx, func(st control.State) error { o = st.Orgs[e.org.String()]; return nil })
		return
	}
	o := org()
	if objRecord(o, model.ObjFloorKey) != 1 || objRecord(o, model.ObjSeenKey) != o.Epoch || o.Epoch < 2 {
		t.Fatalf("after create_org+create_project: epoch=%d settings=%v", o.Epoch, o.Settings)
	}
	project := model.NewID()
	e.mustSave("create_project", auth.AdminPayload{ID: project, Name: "tracked"})
	o = org()
	key := model.ObjEpochKeyPrefix + "project:" + project.String()
	if got := objRecord(o, key); got != o.Epoch {
		t.Fatalf("project record = %d, want epoch %d", got, o.Epoch)
	}
	// An untracked bump moves the floor to the epoch on the next tracked change and prunes everything older.
	e.untracked()
	e.mustSave("create_project", auth.AdminPayload{ID: model.NewID(), Name: "later"})
	o = org()
	records := 0
	for k := range o.Settings {
		if strings.HasPrefix(k, model.ObjEpochKeyPrefix) {
			records++
		}
	}
	if _, kept := o.Settings[key]; kept || records != 1 || objRecord(o, model.ObjFloorKey) != o.Epoch-1 || objRecord(o, model.ObjSeenKey) != o.Epoch {
		t.Fatalf("after the untracked bump: epoch=%d settings=%v", o.Epoch, o.Settings)
	}
}

// The records live in the organization's Settings, so the organization has exactly the members the previous release's strict
// decoder knows: a state, a replacement, a patch or a snapshot that carries them applies there, and no member of the group
// needs to declare anything first (D59). The save conflicts on the object from the first save.
func TestObjectRecordsLeaveTheOrganizationDecodableByThePreviousRelease(t *testing.T) {
	e := objEnv{newCacheFixture(t)}
	u1, u2 := model.NewID(), model.NewID()
	e.cmd("create_user", auth.AdminPayload{ID: u1, Email: "g1@example.test", Password: "object epoch password"})
	e.cmd("create_user", auth.AdminPayload{ID: u2, Email: "g2@example.test", Password: "object epoch password"})
	e.mustSave("membership", auth.AdminPayload{UserID: u1, Enabled: true})
	s := e.snapshot()
	if !strings.Contains(s, model.ObjEpochKeyPrefix+"membership:"+u1.String()) {
		t.Fatalf("no object record after a tracked save: %s", s)
	}
	var legacy struct {
		ID              model.ID
		Name            string
		Epoch           uint64
		Members, Admins map[string]bool
		Projects        map[string]string
		Grants          map[string][]string
		Secrets         map[string]string
		Settings        map[string]json.RawMessage
		Teams           map[string]model.ControlTeam
	}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&legacy); err != nil {
		t.Fatalf("the previous release's strict decoder refuses the organization: %v", err)
	}
	read := e.epoch()
	e.mustSave("membership", auth.AdminPayload{UserID: u2, Enabled: true})
	if err := e.save("team", auth.AdminPayload{ID: model.NewID(), Config: teamConfig()}, read); err != nil {
		t.Fatalf("a save of another object after an unrelated change conflicted: %v", err)
	}
	if err := e.save("membership", auth.AdminPayload{UserID: u2, Enabled: false}, read); err == nil {
		t.Fatal("a stale save of the object that changed was not refused")
	}
}
