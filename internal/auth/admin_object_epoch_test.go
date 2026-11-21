// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// objEnv drives admin commands with the organization epoch the page read (expected_epoch), the way the console does.
type objEnv struct {
	*cacheFixture
}

func (e objEnv) epoch() model.Uint64 {
	e.t.Helper()
	v, err := e.service.AdminRead(e.ctx, e.actor, auth.AdminReadRequest{OrgID: e.org, Kind: "organization"})
	if err != nil {
		e.t.Fatal(err)
	}
	return v.Epoch
}

// save sends a command based on the epoch read.
func (e objEnv) save(kind string, p auth.AdminPayload, read model.Uint64) error {
	e.t.Helper()
	p.Reason = "object epoch test"
	raw, _ := json.Marshal(p)
	_, err := e.service.AdminCommand(e.ctx, e.actor, auth.AdminCommandRequest{CommandID: model.NewID(), OrgID: e.org, Kind: kind, Payload: raw, ExpectedEpoch: &read})
	return err
}

func (e objEnv) mustSave(kind string, p auth.AdminPayload) {
	e.t.Helper()
	if err := e.save(kind, p, e.epoch()); err != nil {
		e.t.Fatal(kind, err)
	}
}

// snapshot is the organization as stored, to prove a refused save changed nothing.
func (e objEnv) snapshot() string {
	e.t.Helper()
	var out []byte
	if err := e.store.View(e.ctx, func(st control.State) error {
		out, _ = json.Marshal(st.Orgs[e.org.String()])
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
	return string(out)
}

// untracked bumps the organization epoch the way code that does not track objects does (restore, retirement, an older build).
func (e objEnv) untracked() {
	e.t.Helper()
	if err := e.store.Update(e.ctx, func(st *control.State) error {
		o := st.Orgs[e.org.String()]
		o.Epoch++
		st.Orgs[e.org.String()] = o
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
}

func teamConfig() json.RawMessage {
	return json.RawMessage(`{"members":[],"projects":[],"permissions":[],"enabled":true}`)
}

// An admin save conflicts only when the object it changes was changed after the epoch it read: an unrelated organization
// change between the read and the save is no reason to refuse it.
func TestAdminSaveIgnoresUnrelatedOrganizationChange(t *testing.T) {
	e := objEnv{newCacheFixture(t)}
	u1, u2 := model.NewID(), model.NewID()
	e.cmd("create_user", auth.AdminPayload{ID: u1, Email: "u1@example.test", Password: "object epoch password"})
	e.cmd("create_user", auth.AdminPayload{ID: u2, Email: "u2@example.test", Password: "object epoch password"})
	e.mustSave("membership", auth.AdminPayload{UserID: u2, Enabled: true})

	read := e.epoch()
	e.mustSave("membership", auth.AdminPayload{UserID: u1, Enabled: true}) // another admin changes something else
	team, project := model.NewID(), model.NewID()
	if err := e.save("team", auth.AdminPayload{ID: team, Config: teamConfig()}, read); err != nil {
		t.Fatalf("team save after an unrelated membership change: %v", err)
	}
	if err := e.save("create_project", auth.AdminPayload{ID: project, Name: "late"}, read); err != nil {
		t.Fatalf("create_project after unrelated changes: %v", err)
	}
	if err := e.save("grant", auth.AdminPayload{UserID: u2, ProjectID: project, Enabled: true, Permissions: []string{string(auth.PolicyWrite)}}, read); err != nil {
		t.Fatalf("grant after unrelated changes: %v", err)
	}
	if err := e.save("org_admin", auth.AdminPayload{UserID: u1, Enabled: true}, read); err != nil {
		t.Fatalf("org_admin after an unrelated membership change: %v", err)
	}
}

// A concurrent change of the SAME object is a lost update: refused, and nothing changes.
func TestAdminSaveConflictsOnSameObjectOnly(t *testing.T) {
	e := objEnv{newCacheFixture(t)}
	u1 := model.NewID()
	e.cmd("create_user", auth.AdminPayload{ID: u1, Email: "u1@example.test", Password: "object epoch password"})
	team, retention := model.NewID(), model.NewID()
	retentionCfg := json.RawMessage(`{"project_id":"` + e.project.String() + `","signal":"metrics","days":14}`)
	for name, tc := range map[string]struct {
		kind string
		p    auth.AdminPayload
	}{
		"membership": {"membership", auth.AdminPayload{UserID: u1, Enabled: true}},
		"team":       {"team", auth.AdminPayload{ID: team, Config: teamConfig()}},
		"retention":  {"retention", auth.AdminPayload{ID: retention, Config: retentionCfg}},
		"project":    {"create_project", auth.AdminPayload{ID: model.NewID(), Name: "same"}},
	} {
		read := e.epoch()
		if err := e.save(tc.kind, tc.p, e.epoch()); err != nil { // the concurrent writer commits first
			t.Fatalf("%s: first save: %v", name, err)
		}
		before := e.snapshot()
		tc.p.Enabled = !tc.p.Enabled
		if err := e.save(tc.kind, tc.p, read); faultCode(err) != model.Conflict {
			t.Fatalf("%s: second save on the stale epoch: %v, want conflict", name, err)
		}
		if after := e.snapshot(); after != before {
			t.Fatalf("%s: a refused save changed the organization:\n%s\n%s", name, before, after)
		}
	}
}

// An epoch bump by code that tracks no object (restore, retirement, an older build) makes every object count as changed.
func TestAdminSaveConflictsEverywhereAfterUntrackedEpochBump(t *testing.T) {
	e := objEnv{newCacheFixture(t)}
	u1 := model.NewID()
	e.cmd("create_user", auth.AdminPayload{ID: u1, Email: "u1@example.test", Password: "object epoch password"})
	e.mustSave("membership", auth.AdminPayload{UserID: u1, Enabled: true})
	read := e.epoch()
	e.untracked()
	before := e.snapshot()
	for name, tc := range map[string]struct {
		kind string
		p    auth.AdminPayload
	}{
		"team":       {"team", auth.AdminPayload{ID: model.NewID(), Config: teamConfig()}},
		"project":    {"create_project", auth.AdminPayload{ID: model.NewID(), Name: "x"}},
		"membership": {"membership", auth.AdminPayload{UserID: u1, Enabled: false}},
	} {
		if err := e.save(tc.kind, tc.p, read); faultCode(err) != model.Conflict {
			t.Fatalf("%s: %v, want conflict after an untracked epoch bump", name, err)
		}
	}
	if after := e.snapshot(); after != before {
		t.Fatalf("refused saves changed the organization")
	}
	// A read taken after the bump is current again for every object, until the next tracked change.
	if err := e.save("team", auth.AdminPayload{ID: model.NewID(), Config: teamConfig()}, e.epoch()); err != nil {
		t.Fatalf("save on the epoch read after the bump: %v", err)
	}
	// ... and an epoch the organization has not reached is a conflict.
	if err := e.save("team", auth.AdminPayload{ID: model.NewID(), Config: teamConfig()}, e.epoch()+1); faultCode(err) != model.Conflict {
		t.Fatalf("future epoch: %v, want conflict", err)
	}
}

// A source onboarded or revoked between the read and an unrelated save is no conflict; a source_policy save of that
// source is.
func TestSourceChangesConflictOnlyWithTheirOwnPolicySave(t *testing.T) {
	e := objEnv{newCacheFixture(t)}
	first := e.structuredSource()
	read := e.epoch()
	second := e.structuredSource() // onboard between read and saves
	if err := e.service.RevokeSource(e.ctx, e.actor, first, "object epoch test"); err != nil {
		t.Fatal(err)
	}
	if err := e.save("team", auth.AdminPayload{ID: model.NewID(), Config: teamConfig()}, read); err != nil {
		t.Fatalf("team save after a source onboard and revoke: %v", err)
	}
	cfg, _ := json.Marshal(auth.SourcePolicyConfig{ProjectID: e.project, Enabled: true})
	for name, source := range map[string]model.ID{"onboarded": second, "revoked": first} {
		before := e.snapshot()
		if err := e.save("source_policy", auth.AdminPayload{ID: source, Config: cfg}, read); faultCode(err) != model.Conflict {
			t.Fatalf("source_policy save of the %s source on the stale epoch: %v, want conflict", name, err)
		}
		if after := e.snapshot(); after != before {
			t.Fatalf("%s: a refused save changed the organization", name)
		}
	}
}
