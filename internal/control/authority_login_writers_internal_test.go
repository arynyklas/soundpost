// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// UpdatePendingLogin leaves AuthorityRevision alone only for a closure that added pending-login
// records, consumed them, or removed records expired at the instant; everything else bumps. In
// particular an elevation record (an access grant) is not a pending-login record: adding or
// removing a live one bumps.
func TestUpdatePendingLoginBumpsOnlyForPendingRecords(t *testing.T) {
	ctx := context.Background()
	const now = int64(1000)
	pending := func(key string, _ json.RawMessage) bool { return strings.HasPrefix(key, "p-") }
	expired := func(key string, _ json.RawMessage) bool { return key == "old" }
	s, _ := openAuthorityStore(t)
	reset := func(st *State) error {
		st.Sessions = sweepSessions(now)
		st.OIDC = map[string]json.RawMessage{"old": json.RawMessage(`1`), "p-live": json.RawMessage(`2`), "elevation:e": json.RawMessage(`3`)}
		st.Users = nil
		return nil
	}
	if err := s.Update(ctx, reset); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		fn      func(*State) error
		pending func(string, json.RawMessage) bool
		bumps   bool
	}{
		{"idle", func(*State) error { return nil }, pending, false},
		{"a pending record added (OIDCStart)", func(st *State) error { st.OIDC["p-new"] = json.RawMessage(`4`); return nil }, pending, false},
		{"a live pending record consumed (callback)", func(st *State) error { delete(st.OIDC, "p-live"); return nil }, pending, false},
		{"expired resident and expired session swept with a start", func(st *State) error {
			delete(st.OIDC, "old")
			delete(st.Sessions, "dead")
			st.OIDC["p-new"] = json.RawMessage(`4`)
			return nil
		}, pending, false},
		{"a non-pending resident added", func(st *State) error { st.OIDC["x"] = json.RawMessage(`4`); return nil }, pending, true},
		{"an elevation record added", func(st *State) error { st.OIDC["elevation:n"] = json.RawMessage(`4`); return nil }, pending, true},
		{"a live elevation record removed", func(st *State) error { delete(st.OIDC, "elevation:e"); return nil }, pending, true},
		{"a pending record altered", func(st *State) error { st.OIDC["p-live"] = json.RawMessage(`9`); return nil }, pending, true},
		{"a session added", func(st *State) error {
			st.Sessions["x"] = model.ControlSession{User: model.ID{1}, Expires: now + 5}
			return nil
		}, pending, true},
		{"a live session removed", func(st *State) error { delete(st.Sessions, "live"); return nil }, pending, true},
		{"another part of the state changed with the record", func(st *State) error {
			st.OIDC["p-new"] = json.RawMessage(`4`)
			st.Users = map[string]model.ControlUser{"u": {ID: model.ID{1}}}
			return nil
		}, pending, true},
		{"a pending record consumed when the caller names none", func(st *State) error { delete(st.OIDC, "p-live"); return nil }, nil, true},
	}
	for _, c := range cases {
		if err := s.updateAs(ctx, writerPendingLogin, reset); err != nil { // same starting records every case
			t.Fatal(err)
		}
		rev0, auth0 := revisions(t, s)
		if err := s.UpdatePendingLogin(ctx, now, c.pending, expired, c.fn); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		rev1, auth1 := revisions(t, s)
		if rev1 != rev0+1 {
			t.Fatalf("%s: revision %d -> %d, want one transition", c.name, rev0, rev1)
		}
		if c.bumps != (auth1 != auth0) {
			t.Fatalf("%s: AuthorityRevision %d -> %d, bumps want %v", c.name, auth0, auth1, c.bumps)
		}
	}
}

// UpdateAuditAppend leaves AuthorityRevision alone only for a closure that appended audit rows;
// removing, altering (also in place, below the slice header) or replacing a row, or changing
// anything else, bumps.
func TestUpdateAuditAppendBumpsOnlyForAppends(t *testing.T) {
	ctx := context.Background()
	s, _ := openAuthorityStore(t)
	row := func(action string) model.ControlAudit {
		return model.ControlAudit{ID: model.NewID(), Principal: model.ID{1}, Action: action, Reason: "r", Targets: []model.ID{{7}}, Time: 5}
	}
	reset := func(st *State) error {
		st.Audits = []model.ControlAudit{row("a"), row("b")}
		st.Users = nil
		return nil
	}
	cases := []struct {
		name  string
		fn    func(*State) error
		bumps bool
	}{
		{"idle", func(*State) error { return nil }, false},
		{"one row appended", func(st *State) error { st.Audits = append(st.Audits, row("c")); return nil }, false},
		{"many rows appended", func(st *State) error { st.Audits = append(st.Audits, row("c"), row("d"), row("e")); return nil }, false},
		{"the last row removed", func(st *State) error { st.Audits = st.Audits[:1]; return nil }, true},
		{"all rows removed", func(st *State) error { st.Audits = nil; return nil }, true},
		{"a row altered in place", func(st *State) error { st.Audits[0].Reason = "forged"; return nil }, true},
		{"a row's targets altered in place", func(st *State) error { st.Audits[1].Targets[0] = model.ID{9}; return nil }, true},
		{"a row replaced by another of the same count", func(st *State) error { st.Audits[1] = row("z"); return nil }, true},
		{"rows reordered", func(st *State) error { st.Audits[0], st.Audits[1] = st.Audits[1], st.Audits[0]; return nil }, true},
		{"another part of the state changed with an append", func(st *State) error {
			st.Audits = append(st.Audits, row("c"))
			st.Users = map[string]model.ControlUser{"u": {ID: model.ID{1}, Admin: true}}
			return nil
		}, true},
	}
	for _, c := range cases {
		if err := s.updateAs(ctx, writerAuditAppend, reset); err != nil { // same starting rows every case
			t.Fatal(err)
		}
		rev0, auth0 := revisions(t, s)
		if err := s.UpdateAuditAppend(ctx, c.fn); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		rev1, auth1 := revisions(t, s)
		if rev1 != rev0+1 {
			t.Fatalf("%s: revision %d -> %d, want one transition", c.name, rev0, rev1)
		}
		if c.bumps != (auth1 != auth0) {
			t.Fatalf("%s: AuthorityRevision %d -> %d, bumps want %v", c.name, auth0, auth1, c.bumps)
		}
	}
}

// The table entries behind the control-level ArtifactIntents test: PublishArtifact is a
// non-authority writer (a new reference intent), the ledger writer is non-authority for ledger
// and ledger-index entries ONLY, so an ArtifactIntents change (the retire transition, a new,
// removed or altered intent) is outside its mask and bumps even beside a ledger write.
func TestArtifactIntentsAreOutsideTheLedgerMask(t *testing.T) {
	for _, w := range []writer{writerPublishArtifact, writerArtifactLedger} {
		if _, ok := nonAuthorityWriters[w]; !ok {
			t.Fatalf("writer %s is not on the non-authority allowlist", w)
		}
	}
	org := model.NewID()
	root, project, source, build, reservation := model.NewID(), model.NewID(), model.NewID(), model.NewID(), model.NewID()
	blob := model.BlobManifest{Org: org, Project: project, Source: source, Root: root, Build: build, ReservationID: reservation}
	intent := model.ArtifactReferenceIntent{ID: root, CommandID: root, State: "published",
		Manifest: model.ArtifactManifest{Org: org, Project: project, Source: source, Build: build},
		Map:      model.BlobReceipt{Manifest: blob, Cursor: model.Cursor{Group: model.NewID()}}}
	// A real state: the zero State does not encode (its installation id is the zero id).
	s, _ := openAuthorityStore(t)
	base := func() State {
		st, err := s.localState()
		if err != nil {
			t.Fatal(err)
		}
		st.Orgs = map[string]model.ControlOrg{org.String(): {ID: org, Settings: map[string]json.RawMessage{}}}
		st.ArtifactIntents = map[string]model.ArtifactReferenceIntent{"k": intent}
		return st
	}
	encode := func(st State) string {
		raw, err := stateWithoutArtifactLedger(&st)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	plain := encode(base())
	withLedger := base()
	withLedger.Orgs[org.String()].Settings[model.ArtifactLedgerKeyPrefix+"p:r"] = json.RawMessage(`{}`)
	withLedger.Orgs[org.String()].Settings[model.ArtifactLedgerIndexKeyPrefix+"p"] = json.RawMessage(`{}`)
	if encode(withLedger) != plain {
		t.Fatal("ledger and ledger-index entries are not masked: the ledger writer would bump")
	}
	retired := base()
	r := retired.ArtifactIntents["k"]
	r.State = "retired"
	retired.ArtifactIntents["k"] = r
	if encode(retired) == plain {
		t.Fatal("an intent's state is inside the ledger mask: the retire transition would not bump")
	}
	added := base()
	added.ArtifactIntents["k2"] = intent
	if encode(added) == plain {
		t.Fatal("a new intent is inside the ledger mask")
	}
}
