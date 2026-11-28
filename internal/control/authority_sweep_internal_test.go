// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// UpdateSweepExpired leaves AuthorityRevision alone only for a closure that deleted records
// expired at the instant; an idle commit, a live record removed, an added or altered record, or
// any other change bumps.
func TestUpdateSweepExpiredBumpsOnlyForExpiredRemovals(t *testing.T) {
	ctx := context.Background()
	const now = int64(1000)
	expired := func(key string, _ json.RawMessage) bool { return key == "old" }
	s, _ := openAuthorityStore(t)
	if err := s.Update(ctx, func(st *State) error {
		st.Sessions = sweepSessions(now)
		st.OIDC = map[string]json.RawMessage{"old": json.RawMessage(`1`), "new": json.RawMessage(`2`)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		fn    func(*State) error
		bumps bool
	}{
		{"idle", func(*State) error { return nil }, false},
		{"expired session removed", func(st *State) error { delete(st.Sessions, "dead"); return nil }, false},
		{"expired resident removed", func(st *State) error { delete(st.OIDC, "old"); return nil }, false},
		{"live session removed", func(st *State) error { delete(st.Sessions, "live"); return nil }, true},
		{"live resident removed", func(st *State) error { delete(st.OIDC, "new"); return nil }, true},
		{"resident altered", func(st *State) error { st.OIDC["new"] = json.RawMessage(`3`); return nil }, true},
		{"session added", func(st *State) error {
			st.Sessions["x"] = model.ControlSession{User: model.ID{1}, Expires: now + 5}
			return nil
		}, true},
		{"resident added", func(st *State) error { st.OIDC["added"] = json.RawMessage(`4`); return nil }, true},
		{"resident added while an expired one is removed", func(st *State) error {
			delete(st.OIDC, "old")
			st.OIDC["added"] = json.RawMessage(`4`)
			return nil
		}, true},
		{"other state changed", func(st *State) error { st.Users = map[string]model.ControlUser{"u": {ID: model.ID{1}}}; return nil }, true},
	}
	for _, c := range cases {
		// restore a full set so each case starts from the same records
		if err := s.updateAs(ctx, writerSweepExpired, func(st *State) error {
			st.Sessions = sweepSessions(now)
			st.OIDC = map[string]json.RawMessage{"old": json.RawMessage(`1`), "new": json.RawMessage(`2`)}
			st.Users = nil
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		rev0, auth0 := revisions(t, s)
		if err := s.UpdateSweepExpired(ctx, now, expired, c.fn); err != nil {
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

func sweepSessions(now int64) map[string]model.ControlSession {
	return map[string]model.ControlSession{"dead": {User: model.ID{1}, Expires: now}, "live": {User: model.ID{1}, Expires: now + 1}}
}
