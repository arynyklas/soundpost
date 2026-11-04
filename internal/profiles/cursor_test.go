// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package profiles

import (
	"context"
	"encoding/json"
	"path/filepath"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"testing"
	"time"
)

func realCursorScope(t *testing.T) auth.Scope {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	store, e := control.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { store.Close() })
	if e = store.EnableSingle(ctx, filepath.Join(dir, "raft-control")); e != nil {
		t.Fatal(e)
	}
	a, e := auth.NewService(auth.AuthDependencies{Control: store})
	if e != nil {
		t.Fatal(e)
	}
	bootstrap, _ := store.BootstrapToken()
	session, e := a.Bootstrap(ctx, bootstrap, "cursor@example.test", "cursor password long enough 2026")
	if e != nil {
		t.Fatal(e)
	}
	actor, e := a.Authenticate(ctx, session.Token)
	if e != nil {
		t.Fatal(e)
	}
	org, project := model.NewID(), model.NewID()
	var user model.ID
	store.View(ctx, func(st model.ControlState) error {
		for _, u := range st.Users {
			user = u.ID
			break
		}
		return nil
	})
	command := func(kind string, p auth.AdminPayload) {
		t.Helper()
		var rev model.Revision
		store.View(ctx, func(st model.ControlState) error { rev = st.Revision; return nil })
		p.Reason = "profile cursor fixture"
		raw, _ := json.Marshal(p)
		if _, e := a.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: org, Kind: kind, Payload: raw}); e != nil {
			t.Fatal(e)
		}
	}
	command("create_org", auth.AdminPayload{Name: "cursor"})
	command("create_project", auth.AdminPayload{ID: project, Name: "cursor"})
	command("membership", auth.AdminPayload{UserID: user, Enabled: true})
	command("grant", auth.AdminPayload{UserID: user, ProjectID: project, Enabled: true, Permissions: []string{"profiles.read"}})
	scope, e := a.Authorize(ctx, actor, org, []model.ID{project}, auth.Permission("profiles.read"))
	if e != nil {
		t.Fatal(e)
	}
	return scope
}
func TestProfileCursorExpiryAndParameterForgeryFailClosed(t *testing.T) {
	scope := realCursorScope(t)
	s := NewService(panicScanner{}, deniedScope{}, unavailableLinks{})
	root := model.NewID()
	w := Window{Start: 10, End: 20, MaxSamples: 8}
	c := profileCursor{Org: scope.OrgID(), Project: scope.ProjectIDs()[0], Profile: root, Fingerprint: scope.VisibilityFingerprint(), Epoch: model.Uint64(scope.PolicyEpoch()), Start: 10, End: 20, Offset: 2, Expires: model.Int64(time.Now().Add(time.Minute).Unix())}
	valid, e := s.encodeCursor(c)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.decodeCursor(valid, scope, root, w); e != nil {
		t.Fatal("real scoped cursor baseline refused", e)
	}
	c.Expires = model.Int64(time.Now().Add(-time.Minute).Unix())
	expired, _ := s.encodeCursor(c)
	if _, e = s.decodeCursor(expired, scope, root, w); e == nil {
		t.Fatal("expired profile cursor accepted")
	}
	changed := w
	changed.End++
	if _, e = s.decodeCursor(valid, scope, root, changed); e == nil {
		t.Fatal("cursor widened query time")
	}
	if _, e = s.decodeCursor(valid, scope, model.NewID(), w); e == nil {
		t.Fatal("cursor reused for another profile")
	}
	if _, e = s.decodeCursor("A"+valid[1:], scope, root, w); e == nil {
		t.Fatal("unauthenticated cursor accepted")
	}
}
