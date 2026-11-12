// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"soundpost/internal/control"
	"soundpost/internal/model"
)

// UpdateSessionCreate keeps AuthorityRevision only for a closure that added sessions and changed
// nothing else; a user edit, a membership, or a removed or altered session bumps.
func TestUpdateSessionCreateBumpsWhenAnythingElseChanged(t *testing.T) {
	addSession := func(st *control.State) {
		st.Sessions[model.NewID().String()] = model.ControlSession{User: model.NewID(), CSRF: "c", Expires: 9_000_000_000, Reauthenticated: 1}
	}
	cases := []struct {
		name  string
		write func(f *fenceFx, st *control.State)
		bumps bool
	}{
		{"one new session", func(f *fenceFx, st *control.State) { addSession(st) }, false},
		{"many new sessions", func(f *fenceFx, st *control.State) { addSession(st); addSession(st); addSession(st) }, false},
		{"no change at all", func(f *fenceFx, st *control.State) {}, false},
		{"user record changed with the session", func(f *fenceFx, st *control.State) {
			addSession(st)
			u := st.Users[f.user.String()]
			u.LastTOTP++
			st.Users[f.user.String()] = u
		}, true},
		{"user disabled", func(f *fenceFx, st *control.State) {
			u := st.Users[f.user.String()]
			u.Disabled = true
			st.Users[f.user.String()] = u
		}, true},
		{"membership with the session", func(f *fenceFx, st *control.State) {
			addSession(st)
			st.Orgs[f.org.String()].Members[model.NewID().String()] = true
		}, true},
		{"existing session removed", func(f *fenceFx, st *control.State) {
			for k := range st.Sessions {
				delete(st.Sessions, k)
			}
		}, true},
		{"existing session removed and a new one added", func(f *fenceFx, st *control.State) {
			for k := range st.Sessions {
				delete(st.Sessions, k)
			}
			addSession(st)
		}, true},
		{"existing session extended", func(f *fenceFx, st *control.State) {
			for k, v := range st.Sessions {
				v.Expires += 3600
				st.Sessions[k] = v
			}
		}, true},
		{"existing session re-bound to another user", func(f *fenceFx, st *control.State) {
			for k, v := range st.Sessions {
				v.User = model.NewID()
				st.Sessions[k] = v
			}
		}, true},
		{"policy epoch with the session", func(f *fenceFx, st *control.State) {
			addSession(st)
			o := st.Orgs[f.org.String()]
			o.Epoch++
			st.Orgs[f.org.String()] = o
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFenceFx(t)
			rev0, auth0 := f.revisions()
			if err := f.store.UpdateSessionCreate(f.ctx, func(st *control.State) error { c.write(f, st); return nil }); err != nil {
				t.Fatal(err)
			}
			rev1, auth1 := f.revisions()
			if rev1 != rev0+1 {
				t.Fatalf("revision %d -> %d", rev0, rev1)
			}
			if c.bumps && auth1 != rev1 || !c.bumps && auth1 != auth0 {
				t.Fatalf("bumps=%v: authority %d -> %d at revision %d", c.bumps, auth0, auth1, rev1)
			}
		})
	}
}

// The real callers: a password login leaves AuthorityRevision alone, a logout (revocation) and a
// TOTP-consuming credential change bump.
func TestLoginKeepsAuthorityLogoutBumps(t *testing.T) {
	f := newFenceFx(t)
	rev0, auth0 := f.revisions()
	s, err := f.svc.Login(f.ctx, "owner@example.test", "a long test password 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	rev1, auth1 := f.revisions()
	if rev1 != rev0+1 || auth1 != auth0 {
		t.Fatalf("login: revision %d -> %d, authority %d -> %d (want the revision to move, authority not)", rev0, rev1, auth0, auth1)
	}
	if err = f.svc.Logout(f.ctx, s.Token); err != nil {
		t.Fatal(err)
	}
	rev2, auth2 := f.revisions()
	if rev2 != rev1+1 || auth2 != rev2 {
		t.Fatalf("logout: revision %d -> %d, authority %d -> %d (want a bump)", rev1, rev2, auth1, auth2)
	}
}

func (f *fenceFx) ledgerKeys(st *control.State) {
	o := st.Orgs[f.org.String()]
	if o.Settings == nil {
		o.Settings = map[string]json.RawMessage{}
	}
	o.Settings[model.ArtifactLedgerKeyPrefix+f.project.String()+":"+model.NewID().String()] = json.RawMessage(`{"seq":1}`)
	o.Settings[model.ArtifactLedgerIndexKeyPrefix+f.project.String()] = json.RawMessage(`{"x":{"seq":1}}`)
	st.Orgs[f.org.String()] = o
}

// UpdateArtifactReferences keeps AuthorityRevision only for ledger and ledger-index entries; the
// retire transition (intent state, delete generation) and anything else bump.
func TestUpdateArtifactReferencesBumpsWhenAnythingElseChanged(t *testing.T) {
	cases := []struct {
		name  string
		write func(f *fenceFx, st *control.State)
		bumps bool
	}{
		{"ledger and index only", func(f *fenceFx, st *control.State) { f.ledgerKeys(st) }, false},
		{"no change at all", func(f *fenceFx, st *control.State) {}, false},
		{"retired project with the ledger", func(f *fenceFx, st *control.State) {
			f.ledgerKeys(st)
			st.RetiredProjects = map[string]model.ID{f.org.String() + ":" + model.NewID().String(): model.NewID()}
		}, true},
		{"delete generation with the ledger", func(f *fenceFx, st *control.State) {
			f.ledgerKeys(st)
			st.DeleteGenerations = map[string]uint64{f.org.String(): 3}
		}, true},
		{"non-ledger setting", func(f *fenceFx, st *control.State) {
			st.Orgs[f.org.String()].Settings["source_policy:"+model.NewID().String()] = json.RawMessage(`{}`)
		}, true},
		{"replay index entry is not a ledger entry", func(f *fenceFx, st *control.State) { f.indexKeys(st, 1) }, true},
		{"membership with the ledger", func(f *fenceFx, st *control.State) {
			f.ledgerKeys(st)
			st.Orgs[f.org.String()].Members[model.NewID().String()] = true
		}, true},
		{"hold", func(f *fenceFx, st *control.State) {
			id := model.NewID()
			st.Holds = map[string]model.LegalHold{id.String(): {ID: id, Org: f.org, Reason: "r", PlacedBy: model.NewID(), PlacedAt: 1}}
		}, true},
		{"a new session", func(f *fenceFx, st *control.State) {
			st.Sessions[model.NewID().String()] = model.ControlSession{User: f.user, CSRF: "c", Expires: 9_000_000_000}
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFenceFx(t)
			rev0, auth0 := f.revisions()
			if err := f.store.UpdateArtifactReferences(f.ctx, func(st *control.State) error { c.write(f, st); return nil }); err != nil {
				t.Fatal(err)
			}
			rev1, auth1 := f.revisions()
			if rev1 != rev0+1 {
				t.Fatalf("revision %d -> %d", rev0, rev1)
			}
			if c.bumps && auth1 != rev1 || !c.bumps && auth1 != auth0 {
				t.Fatalf("bumps=%v: authority %d -> %d at revision %d", c.bumps, auth0, auth1, rev1)
			}
		})
	}
}

// referencingFiles lists the non-test files under the module that mention the selector name.
func referencingFiles(t *testing.T, name string) []string {
	t.Helper()
	var sites []string
	fset := token.NewFileSet()
	for _, root := range []string{"../../internal", "../../tools", "../../cmd"} {
		if _, err := os.Stat(root); err != nil {
			continue
		}
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			file, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			ast.Inspect(file, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.SelectorExpr:
					if x.Sel.Name == name {
						sites = append(sites, filepath.ToSlash(path))
					}
				case *ast.Field: // an interface method declaration
					for _, id := range x.Names {
						if id.Name == name {
							sites = append(sites, filepath.ToSlash(path))
						}
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	slices.Sort(sites)
	return slices.Compact(sites)
}

// The session writer is reached from the auth login paths only (the one interface and its
// dispatch live in service.go); the ledger writer from the artifacts ledger only. A second
// caller is a change a reviewer has to look at.
func TestSessionAndLedgerWritersHaveExactlyTheirCallers(t *testing.T) {
	if got := referencingFiles(t, "UpdateSessionCreate"); !slices.Equal(got, []string{"../../internal/auth/service.go"}) {
		t.Fatalf("UpdateSessionCreate is referenced from %v, want exactly internal/auth/service.go", got)
	}
	if got := referencingFiles(t, "UpdateArtifactReferences"); !slices.Equal(got, []string{"../../internal/artifacts/references.go"}) {
		t.Fatalf("UpdateArtifactReferences is referenced from %v, want exactly internal/artifacts/references.go", got)
	}
}
