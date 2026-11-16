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

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
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
		{"a consumed TOTP step with the session", func(f *fenceFx, st *control.State) {
			addSession(st)
			u := st.Users[f.user.String()]
			u.LastTOTP++
			st.Users[f.user.String()] = u
		}, false},
		{"another field of the user changed with the session", func(f *fenceFx, st *control.State) {
			addSession(st)
			u := st.Users[f.user.String()]
			u.Password = "forged-digest"
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

// Consuming a one-time factor at login writes User.LastTOTP (raised) and User.Recovery (a hash
// spent) and nothing else of the account: no decision reads either field (see writerSessionCreate
// for the proof), so the commit keeps AuthorityRevision. Every other change of the account, a
// lowered floor, a recovery list that gained, reordered or replaced a hash, and an account that
// appeared or vanished bump.
func TestUpdateSessionCreateFactorConsumption(t *testing.T) {
	addSession := func(st *control.State) {
		st.Sessions[model.NewID().String()] = model.ControlSession{User: model.NewID(), CSRF: "c", Expires: 9_000_000_000, Reauthenticated: 1}
	}
	edit := func(f *fenceFx, st *control.State, change func(*model.ControlUser)) {
		u := st.Users[f.user.String()]
		change(&u)
		st.Users[f.user.String()] = u
	}
	cases := []struct {
		name  string
		write func(f *fenceFx, st *control.State)
		bumps bool
	}{
		{"TOTP step raised", func(f *fenceFx, st *control.State) {
			addSession(st)
			edit(f, st, func(u *model.ControlUser) { u.LastTOTP = 101 })
		}, false},
		{"a recovery hash spent", func(f *fenceFx, st *control.State) {
			addSession(st)
			edit(f, st, func(u *model.ControlUser) { u.Recovery = []string{"a", "c"} })
		}, false},
		{"a recovery hash spent in place, as consumeFactor does", func(f *fenceFx, st *control.State) {
			addSession(st)
			edit(f, st, func(u *model.ControlUser) { u.Recovery = append(u.Recovery[:1], u.Recovery[2:]...) })
		}, false},
		{"all recovery hashes spent", func(f *fenceFx, st *control.State) {
			edit(f, st, func(u *model.ControlUser) { u.Recovery = nil })
		}, false},
		{"step raised and hash spent without a session", func(f *fenceFx, st *control.State) {
			edit(f, st, func(u *model.ControlUser) { u.LastTOTP, u.Recovery = 120, []string{"b", "c"} })
		}, false},
		{"TOTP step lowered", func(f *fenceFx, st *control.State) {
			addSession(st)
			edit(f, st, func(u *model.ControlUser) { u.LastTOTP = 99 })
		}, true},
		{"a recovery hash added", func(f *fenceFx, st *control.State) {
			addSession(st)
			edit(f, st, func(u *model.ControlUser) { u.Recovery = append(u.Recovery, "d") })
		}, true},
		{"recovery hashes reordered", func(f *fenceFx, st *control.State) {
			edit(f, st, func(u *model.ControlUser) { u.Recovery = []string{"c", "b", "a"} })
		}, true},
		{"recovery hashes replaced", func(f *fenceFx, st *control.State) {
			edit(f, st, func(u *model.ControlUser) { u.Recovery = []string{"x", "y"} })
		}, true},
		{"the TOTP secret replaced", func(f *fenceFx, st *control.State) {
			edit(f, st, func(u *model.ControlUser) { u.TOTP = "another-sealed-secret" })
		}, true},
		{"a pending TOTP enrolment", func(f *fenceFx, st *control.State) {
			edit(f, st, func(u *model.ControlUser) { u.PendingTOTP = "sealed" })
		}, true},
		{"the user made administrator", func(f *fenceFx, st *control.State) {
			edit(f, st, func(u *model.ControlUser) { u.Admin = !u.Admin })
		}, true},
		{"the user disabled with a spent hash", func(f *fenceFx, st *control.State) {
			edit(f, st, func(u *model.ControlUser) { u.Disabled, u.Recovery = true, []string{"a", "b"} })
		}, true},
		{"the e-mail changed with a raised step", func(f *fenceFx, st *control.State) {
			edit(f, st, func(u *model.ControlUser) { u.Email, u.LastTOTP = "other@example.test", 150 })
		}, true},
		{"an account appeared", func(f *fenceFx, st *control.State) {
			id := model.NewID()
			st.Users[id.String()] = model.ControlUser{ID: id, LastTOTP: 5}
		}, true},
		{"the account removed", func(f *fenceFx, st *control.State) { delete(st.Users, f.user.String()) }, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFenceFx(t)
			if err := f.store.Update(f.ctx, func(st *control.State) error {
				u := st.Users[f.user.String()]
				u.LastTOTP, u.Recovery = 100, []string{"a", "b", "c"}
				st.Users[f.user.String()] = u
				return nil
			}); err != nil {
				t.Fatal(err)
			}
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

// The real callers: a password login leaves AuthorityRevision alone, a logout (revocation) bumps.
// The TOTP- and recovery-code-consuming logins are in TestTOTPAndRecoveryLoginsKeepAuthority.
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

// publishedIntent is the intent PublishArtifact stores for an artifact of f's project, together
// with the consumed artifact reservation whose receipt it carries, exactly as the control state
// validation (validateArtifactReference) requires them: State "published", the command id equal to
// the artifact id, ControlRevision within the log, the manifests agreeing field by field, every id
// set (a zero id does not encode), and the reservation consumed with the same receipt. (The real
// PublishArtifact needs a blob owner that verifies the bytes; its stored result is what a ledger
// write rides with, so the fixture stores that result.)
func (f *fenceFx) publishedIntent() (string, model.ArtifactReferenceIntent, model.ArtifactQuotaReservation) {
	root, build, reservation := model.NewID(), model.NewID(), model.NewID()
	digest := model.HashCanonical([]byte("artifact fixture " + root.String()))
	blob := model.BlobManifest{Org: f.org, Project: f.project, Source: f.source, Root: root, Build: build, DebugID: "debug", Path: "app.js.map",
		GeneratedSHA256: digest, MapSHA256: digest, Hash: digest, Size: 1, PolicyEpoch: 1, PolicyRevision: 1, RetainUntil: 100, ReservationID: reservation}
	receipt := model.BlobReceipt{Manifest: blob, Hash: digest, Fragments: []model.BlobFragmentReceipt{}, Cursor: model.Cursor{Group: model.NewID(), Index: 1}}
	intent := model.ArtifactReferenceIntent{
		ID: root, CommandID: root, State: "published", ControlRevision: 1,
		Manifest: model.ArtifactManifest{Version: 1, Org: f.org, Project: f.project, Source: f.source, Build: build, DebugID: "debug", Path: "app.js.map",
			GeneratedSHA256: digest, MapSHA256: digest, Size: 1, RetainUntil: 100},
		Map: receipt,
	}
	held := model.ArtifactQuotaReservation{ID: reservation, Manifest: blob, ManifestHash: model.BlobManifestHash(blob), Slot: model.BlobOwnerSlot(f.org, f.project, root), State: "consumed", Receipt: &receipt}
	return f.org.String() + ":" + f.project.String() + ":" + root.String(), intent, held
}

// addIntent stores a published intent and its reservation in st.
func addIntent(st *control.State, key string, intent model.ArtifactReferenceIntent, held model.ArtifactQuotaReservation) {
	if st.ArtifactIntents == nil {
		st.ArtifactIntents = map[string]model.ArtifactReferenceIntent{}
	}
	if st.ArtifactReservations == nil {
		st.ArtifactReservations = map[string]model.ArtifactQuotaReservation{}
	}
	st.ArtifactIntents[key] = intent
	st.ArtifactReservations[held.ID.String()] = held
}

// An ArtifactIntents change is outside the reference-ledger mask: the retire transition (the
// intent leaves "published"), a new or removed intent and an altered one bump even when they ride
// in the same commit as a ledger write, while the ledger write alone does not. This is exactly
// the classification tables' split: PublishArtifact is a non-authority writer (a new reference
// intent over bytes that deletion predicates still gate at read time), the ledger writer is
// non-authority for ledger entries only, and the retire transition is authority (artifact
// readability changes).
func TestArtifactIntentRidingWithLedgerWriteBumps(t *testing.T) {
	cases := []struct {
		name  string
		write func(f *fenceFx, st *control.State, key string)
		bumps bool
	}{
		{"ledger alone", func(f *fenceFx, st *control.State, key string) { f.ledgerKeys(st) }, false},
		{"ledger with the intent retired", func(f *fenceFx, st *control.State, key string) {
			f.ledgerKeys(st)
			r := st.ArtifactIntents[key]
			r.State = "retired"
			st.ArtifactIntents[key] = r
		}, true},
		{"intent retired without a ledger entry", func(f *fenceFx, st *control.State, key string) {
			r := st.ArtifactIntents[key]
			r.State = "retired"
			st.ArtifactIntents[key] = r
		}, true},
		{"ledger with a second intent published", func(f *fenceFx, st *control.State, key string) {
			f.ledgerKeys(st)
			other, intent, held := f.publishedIntent()
			addIntent(st, other, intent, held)
		}, true},
		{"ledger with the intent removed", func(f *fenceFx, st *control.State, key string) {
			f.ledgerKeys(st)
			delete(st.ArtifactIntents, key)
		}, true},
		{"ledger with the intent's manifest altered", func(f *fenceFx, st *control.State, key string) {
			f.ledgerKeys(st)
			r := st.ArtifactIntents[key]
			r.Manifest.Size++
			st.ArtifactIntents[key] = r
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFenceFx(t)
			key, intent, held := f.publishedIntent()
			if err := f.store.Update(f.ctx, func(st *control.State) error { addIntent(st, key, intent, held); return nil }); err != nil {
				t.Fatal(err)
			}
			rev0, auth0 := f.revisions()
			if err := f.store.UpdateArtifactReferences(f.ctx, func(st *control.State) error { c.write(f, st, key); return nil }); err != nil {
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
	if got := referencingFiles(t, "UpdatePendingLogin"); !slices.Equal(got, []string{"../../internal/auth/oidc.go"}) {
		t.Fatalf("UpdatePendingLogin is referenced from %v, want exactly internal/auth/oidc.go", got)
	}
	if got := referencingFiles(t, "UpdateAuditAppend"); !slices.Equal(got, []string{"../../internal/auth/elevation.go"}) {
		t.Fatalf("UpdateAuditAppend is referenced from %v, want exactly internal/auth/elevation.go", got)
	}
}
