// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
)

// D102: the scoped delta command (scoped_delta.go). These tests drive the machine directly
// (replicatedControl.Apply and Validate, as audit_delta_internal_test.go does) and the store's record
// writers through their real group.

type scopedFx struct {
	*installFx
	user       model.ID
	userKey    string
	sessionKey string
}

func newScopedFx(t *testing.T) *scopedFx {
	t.Helper()
	f := &scopedFx{installFx: newInstallFx(t), user: model.ID{0x61}}
	f.s.SetStatePatchGate(func() bool { return true })
	f.s.SetAuditDeltaGate(func() bool { return true })
	// The installation is contracted (the mark in the stored state, which the command that writes it takes the
	// books out of the blob for on every voter): the form is proposed on a contracted installation only.
	if err := f.s.Update(f.ctx, func(st *State) error {
		if st.OIDC == nil {
			st.OIDC = map[string]json.RawMessage{}
		}
		st.OIDC[model.IndexesContractedKey] = json.RawMessage(`true`)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !f.s.layoutLedger.Load() {
		t.Fatal("the fixture is not contracted")
	}
	f.userKey, f.sessionKey = f.user.String(), strings.Repeat("ab", 32)
	if err := f.s.Update(f.ctx, func(st *State) error {
		st.Users = map[string]model.ControlUser{f.userKey: {ID: f.user, Email: "owner@scoped.invalid", Password: "digest-1", Admin: true}}
		st.Sessions = map[string]model.ControlSession{f.sessionKey: {User: f.user, CSRF: "csrf", Expires: 1 << 40, Reauthenticated: 5}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return f
}

// reads names the records of refs as the committed state holds them now.
func (f *scopedFx) reads(refs ...scopedRead) []scopedRead {
	f.t.Helper()
	var out []scopedRead
	if err := f.s.db.View(func(tx *bolt.Tx) error {
		raw, err := stateRaw(tx.Bucket([]byte("control")))
		if err != nil {
			return err
		}
		views, err := readRecords(raw, scanStateRoot(raw), refs)
		for _, v := range views {
			out = append(out, scopedRead{Table: v.table, Key: v.key, Digest: v.digest})
		}
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// delta is a scoped delta that reads the user and the session now and a session under newKey (which is not
// there), and writes the new session and an audit row.
func (f *scopedFx) delta(newKey string, at int64) scopedDelta {
	f.t.Helper()
	value, err := json.Marshal(model.ControlSession{User: f.user, CSRF: "new", Expires: 1 << 40, Reauthenticated: 9})
	if err != nil {
		f.t.Fatal(err)
	}
	return scopedDelta{
		Installation: f.state().Installation, At: at,
		Reads:  f.reads(scopedRead{Table: tableUsers, Key: f.userKey}, scopedRead{Table: tableSessions, Key: f.sessionKey}, scopedRead{Table: tableSessions, Key: newKey}),
		Ops:    []patchOp{{Op: opSet, Path: []string{tableSessions, newKey}, Value: value}},
		Audits: []model.ControlAudit{f.audit("instance.scope", at)},
	}
}

// entry is the committed scoped delta for the machine of f at the next replica index, at application slot cursor.
func (f *scopedFx) entry(d scopedDelta, cursor model.Revision) replica.CommittedEntry {
	f.t.Helper()
	payload, err := json.Marshal(scopedDeltaCommand{ScopedDelta: d})
	if err != nil {
		f.t.Fatal(err)
	}
	physical, err := f.s.appliedIndex()
	if err != nil {
		f.t.Fatal(err)
	}
	g := f.s.ReplicaGroup().Status()
	return replica.CommittedEntry{
		Group: g.Group, Term: g.Term, Index: physical + 1,
		ApplicationCursor: model.Cursor{Group: g.Group, Index: model.Uint64(cursor)},
		Entry:             replica.Entry{ID: model.NewID(), Kind: replica.Control, Payload: payload},
	}
}

// What commits that read none of the records of a scoped delta do to it: nothing. The delta is judged at
// apply against the records it read, so an admission, a job, an issue, an organization, a user and a session
// that are not its own commit between its read and its order and it still applies, and the leader's check
// (Validate) agrees. Before D102 every one of them made a login or the grant of an instance scope stale.
func TestScopedDeltaIsNotMadeStaleByCommitsOfOtherRecords(t *testing.T) {
	other := model.ID{0x62}
	unrelated := map[string]func(f *scopedFx, st *State) error{
		"an empty control commit": func(*scopedFx, *State) error { return nil },
		"an admission key": func(_ *scopedFx, st *State) error {
			st.AdmissionKeys = map[string]string{"admission:key": "reservation"}
			return nil
		},
		"a job record": func(f *scopedFx, st *State) error {
			st.JobBooks = map[string]json.RawMessage{f.org.String() + ":" + f.project.String() + ":job": json.RawMessage(`{}`)}
			return nil
		},
		"an issue book": func(f *scopedFx, st *State) error {
			st.IssueBooks = map[string]json.RawMessage{f.org.String() + ":" + f.project.String(): json.RawMessage(`{}`)}
			return nil
		},
		"another organization": func(_ *scopedFx, st *State) error {
			if st.Orgs == nil {
				st.Orgs = map[string]model.ControlOrg{}
			}
			st.Orgs[other.String()] = model.ControlOrg{ID: other, Name: "other", Epoch: 4}
			return nil
		},
		"another user": func(_ *scopedFx, st *State) error {
			st.Users[other.String()] = model.ControlUser{ID: other, Email: "other@scoped.invalid", Password: "digest-2"}
			return nil
		},
		"another session": func(_ *scopedFx, st *State) error {
			st.Sessions[strings.Repeat("cd", 32)] = model.ControlSession{User: other, CSRF: "other", Expires: 1 << 40}
			return nil
		},
		"an audit row": func(f *scopedFx, st *State) error {
			st.Audits = append(st.Audits, f.audit("export.chunk", 3))
			return nil
		},
	}
	for name, commit := range unrelated {
		f := newScopedFx(t) // the machine is applied to directly below, so every case has a group of its own
		d := f.delta(fmt.Sprintf("%064x", 0x1000), 50)
		if err := f.s.Update(f.ctx, func(st *State) error { return commit(f, st) }); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		c := f.entry(d, f.state().Revision+1)
		if err := f.s.repl.Validate(f.ctx, c.Entry); err != nil {
			t.Fatalf("%s: the leader refused the delta: %v", name, err)
		}
		rev, authority := f.state().Revision, f.state().AuthorityRevision
		if err := f.s.repl.Apply(c); err != nil {
			t.Fatalf("%s: a commit of other records made the delta stale: %v", name, err)
		}
		after := f.state()
		if after.Revision != rev+1 || after.AuthorityRevision != authority {
			t.Fatalf("%s: revision %d -> %d, authority %d -> %d: want the revision to step and authority to stay", name, rev, after.Revision, authority, after.AuthorityRevision)
		}
		if _, ok := after.Sessions[d.Ops[0].Path[1]]; !ok || after.Audits[len(after.Audits)-1].ID != d.Audits[0].ID {
			t.Fatalf("%s: the delta applied without its session or its audit row", name)
		}
	}
}

// A change of a record the delta read is the one change that makes it stale: the machine rejects it as it
// rejects a stale replacement (nothing written, the revision stepped to the slot, a marker kept, the same
// answer on a replay), and the leader refuses it before ordering it.
func TestScopedDeltaIsStaleWhenARecordItReadChanged(t *testing.T) {
	changes := map[string]func(f *scopedFx, st *State){
		"the user is disabled": func(f *scopedFx, st *State) { u := st.Users[f.userKey]; u.Disabled = true; st.Users[f.userKey] = u },
		"the password changed": func(f *scopedFx, st *State) {
			u := st.Users[f.userKey]
			u.Password = "digest-2"
			st.Users[f.userKey] = u
		},
		"the administrator was removed": func(f *scopedFx, st *State) { u := st.Users[f.userKey]; u.Admin = false; st.Users[f.userKey] = u },
		"the user is deleted":           func(f *scopedFx, st *State) { delete(st.Users, f.userKey) },
		"the session ended":             func(f *scopedFx, st *State) { delete(st.Sessions, f.sessionKey) },
		"the session was refreshed": func(f *scopedFx, st *State) {
			s := st.Sessions[f.sessionKey]
			s.Reauthenticated++
			st.Sessions[f.sessionKey] = s
		},
		"the session key it meant to create was taken": func(f *scopedFx, st *State) {
			st.Sessions[strings.Repeat("ee", 32)] = model.ControlSession{User: f.user, CSRF: "raced", Expires: 1 << 40}
		},
	}
	for name, change := range changes {
		f := newScopedFx(t)
		d := f.delta(strings.Repeat("ee", 32), 60)
		if err := f.s.Update(f.ctx, func(st *State) error { change(f, st); return nil }); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		c := f.entry(d, f.state().Revision+1)
		if err := f.s.repl.Validate(f.ctx, c.Entry); mutantCode(err) != model.Stale {
			t.Fatalf("%s: the leader answered %v, want stale", name, err)
		}
		before := f.state()
		if err := f.s.repl.Apply(c); !errors.Is(err, replica.ErrConflict) {
			t.Fatalf("%s: the delta answered %v, want replica.ErrConflict", name, err)
		}
		after := f.state()
		want := before
		want.Revision = before.Revision + 1
		if f.canonical(after) != f.canonical(want) {
			t.Fatalf("%s: a rejected delta changed the state beyond its revision:\n got  %.300s\n want %.300s", name, f.canonical(after), f.canonical(want))
		}
		if got := f.mutantMeta("rejected:" + c.Entry.ID.String()); len(got) != 1 || got[0] != 1 {
			t.Fatalf("%s: the rejection left no marker: %v", name, got)
		}
		if err := f.s.repl.Apply(c); !errors.Is(err, replica.ErrConflict) {
			t.Fatalf("%s: a replay of the rejected delta answered %v, want the same conflict", name, err)
		}
	}
}

// The group may hand the machine an applied scoped delta again (a restart replays what the machine had
// applied): the same command changes nothing; a different one at the same slot, or another installation's, is
// corrupt.
func TestScopedDeltaReplayIsVerifiedNotReapplied(t *testing.T) {
	f := newScopedFx(t)
	d := f.delta(strings.Repeat("ee", 32), 70)
	slot := f.state().Revision + 1
	c := f.entry(d, slot)
	if err := f.s.repl.Apply(c); err != nil {
		t.Fatal(err)
	}
	after := f.state()
	if err := f.s.repl.Apply(c); err != nil {
		t.Fatalf("a replay of the applied delta answered %v", err)
	}
	if f.canonical(f.state()) != f.canonical(after) {
		t.Fatal("a replay of the applied delta changed the state")
	}
	forged := c
	other := d
	other.Ops = []patchOp{{Op: opSet, Path: []string{tableSessions, strings.Repeat("ee", 32)}, Value: json.RawMessage(`{"User":"` + f.user.String() + `","CSRF":"forged","Expires":"1099511627776","Reauthenticated":"9"}`)}}
	payload, _ := json.Marshal(scopedDeltaCommand{ScopedDelta: other})
	forged.Entry.Payload = payload
	if err := f.s.repl.Apply(forged); mutantCode(err) != model.Corrupt {
		t.Fatalf("a different delta at an applied slot answered %v, want corrupt", err)
	}
	foreign := c
	d.Installation = model.ID{0x77}
	payload, _ = json.Marshal(scopedDeltaCommand{ScopedDelta: d})
	foreign.Entry.Payload = payload
	if err := f.s.repl.Apply(foreign); mutantCode(err) != model.Corrupt {
		t.Fatalf("a replay of a delta of another installation answered %v, want corrupt", err)
	}
}

// The leader orders a scoped delta where it lands: a proposal that names an application index is refused,
// and one that names the installation of another is stale.
func TestScopedDeltaValidateRefusesAnIndexAndAForeignInstallation(t *testing.T) {
	f := newScopedFx(t)
	d := f.delta(strings.Repeat("ee", 32), 80)
	c := f.entry(d, f.state().Revision+1)
	named := c.Entry
	named.ApplicationIndex = uint64(f.state().Revision + 1)
	if err := f.s.repl.Validate(f.ctx, named); mutantCode(err) != model.Invalid {
		t.Fatalf("a scoped delta that names its index answered %v, want invalid", err)
	}
	d.Installation = model.ID{0x77}
	payload, _ := json.Marshal(scopedDeltaCommand{ScopedDelta: d})
	foreign := c.Entry
	foreign.Payload = payload
	if err := f.s.repl.Validate(f.ctx, foreign); mutantCode(err) != model.Stale {
		t.Fatalf("a scoped delta of another installation answered %v, want stale", err)
	}
}

// What the record writers of the store leave is what the previous forms leave: the same session, the same
// factor state, the same audit log, the same revisions and AuthorityRevision, the same revision clock.
func TestScopedRecordWritersLeaveWhatThePreviousFormsLeave(t *testing.T) {
	scoped, previous := newScopedFx(t), newScopedFx(t)
	previous.s.layoutLedger.Store(false) // RecordScope is false: the previous forms commit
	if scoped.s.RecordScope() == previous.s.RecordScope() || !scoped.s.RecordScope() {
		t.Fatalf("the fixtures do not differ in RecordScope: %v %v (the fresh installation must be contracted)", scoped.s.RecordScope(), previous.s.RecordScope())
	}
	r := rand.New(rand.NewPCG(102, 102))
	now := int64(5_000)
	clock := func() time.Time { return time.Unix(0, now) }
	scoped.s.SetClock(clock)
	previous.s.SetClock(clock)
	// Both fixtures start from the same state: the same stamps (they were built by the same steps).
	for _, f := range []*scopedFx{scoped, previous} {
		if err := f.s.Update(f.ctx, func(st *State) error {
			st.RevisionClock = []model.RevisionStamp{{Revision: 1, At: 1_000}}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if a, b := scoped.state().Revision, previous.state().Revision; a != b {
		t.Fatalf("fixtures disagree on the revision: %d vs %d", a, b)
	}
	for i := range 40 {
		now += int64(r.IntN(3)) * int64(time.Minute) * int64(r.IntN(40)+1)
		key := fmt.Sprintf("%064x", i+1)
		for _, f := range []*scopedFx{scoped, previous} {
			login := func(st *State) error {
				u := st.Users[f.userKey]
				if u.ID != f.user {
					return model.Fail(model.Stale)
				}
				if i%3 == 0 {
					u.LastTOTP = int64(100 + i) // a consumed factor: the user record changes, authority does not
					st.Users[f.userKey] = u
				}
				st.Sessions[key] = model.ControlSession{User: u.ID, CSRF: "c", Expires: 1 << 40, Reauthenticated: now}
				return nil
			}
			if err := f.s.UpdateSessionCreateRecords(f.ctx, model.ControlRecords{Users: []string{f.userKey}, Sessions: []string{key}}, login); err != nil {
				t.Fatalf("login %d: %v", i, err)
			}
		}
		row := scoped.audit("instance.scope", now)
		row.Reason = fmt.Sprintf("a backup <%d> & more", i)
		for _, f := range []*scopedFx{scoped, previous} {
			// The previous form of the audit is the audit-append writer: the whole-state Update bumps authority.
			grant := func(st *State) error {
				if _, ok := st.Sessions[f.sessionKey]; !ok || !st.Users[f.userKey].Admin {
					return model.Fail(model.Unauthenticated)
				}
				st.Audits = append(st.Audits, row)
				return nil
			}
			var err error
			if f == scoped {
				err = f.s.UpdateAuditRecords(f.ctx, model.ControlRecords{Users: []string{f.userKey}, Sessions: []string{f.sessionKey}}, grant)
			} else {
				err = f.s.UpdateAuditAppend(f.ctx, grant)
			}
			if err != nil {
				t.Fatalf("grant %d: %v", i, err)
			}
		}
		a, b := scoped.state(), previous.state()
		a.Installation, b.Installation = model.ID{0x66}, model.ID{0x66}
		b.BootstrapHash = a.BootstrapHash
		if scoped.canonical(a) != previous.canonical(b) {
			t.Fatalf("step %d: the scoped commits left a state that differs from the previous forms':\n got  %.400s\n want %.400s", i, scoped.canonical(a), previous.canonical(b))
		}
		if a.AuthorityRevision != b.AuthorityRevision || a.Revision != b.Revision {
			t.Fatalf("step %d: revision %d vs %d, authority %d vs %d", i, a.Revision, b.Revision, a.AuthorityRevision, b.AuthorityRevision)
		}
	}
	if n, _ := scoped.s.ScopedDeltaStats(); n != 80 {
		t.Fatalf("the scoped store proposed %d scoped deltas, want 80", n)
	}
	if n, _ := previous.s.ScopedDeltaStats(); n != 0 {
		t.Fatalf("the store that is not scoped proposed %d scoped deltas, want 0", n)
	}
	if a := scoped.state(); a.AuthorityRevision == a.Revision {
		t.Fatalf("the scoped commits moved AuthorityRevision to %d", a.AuthorityRevision)
	}
}

// A scoped transition that is handed the records it names and nothing else is refused when it writes what
// it did not declare, and writes nothing then.
func TestScopedRecordWritersRefuseWhatTheTransitionDidNotDeclare(t *testing.T) {
	f := newScopedFx(t)
	reads := model.ControlRecords{Users: []string{f.userKey}, Sessions: []string{strings.Repeat("ee", 32)}}
	for name, fn := range map[string]func(*State) error{
		"an undeclared session": func(st *State) error {
			st.Sessions[strings.Repeat("ff", 32)] = model.ControlSession{User: f.user}
			return nil
		},
		"an undeclared user":    func(st *State) error { st.Users["x"] = model.ControlUser{}; return nil },
		"another member":        func(st *State) error { st.BootstrapHash = "changed"; return nil },
		"another member (orgs)": func(st *State) error { st.Orgs = map[string]model.ControlOrg{"o": {}}; return nil },
	} {
		rev := f.state().Revision
		if err := f.s.UpdateSessionCreateRecords(f.ctx, reads, fn); mutantCode(err) != model.Invalid {
			t.Fatalf("%s: answered %v, want invalid", name, err)
		}
		if f.state().Revision != rev {
			t.Fatalf("%s: a refused transition committed", name)
		}
	}
	// A transition that changes nothing commits nothing.
	rev := f.state().Revision
	if err := f.s.UpdateSessionCreateRecords(f.ctx, reads, func(*State) error { return nil }); err != nil || f.state().Revision != rev {
		t.Fatalf("a transition that changed nothing: %v, revision %d -> %d", err, rev, f.state().Revision)
	}
	// An error of the transition is the answer, and the records it was given are the committed ones.
	var seen model.ControlUser
	sentinel := errors.New("sentinel")
	if err := f.s.UpdateSessionCreateRecords(f.ctx, reads, func(st *State) error { seen = st.Users[f.userKey]; return sentinel }); !errors.Is(err, sentinel) || seen.Email != "owner@scoped.invalid" {
		t.Fatalf("the transition's error was answered %v, user it read %+v", err, seen)
	}
	// A user the state does not hold is not in the view: the transition sees it absent.
	if err := f.s.UpdateAuditRecords(f.ctx, model.ControlRecords{Users: []string{"absent"}}, func(st *State) error {
		if _, ok := st.Users["absent"]; ok {
			t.Error("an absent user is in the view")
		}
		return model.Fail(model.Unauthenticated)
	}); mutantCode(err) != model.Unauthenticated {
		t.Fatalf("answered %v, want unauthenticated", err)
	}
}

// A record writer commits the scoped delta only where the form is proposed: not without the gate of the
// state patch protocol, not on a file that is not contracted; the previous forms commit there.
func TestScopedRecordWritersFollowTheGateAndTheContraction(t *testing.T) {
	f := newScopedFx(t)
	writes := func(label string) (granted uint64) {
		t.Helper()
		before, _ := f.s.ScopedDeltaStats()
		key := strings.Repeat("ee", 32)
		if err := f.s.UpdateSessionCreateRecords(f.ctx, model.ControlRecords{Users: []string{f.userKey}, Sessions: []string{key}}, func(st *State) error {
			st.Sessions[key] = model.ControlSession{User: f.user, CSRF: label, Expires: 1 << 40}
			return nil
		}); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if _, ok := f.state().Sessions[key]; !ok {
			t.Fatalf("%s: the session was not committed", label)
		}
		after, _ := f.s.ScopedDeltaStats()
		if err := f.s.Update(f.ctx, func(st *State) error { delete(st.Sessions, key); return nil }); err != nil {
			t.Fatal(err)
		}
		return after - before
	}
	if got := writes("open"); got != 1 {
		t.Fatalf("gate open, contracted: %d scoped deltas, want 1", got)
	}
	f.s.SetStatePatchGate(func() bool { return false })
	if got := writes("gate closed"); got != 0 {
		t.Fatalf("gate closed: %d scoped deltas, want 0", got)
	}
	f.s.SetStatePatchGate(nil)
	if got := writes("no gate"); got != 0 || f.s.RecordScope() {
		t.Fatalf("no gate: %d scoped deltas (RecordScope %v), want 0", got, f.s.RecordScope())
	}
	f.s.SetStatePatchGate(func() bool { return true })
	f.s.layoutLedger.Store(false)
	if got := writes("not contracted"); got != 0 || f.s.RecordScope() {
		t.Fatalf("not contracted: %d scoped deltas (RecordScope %v), want 0", got, f.s.RecordScope())
	}
}

// The splice that applies a scoped delta to the bytes of the state leaves the bytes the decode/encode of the
// state leaves: over random deltas (records set, replaced and deleted, a Sessions member that is null or
// absent, audit rows, AuthorityRevision bumped, a revision clock that stamps and prunes).
func TestScopedDeltaRawSpliceEqualsDecodeEncode(t *testing.T) {
	f := newScopedFx(t)
	r := rand.New(rand.NewPCG(1020, 1020))
	spliced := 0
	for i := range 400 {
		st := f.state()
		if r.IntN(3) == 0 {
			st.Sessions = nil
		}
		if r.IntN(4) == 0 {
			st.Audits = nil
		}
		if r.IntN(2) == 0 {
			st.RevisionClock = nil
		}
		raw, err := json.Marshal(st)
		if err != nil {
			t.Fatal(err)
		}
		d := scopedDelta{Installation: st.Installation, At: int64(r.IntN(3)) * int64(time.Hour) * int64(r.IntN(100)), Bump: r.IntN(3) == 0}
		for _, key := range []string{f.userKey, "u-2", "u-3"} {
			if r.IntN(2) == 0 {
				continue
			}
			d.Reads = append(d.Reads, scopedRead{Table: tableUsers, Key: key})
			switch r.IntN(3) {
			case 0:
				d.Ops = append(d.Ops, patchOp{Op: opDelete, Path: []string{tableUsers, key}})
			default:
				v, _ := json.Marshal(model.ControlUser{ID: model.ID{byte(i%200 + 1)}, Email: fmt.Sprintf("<%d>@x.invalid", i), Password: "p&q", Recovery: []string{"a", "b"}[:r.IntN(3)], LastTOTP: int64(i)})
				d.Ops = append(d.Ops, patchOp{Op: opSet, Path: []string{tableUsers, key}, Value: v})
			}
		}
		for _, key := range []string{f.sessionKey, "s-2", "s-3"} {
			if r.IntN(2) == 0 {
				continue
			}
			d.Reads = append(d.Reads, scopedRead{Table: tableSessions, Key: key})
			if r.IntN(3) == 0 {
				d.Ops = append(d.Ops, patchOp{Op: opDelete, Path: []string{tableSessions, key}})
			} else {
				v, _ := json.Marshal(model.ControlSession{User: f.user, CSRF: "c<" + key, Expires: int64(i), Reauthenticated: 3})
				d.Ops = append(d.Ops, patchOp{Op: opSet, Path: []string{tableSessions, key}, Value: v})
			}
		}
		for range r.IntN(3) {
			d.Audits = append(d.Audits, randomAudit(r, f.installFx))
		}
		if len(d.Ops) == 0 && len(d.Audits) == 0 {
			continue
		}
		revision := st.Revision + 1
		var decoded State
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if _, err := applyScopedDelta(&decoded, d, revision); err != nil {
			t.Fatalf("delta %d: %v", i, err)
		}
		want, err := json.Marshal(decoded)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := scopedRaw(raw, scanStateRoot(raw), d, revision)
		if !ok {
			continue // the splice does not prove it applies: the machine decodes, which the other half pinned
		}
		spliced++
		if !bytes.Equal(got, want) {
			t.Fatalf("delta %d: the splice left other bytes than the decode/encode:\n got  %.300s\n want %.300s", i, got, want)
		}
	}
	if spliced < 100 {
		t.Fatalf("the splice applied %d of 400 deltas: the equivalence was not exercised", spliced)
	}
}

// The payload decoder reads a scoped delta strictly and refuses what no proposer writes.
func TestScopedDeltaDecoderIsStrict(t *testing.T) {
	f := newScopedFx(t)
	good := f.delta(strings.Repeat("ee", 32), 90)
	encode := func(d scopedDelta) []byte {
		raw, err := json.Marshal(scopedDeltaCommand{ScopedDelta: d})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if c, err := decodeControlCommand(encode(good)); err != nil || c.scoped == nil || c.delta != nil || c.patch != nil || c.replacement != nil || len(c.scoped.Reads) != 3 {
		t.Fatalf("a scoped delta did not decode as one: %v", err)
	}
	mutate := func(edit func(*scopedDelta)) []byte {
		d := good
		d.Reads = append([]scopedRead(nil), good.Reads...)
		d.Ops = append([]patchOp(nil), good.Ops...)
		d.Audits = append([]model.ControlAudit(nil), good.Audits...)
		edit(&d)
		return encode(d)
	}
	digest := strings.Repeat("0", 64)
	record, _ := json.Marshal(model.ControlSession{User: f.user})
	good2 := string(encode(good))
	for name, payload := range map[string][]byte{
		"no reads":             mutate(func(d *scopedDelta) { d.Reads, d.Ops = nil, nil }),
		"too many reads":       mutate(func(d *scopedDelta) { d.Reads = append(d.Reads, make([]scopedRead, maxScopedReads)...) }),
		"nothing written":      mutate(func(d *scopedDelta) { d.Ops, d.Audits = nil, nil }),
		"a table of its own":   mutate(func(d *scopedDelta) { d.Reads[0].Table = "Orgs" }),
		"an empty key":         mutate(func(d *scopedDelta) { d.Reads[0].Key = "" }),
		"a long key":           mutate(func(d *scopedDelta) { d.Reads[0].Key = strings.Repeat("k", maxRecordKey+1) }),
		"a bad digest":         mutate(func(d *scopedDelta) { d.Reads[0].Digest = "XYZ" }),
		"an upper case digest": mutate(func(d *scopedDelta) { d.Reads[0].Digest = strings.Repeat("A", 64) }),
		"a read named twice":   mutate(func(d *scopedDelta) { d.Reads[1] = d.Reads[0] }),
		"a write it did not read": mutate(func(d *scopedDelta) {
			d.Ops = append(d.Ops, patchOp{Op: opSet, Path: []string{tableSessions, "unread"}, Value: record})
		}),
		"a write twice": mutate(func(d *scopedDelta) {
			d.Reads = append(d.Reads, scopedRead{Table: tableSessions, Key: "extra", Digest: digest})
			d.Ops = append(d.Ops, d.Ops[0])
		}),
		"a deep path":           mutate(func(d *scopedDelta) { d.Ops[0].Path = []string{tableSessions, d.Ops[0].Path[1], "CSRF"} }),
		"an array op":           mutate(func(d *scopedDelta) { d.Ops[0].Op = opArray }),
		"a cut":                 mutate(func(d *scopedDelta) { d.Ops[0].Cut = 1 }),
		"a delete with a value": mutate(func(d *scopedDelta) { d.Ops[0].Op = opDelete }),
		"an invalid record": mutate(func(d *scopedDelta) {
			d.Ops[0].Value = json.RawMessage(`{"User":"x"}`)
		}),
		"a record with a member this build does not know": mutate(func(d *scopedDelta) {
			d.Ops[0].Value = json.RawMessage(`{"User":"` + f.user.String() + `","Extra":1}`)
		}),
		"too many audit rows": mutate(func(d *scopedDelta) {
			for range maxAuditDeltaRows {
				d.Audits = append(d.Audits, f.audit("instance.scope", 90))
			}
		}),
		"an unknown member":         []byte(good2[:len(good2)-2] + `,"extra":1}}`),
		"another member next to it": []byte(good2[:len(good2)-1] + `,"audit_delta":{}}`),
		"trailing data":             []byte(good2 + " {}"),
	} {
		if c, err := decodeControlCommand(payload); err == nil {
			t.Errorf("%s: decoded (scoped %v), want a refusal", name, c.scoped != nil)
		}
	}
	// The row of an audit is exactly what this build writes: one with a member it does not know would
	// decode and encode without it.
	row, _ := json.Marshal(good.Audits[0])
	forged := strings.Replace(good2, string(row), string(row[:len(row)-1])+`,"Unknown":true}`, 1)
	if forged == good2 {
		t.Fatal("the test did not find the audit row in the payload")
	}
	if _, err := decodeControlCommand([]byte(forged)); err == nil {
		t.Error("a row with a member this build does not know decoded")
	}
}

// The machine applies a scoped delta to a file that is not contracted (the books in the blob; no voter of a
// contracted installation can hold one, but a voter applies what it is given) and to a state whose Users and
// Sessions are null: the records are created, the revision steps and a replay verifies.
func TestScopedDeltaAppliesToANullMapOnAFileThatIsNotContracted(t *testing.T) {
	f := newInstallFx(t)
	if f.s.layoutLedger.Load() {
		t.Fatal("the fixture is contracted")
	}
	user, session := model.ID{0x63}, strings.Repeat("ab", 32)
	if err := f.s.Update(f.ctx, func(st *State) error { st.Users, st.Sessions = nil, nil; return nil }); err != nil {
		t.Fatal(err)
	}
	if st := f.state(); len(st.Users) != 0 || len(st.Sessions) != 0 {
		t.Fatalf("the fixture holds users %v sessions %v", st.Users, st.Sessions)
	}
	u, _ := json.Marshal(model.ControlUser{ID: user, Email: "owner@null.invalid", Password: "p", Admin: true})
	s, _ := json.Marshal(model.ControlSession{User: user, CSRF: "c", Expires: 1 << 40})
	d := scopedDelta{
		Installation: f.state().Installation, At: 5,
		Reads: []scopedRead{{Table: tableUsers, Key: user.String()}, {Table: tableSessions, Key: session}},
		Ops: []patchOp{
			{Op: opSet, Path: []string{tableUsers, user.String()}, Value: u},
			{Op: opSet, Path: []string{tableSessions, session}, Value: s},
		},
		Audits: []model.ControlAudit{f.audit("instance.scope", 5)},
	}
	payload, err := json.Marshal(scopedDeltaCommand{ScopedDelta: d})
	if err != nil {
		t.Fatal(err)
	}
	physical, err := f.s.appliedIndex()
	if err != nil {
		t.Fatal(err)
	}
	rev := f.state().Revision
	g := f.s.ReplicaGroup().Status()
	c := replica.CommittedEntry{
		Group: g.Group, Term: g.Term, Index: physical + 1,
		ApplicationCursor: model.Cursor{Group: g.Group, Index: model.Uint64(rev + 1)},
		Entry:             replica.Entry{ID: model.NewID(), Kind: replica.Control, Payload: payload},
	}
	if err := f.s.repl.Validate(f.ctx, c.Entry); err != nil {
		t.Fatalf("the leader refused a delta that creates records: %v", err)
	}
	if err := f.s.repl.Apply(c); err != nil {
		t.Fatal(err)
	}
	after := f.state()
	if after.Revision != rev+1 || after.Users[user.String()].Email != "owner@null.invalid" || after.Sessions[session].CSRF != "c" || len(after.Audits) == 0 || after.Audits[len(after.Audits)-1].ID != d.Audits[0].ID {
		t.Fatalf("the delta left revision %d (was %d), users %v sessions %v", after.Revision, rev, after.Users, after.Sessions)
	}
	if err := f.s.repl.Apply(c); err != nil {
		t.Fatalf("a replay of the applied delta answered %v", err)
	}
	if f.canonical(f.state()) != f.canonical(after) {
		t.Fatal("a replay of the applied delta changed the state")
	}
}

// The records are read from the bytes of the state when they are the compact encoding of a State, and from
// the decoded state when they are not (white space between members, a state that is not the encoder's):
// both read the same records and digest them alike, so a voter never judges a delta differently for the way
// its bytes happen to be laid out.
func TestScopedRecordsAreReadAlikeFromTheBytesAndFromTheDecodedState(t *testing.T) {
	f := newScopedFx(t)
	st := f.state()
	compact, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	spaced, err := json.MarshalIndent(st, " ", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if scanStateRoot(spaced).ok || !scanStateRoot(compact).ok {
		t.Fatal("the fixture encodings do not differ in whether the bytes can be scanned")
	}
	refs := []scopedRead{
		{Table: tableUsers, Key: f.userKey}, {Table: tableUsers, Key: "absent"},
		{Table: tableSessions, Key: f.sessionKey}, {Table: tableSessions, Key: strings.Repeat("00", 32)},
	}
	a, err := readRecords(compact, scanStateRoot(compact), refs)
	if err != nil {
		t.Fatal(err)
	}
	b, err := readRecords(spaced, scanStateRoot(spaced), refs)
	if err != nil {
		t.Fatal(err)
	}
	for i := range refs {
		if a[i].found != b[i].found || a[i].digest != b[i].digest || a[i].rec.user.Email != b[i].rec.user.Email || a[i].rec.session != b[i].rec.session {
			t.Fatalf("%v: from the bytes %+v, from the decoded state %+v", refs[i], a[i], b[i])
		}
	}
	if !a[0].found || a[1].found || !a[2].found || a[3].found || a[0].digest == "" || a[1].digest != "" {
		t.Fatalf("the records read: %+v", a)
	}
	// A delta judged against either encoding is judged alike.
	d := scopedDelta{Installation: st.Installation, Reads: f.reads(refs...)}
	for name, raw := range map[string][]byte{"compact": compact, "decoded": spaced} {
		if ok, err := d.holds(raw, scanStateRoot(raw)); err != nil || !ok {
			t.Fatalf("%s: a delta that read the committed records does not hold: %v %v", name, ok, err)
		}
	}
	d.Reads[0].Digest = strings.Repeat("0", 64)
	for name, raw := range map[string][]byte{"compact": compact, "decoded": spaced} {
		if ok, err := d.holds(raw, scanStateRoot(raw)); err != nil || ok {
			t.Fatalf("%s: a delta that read another user record holds: %v %v", name, ok, err)
		}
	}
}
