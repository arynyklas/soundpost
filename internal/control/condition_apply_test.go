// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

// condFx is the real control store (activated single-voter Raft group, real auth
// scopes) with the condition dispatcher bound. Leases come from the group.
type condFx struct {
	*fenceFx
	cond model.ID
}

func newCondFx(t *testing.T) *condFx {
	t.Helper()
	f := &condFx{fenceFx: newFenceFx(t), cond: model.ID{0xc1}}
	if err := f.store.BindConditionApply(); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *condFx) lease() replica.FenceToken {
	f.t.Helper()
	token, err := f.store.ReplicaGroup().Fence(f.ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	return token
}

// condState is a state whose header is the closed schema control checks; the
// rest is opaque to control.
func condState(org, project, cond model.ID, version uint64, tag string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"condition_id":%q,"org_id":%q,"project_id":%q,"version":"%d","tag":%q}`, cond.String(), org.String(), project.String(), version, tag))
}

func (f *condFx) command(expected uint64, tag, change string) control.ConditionCommand {
	lease := f.lease()
	state := condState(f.org, f.project, f.cond, expected+1, tag)
	return control.ConditionCommand{Project: f.project, Condition: f.cond, Lease: &lease, ExpectedVersion: model.Revision(expected), NewVersion: model.Revision(expected + 1),
		At: 100, Change: change, State: state, Digest: digest(state)}
}

func (f *condFx) send(id model.ID, c control.ConditionCommand) (control.Result, error) {
	f.t.Helper()
	return f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindApplyCondition, id, c))
}

func (f *condFx) record() control.ConditionRecord {
	f.t.Helper()
	r, ok, err := f.store.Condition(f.ctx, f.adminScope(), f.project, f.cond)
	if err != nil || !ok {
		f.t.Fatalf("record: %v %v", ok, err)
	}
	return r
}

func TestConditionApplyRequiresBoundDispatcher(t *testing.T) {
	f := newFenceFx(t)
	lease, err := f.store.ReplicaGroup().Fence(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	cond := model.ID{0xc1}
	state := condState(f.org, f.project, cond, 1, "a")
	c := control.ConditionCommand{Project: f.project, Condition: cond, Lease: &lease, NewVersion: 1, At: 100, State: state, Digest: digest(state)}
	if _, err = f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindApplyCondition, model.NewID(), c)); code(err) != model.Unsupported {
		t.Fatalf("an unbound condition dispatcher committed: %v", err)
	}
	if err = f.store.BindConditionApply(); err != nil {
		t.Fatal(err)
	}
	if code(f.store.BindConditionApply()) != model.Conflict {
		t.Fatal("the dispatcher bound twice")
	}
}

func TestConditionApplyVersionCompareAndSet(t *testing.T) {
	f := newCondFx(t)
	first, err := f.send(model.NewID(), f.command(0, "a", "firing"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Phase != "applied" || len(first.AffectedIDs) != 1 || first.AffectedIDs[0] != f.cond {
		t.Fatalf("result %+v", first)
	}
	if r := f.record(); r.Version != 1 || r.Org != f.org || r.Project != f.project || r.ID != f.cond {
		t.Fatalf("record %+v", r)
	}
	// Two commands that both expect version 1: exactly one commits.
	if _, err = f.send(model.NewID(), f.command(1, "b", "")); err != nil {
		t.Fatal(err)
	}
	_, err = f.send(model.NewID(), f.command(1, "c", "recovered"))
	if code(err) != model.Conflict || !strings.Contains(err.Error(), control.ConditionVersionConflict) {
		t.Fatalf("second writer at expected version 1: %v", err)
	}
	if r := f.record(); r.Version != 2 || !strings.Contains(string(r.State), `"tag":"b"`) {
		t.Fatalf("a loser overwrote state: %+v", r)
	}
	// A missing condition is NotFound, never created at a nonzero expected version.
	f.cond = model.ID{0xc2}
	if _, err = f.send(model.NewID(), f.command(3, "x", "")); code(err) != model.NotFound {
		t.Fatalf("missing condition: %v", err)
	}
}

func TestConditionApplyRetryReturnsOriginalResult(t *testing.T) {
	f := newCondFx(t)
	id := model.NewID()
	c := f.command(0, "a", "firing")
	first, err := f.send(id, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.send(model.NewID(), f.command(1, "b", "recovered")); err != nil {
		t.Fatal(err)
	}
	audits := len(f.audits("conditions.firing"))
	retry, err := f.send(id, c)
	if err != nil || retry.Revision != first.Revision || len(retry.AffectedIDs) != 1 {
		t.Fatalf("retry %+v %v", retry, err)
	}
	if r := f.record(); r.Version != 2 || len(f.audits("conditions.firing")) != audits {
		t.Fatalf("retry changed state or audited twice: %+v", r)
	}
}

// The lease is the fence: a lease older than the highest one the condition has
// accepted is a deposed leader's, and a lease of another group is never one.
func TestConditionApplyFence(t *testing.T) {
	f := newCondFx(t)
	lease := f.lease()
	newer := lease
	newer.Term++
	c := f.command(0, "a", "")
	c.Lease = &newer
	if _, err := f.send(model.NewID(), c); err != nil {
		t.Fatalf("a newer-term lease: %v", err)
	}
	if r := f.record(); r.Fence == nil || r.Fence.Term != newer.Term {
		t.Fatalf("the accepted lease was not recorded: %+v", r.Fence)
	}
	stale := f.command(1, "b", "")
	stale.Lease = &lease
	_, err := f.send(model.NewID(), stale)
	if code(err) != model.Stale || faultDetail(err) != "condition_lease_stale" {
		t.Fatalf("a deposed leader's lease committed: %v", err)
	}
	// Same term, older membership revision, is stale too.
	older := newer
	if older.Revision > 0 {
		older.Revision--
		c = f.command(1, "b", "")
		c.Lease = &older
		if _, err = f.send(model.NewID(), c); code(err) != model.Stale {
			t.Fatalf("an older membership revision committed: %v", err)
		}
	}
	// The lease of another group, a zero term and a missing lease are invalid.
	foreign := newer
	foreign.Group = model.ID{0xee}
	zero := newer
	zero.Term = 0
	for name, l := range map[string]*replica.FenceToken{"foreign": &foreign, "zero term": &zero, "missing": nil} {
		c = f.command(1, "b", "")
		c.Lease = l
		if _, err = f.send(model.NewID(), c); code(err) != model.Invalid {
			t.Errorf("%s lease: %v", name, err)
		}
	}
	if r := f.record(); r.Version != 1 || !strings.Contains(string(r.State), `"tag":"a"`) {
		t.Fatalf("a rejected command changed the record: %+v", r)
	}
	// The same or a newer lease still commits.
	c = f.command(1, "b", "")
	c.Lease = &newer
	if _, err = f.send(model.NewID(), c); err != nil {
		t.Fatalf("the accepted lease itself: %v", err)
	}
}

func TestConditionApplyActorAndAuditAreSafe(t *testing.T) {
	f := newCondFx(t)
	id := model.NewID()
	if _, err := f.send(id, f.command(0, "SECRET-EVIDENCE-TEXT", "firing")); err != nil {
		t.Fatal(err)
	}
	a := f.audits("conditions.firing")
	if len(a) != 1 || a[0].Principal != f.user || a[0].ID != id || len(a[0].Targets) != 1 || a[0].Targets[0] != f.cond || a[0].Outcome != model.AuditAllowed {
		t.Fatalf("audit %+v", a)
	}
	if raw, _ := json.Marshal(a[0]); strings.Contains(string(raw), "SECRET") {
		t.Fatalf("audit holds state content: %s", raw)
	}
	// A freshness-only change (no lifecycle change) is not audited.
	if _, err := f.send(model.NewID(), f.command(1, "b", "")); err != nil {
		t.Fatal(err)
	}
	total := 0
	if err := f.store.View(f.ctx, func(st control.State) error {
		for _, a := range st.Audits {
			if strings.HasPrefix(a.Action, "conditions.") {
				total++
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Fatalf("%d condition audits after a change that named no lifecycle phase", total)
	}
}

func TestConditionApplyScopeBeforeLookup(t *testing.T) {
	f := newCondFx(t)
	if _, err := f.send(model.NewID(), f.command(0, "a", "")); err != nil {
		t.Fatal(err)
	}
	wrong := f.command(1, "b", "")
	wrong.Project = model.NewID()
	_, errWrongScope := f.send(model.NewID(), wrong)
	missing := f.command(1, "b", "")
	missing.Condition = model.ID{0xc9}
	missing.State = condState(f.org, f.project, missing.Condition, 2, "b")
	missing.Digest = digest(missing.State)
	_, errMissing := f.send(model.NewID(), missing)
	if code(errWrongScope) != model.NotFound || code(errMissing) != model.NotFound || errWrongScope.Error() != errMissing.Error() {
		t.Fatalf("wrong scope %v vs missing %v", errWrongScope, errMissing)
	}
	read, err := f.readScope(f.project)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(f.command(1, "b", ""))
	_, err = f.store.Transact(f.ctx, read, control.Command{CommandID: model.NewID(), ExpectedRevision: f.revision(), Kind: string(control.KindApplyCondition), Payload: raw})
	if code(err) != model.Forbidden {
		t.Fatalf("read-only scope applied a condition: %v", err)
	}
	if _, _, err = f.store.Condition(f.ctx, read, model.NewID(), f.cond); code(err) != model.NotFound {
		t.Fatalf("read of a project outside the scope: %v", err)
	}
	if _, err = f.store.Conditions(f.ctx, read, model.NewID()); code(err) != model.NotFound {
		t.Fatalf("list of a project outside the scope: %v", err)
	}
}

func TestConditionApplyRejectsMalformedCommands(t *testing.T) {
	f := newCondFx(t)
	if _, err := f.send(model.NewID(), f.command(0, "a", "firing")); err != nil {
		t.Fatal(err)
	}
	withState := func(c *control.ConditionCommand, org, cond model.ID, version uint64) {
		c.State = condState(org, f.project, cond, version, "z")
		c.Digest = digest(c.State)
	}
	cases := map[string]func(c *control.ConditionCommand){
		"digest":          func(c *control.ConditionCommand) { c.Digest = model.Hash{1} },
		"skipped version": func(c *control.ConditionCommand) { withState(c, f.org, f.cond, 3); c.NewVersion = 3 },
		"header version":  func(c *control.ConditionCommand) { withState(c, f.org, f.cond, 5) },
		"header org":      func(c *control.ConditionCommand) { withState(c, model.ID{9}, f.cond, 2) },
		"header cond":     func(c *control.ConditionCommand) { withState(c, f.org, model.ID{9}, 2) },
		"change token":    func(c *control.ConditionCommand) { c.Change = "Firing Now" },
		"zero time":       func(c *control.ConditionCommand) { c.At = 0 },
		"empty state":     func(c *control.ConditionCommand) { c.State = nil },
		"oversize state": func(c *control.ConditionCommand) {
			c.State = json.RawMessage(`{"condition_id":"` + f.cond.String() + `","pad":"` + strings.Repeat("x", 64<<10) + `"}`)
			c.Digest = digest(c.State)
		},
	}
	names := make([]string, 0, len(cases))
	for n := range cases {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		c := f.command(1, "b", "")
		cases[name](&c)
		if _, err := f.send(model.NewID(), c); code(err) != model.Invalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	if r := f.record(); r.Version != 1 {
		t.Fatalf("a rejected command changed the record: %+v", r)
	}
	unknown := control.Command{CommandID: model.NewID(), ExpectedRevision: f.revision(), Kind: string(control.KindApplyCondition), Payload: json.RawMessage(`{"project":"` + f.project.String() + `","surprise":1}`)}
	if _, err := f.store.Transact(f.ctx, f.adminScope(), unknown); code(err) != model.Invalid {
		t.Fatalf("unknown payload field: %v", err)
	}
	// A payload that names no condition at all (the zero ID is not even
	// representable on the wire) is invalid, after the scope check.
	var fields map[string]json.RawMessage
	raw, _ := json.Marshal(f.command(1, "b", ""))
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "condition")
	raw, _ = json.Marshal(fields)
	anon := control.Command{CommandID: model.NewID(), ExpectedRevision: f.revision(), Kind: string(control.KindApplyCondition), Payload: raw}
	if _, err := f.store.Transact(f.ctx, f.adminScope(), anon); code(err) != model.Invalid {
		t.Fatalf("a payload without a condition: %v", err)
	}
}

func TestConditionsListInIDOrder(t *testing.T) {
	f := newCondFx(t)
	for _, seed := range []byte{0xc5, 0xc3, 0xc4} {
		f.cond = model.ID{seed}
		if _, err := f.send(model.NewID(), f.command(0, "a", "")); err != nil {
			t.Fatal(err)
		}
	}
	got, err := f.store.Conditions(f.ctx, f.adminScope(), f.project)
	if err != nil || len(got) != 3 || got[0].ID[0] != 0xc3 || got[1].ID[0] != 0xc4 || got[2].ID[0] != 0xc5 {
		t.Fatalf("list %+v %v", got, err)
	}
	if none, err := f.store.Conditions(f.ctx, f.adminScope(), f.otherProject); err != nil || len(none) != 0 {
		t.Fatalf("another project's list: %+v %v", none, err)
	}
}

// The per-project record count is bounded; the bound is a visible quota error,
// never a silent eviction of a settled condition's history. The state is seeded
// directly (one control transition per record would take minutes); the records
// of another project do not count.
func TestConditionApplyBoundsRecordsPerProject(t *testing.T) {
	f := newCondFx(t)
	seed := func(project model.ID, n int) {
		if err := f.store.Update(f.ctx, func(st *control.State) error {
			if st.ConditionBooks == nil {
				st.ConditionBooks = map[string]json.RawMessage{}
			}
			for i := range n {
				var id model.ID
				id[0], id[1], id[2] = 0xd0, byte(i>>8), byte(i)
				raw, err := json.Marshal(control.ConditionRecord{Org: f.org, Project: project, ID: id, Version: 1, State: condState(f.org, project, id, 1, "seed")})
				if err != nil {
					return err
				}
				st.ConditionBooks[f.org.String()+":"+project.String()+":"+id.String()] = raw
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	seed(f.otherProject, 3)
	seed(f.project, control.MaxConditionsPerProject-1)
	lease := f.lease()
	send := func(version uint64, id model.ID) error {
		state := condState(f.org, f.project, id, version, "a")
		c := control.ConditionCommand{Project: f.project, Condition: id, Lease: &lease, ExpectedVersion: model.Revision(version - 1), NewVersion: model.Revision(version), At: 100, State: state, Digest: digest(state)}
		_, err := f.send(model.NewID(), c)
		return err
	}
	if err := send(1, model.ID{0xe1}); err != nil {
		t.Fatalf("the last record under the bound: %v", err)
	}
	if err := send(1, model.ID{0xe2}); code(err) != model.Quota {
		t.Fatalf("record past the bound: %v", err)
	}
	// An existing record is still updatable at the bound.
	if err := send(2, model.ID{0xe1}); err != nil {
		t.Fatalf("update at the bound: %v", err)
	}
}

func (f *condFx) semantic() string {
	f.t.Helper()
	var out string
	if err := f.store.View(f.ctx, func(st control.State) error { out = condSemantic(f.t, st, f.org, f.project); return nil }); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// condSemantic is the committed condition facts with the per-run IDs normalized,
// so two independent stores can be compared.
func condSemantic(t *testing.T, st control.State, org, project model.ID) string {
	t.Helper()
	var recs []control.ConditionRecord
	for _, raw := range st.ConditionBooks {
		var r control.ConditionRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		r.Digest = model.Hash{}
		r.Org, r.Project = model.ID{1}, model.ID{2}
		r.Fence = nil
		r.State = json.RawMessage(strings.NewReplacer(org.String(), "ORG", project.String(), "PROJECT").Replace(string(r.State)))
		recs = append(recs, r)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].ID.String() < recs[j].ID.String() })
	raw, err := json.Marshal(recs)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestConditionApplyDeterministicUnderReorderedRetries(t *testing.T) {
	type step struct {
		id       model.ID
		expected uint64
		tag      string
	}
	steps := []step{{model.ID{1}, 0, "a"}, {model.ID{2}, 1, "b"}, {model.ID{3}, 2, "c"}}
	run := func(order []int) string {
		f := newCondFx(t)
		for _, i := range order {
			s := steps[i]
			if _, err := f.send(s.id, f.command(s.expected, s.tag, "firing")); err != nil && code(err) != model.Conflict && code(err) != model.NotFound {
				t.Fatal(err)
			}
		}
		return f.semantic()
	}
	ordered := run([]int{0, 1, 2})
	reordered := run([]int{0, 2, 1, 0, 2, 1, 0, 2, 2})
	if ordered != reordered || !strings.Contains(ordered, `"tag":"c"`) {
		t.Fatalf("state depends on retry order:\n%s\n%s", ordered, reordered)
	}
}

// Condition state and command results survive a control snapshot import and a
// restart; a restarted store still answers the committed command once.
func TestConditionApplySurvivesRestartAndSnapshotImport(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	now := time.Unix(1_800_000_000, 0)
	open := func() (*control.Store, *auth.Service) {
		store, err := control.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		svc, err := auth.NewService(auth.AuthDependencies{Control: store, Now: func() time.Time { return now }})
		if err != nil {
			store.Close()
			t.Fatal(err)
		}
		if err = store.EnableSingle(ctx, filepath.Join(dir, "raft-control")); err != nil {
			store.Close()
			t.Fatal(err)
		}
		if err = store.BindConditionApply(); err != nil {
			store.Close()
			t.Fatal(err)
		}
		return store, svc
	}
	store, svc := open()
	boot, _ := store.BootstrapToken()
	session, err := svc.Bootstrap(ctx, boot, "owner@example.test", "a long test password 2026")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := svc.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	org, project, cond := model.NewID(), model.NewID(), model.ID{0xc1}
	admin := func(kind string, p auth.AdminPayload) {
		var revision model.Revision
		_ = store.View(ctx, func(st control.State) error { revision = st.Revision; return nil })
		raw, _ := json.Marshal(p)
		if _, err := svc.AdminCommand(ctx, cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); err != nil {
			t.Fatal(kind, err)
		}
	}
	admin("create_org", auth.AdminPayload{Name: "restart", Reason: "fixture"})
	admin("create_project", auth.AdminPayload{ID: project, Name: "p1", Reason: "fixture"})
	send := func(store *control.Store, svc *auth.Service, cred auth.Credential, id model.ID, c control.ConditionCommand) (control.Result, error) {
		scope, err := svc.Authorize(ctx, cred, org, nil, auth.OrgAdmin)
		if err != nil {
			t.Fatal(err)
		}
		var revision model.Revision
		_ = store.View(ctx, func(st control.State) error { revision = st.Revision; return nil })
		raw, _ := json.Marshal(c)
		return store.Transact(ctx, scope, control.Command{CommandID: id, ExpectedRevision: revision, Kind: string(control.KindApplyCondition), Payload: raw})
	}
	mk := func(store *control.Store, expected uint64, tag string) control.ConditionCommand {
		lease, err := store.ReplicaGroup().Fence(ctx)
		if err != nil {
			t.Fatal(err)
		}
		state := condState(org, project, cond, expected+1, tag)
		return control.ConditionCommand{Project: project, Condition: cond, Lease: &lease, ExpectedVersion: model.Revision(expected), NewVersion: model.Revision(expected + 1), At: 100, Change: "firing", State: state, Digest: digest(state)}
	}
	id1 := model.NewID()
	first, err := send(store, svc, cred, id1, mk(store, 0, "a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = send(store, svc, cred, model.NewID(), mk(store, 1, "b")); err != nil {
		t.Fatal(err)
	}
	var before string
	if err = store.View(ctx, func(st control.State) error { before = condSemantic(t, st, org, project); return nil }); err != nil {
		t.Fatal(err)
	}
	seed, _, err := store.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	imported, err := control.OpenSeed(filepath.Join(t.TempDir(), "imported"), seed)
	if err != nil {
		t.Fatal(err)
	}
	var restored string
	if err = imported.View(ctx, func(st control.State) error { restored = condSemantic(t, st, org, project); return nil }); err != nil {
		t.Fatal(err)
	}
	imported.Close()
	if restored != before || !strings.Contains(before, `"tag":"b"`) {
		t.Fatalf("snapshot import changed the condition state:\n%s\n%s", before, restored)
	}
	// The fence is part of the snapshot too: the importing store knows the lease.
	var fenced bool
	imported2, err := control.OpenSeed(filepath.Join(t.TempDir(), "imported2"), seed)
	if err != nil {
		t.Fatal(err)
	}
	_ = imported2.View(ctx, func(st control.State) error {
		for _, raw := range st.ConditionBooks {
			var r control.ConditionRecord
			fenced = json.Unmarshal(raw, &r) == nil && r.Fence != nil && r.Fence.Term > 0
		}
		return nil
	})
	imported2.Close()
	if !fenced {
		t.Fatal("snapshot import lost the condition fence")
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, svc = open()
	defer store.Close()
	if cred, err = svc.Authenticate(ctx, session.Token); err != nil {
		t.Fatal(err)
	}
	var after string
	if err = store.View(ctx, func(st control.State) error { after = condSemantic(t, st, org, project); return nil }); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("restart changed the condition state:\n%s\n%s", before, after)
	}
	again, err := send(store, svc, cred, id1, mk(store, 0, "a"))
	if err != nil || again.Revision != first.Revision {
		t.Fatalf("committed command not recognized after restart: %+v vs %+v (%v)", again, first, err)
	}
	if _, err = send(store, svc, cred, model.NewID(), mk(store, 1, "late")); code(err) != model.Conflict {
		t.Fatalf("a stale expected version committed after restart: %v", err)
	}
}
