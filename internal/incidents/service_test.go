// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package incidents_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/incidents"
	"soundpost/internal/model"
)

type fixedClock struct{}

func (fixedClock) Now() model.UnixNano { return model.UnixNano(1_800_000_000 * int64(time.Second)) }

// fx is a real in-process node: the real control store (activated single-voter
// Raft group, real auth) with two real authenticated human org-admin sessions.
type fx struct {
	t            *testing.T
	ctx          context.Context
	dir          string
	store        *control.Store
	auth         *auth.Service
	svc          *incidents.Service
	org, project model.ID
	a, b         session
	now          time.Time
}

type session struct {
	user  model.ID
	token string
	cred  auth.Credential
}

func newFx(t *testing.T) *fx {
	t.Helper()
	f := &fx{t: t, ctx: context.Background(), dir: t.TempDir(), now: time.Unix(1_800_000_000, 0), org: model.NewID(), project: model.NewID()}
	f.open()
	t.Cleanup(func() { f.store.Close() })
	boot, _ := f.store.BootstrapToken()
	first, err := f.auth.Bootstrap(f.ctx, boot, "a@example.test", "a long test password 2026")
	if err != nil {
		t.Fatal(err)
	}
	f.a = session{user: first.User, token: first.Token}
	f.a.cred = f.credential(f.a.token)
	f.admin("create_org", f.org, auth.AdminPayload{Name: "incidents", Reason: "fixture"})
	f.admin("create_project", f.org, auth.AdminPayload{ID: f.project, Name: "p1", Reason: "fixture"})
	second := model.NewID()
	f.admin("create_user", f.org, auth.AdminPayload{ID: second, Email: "b@example.test", Password: "another long test password 2026", Reason: "fixture"})
	f.admin("org_admin", f.org, auth.AdminPayload{UserID: second, Enabled: true, Reason: "fixture"})
	login, err := f.auth.Login(f.ctx, "b@example.test", "another long test password 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	f.b = session{user: second, token: login.Token}
	f.b.cred = f.credential(f.b.token)
	return f
}

func (f *fx) open() {
	f.t.Helper()
	var err error
	if f.store, err = control.Open(f.dir); err != nil {
		f.t.Fatal(err)
	}
	if f.auth, err = auth.NewService(auth.AuthDependencies{Control: f.store, Now: func() time.Time { return f.now }}); err != nil {
		f.t.Fatal(err)
	}
	if err = f.store.EnableSingle(f.ctx, filepath.Join(f.dir, "raft-control")); err != nil {
		f.t.Fatal(err)
	}
	if err = f.store.BindIncidentAction(); err != nil {
		f.t.Fatal(err)
	}
	if f.svc, err = incidents.New(f.store, fixedClock{}); err != nil {
		f.t.Fatal(err)
	}
}

// restart closes the node and reopens it from disk; both sessions survive.
func (f *fx) restart() {
	f.t.Helper()
	if err := f.store.Close(); err != nil {
		f.t.Fatal(err)
	}
	f.open()
	f.a.cred, f.b.cred = f.credential(f.a.token), f.credential(f.b.token)
}

func (f *fx) credential(token string) auth.Credential {
	f.t.Helper()
	c, err := f.auth.Authenticate(f.ctx, token)
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

func (f *fx) admin(kind string, org model.ID, p auth.AdminPayload) {
	f.t.Helper()
	var revision model.Revision
	_ = f.store.View(f.ctx, func(st control.State) error { revision = st.Revision; return nil })
	raw, _ := json.Marshal(p)
	if _, err := f.auth.AdminCommand(f.ctx, f.a.cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); err != nil {
		f.t.Fatal(kind, err)
	}
}

func (f *fx) scope(s session) auth.Scope {
	f.t.Helper()
	sc, err := f.auth.Authorize(f.ctx, s.cred, f.org, nil, auth.OrgAdmin)
	if err != nil {
		f.t.Fatal(err)
	}
	return sc
}

func (f *fx) target(id model.ID) incidents.Target {
	return incidents.Target{Org: f.org, Project: f.project, Incident: id}
}

func (f *fx) act(s session, a incidents.Action) (incidents.State, error) {
	return f.svc.Act(f.ctx, f.scope(s), a, model.UnixNano(f.now.UnixNano()))
}

func (f *fx) mustAct(s session, a incidents.Action) incidents.State {
	f.t.Helper()
	st, err := f.act(s, a)
	if err != nil {
		f.t.Fatalf("%s: %v", a.Type, err)
	}
	return st
}

func (f *fx) openIncident(id model.ID) incidents.State {
	f.t.Helper()
	return f.mustAct(f.a, incidents.Action{CommandID: model.NewID(), Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Target: f.target(id), Impact: impact(ep1, incidents.SeverityMajor, incidents.ConditionFiring, incidents.FreshnessFresh)})
}

func (f *fx) human(s session, id model.ID, ver model.Revision, typ incidents.Type, reason string) incidents.Action {
	return incidents.Action{CommandID: model.NewID(), ExpectedVersion: ver, Type: typ, Origin: incidents.OriginHuman, Target: f.target(id), Reason: reason}
}

func (f *fx) worse(id model.ID, ver model.Revision) incidents.Action {
	return incidents.Action{CommandID: model.NewID(), ExpectedVersion: ver, Type: incidents.TypeImpact, Origin: incidents.OriginSystem, Target: f.target(id), Impact: impact(ep1, incidents.SeverityCritical, incidents.ConditionFiring, incidents.FreshnessFresh)}
}

func (f *fx) record(id model.ID) control.IncidentRecord {
	f.t.Helper()
	r, ok, err := f.store.Incident(f.ctx, f.scope(f.a), f.project, id)
	if err != nil || !ok {
		f.t.Fatalf("record %v %v", ok, err)
	}
	return r
}

func (f *fx) get(id model.ID) incidents.State {
	f.t.Helper()
	s, err := f.svc.Get(f.ctx, f.scope(f.a), f.project, id)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

// buildToVersion4 opens an incident and brings it to version 4 (open, ack,
// assign, link) with an ACK in place.
func (f *fx) buildToVersion4(id model.ID) incidents.State {
	f.t.Helper()
	f.openIncident(id)
	f.mustAct(f.a, f.human(f.a, id, 1, incidents.TypeAck, ""))
	as := f.human(f.b, id, 2, incidents.TypeAssign, "")
	as.Owner = &f.b.user
	f.mustAct(f.b, as)
	link := incidents.Action{CommandID: model.NewID(), ExpectedVersion: 3, Type: incidents.TypeLink, Origin: incidents.OriginSystem, Target: f.target(id), Link: &incidents.Link{Kind: incidents.LinkService, ID: model.ID{0x71}}}
	st := f.mustAct(f.a, link)
	if st.Version != 4 {
		f.t.Fatalf("version %d", st.Version)
	}
	return st
}

// current returns the post-restart copy of a session.
func (f *fx) current(s session) session {
	if s.user == f.a.user {
		return f.a
	}
	return f.b
}

func TestIncidentServiceActorScopeAndAudit(t *testing.T) {
	f := newFx(t)
	id := model.ID{0x31}
	// A forged actor and organization in the body are overwritten by the session.
	forged := incidents.Action{CommandID: model.NewID(), Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Actor: model.ID{0xee}, Target: incidents.Target{Org: model.ID{0xdd}, Project: f.project, Incident: id},
		Impact: impact(ep1, incidents.SeverityMajor, incidents.ConditionFiring, incidents.FreshnessFresh)}
	opened := f.mustAct(f.a, forged)
	if opened.Org != f.org || opened.Timeline[0].Action.Actor != f.a.user {
		t.Fatalf("body fields were trusted: %+v", opened.Timeline[0].Action)
	}
	ack := f.human(f.b, id, 1, incidents.TypeAck, "")
	ack.Actor = f.a.user // impersonation attempt
	acked := f.mustAct(f.b, ack)
	if acked.Ack == nil || acked.Ack.Actor != f.b.user {
		t.Fatalf("ack actor %+v", acked.Ack)
	}

	// Wrong scope and a missing incident are indistinguishable.
	wrongProject := f.human(f.a, id, 2, incidents.TypeAssign, "")
	wrongProject.Target.Project = model.NewID()
	wrongProject.Owner = &f.b.user
	missing := f.human(f.a, model.ID{0x32}, 2, incidents.TypeAssign, "")
	missing.Owner = &f.b.user
	_, e1 := f.act(f.a, wrongProject)
	_, e2 := f.act(f.a, missing)
	var f1, f2 *model.Fault
	if !errors.As(e1, &f1) || !errors.As(e2, &f2) || f1.Code != model.NotFound || f1.Code != f2.Code || f1.SafeDetail != f2.SafeDetail || e1.Error() != e2.Error() {
		t.Fatalf("wrong scope %v vs missing %v", e1, e2)
	}
	if _, err := f.svc.Get(f.ctx, f.scope(f.a), model.NewID(), id); !errors.As(err, &f1) || f1.Code != model.NotFound {
		t.Fatalf("get outside scope: %v", err)
	}

	// Another command's ID cannot be replayed by another principal.
	if _, err := f.act(f.b, incidents.Action{CommandID: forged.CommandID, Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Target: f.target(id), Impact: forged.Impact}); !errors.As(err, &f1) || f1.Code != model.NotFound {
		t.Fatalf("another principal's command ID: %v", err)
	}

	// A read-only grant cannot act, and is refused before any lookup.
	f.admin("create_user", f.org, auth.AdminPayload{ID: model.ID{0x61}, Email: "r@example.test", Password: "a reader test password 2026", Reason: "fixture"})
	f.admin("membership", f.org, auth.AdminPayload{UserID: model.ID{0x61}, Enabled: true, Reason: "fixture"})
	f.admin("grant", f.org, auth.AdminPayload{UserID: model.ID{0x61}, ProjectID: f.project, Enabled: true, Permissions: []string{string(auth.Read)}, Reason: "fixture"})
	login, err := f.auth.Login(f.ctx, "r@example.test", "a reader test password 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := f.auth.Authorize(f.ctx, f.credential(login.Token), f.org, []model.ID{f.project}, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []model.ID{id, model.ID{0x32}} {
		a := f.human(f.a, target, 2, incidents.TypeResolve, "nope")
		if _, err = f.svc.Act(f.ctx, reader, a, 1); !errors.As(err, &f1) || f1.Code != model.Forbidden {
			t.Fatalf("read grant acted on %x: %v", target[0], err)
		}
	}

	// Audit holds safe identifiers: principal, action, incident ID; never the
	// human reason or the state.
	secret := "SECRET-EVIDENCE-TEXT"
	f.mustAct(f.a, f.human(f.a, id, 2, incidents.TypeResolve, secret))
	var audits []model.ControlAudit
	_ = f.store.View(f.ctx, func(st control.State) error { audits = append(audits, st.Audits...); return nil })
	seen := map[string]model.ID{}
	for _, a := range audits {
		raw, _ := json.Marshal(a)
		if strings.Contains(string(raw), secret) {
			t.Fatalf("audit holds the reason text: %s", raw)
		}
		if strings.HasPrefix(a.Action, "incidents.") {
			if len(a.Targets) != 1 || a.Targets[0] != id || a.Org != f.org.String() {
				t.Fatalf("audit %+v", a)
			}
			seen[a.Action] = a.Principal
		}
	}
	if seen["incidents.open"] != f.a.user || seen["incidents.ack"] != f.b.user || seen["incidents.resolve"] != f.a.user || len(seen) != 3 {
		t.Fatalf("audited principals %+v", seen)
	}
}

func TestIncidentServiceRetryReturnsOriginalState(t *testing.T) {
	f := newFx(t)
	id := model.ID{0x41}
	f.openIncident(id)
	ack := f.human(f.a, id, 1, incidents.TypeAck, "")
	first := f.mustAct(f.a, ack)
	f.mustAct(f.b, f.worse(id, 2))
	recordBefore := f.record(id)
	again, err := f.svc.Act(f.ctx, f.scope(f.a), ack, 12345) // a later retry with a different clock
	if err != nil || !reflect.DeepEqual(again, first) || again.Version != 2 {
		t.Fatalf("retry: %+v %v", again, err)
	}
	if after := f.record(id); after.Version != recordBefore.Version || len(after.Intents) != len(recordBefore.Intents) {
		t.Fatal("retry changed the committed record")
	}
	f.restart()
	again, err = f.svc.Act(f.ctx, f.scope(f.a), ack, 99)
	if err != nil || !reflect.DeepEqual(again, first) {
		t.Fatalf("retry after restart: %+v %v", again, err)
	}
}

// A resolve and a worse impact that both expect version 4: exactly one commits,
// the other gets the current version, and nothing retries it as another human
// action. ACK never suppresses the worse-impact intent.
func TestIncidentConcurrentResolveImpact(t *testing.T) {
	f := newFx(t)
	for i := range 12 {
		id := model.ID{0x50, byte(i)}
		f.buildToVersion4(id)
		resolve := f.human(f.a, id, 4, incidents.TypeResolve, "rolled back")
		worse := f.worse(id, 4)
		var wg sync.WaitGroup
		var errResolve, errWorse error
		wg.Add(2)
		go func() { defer wg.Done(); _, errResolve = f.act(f.a, resolve) }()
		go func() { defer wg.Done(); _, errWorse = f.act(f.b, worse) }()
		wg.Wait()
		if (errResolve == nil) == (errWorse == nil) {
			t.Fatalf("round %d: exactly one must commit: resolve=%v impact=%v", i, errResolve, errWorse)
		}
		loserErr, loser, winner := errResolve, resolve.CommandID, worse.CommandID
		if errResolve == nil {
			loserErr, loser, winner = errWorse, worse.CommandID, resolve.CommandID
		}
		if current, ok := incidents.IsVersionConflict(loserErr); !ok || current != 5 {
			t.Fatalf("round %d: the loser must conflict with current version 5: %v", i, loserErr)
		}
		s := f.get(id)
		if s.Version != 5 || len(s.Timeline) != 5 {
			t.Fatalf("round %d: %+v", i, s)
		}
		if _, ok := s.Applied(loser); ok {
			t.Fatalf("round %d: the loser was retried and committed", i)
		}
		if v, ok := s.Applied(winner); !ok || v != 5 {
			t.Fatalf("round %d: winner at %d", i, v)
		}
		if errResolve == nil {
			if s.Status != incidents.StatusResolved || s.Condition.State != incidents.ConditionFiring || s.ImpactRevision != 1 {
				t.Fatalf("round %d: resolve won: %+v", i, s)
			}
		} else {
			intents := f.record(id).Intents
			last := intents[len(intents)-1]
			if s.Status != incidents.StatusOpen || s.ImpactRevision != 2 || s.AckCurrent() || last.Kind != "notify_impact" || !last.Eligible || last.ImpactRevision != 2 || last.Version != 5 {
				t.Fatalf("round %d: impact won over an ack: %+v last intent %+v", i, s, last)
			}
		}
		// The loser's author decides again against the current version.
		if errResolve != nil {
			redo := f.human(f.a, id, 5, incidents.TypeResolve, "rolled back")
			if st := f.mustAct(f.a, redo); st.Version != 6 || st.Status != incidents.StatusResolved {
				t.Fatalf("round %d: explicit re-decision %+v", i, st)
			}
		}
	}
}

// Two real authenticated sessions drive an incident concurrently through a real
// control machine and a restart.
func TestIncidentTwoSessionDurability(t *testing.T) {
	f := newFx(t)
	id := model.ID{0x60}
	f.openIncident(id)
	type op struct {
		name    string
		who     session
		action  incidents.Action
		applied bool
		err     error
	}
	assign := f.human(f.b, id, 0, incidents.TypeAssign, "")
	assign.Owner = &f.b.user
	ops := []*op{
		{name: "assign", who: f.a, action: assign},
		{name: "ack", who: f.b, action: f.human(f.b, id, 0, incidents.TypeAck, "")},
		{name: "resolve", who: f.a, action: f.human(f.a, id, 0, incidents.TypeResolve, "mitigated by session a")},
		{name: "impact", who: f.b, action: f.worse(id, 0)},
	}
	var wg sync.WaitGroup
	for _, o := range ops {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each author re-reads and decides again after a lost race; that
			// is the explicit re-decision of that same author, bounded.
			for range 40 {
				s, err := f.svc.Get(f.ctx, f.scope(o.who), f.project, id)
				if err != nil {
					o.err = err
					return
				}
				o.action.ExpectedVersion = s.Version
				_, o.err = f.svc.Act(f.ctx, f.scope(o.who), o.action, model.UnixNano(f.now.UnixNano()))
				if o.err == nil {
					o.applied = true
					return
				}
				if _, conflict := incidents.IsVersionConflict(o.err); !conflict {
					return
				}
			}
		}()
	}
	wg.Wait()
	byName := map[string]*op{}
	for _, o := range ops {
		byName[o.name] = o
	}
	if !byName["resolve"].applied || !byName["impact"].applied {
		t.Fatalf("resolve=%v impact=%v", byName["resolve"].err, byName["impact"].err)
	}
	for _, name := range []string{"assign", "ack"} {
		o := byName[name]
		if !o.applied {
			// Only the resolved incident may refuse a human action.
			var fl *model.Fault
			if !errors.As(o.err, &fl) || fl.Code != model.Conflict || fl.SafeDetail != "incident_resolved" {
				t.Fatalf("%s: %v", name, o.err)
			}
		}
	}

	// A system condition event keeps reporting the unresolved source after the
	// human resolution; restart in between.
	f.restart()
	s := f.get(id)
	if s.Status != incidents.StatusResolved {
		t.Fatalf("status %s", s.Status)
	}
	stale := incidents.Action{CommandID: model.NewID(), ExpectedVersion: s.Version, Type: incidents.TypeImpact, Origin: incidents.OriginSystem, Target: f.target(id), Impact: impact(ep1, incidents.SeverityCritical, incidents.ConditionFiring, incidents.FreshnessStale)}
	f.mustAct(f.a, stale)
	f.restart()
	final := f.get(id)
	if final.Status != incidents.StatusResolved || final.Condition.State != incidents.ConditionFiring || final.Condition.Freshness != incidents.FreshnessStale {
		t.Fatalf("unresolved source evidence lost: %+v", final)
	}

	// Serializable: the committed actions form one chain in which every action
	// expected exactly the version it was applied on, and the state is exactly
	// the replay of that chain; one result per command ID.
	replayed, err := incidents.Replay(final.Timeline)
	if err != nil || !reflect.DeepEqual(replayed, final) {
		t.Fatalf("state is not the replay of its timeline: %v", err)
	}
	ids := map[model.ID]bool{}
	for i, e := range final.Timeline {
		if e.Action.ExpectedVersion != model.Revision(i) || ids[e.Action.CommandID] {
			t.Fatalf("entry %d: %+v", i, e.Action)
		}
		ids[e.Action.CommandID] = true
	}
	committed := 2 // open and the late stale observation
	for _, o := range ops {
		if o.applied {
			committed++
			v, ok := final.Applied(o.action.CommandID)
			if !ok {
				t.Fatalf("%s reported success but is not in the timeline", o.name)
			}
			// Retrying with the other session's clock returns the original result.
			again, err := f.svc.Act(f.ctx, f.scope(f.current(o.who)), o.action, 1)
			past, _ := final.At(v)
			if err != nil || !reflect.DeepEqual(again, past) {
				t.Fatalf("%s retry: %v", o.name, err)
			}
		} else if _, ok := final.Applied(o.action.CommandID); ok {
			t.Fatalf("%s failed but is in the timeline", o.name)
		}
	}
	if len(final.Timeline) != committed {
		t.Fatalf("%d entries for %d committed actions", len(final.Timeline), committed)
	}
	rec := f.record(id)
	if rec.Version != final.Version {
		t.Fatalf("control version %d, state %d", rec.Version, final.Version)
	}
}

// hookControl lets a test commit another action between a command's commit and
// the service reading its result.
type hookControl struct {
	*control.Store
	after func()
}

func (h *hookControl) Transact(ctx context.Context, scope auth.Scope, cmd control.Command) (control.Result, error) {
	res, err := h.Store.Transact(ctx, scope, cmd)
	if err == nil && h.after != nil {
		fn := h.after
		h.after = nil
		fn()
	}
	return res, err
}

// A committed action answers with the incident as it stood at that action, even
// when another session committed right after it.
func TestIncidentActReturnsStateAtItsOwnVersion(t *testing.T) {
	f := newFx(t)
	id := model.ID{0x70}
	f.openIncident(id)
	hook := &hookControl{Store: f.store}
	svc, err := incidents.New(hook, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	hook.after = func() {
		as := f.human(f.b, id, 2, incidents.TypeAssign, "")
		as.Owner = &f.b.user
		f.mustAct(f.b, as)
	}
	got, err := svc.Act(f.ctx, f.scope(f.a), f.human(f.a, id, 1, incidents.TypeAck, ""), 7)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 2 || got.Owner != nil || got.Ack == nil || len(got.Timeline) != 2 {
		t.Fatalf("result is not the state at the command's own version: %+v", got)
	}
	if cur := f.get(id); cur.Version != 3 || cur.Owner == nil {
		t.Fatalf("the later action is lost: %+v", cur)
	}
}
