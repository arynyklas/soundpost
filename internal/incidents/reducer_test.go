// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package incidents_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"soundpost/internal/incidents"
	"soundpost/internal/model"
)

var (
	org, project, inc = model.ID{0x01}, model.ID{0x02}, model.ID{0x03}
	cond, ep1, ep2    = model.ID{0xc0}, model.ID{0xe1}, model.ID{0xe2}
	alice, bob, bot   = model.ID{0xa1}, model.ID{0xb1}, model.ID{0xd1}
)

const sec = model.UnixNano(time.Second)

// run applies actions in sequence, each expecting the current version, and
// fails the test on any error.
type run struct {
	t     *testing.T
	state incidents.State
	n     byte
	at    model.UnixNano
}

func newRun(t *testing.T) *run { return &run{t: t, at: 1000 * sec} }

func (r *run) cmd(typ incidents.Type, origin incidents.Origin, actor model.ID) incidents.Action {
	r.n++
	return incidents.Action{CommandID: model.ID{0xf0, r.n}, ExpectedVersion: r.state.Version, Type: typ, Origin: origin, Actor: actor, Target: incidents.Target{Org: org, Project: project, Incident: inc}}
}

func impact(ep model.ID, sev incidents.Severity, state incidents.ConditionState, fresh incidents.Freshness) *incidents.Impact {
	return &incidents.Impact{Condition: cond, Episode: ep, Severity: sev, State: state, Freshness: fresh}
}

func (r *run) do(a incidents.Action) []incidents.Effect {
	r.t.Helper()
	r.at += sec
	next, effects, err := incidents.Apply(r.state, a, r.at)
	if err != nil {
		r.t.Fatalf("%s: %v", a.Type, err)
	}
	r.state = next
	return effects
}

func (r *run) open(sev incidents.Severity) []incidents.Effect {
	a := r.cmd(incidents.TypeOpen, incidents.OriginSystem, bot)
	a.Impact = impact(ep1, sev, incidents.ConditionFiring, incidents.FreshnessFresh)
	return r.do(a)
}

func (r *run) human(typ incidents.Type, reason string) []incidents.Effect {
	a := r.cmd(typ, incidents.OriginHuman, alice)
	a.Reason = reason
	return r.do(a)
}

func (r *run) observe(i *incidents.Impact) []incidents.Effect {
	a := r.cmd(incidents.TypeImpact, incidents.OriginSystem, bot)
	a.Impact = i
	return r.do(a)
}

func kinds(effects []incidents.Effect) []incidents.EffectKind {
	var out []incidents.EffectKind
	for _, e := range effects {
		out = append(out, e.Kind)
	}
	return out
}

func find(effects []incidents.Effect, k incidents.EffectKind) *incidents.Effect {
	for i := range effects {
		if effects[i].Kind == k {
			return &effects[i]
		}
	}
	return nil
}

func code(err error) model.Code {
	if f, ok := err.(*model.Fault); ok {
		return f.Code
	}
	if _, ok := incidents.IsVersionConflict(err); ok {
		return model.Conflict
	}
	return ""
}

func TestIncidentHumanSourceSeparation(t *testing.T) {
	t.Run("ack keeps condition firing and incident open", func(t *testing.T) {
		r := newRun(t)
		opened := r.open(incidents.SeverityMajor)
		if e := find(opened, incidents.EffectNotifyOpen); e == nil || !e.Eligible || e.ImpactRevision != 1 {
			t.Fatalf("opening intent %+v", opened)
		}
		effects := r.human(incidents.TypeAck, "")
		s := r.state
		if s.Status != incidents.StatusOpen || s.Condition.State != incidents.ConditionFiring || s.Ack == nil || s.Ack.Actor != alice || s.Ack.ImpactRevision != 1 || s.Ack.At == 0 || s.Ack.Version != 2 {
			t.Fatalf("state after ack %+v", s)
		}
		if !reflect.DeepEqual(kinds(effects), []incidents.EffectKind{incidents.EffectAudit, incidents.EffectRemindersPause}) {
			t.Fatalf("ack effects %v", kinds(effects))
		}
		if !s.ReminderPaused(r.at) {
			t.Fatal("ack must pause reminders")
		}
	})
	t.Run("source recovery leaves the incident acknowledged and open", func(t *testing.T) {
		r := newRun(t)
		r.open(incidents.SeverityMajor)
		r.human(incidents.TypeAck, "")
		effects := r.observe(impact(ep1, incidents.SeverityMajor, incidents.ConditionRecovered, incidents.FreshnessFresh))
		s := r.state
		if s.Condition.State != incidents.ConditionRecovered || s.Status != incidents.StatusOpen || s.Ack == nil || s.Owner != nil {
			t.Fatalf("state after recovery %+v", s)
		}
		if find(effects, incidents.EffectNotifyImpact) != nil {
			t.Fatal("a recovery must not notify as worse impact")
		}
	})
	t.Run("human resolve needs a reason and leaves the alert firing", func(t *testing.T) {
		r := newRun(t)
		r.open(incidents.SeverityMajor)
		r.human(incidents.TypeAck, "")
		bad := r.cmd(incidents.TypeResolve, incidents.OriginHuman, alice)
		if _, _, err := incidents.Apply(r.state, bad, r.at+sec); code(err) != model.Invalid {
			t.Fatalf("resolve without reason: %v", err)
		}
		before := r.state.Version
		r.human(incidents.TypeResolve, "fixed by rollback")
		s := r.state
		if s.Status != incidents.StatusResolved || s.Condition.State != incidents.ConditionFiring || s.Condition.Freshness != incidents.FreshnessFresh || s.Ack == nil || s.Version != before+1 {
			t.Fatalf("state after resolve %+v", s)
		}
		// The still-firing source keeps reporting: the evidence persists and the
		// resolved human record is not reopened or rewritten.
		timeline := append([]incidents.Entry(nil), s.Timeline...)
		r.observe(impact(ep1, incidents.SeverityMajor, incidents.ConditionFiring, incidents.FreshnessStale))
		if r.state.Status != incidents.StatusResolved || r.state.Condition.Freshness != incidents.FreshnessStale || !reflect.DeepEqual(r.state.Timeline[:len(timeline)], timeline) {
			t.Fatalf("resolved record changed: %+v", r.state)
		}
	})
	t.Run("same command retry returns the original result", func(t *testing.T) {
		r := newRun(t)
		r.open(incidents.SeverityMajor)
		ack := r.cmd(incidents.TypeAck, incidents.OriginHuman, alice)
		r.do(ack)
		atAck := r.state
		a := r.cmd(incidents.TypeAssign, incidents.OriginHuman, alice)
		a.Owner = &bob
		r.do(a)
		r.observe(impact(ep1, incidents.SeverityCritical, incidents.ConditionFiring, incidents.FreshnessFresh))
		// The ack is retried long after: it answers with the state at the ack,
		// not the newer state, and produces no new effects.
		got, effects, err := incidents.Apply(r.state, ack, r.at+sec)
		if err != nil || len(effects) != 0 || !reflect.DeepEqual(got, atAck) || got.Version != 2 {
			t.Fatalf("retry: %+v %v %v", got, effects, err)
		}
		// The same ID with different content is a conflict, not a replay.
		other := ack
		other.Reason = "different"
		if _, _, err = incidents.Apply(r.state, other, r.at+sec); code(err) != model.Conflict {
			t.Fatalf("command ID reuse: %v", err)
		}
	})
	t.Run("two commands expecting the same version cannot both commit", func(t *testing.T) {
		r := newRun(t)
		r.open(incidents.SeverityMajor)
		r.human(incidents.TypeAck, "")
		a := r.cmd(incidents.TypeAssign, incidents.OriginHuman, alice)
		a.Owner = &bob
		r.do(a)
		s := r.cmd(incidents.TypeSnooze, incidents.OriginHuman, alice)
		s.Reason, s.Until = "known flake", r.at+model.UnixNano(time.Hour)
		r.do(s)
		if r.state.Version != 4 {
			t.Fatalf("version %d", r.state.Version)
		}
		resolve := r.cmd(incidents.TypeResolve, incidents.OriginHuman, alice)
		resolve.Reason = "done"
		worse := r.cmd(incidents.TypeImpact, incidents.OriginSystem, bot)
		worse.Impact = impact(ep1, incidents.SeverityCritical, incidents.ConditionFiring, incidents.FreshnessFresh)
		if resolve.ExpectedVersion != 4 || worse.ExpectedVersion != 4 {
			t.Fatal("both must expect version 4")
		}
		won, _, err := incidents.Apply(r.state, resolve, r.at+sec)
		if err != nil || won.Version != 5 {
			t.Fatalf("first: %v", err)
		}
		_, _, err = incidents.Apply(won, worse, r.at+2*sec)
		current, ok := incidents.IsVersionConflict(err)
		if !ok || current != 5 || code(err) != model.Conflict {
			t.Fatalf("second writer must conflict with the current version 5: %v", err)
		}
	})
	t.Run("later worse impact increments the revision despite ack", func(t *testing.T) {
		r := newRun(t)
		r.open(incidents.SeverityMajor)
		r.human(incidents.TypeAck, "")
		effects := r.observe(impact(ep1, incidents.SeverityCritical, incidents.ConditionFiring, incidents.FreshnessFresh))
		s := r.state
		e := find(effects, incidents.EffectNotifyImpact)
		if s.ImpactRevision != 2 || s.Ack == nil || s.Ack.ImpactRevision != 1 || s.AckCurrent() || e == nil || !e.Eligible || e.ImpactRevision != 2 {
			t.Fatalf("worse impact: state %+v effects %+v", s, effects)
		}
		if s.ReminderPaused(r.at) {
			t.Fatal("the old ack must not pause reminders for the new impact revision")
		}
		// Not worse: no new revision, no intent.
		again := r.observe(impact(ep1, incidents.SeverityMajor, incidents.ConditionFiring, incidents.FreshnessFresh))
		if r.state.ImpactRevision != 2 || find(again, incidents.EffectNotifyImpact) != nil {
			t.Fatalf("lower impact %+v", r.state)
		}
	})
}

func TestIncidentSnoozeAndMaintenanceAreDifferentScopes(t *testing.T) {
	r := newRun(t)
	r.open(incidents.SeverityMinor)
	snooze := r.cmd(incidents.TypeSnooze, incidents.OriginHuman, alice)
	snooze.Reason, snooze.Until = "planned noise", r.at+2*sec+model.UnixNano(time.Hour)
	effects := r.do(snooze)
	s := r.state
	if s.Snooze == nil || s.Maintenance != nil || !s.Snooze.Active(r.at) || s.Snooze.Reason != "planned noise" || s.Snooze.Actor != alice {
		t.Fatalf("snooze state %+v", s)
	}
	if e := find(effects, incidents.EffectRemindersPause); e == nil || e.Until != snooze.Until {
		t.Fatalf("snooze intent %+v", effects)
	}
	if !s.ReminderPaused(r.at) || s.ReminderPaused(snooze.Until) {
		t.Fatal("snooze must pause reminders only until it expires")
	}
	if _, _, err := incidents.Apply(s, withExpected(snooze, s.Version, 0xaa), r.at+sec); code(err) != model.Conflict {
		t.Fatalf("second snooze while active: %v", err)
	}
	// A snooze never suppresses a worse-impact notification.
	worse := r.observe(impact(ep1, incidents.SeverityMajor, incidents.ConditionFiring, incidents.FreshnessFresh))
	if e := find(worse, incidents.EffectNotifyImpact); e == nil || !e.Eligible {
		t.Fatalf("worse impact during snooze %+v", worse)
	}
	noReason := r.cmd(incidents.TypeUnsnooze, incidents.OriginHuman, alice)
	if _, _, err := incidents.Apply(r.state, noReason, r.at+sec); code(err) != model.Invalid {
		t.Fatalf("unsnooze without reason: %v", err)
	}
	if e := r.human(incidents.TypeUnsnooze, "done early"); find(e, incidents.EffectRemindersResume) == nil || r.state.Snooze.Ended == 0 || r.state.Snooze.Active(r.at) {
		t.Fatalf("unsnooze %+v", r.state.Snooze)
	}

	// Maintenance is a different scope with its own history and suppresses new
	// notification intents while recording them with the reason.
	maint := r.cmd(incidents.TypeMaintenance, incidents.OriginHuman, bob)
	maint.Reason, maint.Until = "database migration", r.at+2*sec+model.UnixNano(2*time.Hour)
	mEffects := r.do(maint)
	s = r.state
	if s.Maintenance == nil || !s.Maintenance.Active(r.at) || s.Snooze == nil || s.Snooze.Ended == 0 || s.Maintenance.Actor != bob || find(mEffects, incidents.EffectMaintBegin) == nil {
		t.Fatalf("maintenance state %+v", s)
	}
	during := r.observe(impact(ep1, incidents.SeverityCritical, incidents.ConditionFiring, incidents.FreshnessFresh))
	e := find(during, incidents.EffectNotifyImpact)
	if e == nil || e.Eligible || e.Code != "maintenance" || e.ImpactRevision != 3 || r.state.ImpactRevision != 3 {
		t.Fatalf("impact during maintenance %+v (state revision %d)", during, r.state.ImpactRevision)
	}
	r.human(incidents.TypeMaintenanceEnd, "migration finished")
	if r.state.Maintenance.Active(r.at) || r.state.Maintenance.Ended == 0 {
		t.Fatal("maintenance did not end explicitly")
	}
	// The incident and its failure display stay: nothing was suppressed in state.
	if r.state.Condition.State != incidents.ConditionFiring || r.state.Status != incidents.StatusOpen {
		t.Fatalf("maintenance changed the source or the status: %+v", r.state)
	}
	r.observe(impact(ep1, incidents.SeverityMinor, incidents.ConditionFiring, incidents.FreshnessFresh))
	after := r.observe(impact(ep1, incidents.SeverityCritical, incidents.ConditionFiring, incidents.FreshnessFresh))
	if e = find(after, incidents.EffectNotifyImpact); e == nil || !e.Eligible {
		t.Fatalf("notification after maintenance ended %+v", after)
	}
}

func withExpected(a incidents.Action, version model.Revision, id byte) incidents.Action {
	a.ExpectedVersion, a.CommandID = version, model.ID{0xf1, id}
	return a
}

func TestIncidentWindowLimits(t *testing.T) {
	at := 500 * sec
	open := func() incidents.State {
		a := incidents.Action{CommandID: model.ID{9}, Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Actor: bot, Target: incidents.Target{Org: org, Project: project, Incident: inc}, Impact: impact(ep1, incidents.SeverityMinor, incidents.ConditionFiring, incidents.FreshnessFresh)}
		s, _, err := incidents.Apply(incidents.State{}, a, at)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	for _, typ := range []incidents.Type{incidents.TypeSnooze, incidents.TypeMaintenance} {
		try := func(until, max model.UnixNano, reason string) error {
			a := incidents.Action{CommandID: model.ID{8}, ExpectedVersion: 1, Type: typ, Origin: incidents.OriginHuman, Actor: alice, Target: incidents.Target{Org: org, Project: project, Incident: inc}, Reason: reason, Until: until, MaxWindow: max}
			_, _, err := incidents.Apply(open(), a, at)
			return err
		}
		week := model.UnixNano(7 * 24 * time.Hour)
		if err := try(at+week, 0, "ok"); err != nil {
			t.Errorf("%s: exactly the 7-day default must be allowed: %v", typ, err)
		}
		for name, err := range map[string]error{
			"past 7 days":    try(at+week+1, 0, "ok"),
			"not in future":  try(at, 0, "ok"),
			"no reason":      try(at+sec, 0, ""),
			"custom limit":   try(at+2*model.UnixNano(time.Hour), model.UnixNano(time.Hour), "ok"),
			"unbounded":      try(at+400*24*3600*sec, 1<<62, "ok"),
			"control char":   try(at+sec, 0, "line\nbreak"),
			"over long":      try(at+sec, 0, strings.Repeat("x", incidents.MaxReasonBytes+1)),
			"negative limit": try(at+sec, -1, "ok"),
		} {
			if code(err) != model.Invalid {
				t.Errorf("%s %s: %v", typ, name, err)
			}
		}
		if err := try(at+model.UnixNano(time.Hour), model.UnixNano(time.Hour), "ok"); err != nil {
			t.Errorf("%s: exactly the custom limit must be allowed: %v", typ, err)
		}
	}
}

func TestIncidentSystemCannotChangeHumanState(t *testing.T) {
	r := newRun(t)
	r.open(incidents.SeverityMajor)
	for _, typ := range []incidents.Type{incidents.TypeAck, incidents.TypeResolve, incidents.TypeAssign, incidents.TypeSnooze, incidents.TypeUnsnooze, incidents.TypeMaintenance, incidents.TypeMaintenanceEnd} {
		a := r.cmd(typ, incidents.OriginSystem, bot)
		a.Reason = "system"
		if typ == incidents.TypeAssign {
			a.Owner = &bot
		}
		if typ == incidents.TypeSnooze || typ == incidents.TypeMaintenance {
			a.Until = r.at + 10*sec
		}
		if _, _, err := incidents.Apply(r.state, a, r.at+sec); code(err) != model.Forbidden {
			t.Errorf("system %s: %v", typ, err)
		}
	}
	human := r.cmd(incidents.TypeImpact, incidents.OriginHuman, alice)
	human.Impact = impact(ep1, incidents.SeverityCritical, incidents.ConditionFiring, incidents.FreshnessFresh)
	if _, _, err := incidents.Apply(r.state, human, r.at+sec); code(err) != model.Forbidden {
		t.Errorf("human-forged condition event: %v", err)
	}
	// Condition events flow through every state without touching owner or status.
	for _, i := range []*incidents.Impact{
		impact(ep1, incidents.SeverityCritical, incidents.ConditionFiring, incidents.FreshnessFresh),
		impact(ep1, incidents.SeverityCritical, incidents.ConditionUnknown, incidents.FreshnessStale),
		impact(ep1, incidents.SeverityCritical, incidents.ConditionRecovered, incidents.FreshnessFresh),
	} {
		r.observe(i)
		if r.state.Owner != nil || r.state.Status != incidents.StatusOpen || r.state.Ack != nil {
			t.Fatalf("a system event changed human state: %+v", r.state)
		}
	}
}

func TestIncidentUnknownIsNeverRecovered(t *testing.T) {
	r := newRun(t)
	r.open(incidents.SeverityMajor)
	for _, f := range []incidents.Freshness{incidents.FreshnessStale, incidents.FreshnessUnknown} {
		a := r.cmd(incidents.TypeImpact, incidents.OriginSystem, bot)
		a.Impact = impact(ep1, incidents.SeverityMajor, incidents.ConditionRecovered, f)
		if _, _, err := incidents.Apply(r.state, a, r.at+sec); code(err) != model.Invalid {
			t.Errorf("recovered from %s data accepted: %v", f, err)
		}
	}
	r.observe(impact(ep1, incidents.SeverityMajor, incidents.ConditionUnknown, incidents.FreshnessUnknown))
	if r.state.Condition.State != incidents.ConditionUnknown || r.state.Status != incidents.StatusOpen {
		t.Fatalf("%+v", r.state)
	}
	other := r.cmd(incidents.TypeImpact, incidents.OriginSystem, bot)
	other.Impact = impact(ep1, incidents.SeverityMajor, incidents.ConditionFiring, incidents.FreshnessFresh)
	other.Impact.Condition = model.ID{0xcc}
	if _, _, err := incidents.Apply(r.state, other, r.at+sec); code(err) != model.Invalid {
		t.Fatalf("another condition's event: %v", err)
	}
}

func TestIncidentResolvedTimelineNeverRewritten(t *testing.T) {
	r := newRun(t)
	r.open(incidents.SeverityMajor)
	r.human(incidents.TypeResolve, "mitigated")
	frozen := append([]incidents.Entry(nil), r.state.Timeline...)
	resolvedAt := r.state.ResolvedAt
	for name, i := range map[string]*incidents.Impact{
		"new episode":  impact(ep2, incidents.SeverityMajor, incidents.ConditionFiring, incidents.FreshnessFresh),
		"worse impact": impact(ep1, incidents.SeverityCritical, incidents.ConditionFiring, incidents.FreshnessFresh),
	} {
		rr := &run{t: t, state: r.state, n: 100, at: r.at}
		effects := rr.observe(i)
		e := find(effects, incidents.EffectOpenLinked)
		if e == nil || e.Subject == nil || *e.Subject != inc || !e.Eligible || find(effects, incidents.EffectNotifyImpact) != nil {
			t.Fatalf("%s: %+v", name, effects)
		}
		s := rr.state
		if s.Status != incidents.StatusResolved || s.ResolvedAt != resolvedAt || s.ImpactRevision != 1 || s.Episode != ep1 || !reflect.DeepEqual(s.Timeline[:len(frozen)], frozen) {
			t.Fatalf("%s rewrote the resolved incident: %+v", name, s)
		}
	}
	// A recovery after resolve is condition evidence only.
	if e := r.observe(impact(ep1, incidents.SeverityMajor, incidents.ConditionRecovered, incidents.FreshnessFresh)); find(e, incidents.EffectOpenLinked) != nil || r.state.Condition.State != incidents.ConditionRecovered {
		t.Fatalf("recovery after resolve %+v", e)
	}
	for _, a := range []incidents.Action{r.cmd(incidents.TypeAck, incidents.OriginHuman, alice), r.cmd(incidents.TypeAssign, incidents.OriginHuman, alice)} {
		a.Owner = &bob
		if a.Type == incidents.TypeAck {
			a.Owner = nil
		}
		if _, _, err := incidents.Apply(r.state, a, r.at+sec); code(err) != model.Conflict {
			t.Errorf("%s on a resolved incident: %v", a.Type, err)
		}
	}
	link := r.cmd(incidents.TypeLink, incidents.OriginHuman, alice)
	link.Link = &incidents.Link{Kind: incidents.LinkService, ID: model.ID{0x77}}
	if _, _, err := incidents.Apply(r.state, link, r.at+sec); code(err) != model.Conflict {
		t.Fatalf("link on a resolved incident: %v", err)
	}

	// The new episode becomes a new incident linked to the old one.
	n := &run{t: t, at: r.at}
	a := incidents.Action{CommandID: model.ID{0x55}, Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Actor: bot, Target: incidents.Target{Org: org, Project: project, Incident: model.ID{0x04}}, Previous: &inc,
		Impact: impact(ep2, incidents.SeverityMajor, incidents.ConditionFiring, incidents.FreshnessFresh)}
	n.do(a)
	if n.state.Previous == nil || *n.state.Previous != inc || n.state.Status != incidents.StatusOpen || !reflect.DeepEqual(n.state.Links[1], incidents.Link{Kind: incidents.LinkIncident, ID: inc}) || len(n.state.Timeline) != 1 {
		t.Fatalf("linked incident %+v", n.state)
	}
}

func TestIncidentActionValidation(t *testing.T) {
	r := newRun(t)
	ack := r.cmd(incidents.TypeAck, incidents.OriginHuman, alice)
	if _, _, err := incidents.Apply(incidents.State{}, ack, r.at); code(err) != model.NotFound {
		t.Fatalf("action on a missing incident: %v", err)
	}
	r.open(incidents.SeverityMinor)
	reopen := r.cmd(incidents.TypeOpen, incidents.OriginSystem, bot)
	reopen.ExpectedVersion = 0
	reopen.Impact = impact(ep1, incidents.SeverityMinor, incidents.ConditionFiring, incidents.FreshnessFresh)
	if _, ok := func() (model.Revision, bool) {
		_, _, err := incidents.Apply(r.state, reopen, r.at+sec)
		return incidents.IsVersionConflict(err)
	}(); !ok {
		t.Fatal("opening an existing incident must conflict")
	}
	wrong := r.cmd(incidents.TypeAck, incidents.OriginHuman, alice)
	wrong.Target.Project = model.ID{0x99}
	if _, _, err := incidents.Apply(r.state, wrong, r.at+sec); code(err) != model.NotFound {
		t.Fatalf("target mismatch: %v", err)
	}
	bad := map[string]incidents.Action{}
	mk := func(name string, typ incidents.Type, f func(*incidents.Action)) {
		a := r.cmd(typ, incidents.OriginHuman, alice)
		f(&a)
		bad[name] = a
	}
	mk("owner on ack", incidents.TypeAck, func(a *incidents.Action) { a.Owner = &bob })
	mk("until on resolve", incidents.TypeResolve, func(a *incidents.Action) { a.Reason, a.Until = "r", r.at+10*sec })
	mk("impact on ack", incidents.TypeAck, func(a *incidents.Action) {
		a.Impact = impact(ep1, 1, incidents.ConditionFiring, incidents.FreshnessFresh)
	})
	mk("zero actor", incidents.TypeAck, func(a *incidents.Action) { a.Actor = model.ID{} })
	mk("zero command", incidents.TypeAck, func(a *incidents.Action) { a.CommandID = model.ID{} })
	mk("unknown type", incidents.Type("delete"), func(a *incidents.Action) {})
	mk("self link", incidents.TypeLink, func(a *incidents.Action) { a.Link = &incidents.Link{Kind: incidents.LinkIncident, ID: inc} })
	mk("bad link kind", incidents.TypeLink, func(a *incidents.Action) { a.Link = &incidents.Link{Kind: "text", ID: bob} })
	mk("missing link", incidents.TypeLink, func(a *incidents.Action) {})
	for name, a := range bad {
		if _, _, err := incidents.Apply(r.state, a, r.at+sec); code(err) != model.Invalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, impactBad := range []*incidents.Impact{
		impact(ep1, 0, incidents.ConditionFiring, incidents.FreshnessFresh),
		impact(ep1, 4, incidents.ConditionFiring, incidents.FreshnessFresh),
		impact(ep1, 1, "healed", incidents.FreshnessFresh),
		impact(model.ID{}, 1, incidents.ConditionFiring, incidents.FreshnessFresh),
	} {
		a := r.cmd(incidents.TypeImpact, incidents.OriginSystem, bot)
		a.Impact = impactBad
		if _, _, err := incidents.Apply(r.state, a, r.at+sec); code(err) != model.Invalid {
			t.Errorf("impact %+v: %v", *impactBad, err)
		}
	}
	// Owner changes, duplicates and links.
	assign := r.cmd(incidents.TypeAssign, incidents.OriginHuman, alice)
	assign.Owner = &bob
	r.do(assign)
	same := r.cmd(incidents.TypeAssign, incidents.OriginHuman, alice)
	same.Owner = &bob
	if _, _, err := incidents.Apply(r.state, same, r.at+sec); code(err) != model.Conflict {
		t.Fatalf("assigning the current owner: %v", err)
	}
	r.human(incidents.TypeAssign, "") // unassign
	if r.state.Owner != nil {
		t.Fatal("unassign kept the owner")
	}
	link := r.cmd(incidents.TypeLink, incidents.OriginSystem, bot)
	link.Link = &incidents.Link{Kind: incidents.LinkRelease, ID: model.ID{0x88}}
	r.do(link)
	dup := r.cmd(incidents.TypeLink, incidents.OriginHuman, alice)
	dup.Link = link.Link
	if _, _, err := incidents.Apply(r.state, dup, r.at+sec); code(err) != model.Conflict {
		t.Fatalf("duplicate link: %v", err)
	}
	ack2 := r.cmd(incidents.TypeAck, incidents.OriginHuman, alice)
	r.do(ack2)
	if _, _, err := incidents.Apply(r.state, r.cmd(incidents.TypeAck, incidents.OriginHuman, bob), r.at+sec); code(err) != model.Conflict {
		t.Fatalf("second ack at the same impact revision: %v", err)
	}
}

func TestIncidentTimelineIsBounded(t *testing.T) {
	r := newRun(t)
	r.open(incidents.SeverityMinor)
	for i := 1; i < incidents.MaxTimeline; i++ {
		a := r.cmd(incidents.TypeAssign, incidents.OriginHuman, alice)
		if i%2 == 1 {
			a.Owner = &bob
		}
		r.do(a)
	}
	if len(r.state.Timeline) != incidents.MaxTimeline {
		t.Fatalf("timeline %d", len(r.state.Timeline))
	}
	a := r.cmd(incidents.TypeAssign, incidents.OriginHuman, alice)
	a.Owner = &bob
	if _, _, err := incidents.Apply(r.state, a, r.at+sec); code(err) != model.Quota {
		t.Fatalf("timeline overflow: %v", err)
	}
}

// State is exactly the replay of its timeline, any past state can be recovered,
// and retries interleaved anywhere do not change the final state.
func TestIncidentReplayAndDeterministicRetries(t *testing.T) {
	build := func(retries bool) (incidents.State, []incidents.Action) {
		r := newRun(t)
		r.open(incidents.SeverityMinor)
		var actions []incidents.Action
		step := func(a incidents.Action) {
			r.do(a)
			actions = append(actions, a)
			if retries {
				for _, past := range actions {
					got, effects, err := incidents.Apply(r.state, past, r.at+sec)
					if err != nil || len(effects) != 0 || got.Version > r.state.Version {
						t.Fatalf("retry of %s: %v", past.Type, err)
					}
				}
			}
		}
		step(r.cmd(incidents.TypeAck, incidents.OriginHuman, alice))
		a := r.cmd(incidents.TypeAssign, incidents.OriginHuman, alice)
		a.Owner = &bob
		step(a)
		w := r.cmd(incidents.TypeImpact, incidents.OriginSystem, bot)
		w.Impact = impact(ep1, incidents.SeverityCritical, incidents.ConditionFiring, incidents.FreshnessFresh)
		step(w)
		s := r.cmd(incidents.TypeResolve, incidents.OriginHuman, bob)
		s.Reason = "done"
		step(s)
		return r.state, actions
	}
	plain, _ := build(false)
	retried, _ := build(true)
	if !reflect.DeepEqual(plain, retried) {
		t.Fatalf("retries changed the state:\n%+v\n%+v", plain, retried)
	}
	replayed, err := incidents.Replay(plain.Timeline)
	if err != nil || !reflect.DeepEqual(replayed, plain) {
		t.Fatalf("state is not the replay of its timeline: %v", err)
	}
	for v := model.Revision(1); v <= plain.Version; v++ {
		past, err := plain.At(v)
		if err != nil || past.Version != v || len(past.Timeline) != int(v) {
			t.Fatalf("At(%d): %+v %v", v, past, err)
		}
	}
	if _, err = plain.At(plain.Version + 1); code(err) != model.NotFound {
		t.Fatalf("future version: %v", err)
	}
}

func TestIncidentCorrelationOnlyProposes(t *testing.T) {
	svc, rel := incidents.Link{Kind: incidents.LinkService, ID: model.ID{0x71}}, incidents.Link{Kind: incidents.LinkRelease, ID: model.ID{0x72}}
	mkState := func(id model.ID, links ...incidents.Link) incidents.State {
		r := newRun(t)
		a := incidents.Action{CommandID: id, Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Actor: bot, Target: incidents.Target{Org: org, Project: project, Incident: id}, Impact: impact(ep1, incidents.SeverityMinor, incidents.ConditionFiring, incidents.FreshnessFresh)}
		a.Impact.Condition = id // each incident has its own condition: no shared condition link
		r.do(a)
		for i, l := range links {
			lk := incidents.Action{CommandID: model.ID{0xaa, byte(i), id[0]}, ExpectedVersion: r.state.Version, Type: incidents.TypeLink, Origin: incidents.OriginSystem, Actor: bot, Target: a.Target, Link: &l}
			r.do(lk)
		}
		return r.state
	}
	a, b, c, d := mkState(model.ID{0x11}, svc, rel), mkState(model.ID{0x12}, svc), mkState(model.ID{0x13}, incidents.Link{Kind: incidents.LinkService, ID: model.ID{0x79}}), mkState(model.ID{0x14}, svc)
	d.Status = incidents.StatusResolved
	states := []incidents.State{b, a, c, d}
	snapshot, err := json.Marshal(states)
	if err != nil {
		t.Fatal(err)
	}
	want := []incidents.Proposal{{A: a.ID, B: b.ID, Evidence: svc}}
	if got := incidents.Correlate(states); !reflect.DeepEqual(got, want) {
		t.Fatalf("proposals %+v", got)
	}
	if after, _ := json.Marshal(states); string(after) != string(snapshot) {
		t.Fatal("correlation changed an incident")
	}
}

// Only a strictly higher severity or a new firing episode is a worse impact;
// the same impact reported again (even with different freshness) is not.
func TestIncidentWorseImpactBoundaries(t *testing.T) {
	r := newRun(t)
	r.open(incidents.SeverityMajor)
	same := r.observe(impact(ep1, incidents.SeverityMajor, incidents.ConditionFiring, incidents.FreshnessStale))
	if r.state.ImpactRevision != 1 || find(same, incidents.EffectNotifyImpact) != nil || r.state.Condition.Freshness != incidents.FreshnessStale {
		t.Fatalf("same severity is not worse: %+v %+v", r.state, same)
	}
	fresh := r.observe(impact(ep2, incidents.SeverityMajor, incidents.ConditionFiring, incidents.FreshnessFresh))
	e := find(fresh, incidents.EffectNotifyImpact)
	if r.state.ImpactRevision != 2 || r.state.Episode != ep2 || e == nil || !e.Eligible || e.ImpactRevision != 2 {
		t.Fatalf("a new firing episode is a new impact: %+v %+v", r.state, fresh)
	}
	// A new episode that is not firing is not an impact.
	r.observe(impact(ep1, incidents.SeverityCritical, incidents.ConditionUnknown, incidents.FreshnessUnknown))
	if r.state.ImpactRevision != 2 || r.state.Episode != ep2 {
		t.Fatalf("a non-firing observation changed impact: %+v", r.state)
	}
}
