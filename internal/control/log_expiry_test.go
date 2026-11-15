// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

const day = 24 * time.Hour

// auditPayload is the Transact "Audit" payload of one audit row (the identities Transact itself
// stamps are placeholders: the row must be encodable).
func (f *fenceFx) auditPayload(action string, at time.Time) json.RawMessage {
	f.t.Helper()
	raw, err := json.Marshal(model.ControlAudit{ID: model.NewID(), Principal: f.user, RequestID: model.NewID(), Action: action, Reason: "log expiry fixture", Time: at.UnixNano()})
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

// audit commits one audit row through the Transact "Audit" kind, which also records one applied
// command, and returns the command's id.
func (f *fenceFx) audit(action string, at time.Time) model.ID {
	f.t.Helper()
	id := model.NewID()
	if _, err := f.store.Transact(f.ctx, f.adminScope(), control.Command{CommandID: id, ExpectedRevision: f.revision(), Kind: string(control.KindAudit), Payload: f.auditPayload(action, at)}); err != nil {
		f.t.Fatal(err)
	}
	return id
}

// state is the committed control state, linearizably read.
func (f *fenceFx) state() control.State {
	f.t.Helper()
	var out control.State
	if err := f.store.View(f.ctx, func(st control.State) error { out = st; return nil }); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// authorityRevision is the AuthorityRevision of the committed state.
func (f *fenceFx) authorityRevision() model.Revision { return f.state().AuthorityRevision }

// countAudits counts the audit rows of an action.
func countAudits(st control.State, action string) int {
	n := 0
	for _, a := range st.Audits {
		if a.Action == action {
			n++
		}
	}
	return n
}

// appendAudits commits audit rows with explicit times in one transition.
func (f *fenceFx) appendAudits(rows ...model.ControlAudit) {
	f.t.Helper()
	if err := f.store.Update(f.ctx, func(st *control.State) error {
		for _, r := range rows {
			r.ID, r.Principal, r.RequestID = model.NewID(), f.user, model.NewID()
			if r.Org == "" {
				r.Org = f.org.String()
			}
			st.Audits = append(st.Audits, r)
		}
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
}

// commandRevision is the revision command id committed at.
func (f *fenceFx) commandRevision(id model.ID) model.Revision {
	f.t.Helper()
	c, ok := f.state().Commands[id.String()]
	if !ok {
		f.t.Fatalf("command %s is not in the log", id)
	}
	return c.Revision
}

// ageClock makes every revision up to through at least as old as at, the way a day of traffic would:
// the revision clock is replaced by the one stamp that says so.
func (f *fenceFx) ageClock(through model.Revision, at time.Time) {
	f.t.Helper()
	if err := f.store.Update(f.ctx, func(st *control.State) error {
		st.RevisionClock = []model.RevisionStamp{{Revision: through, At: at.UnixNano()}}
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fenceFx) auditSetting(days uint32) {
	f.t.Helper()
	cfg, _ := json.Marshal(auth.RetentionConfig{ProjectID: f.project, Signal: "audit", Days: days})
	f.admin("retention", f.org, auth.AdminPayload{ID: model.NewID(), Config: cfg, Reason: "audit retention"})
}

func (f *fenceFx) expire(now time.Time, mut ...func(*control.ControlLogPolicy)) control.ControlLogReport {
	f.t.Helper()
	p := control.ControlLogPolicy{Now: now, AuditDays: 365}
	for _, m := range mut {
		m(&p)
	}
	rep, err := f.store.ExpireControlLog(f.ctx, p)
	if err != nil {
		f.t.Fatal(err)
	}
	return rep
}

// An audit row lives AuditDays (365 by default) and then goes; the erasing and scrubbing audits, which
// the control scrub and the attestations are accounted from, and rows with no time stay; a pass that
// finds nothing commits nothing.
func TestExpiryDropsAuditsPastTheirRetentionAndKeepsTheRest(t *testing.T) {
	f := newFenceFx(t)
	now := time.Now()
	f.appendAudits(
		model.ControlAudit{Action: "x.old", Time: now.Add(-366 * day).UnixNano()},
		model.ControlAudit{Action: "x.edge", Time: now.Add(-364 * day).UnixNano()},
		model.ControlAudit{Action: "x.young", Time: now.Add(-day).UnixNano()},
		model.ControlAudit{Action: "x.undated"},
		model.ControlAudit{Action: "x.noorg", Org: "-", Time: now.Add(-400 * day).UnixNano()},
		model.ControlAudit{Action: "delete.control_erased", Time: now.Add(-1000 * day).UnixNano(), Targets: []model.ID{model.NewID()}},
		model.ControlAudit{Action: "delete.control_scrubbed", Time: now.Add(-1000 * day).UnixNano(), Targets: []model.ID{model.NewID()}},
	)
	before := f.state()
	rep := f.expire(now)
	if rep.Audits != 2 {
		t.Fatalf("expired audits: %+v, want the two older than 365 days (x.old, x.noorg)", rep)
	}
	after := f.state()
	for action, want := range map[string]int{"x.old": 0, "x.noorg": 0, "x.edge": 1, "x.young": 1, "x.undated": 1, "delete.control_erased": 1, "delete.control_scrubbed": 1} {
		if got := countAudits(after, action); got != want {
			t.Errorf("%s: %d rows after the pass, want %d", action, got, want)
		}
	}
	if len(after.Audits) != len(before.Audits)-2 {
		t.Fatalf("the pass changed more than the two expired rows: %d -> %d", len(before.Audits), len(after.Audits))
	}
	// Nothing due: no commit, no revision, no authority move.
	revision, authority := f.revision(), f.authorityRevision()
	if rep = f.expire(now); rep != (control.ControlLogReport{}) {
		t.Fatalf("second pass: %+v", rep)
	}
	if f.revision() != revision || f.authorityRevision() != authority {
		t.Fatal("a pass that found nothing committed a transition")
	}
}

// The expiry commit is bookkeeping: it moves the revision, never AuthorityRevision (a deletion's Begin
// holding an older view is not refused because a log row aged out).
func TestExpiryDoesNotMoveAuthorityRevision(t *testing.T) {
	f := newFenceFx(t)
	now := time.Now()
	f.appendAudits(model.ControlAudit{Action: "x.old", Time: now.Add(-400 * day).UnixNano()})
	authority, revision := f.authorityRevision(), f.revision()
	if rep := f.expire(now); rep.Audits != 1 {
		t.Fatalf("setup: %+v", rep)
	}
	if got := f.authorityRevision(); got != authority {
		t.Fatalf("expiry moved AuthorityRevision %d -> %d", authority, got)
	}
	if f.revision() != revision+1 {
		t.Fatalf("expiry did not commit exactly one transition: %d -> %d", revision, f.revision())
	}
}

// An organization's "audit" retention setting can lengthen the audit period and can never shorten it:
// an administrator does not get to age out the record of their own actions.
func TestAuditRetentionSettingCanOnlyLengthenIt(t *testing.T) {
	f := newFenceFx(t)
	now := time.Now()
	f.auditSetting(30)
	f.appendAudits(
		model.ControlAudit{Action: "s.300", Time: now.Add(-300 * day).UnixNano()},
		model.ControlAudit{Action: "s.380", Time: now.Add(-380 * day).UnixNano()},
		model.ControlAudit{Action: "s.420", Time: now.Add(-420 * day).UnixNano()},
	)
	if rep := f.expire(now); rep.Audits != 2 {
		t.Fatalf("with a 30 day setting: %+v, want the 380 and 420 day rows gone (365 days still applies)", rep)
	}
	if got := countAudits(f.state(), "s.300"); got != 1 {
		t.Fatalf("a 30 day setting shortened the audit period: the 300 day row is gone")
	}
	f.auditSetting(400)
	f.appendAudits(model.ControlAudit{Action: "t.380", Time: now.Add(-380 * day).UnixNano()}, model.ControlAudit{Action: "t.420", Time: now.Add(-420 * day).UnixNano()})
	if rep := f.expire(now); rep.Audits != 1 {
		t.Fatalf("with a 400 day setting: %+v, want only the 420 day row gone", rep)
	}
	if countAudits(f.state(), "t.380") != 1 || countAudits(f.state(), "t.420") != 0 {
		t.Fatal("a 400 day setting did not lengthen the audit period to 400 days")
	}
}

// The applied-command log answers a retry for the dedup window and then forgets the command with its
// owner row. A retry after that is a fresh command, which the expected-revision rule refuses; a retry
// of a command inside the window is still answered from the log.
func TestExpiryForgetsAppliedCommandsPastTheDedupWindow(t *testing.T) {
	f := newFenceFx(t)
	now := time.Now()
	oldView := f.revision() // the view the first submission of each command carried
	old := f.audit("c.old", now)
	youngView := f.revision()
	young := f.audit("c.young", now)
	oldRevision := f.commandRevision(old)
	before := f.state()
	wantGone := 0
	for _, c := range before.Commands {
		if c.Revision != 0 && c.Revision <= oldRevision {
			wantGone++
		}
	}
	f.ageClock(oldRevision, now.Add(-25*time.Hour)) // everything up to c.old is more than a day old
	rep := f.expire(now)
	if rep.Commands != wantGone || rep.Audits != 0 || rep.Capped != 0 {
		t.Fatalf("expiry report %+v, want the %d commands up to c.old and nothing else", rep, wantGone)
	}
	st := f.state()
	if _, ok := st.Commands[old.String()]; ok || st.CommandOwners[old.String()] != "" {
		t.Fatal("the expired command is still in the log or its owner row survived")
	}
	if _, ok := st.Commands[young.String()]; !ok || st.CommandOwners[young.String()] == "" {
		t.Fatal("a command committed after the aged revisions was forgotten")
	}
	if len(st.Commands) != len(st.CommandOwners) {
		t.Fatalf("log rows out of step: %d commands, %d owners", len(st.Commands), len(st.CommandOwners))
	}
	// The retained command is still answered from the log; the forgotten one is not replayed.
	if _, err := f.store.Transact(f.ctx, f.adminScope(), control.Command{CommandID: young, ExpectedRevision: youngView, Kind: string(control.KindAudit), Payload: f.auditPayload("c.young", now)}); err != nil {
		t.Fatalf("a retry inside the dedup window was not answered from the log: %v", err)
	}
	if _, err := f.store.Transact(f.ctx, f.adminScope(), control.Command{CommandID: old, ExpectedRevision: oldView, Kind: string(control.KindAudit), Payload: f.auditPayload("c.old", now)}); err == nil || code(err) != model.Conflict {
		t.Fatalf("a retry after the dedup window was not refused by the expected-revision rule: %v", err)
	}
	if got := countAudits(f.state(), "c.young"); got != 1 {
		t.Fatalf("a retry inside the window was applied again: %d c.young rows", got)
	}
	if got := countAudits(f.state(), "c.old"); got != 1 {
		t.Fatalf("the forgotten command was applied again: %d c.old rows", got)
	}
}

// A retention command's retry after its log row aged out is refused as well: the command that wrote the
// row moved AuthorityRevision past the view it carried.
func TestRetryOfAnExpiredRetentionCommandIsRefused(t *testing.T) {
	f := newFenceFx(t)
	now := time.Now()
	id := model.NewID()
	hold := control.PlaceHold{Projects: []model.ID{f.project}, Reason: "litigation", At: model.UnixNano(now.UnixNano())}
	cmd := f.cmd(control.KindPolicyChange, id, control.PolicyChange{Kind: "hold_place", Hold: &hold})
	if _, err := f.store.Transact(f.ctx, f.adminScope(), cmd); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Transact(f.ctx, f.adminScope(), cmd); err != nil {
		t.Fatalf("an immediate retry is answered from the log: %v", err)
	}
	f.ageClock(f.commandRevision(id), now.Add(-48*time.Hour))
	if rep := f.expire(now); rep.Commands == 0 {
		t.Fatalf("setup: %+v", rep)
	}
	if _, ok := f.state().Commands[id.String()]; ok {
		t.Fatal("setup: the hold command is still in the log")
	}
	if _, err := f.store.Transact(f.ctx, f.adminScope(), cmd); err == nil || code(err) != model.Conflict {
		t.Fatalf("a retention command retried after its log row expired: %v", err)
	}
	if got := countAudits(f.state(), "hold.place"); got != 1 {
		t.Fatalf("the hold was placed twice: %d audits", got)
	}
}

// The command log keeps at most CommandMax entries, dropping the oldest by revision first.
func TestExpiryCapsTheAppliedCommandLogOldestFirst(t *testing.T) {
	f := newFenceFx(t)
	now := time.Now()
	var ids []model.ID
	for i := range 8 {
		ids = append(ids, f.audit(fmt.Sprintf("cap.%d", i), now))
	}
	baseline := len(f.state().Commands) - 8 // the fixture's own, older commands
	rep := f.expire(now, func(p *control.ControlLogPolicy) { p.CommandMax = 5 })
	if rep.Capped != baseline+3 || rep.Commands != 0 {
		t.Fatalf("report %+v, want the %d fixture commands and the 3 oldest of the eight capped", rep, baseline)
	}
	st := f.state()
	for i, id := range ids {
		_, kept := st.Commands[id.String()]
		if want := i >= 3; kept != want {
			t.Errorf("command %d kept=%v, want %v (oldest first)", i, kept, want)
		}
	}
	if len(st.Commands) != 5 || len(st.CommandOwners) != len(st.Commands) {
		t.Fatalf("log rows after the cap: %d commands, %d owners, want 5", len(st.Commands), len(st.CommandOwners))
	}
}

// The update funnel dates revisions coarsely: one stamp when the clock is empty, another only once the
// newest is a minute old, and a stamp is dropped once it is older than the dedup window unless it is the
// newest such one (the anchor "everything up to here is at least that old"). The clock is bounded by
// the window, never by the traffic.
func TestRevisionClockIsStampedOncePerMinuteAndBoundedByTheWindow(t *testing.T) {
	f := newFenceFx(t)
	sim := time.Now()
	f.store.SetClock(func() time.Time { return sim })
	if err := f.store.Update(f.ctx, func(st *control.State) error { st.RevisionClock = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	clock := func() []model.RevisionStamp { return f.state().RevisionClock }
	first := clock()
	if len(first) != 1 || first[0].At != sim.UnixNano() || first[0].Revision != f.revision() {
		t.Fatalf("a state with no clock must be stamped by the next update: %+v at revision %d", first, f.revision())
	}
	for range 5 { // many commits inside one minute add nothing
		sim = sim.Add(5 * time.Second)
		f.audit("clock.burst", sim)
	}
	if got := clock(); len(got) != 1 {
		t.Fatalf("commits within a minute of the newest stamp added stamps: %+v", got)
	}
	sim = sim.Add(time.Minute)
	f.audit("clock.minute", sim)
	if got := clock(); len(got) != 2 || got[1].At != sim.UnixNano() || got[1].Revision != f.revision() {
		t.Fatalf("a commit a minute after the newest stamp must add one: %+v at revision %d", got, f.revision())
	}
	// A stamp older than the window is dropped, except the newest of the older ones.
	for range 3 {
		sim = sim.Add(10 * time.Hour)
		f.audit("clock.hours", sim)
	}
	got := clock()
	cutoff := sim.Add(-24 * time.Hour).UnixNano()
	older := 0
	for _, s := range got {
		if s.At < cutoff {
			older++
		}
	}
	if older != 1 || len(got) > 4 {
		t.Fatalf("clock after 30 hours: %+v, want at most one stamp older than the window (the anchor)", got)
	}
	// A clock that moves backwards stamps nothing and breaks nothing.
	before := len(clock())
	sim = sim.Add(-48 * time.Hour)
	f.audit("clock.backwards", sim)
	if after := clock(); len(after) != before {
		t.Fatalf("a clock that moved backwards stamped the revision clock: %d -> %d", before, len(after))
	}
}

// A long-running installation does not grow without bound. 420 simulated days of one applied command
// and one audit row a day, the control store's clock moved with them and the expiry run once a day: the
// audit log settles at its retention (366 rows of the daily action: day D-365 .. D), the command log at
// the dedup window, and the revision clock at a window's worth of stamps.
func TestControlStateStaysBoundedOverALongRun(t *testing.T) {
	if testing.Short() {
		t.Skip("420 simulated days")
	}
	f := newFenceFx(t)
	start := time.Now()
	sim := start
	f.store.SetClock(func() time.Time { return sim })
	const days = 420
	var peakCommands, peakClock int
	for d := 0; d <= days; d++ {
		sim = start.Add(time.Duration(d) * day)
		f.audit("daily.tick", sim)
		f.expire(sim)
		st := f.state()
		peakCommands, peakClock = max(peakCommands, len(st.Commands)), max(peakClock, len(st.RevisionClock))
		if d == 100 || d == days {
			if got, want := countAudits(st, "daily.tick"), min(d+1, 366); got != want {
				t.Fatalf("day %d: %d daily audit rows, want %d", d, got, want)
			}
		}
	}
	st := f.state()
	if len(st.Commands) != len(st.CommandOwners) {
		t.Fatalf("log rows out of step: %d commands, %d owners", len(st.Commands), len(st.CommandOwners))
	}
	// A day of traffic is one command; the fixture's own setup commands are older than the window by now.
	if peakCommands > 40 || len(st.Commands) > 4 {
		t.Fatalf("the applied-command log is not bounded by the dedup window: peak %d, final %d", peakCommands, len(st.Commands))
	}
	if peakClock > 4 {
		t.Fatalf("the revision clock is not bounded by the dedup window: peak %d stamps", peakClock)
	}
	if len(st.Audits) > 366+64 {
		t.Fatalf("the audit log grew past its retention: %d rows", len(st.Audits))
	}
}
