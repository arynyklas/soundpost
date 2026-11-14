// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"context"
	"encoding/json"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
)

// addProject creates a second project of the fixture's organization and grants
// the fixture's user read access to it.
func (c *ctl) addProject() model.ID {
	c.t.Helper()
	p := model.NewID()
	c.command("create_project", auth.AdminPayload{ID: p, Name: "extra", Reason: "fixture"})
	c.command("grant", auth.AdminPayload{UserID: c.user, ProjectID: p, Enabled: true, Permissions: []string{string(auth.Read)}, Reason: "fixture"})
	return p
}

func (c *ctl) scope(project model.ID, permission auth.Permission) auth.Scope {
	c.t.Helper()
	s, err := c.svc.Authorize(c.ctx, c.cred, c.org, []model.ID{project}, permission)
	if err != nil {
		c.t.Fatal(err)
	}
	return s
}

// A scheduling pass runs as the project-scoped worker of the rule's project:
// both scopes must name exactly that project, or nothing is read or committed.
// The same rule ID in another project (here with a committed book) must never be
// folded into this rule's evaluation.
func TestRunOnceRefusesScopesOfAnotherProject(t *testing.T) {
	c := newCtl(t)
	other := c.addProject()
	rule := c.alert(0, 0)
	twin := rule
	twin.Project = other
	exec := &fakeExec{fn: func(req query.Request) (query.Result, error) {
		return vectorResult(req.Projects[0], elem(1, "job", "api")), nil
	}}
	clock := newClock(65)
	s := schedulerFor(c, exec, clock)
	lease := c.lease()
	if _, err := s.RunOnce(c.ctx, c.scope(other, auth.Read), c.scope(other, auth.OrgAdmin), twin, lease); err != nil {
		t.Fatalf("the twin rule in its own project: %v", err)
	}
	queries := len(exec.calls)

	for name, scopes := range map[string][2]auth.Scope{
		"read scope of another project":   {c.scope(other, auth.Read), c.scope(c.project, auth.OrgAdmin)},
		"commit scope of another project": {c.scope(c.project, auth.Read), c.scope(other, auth.OrgAdmin)},
	} {
		if _, err := s.RunOnce(c.ctx, scopes[0], scopes[1], rule, lease); code(err) != model.Invalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := s.evaluator.Evaluate(c.ctx, c.scope(other, auth.Read), rule, 60*sec, lease); code(err) != model.Invalid {
		t.Errorf("Evaluate with a scope of another project: %v", err)
	}
	if len(exec.calls) != queries {
		t.Fatalf("a mismatched scope reached the query engine (%d -> %d queries)", queries, len(exec.calls))
	}
	if _, found, err := c.store.RuleBook(c.ctx, c.scope(c.project, auth.OrgAdmin), c.project, rule.ID); err != nil || found {
		t.Fatalf("a mismatched pass wrote a book for the rule: found=%v %v", found, err)
	}
	if _, err := s.RunOnce(c.ctx, c.scope(c.project, auth.Read), c.scope(c.project, auth.OrgAdmin), rule, lease); err != nil {
		t.Fatalf("the matching scopes: %v", err)
	}
}

// The backfill bound survives the end of the int64 time axis: stepping past the
// newest grid point must not wrap into negative times.
func TestPlanGridNearTheEndOfTime(t *testing.T) {
	rule := alertRule(0, 0)
	rule.Interval = 24 * time.Hour
	interval := model.UnixNano(rule.Interval)
	now := model.UnixNano(math.MaxInt64)
	newest := now - now%interval

	fresh := PlanGrid(rule, State{}, now, 2)
	if !reflect.DeepEqual(fresh.Due, []model.UnixNano{newest}) || fresh.Missed != nil {
		t.Fatalf("fresh version: %+v", fresh)
	}
	behind := PlanGrid(rule, State{Version: rule.Version, Applied: &EvaluationRef{At: newest - 10*interval}}, now, 2)
	if !reflect.DeepEqual(behind.Due, []model.UnixNano{newest - 2*interval, newest - interval, newest}) {
		t.Fatalf("backfill bound lost: %d due points, first %d", len(behind.Due), behind.Due[0])
	}
	if behind.Missed == nil || behind.Missed.From != newest-9*interval || behind.Missed.To != newest-interval || behind.Missed.Count != 9 {
		t.Fatalf("missed %+v", behind.Missed)
	}
}

// racingControl lets the control revision move between the revision read and the
// command, as a concurrent writer would, and rewrites the resulting conflict's
// detail text: whether a conflict is a lost race must not depend on prose.
type racingControl struct {
	Control
	race    func()
	raced   bool
	attempt int
}

func (r *racingControl) Transact(ctx context.Context, scope auth.Scope, cmd control.Command) (control.Result, error) {
	r.attempt++
	if !r.raced {
		r.raced = true
		r.race()
	}
	res, err := r.Control.Transact(ctx, scope, cmd)
	if fault, ok := err.(*model.Fault); ok && fault.Code == model.Conflict {
		changed := *fault
		changed.SafeDetail = "revision text that is not the generic conflict text"
		return res, &changed
	}
	return res, err
}

func TestCommitRetriesARevisionRaceWhateverTheConflictText(t *testing.T) {
	c := newCtl(t)
	rule := c.alert(0, 0)
	var calls []int64
	e := c.evaluator(presentWhile(c.project, &calls, func(int64) bool { return true }), newClock(65))
	lease := c.lease()
	ev, err := e.Evaluate(c.ctx, c.reader(), rule, 60*sec, lease)
	if err != nil {
		t.Fatal(err)
	}
	racing := &racingControl{Control: c.store, race: func() {
		// Another writer's commit moves the control revision (without touching
		// the policy epoch, which would invalidate this test's scopes).
		other := c.alert(0, 0)
		if _, err := c.committer().RecordMissed(c.ctx, c.admin(), other, MissedInterval{From: 0, To: 60 * sec, Count: 1}, 100*sec, lease); err != nil {
			t.Error(err)
		}
	}}
	res, err := NewCommitter(racing, c.store.ReplicaGroup()).Commit(c.ctx, c.admin(), ev, lease)
	if err != nil || res.Phase != "applied" || racing.attempt != 2 {
		t.Fatalf("a lost revision race: %+v after %d attempts: %v", res, racing.attempt, err)
	}
	// A semantic conflict is never retried away: the first committed payload wins.
	rival := ev
	rival.ObservedAt++
	racing.attempt = 0
	if _, err = NewCommitter(racing, c.store.ReplicaGroup()).Commit(c.ctx, c.admin(), rival, lease); code(err) != model.Conflict || racing.attempt != 1 {
		t.Fatalf("a semantic conflict: %v after %d attempts", err, racing.attempt)
	}
}

// The recording producer is resolved at every evaluation when a resolver is
// configured, so a policy revision bump is picked up without a restart; a
// resolver failure is the evaluation's failure, not a silent fallback.
func TestEvaluateResolvesTheProducerEveryTime(t *testing.T) {
	rule := recordingRule()
	revision := model.Revision(2)
	resolves := 0
	resolver := func(context.Context) (ProducerIdentity, error) {
		resolves++
		p := producer()
		p.PolicyRevision = revision
		return p, nil
	}
	store := newFakeStore()
	exec := &fakeExec{fn: func(query.Request) (query.Result, error) {
		return vectorResult(rule.Project, elem(1.5, "job", "api")), nil
	}}
	e := evaluator(exec, store, 125*sec, WithProducerResolver(resolver))
	ev := evaluate(t, e, rule, 60)
	if resolves != 1 || ev.Producer == nil || ev.Producer.PolicyRevision != 2 || len(ev.Recording) != 1 || ev.Recording[0].Batch.PolicyRevision != 2 {
		t.Fatalf("producer %+v after %d resolutions", ev.Producer, resolves)
	}
	store.commit(ev)
	revision = 3
	if ev = evaluate(t, e, rule, 120); resolves != 2 || ev.Producer.PolicyRevision != 3 || ev.Recording[0].Batch.PolicyRevision != 3 {
		t.Fatalf("producer %+v after %d resolutions", ev.Producer, resolves)
	}
	broken := evaluator(exec, newFakeStore(), 65*sec, WithProducerResolver(func(context.Context) (ProducerIdentity, error) {
		return ProducerIdentity{}, model.Fail(model.Unavailable)
	}))
	if _, err := broken.Evaluate(context.Background(), auth.Scope{}, rule, 60*sec, testLease); code(err) != model.Unavailable {
		t.Fatalf("a failing resolver: %v", err)
	}
}

// Deleting (retiring) a project strands nothing in control once the rule side
// has collected: through the committer, with an organization administrator's
// scope that names no project (the retired one can no longer be authorized).
func TestCollectRetiredDropsTheRetiredProjectsRulePayloads(t *testing.T) {
	c, rule, e, committer, _ := recordingFixture(t)
	lease := c.lease()
	ev, err := e.Evaluate(c.ctx, c.reader(), rule, 60*sec, lease)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = committer.Commit(c.ctx, c.admin(), ev, lease); err != nil {
		t.Fatal(err)
	}
	orgAdmin, err := c.svc.Authorize(c.ctx, c.cred, c.org, nil, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = committer.CollectRetired(c.ctx, orgAdmin, c.project); err == nil {
		t.Fatal("the rule facts of a live project were collected")
	}
	raw, _ := json.Marshal(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{c.project}, Reason: "fixture", At: 1000, PhysicalDeadline: 2000, BackupDeadline: 3000})
	var revision model.Revision
	if err = c.store.View(c.ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err = c.store.Transact(c.ctx, orgAdmin, control.Command{CommandID: model.NewID(), ExpectedRevision: revision, Kind: string(control.KindDeleteScope), Payload: raw}); err != nil {
		t.Fatal(err)
	}
	if orgAdmin, err = c.svc.Authorize(c.ctx, c.cred, c.org, nil, auth.OrgAdmin); err != nil {
		t.Fatal(err)
	}
	if res, err := committer.CollectRetired(c.ctx, orgAdmin, c.project); err != nil || res.Phase != "retired" {
		t.Fatalf("collection: %+v %v", res, err)
	}
	outs, err := c.store.RuleOutputs(c.ctx, orgAdmin, c.project, rule.ID, "", 0)
	if err != nil || len(outs) != 1 || outs[0].Phase != control.RulePhaseSuppress || len(outs[0].Payload) > 4 {
		t.Fatalf("outputs after collection: %+v %v", outs, err)
	}
	book, found, err := c.store.RuleBook(c.ctx, orgAdmin, c.project, rule.ID)
	if err != nil || !found || len(book.Versions) != 1 || len(book.Versions[0].Recent) != 0 || book.Versions[0].Last == nil {
		t.Fatalf("book after collection: %+v %v", book, err)
	}
}

// The two scopes of a pass must be of one organization: a project ID is only
// unique within its organization, so the project check alone would let a read
// of one tenant's rule be committed under another's principal.
func TestRunOnceRefusesScopesOfDifferentOrganizations(t *testing.T) {
	c := newCtl(t)
	org2 := model.NewID()
	in := func(kind string, p auth.AdminPayload) {
		t.Helper()
		var revision model.Revision
		if err := c.store.View(c.ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
			t.Fatal(err)
		}
		p.Reason = "fixture"
		raw, _ := json.Marshal(p)
		if _, err := c.svc.AdminCommand(c.ctx, c.cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org2, Kind: kind, Payload: raw}); err != nil {
			t.Fatal(kind, err)
		}
	}
	in("create_org", auth.AdminPayload{Name: "other tenant"})
	in("create_project", auth.AdminPayload{ID: c.project, Name: "same project id"})
	in("membership", auth.AdminPayload{UserID: c.user, Enabled: true})
	in("grant", auth.AdminPayload{UserID: c.user, ProjectID: c.project, Enabled: true, Permissions: []string{string(auth.Read)}})
	foreign, err := c.svc.Authorize(c.ctx, c.cred, org2, []model.ID{c.project}, auth.OrgAdmin)
	if err != nil {
		t.Skipf("the same project ID cannot be created in a second organization: %v", err)
	}
	rule := c.alert(0, 0)
	exec := &fakeExec{fn: func(req query.Request) (query.Result, error) { return vectorResult(req.Projects[0]), nil }}
	s := schedulerFor(c, exec, newClock(65))
	if _, err = s.RunOnce(c.ctx, c.reader(), foreign, rule, c.lease()); code(err) != model.Invalid || len(exec.calls) != 0 {
		t.Fatalf("scopes of two organizations: %v (%d queries)", err, len(exec.calls))
	}
}
