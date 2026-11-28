// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package issues_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
)

const trackerURL = "https://git.example.test/shop/web/-/issues/12"

// lastAudit is the audit of the most recent commit.
func (f *fx) lastAudit() model.ControlAudit {
	f.t.Helper()
	if len(f.store.audits) == 0 {
		f.t.Fatal("no audit")
	}
	return f.store.audits[len(f.store.audits)-1]
}

func (f *fx) assign(i issues.Issue, owner *model.ID, mutate func(*issues.IssueAction)) (issues.Issue, error) {
	return f.act("assign", i, func(a *issues.IssueAction) {
		a.Reason, a.Owner = "", owner
		if mutate != nil {
			mutate(a)
		}
	})
}

func (f *fx) external(kind string, i issues.Issue, op model.ExternalOp, mutate func(*issues.IssueAction)) (issues.Issue, error) {
	return f.act(kind, i, func(a *issues.IssueAction) {
		a.Reason, a.External = "", &op
		if mutate != nil {
			mutate(a)
		}
	})
}

func TestIssueAssign(t *testing.T) {
	f := newFx(t)
	f.apply(f.ev(1, f.A, 50))
	current := f.issueFor(1)
	owner, other := model.ID{0xa1}, model.ID{0xa2}

	if current.Owner != nil {
		t.Fatalf("a new issue has an owner: %v", current.Owner)
	}
	assigned, e := f.assign(current, &owner, nil)
	if e != nil || assigned.Owner == nil || *assigned.Owner != owner || assigned.Revision != current.Revision+1 || assigned.Workflow != "open" {
		t.Fatalf("assign: %v %+v", e, assigned)
	}
	if a := f.lastAudit(); a.Action != "issues.assign" || a.Reason != "owner assigned" || a.Principal != f.writer.PrincipalID() || !reflect.DeepEqual(a.Targets, []model.ID{current.ID, owner}) {
		t.Fatalf("audit %+v", a)
	}
	if stored := f.issueFor(1); stored.Owner == nil || *stored.Owner != owner {
		t.Fatalf("not stored: %+v", stored.Owner)
	}
	*assigned.Owner = other
	if stored := f.issueFor(1); *stored.Owner != owner {
		t.Fatal("the returned owner aliases the stored one")
	}

	current = f.issueFor(1)
	if _, e = f.assign(current, &owner, nil); code(e) != model.Conflict {
		t.Fatalf("same owner: %v", e)
	}
	reassigned, e := f.assign(current, &other, func(a *issues.IssueAction) { a.Reason = "handover to the payments team" })
	if e != nil || *reassigned.Owner != other || f.lastAudit().Reason != "handover to the payments team" {
		t.Fatalf("reassign: %v %+v %+v", e, reassigned.Owner, f.lastAudit())
	}
	cleared, e := f.assign(reassigned, nil, nil)
	if e != nil || cleared.Owner != nil || f.lastAudit().Reason != "owner cleared" || !reflect.DeepEqual(f.lastAudit().Targets, []model.ID{current.ID}) {
		t.Fatalf("unassign: %v %+v %+v", e, cleared.Owner, f.lastAudit())
	}
	if _, e = f.assign(cleared, nil, nil); code(e) != model.Conflict {
		t.Fatalf("unassign of an unassigned issue: %v", e)
	}

	commits := len(f.store.commits)
	zero := model.ID{}
	for name, mutate := range map[string]func(*issues.IssueAction){
		"zero owner":    func(a *issues.IssueAction) { a.Owner = &zero },
		"control text":  func(a *issues.IssueAction) { a.Owner = &owner; a.Reason = "bad\x00reason" },
		"too long":      func(a *issues.IssueAction) { a.Owner = &owner; a.Reason = strings.Repeat("r", 513) },
		"stale version": func(a *issues.IssueAction) { a.Owner = &owner; a.ExpectedVersion-- },
	} {
		_, e := f.act("assign", cleared, mutate)
		if name == "stale version" && code(e) != model.Conflict || name != "stale version" && code(e) != model.Invalid {
			t.Fatalf("%s: %v", name, e)
		}
	}
	if _, e = f.act("resolve", cleared, func(a *issues.IssueAction) { a.Owner = &owner }); code(e) != model.Invalid {
		t.Fatalf("an owner on a resolve: %v", e)
	}
	if len(f.store.commits) != commits {
		t.Fatal("a refused assign committed")
	}
}

func TestIssueAssignRetryAndConcurrency(t *testing.T) {
	f := newFx(t)
	f.apply(f.ev(1, f.A, 50))
	current := f.issueFor(1)
	owner, other := model.ID{0xa1}, model.ID{0xa2}
	command := model.NewID()
	assign := func(o *model.ID) (issues.Issue, error) {
		return f.assign(current, o, func(a *issues.IssueAction) { a.CommandID = command })
	}
	first, e := assign(&owner)
	if e != nil {
		t.Fatal(e)
	}
	commits := len(f.store.commits)
	again, e := assign(&owner)
	if e != nil || again.Revision != first.Revision || len(f.store.commits) != commits {
		t.Fatalf("retry re-applied: %v", e)
	}
	if _, e = assign(&other); code(e) != model.Conflict {
		t.Fatalf("command reused for another owner: %v", e)
	}
	if _, e = assign(nil); code(e) != model.Conflict {
		t.Fatalf("command reused to unassign: %v", e)
	}
	if _, e = f.assign(current, &other, nil); code(e) != model.Conflict {
		t.Fatalf("stale revision: %v", e)
	}
}

func TestIssueAssignWorksInEveryWorkflowAndSurvivesEvidence(t *testing.T) {
	f := newFx(t)
	f.apply(f.ev(1, f.A, 50))
	owner, other := model.ID{0xa1}, model.ID{0xa2}
	i, e := f.assign(f.issueFor(1), &owner, nil)
	if e != nil {
		t.Fatal(e)
	}
	keeps := func(step string, want model.ID) {
		t.Helper()
		if i.Owner == nil || *i.Owner != want {
			t.Fatalf("%s: owner %v, want %v", step, i.Owner, want)
		}
	}
	f.clock.at = 100
	if i, e = f.act("resolve", i, nil); e != nil || i.Workflow != "resolved" {
		t.Fatalf("resolve: %v", e)
	}
	keeps("resolve", owner)
	if i, e = f.assign(i, &other, nil); e != nil || i.Workflow != "resolved" {
		t.Fatalf("assign on a resolved issue: %v", e)
	}
	keeps("assign on resolved", other)
	if i, e = f.act("reopen", i, nil); e != nil {
		t.Fatal(e)
	}
	keeps("reopen", other)
	if i, e = f.act("ignore", i, nil); e != nil {
		t.Fatal(e)
	}
	if i, e = f.assign(i, &owner, nil); e != nil || i.Workflow != "ignored" {
		t.Fatalf("assign on an ignored issue: %v", e)
	}
	keeps("assign on ignored", owner)
	if i, e = f.act("unignore", i, nil); e != nil {
		t.Fatal(e)
	}
	keeps("unignore", owner)

	f.apply(f.ev(1, f.A, 60))
	if got := f.issueFor(1); got.Owner == nil || *got.Owner != owner {
		t.Fatalf("evidence changed the owner: %v", got.Owner)
	}
	f.clock.at = 100
	if _, e = f.act("resolve", f.issueFor(1), nil); e != nil {
		t.Fatal(e)
	}
	f.apply(f.ev(1, f.B, 200))
	if got := f.issueFor(1); got.Workflow != "open" || got.Owner == nil || *got.Owner != owner {
		t.Fatalf("a regression changed the owner: %s %v", got.Workflow, got.Owner)
	}
}

func TestIssueAssignNeedsIssuesWriteAndTheRightOrganization(t *testing.T) {
	f := newFx(t)
	f.apply(f.ev(1, f.A, 50))
	current := f.issueFor(1)
	owner := model.ID{0xa1}
	commits := len(f.store.commits)
	a := issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: current.Revision, IssueID: current.ID, Kind: "assign", Owner: &owner}
	if _, e := f.svc.Act(context.Background(), f.reader, a); code(e) != model.Forbidden {
		t.Fatalf("a reader assigned: %v", e)
	}
	_, e1 := f.svc.Act(context.Background(), f.otherWriter, a)
	a.IssueID = model.NewID()
	a.CommandID = model.NewID()
	_, e2 := f.svc.Act(context.Background(), f.otherWriter, a)
	if code(e1) != model.NotFound || code(e1) != code(e2) || e1.Error() != e2.Error() {
		t.Fatalf("foreign assign: %v / %v", e1, e2)
	}
	if len(f.store.commits) != commits {
		t.Fatal("a refused assign committed")
	}
}

func TestIssueExternalLink(t *testing.T) {
	f := newFx(t)
	f.apply(f.ev(1, f.A, 50))
	f.clock.at = 1_000
	current := f.issueFor(1)
	marker := model.ExternalMarker(f.org, "issue", current.ID)
	begin := model.ExternalOp{Provider: "gitlab", Kind: model.ExternalBegin, Marker: marker, Project: "shop/web", Until: 1_000 + 60}

	creating, e := f.external("external_begin", current, begin, nil)
	if e != nil || len(creating.External) != 1 || creating.External[0].State != model.ExternalCreating || creating.External[0].Actor != f.writer.PrincipalID() || creating.External[0].At != 1_000 || creating.Revision != current.Revision+1 {
		t.Fatalf("begin: %v %+v", e, creating.External)
	}
	a := f.lastAudit()
	if a.Action != "issues.external_begin" || a.Reason != "external link begin" || !reflect.DeepEqual(a.Targets, []model.ID{current.ID}) {
		t.Fatalf("audit %+v", a)
	}
	commits := len(f.store.commits)
	if _, e = f.external("external_begin", creating, begin, nil); code(e) != model.Conflict || !strings.Contains(e.Error(), "external_in_progress") {
		t.Fatalf("second begin: %v", e)
	}
	if len(f.store.commits) != commits {
		t.Fatal("a refused begin committed")
	}

	end := model.ExternalOp{Provider: "gitlab", Kind: model.ExternalEnd, Marker: marker, Project: "shop/web", Result: model.ExternalLinked, IID: 12, URL: trackerURL}
	linked, e := f.external("external_end", creating, end, nil)
	if e != nil || linked.External[0].State != model.ExternalLinked || linked.External[0].IID != 12 || linked.External[0].URL != trackerURL || linked.Revision != creating.Revision+1 {
		t.Fatalf("end: %v %+v", e, linked.External)
	}
	raw, _ := json.Marshal(f.store.audits)
	if strings.Contains(string(raw), "git.example.test") || strings.Contains(string(raw), "shop/web") {
		t.Fatalf("the tracker location is in an audit: %s", raw)
	}
	adopt := end
	adopt.Kind = model.ExternalAdopt
	if _, e = f.external("external_adopt", linked, adopt, nil); code(e) != model.Conflict || !strings.Contains(e.Error(), "external_already_linked") {
		t.Fatalf("adopt over a link: %v", e)
	}
	if linked.Workflow != "open" {
		t.Fatalf("workflow %s", linked.Workflow)
	}
	linked.External[0].URL = "https://changed.example.test"
	if got := f.issueFor(1); got.External[0].URL != trackerURL {
		t.Fatal("the returned links alias the stored ones")
	}
}

func TestIssueExternalLeaseTakeoverAndAdopt(t *testing.T) {
	f := newFx(t)
	f.apply(f.ev(1, f.A, 50))
	f.clock.at = 1_000
	current := f.issueFor(1)
	marker := model.ExternalMarker(f.org, "issue", current.ID)
	begin := func(until model.UnixNano) model.ExternalOp {
		return model.ExternalOp{Provider: "gitlab", Kind: model.ExternalBegin, Marker: marker, Project: "shop/web", Until: until}
	}
	command := model.NewID()
	first, e := f.external("external_begin", current, begin(1_100), func(a *issues.IssueAction) { a.CommandID = command })
	if e != nil {
		t.Fatal(e)
	}
	f.clock.at = 1_200
	taken, e := f.external("external_begin", first, begin(1_300), nil)
	if e != nil || taken.External[0].Until != 1_300 || taken.External[0].At != 1_200 {
		t.Fatalf("takeover: %v %+v", e, taken.External)
	}
	commits := len(f.store.commits)
	f.clock.at = 9_999
	again, e := f.external("external_begin", current, begin(1_100), func(a *issues.IssueAction) { a.CommandID = command })
	if e != nil || again.Revision != taken.Revision || len(f.store.commits) != commits {
		t.Fatalf("late retry: %v", e)
	}
	adopt := model.ExternalOp{Provider: "gitlab", Kind: model.ExternalAdopt, Marker: marker, Project: "shop/web", Result: model.ExternalLinked, IID: 3, URL: trackerURL}
	adopted, e := f.external("external_adopt", taken, adopt, nil)
	if e != nil || adopted.External[0].State != model.ExternalLinked || f.lastAudit().Action != "issues.external_adopt" {
		t.Fatalf("adopt: %v %+v", e, adopted.External)
	}
}

func TestIssueExternalValidationAndScope(t *testing.T) {
	f := newFx(t)
	f.apply(f.ev(1, f.A, 50))
	f.clock.at = 1_000
	current := f.issueFor(1)
	marker := model.ExternalMarker(f.org, "issue", current.ID)
	good := model.ExternalOp{Provider: "gitlab", Kind: model.ExternalBegin, Marker: marker, Project: "shop/web", Until: 1_060}
	commits := len(f.store.commits)

	adopt := good
	adopt.Kind = model.ExternalAdopt
	insecure := model.ExternalOp{Provider: "gitlab", Kind: model.ExternalEnd, Marker: marker, Project: "shop/web", Result: model.ExternalLinked, IID: 1, URL: "http://git.example.test/a"}
	type refusal struct {
		run  func() error
		want model.Code
	}
	for name, tc := range map[string]refusal{
		"kind and operation disagree": {func() error { _, e := f.external("external_end", current, good, nil); return e }, model.Invalid},
		"adopt as begin":              {func() error { _, e := f.external("external_begin", current, adopt, nil); return e }, model.Invalid},
		"insecure url":                {func() error { _, e := f.external("external_end", current, insecure, nil); return e }, model.Invalid},
		"no operation": {func() error {
			_, e := f.act("external_begin", current, func(a *issues.IssueAction) { a.Reason = "" })
			return e
		}, model.Invalid},
		"a reason": {func() error {
			_, e := f.external("external_begin", current, good, func(a *issues.IssueAction) { a.Reason = "why" })
			return e
		}, model.Invalid},
		"an owner": {func() error {
			o := model.ID{1}
			_, e := f.external("external_begin", current, good, func(a *issues.IssueAction) { a.Owner = &o })
			return e
		}, model.Invalid},
		"an operation on a resolve": {func() error {
			_, e := f.act("resolve", current, func(a *issues.IssueAction) { a.External = &good })
			return e
		}, model.Invalid},
		"end without a lease": {func() error {
			end := model.ExternalOp{Provider: "gitlab", Kind: model.ExternalEnd, Marker: marker, Project: "shop/web", Result: model.ExternalUnknown, Code: "gitlab_timeout"}
			_, e := f.external("external_end", current, end, nil)
			return e
		}, model.Conflict},
	} {
		if e := tc.run(); code(e) != tc.want {
			t.Fatalf("%s: %v, want %s", name, e, tc.want)
		}
	}
	if len(f.store.commits) != commits {
		t.Fatal("a refused external action committed")
	}
	a := issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: current.Revision, IssueID: current.ID, Kind: "external_begin", External: &good}
	if _, e := f.svc.Act(context.Background(), f.reader, a); code(e) != model.Forbidden {
		t.Fatalf("a reader linked: %v", e)
	}
	_, e1 := f.svc.Act(context.Background(), f.otherWriter, a)
	a.IssueID, a.CommandID = model.NewID(), model.NewID()
	_, e2 := f.svc.Act(context.Background(), f.otherWriter, a)
	if code(e1) != model.NotFound || e1.Error() != e2.Error() {
		t.Fatalf("foreign link: %v / %v", e1, e2)
	}
}

func TestIssueExternalSurvivesEvidence(t *testing.T) {
	f := newFx(t)
	f.apply(f.ev(1, f.A, 50))
	f.clock.at = 1_000
	current := f.issueFor(1)
	marker := model.ExternalMarker(f.org, "issue", current.ID)
	adopt := model.ExternalOp{Provider: "gitlab", Kind: model.ExternalAdopt, Marker: marker, Project: "shop/web", Result: model.ExternalLinked, IID: 12, URL: trackerURL}
	if _, e := f.external("external_adopt", current, adopt, nil); e != nil {
		t.Fatal(e)
	}
	f.apply(f.ev(1, f.A, 60), f.ev(1, f.B, 70))
	if got := f.issueFor(1); len(got.External) != 1 || got.External[0].IID != 12 || got.Revision <= current.Revision+1 {
		t.Fatalf("evidence changed the links: %+v", got.External)
	}
}

// D93: assign and the external kinds are refused (Unsupported) until the installation is contracted.
func TestIssueOwnerAndExternalNeedAContractedInstallation(t *testing.T) {
	f := newFx(t)
	f.apply(f.ev(1, f.A, 50))
	current := f.issueFor(1)
	contracted := false
	svc, e := issues.New(issues.Deps{Store: f.store, Authorizer: f.app.Auth, Graphs: f.graphs, Fence: f.fence, Policy: f.policy, Clock: f.clock,
		Regression: issues.RegressionPolicy{MinOccurrences: 1}, Contracted: func(context.Context, model.ID) (bool, error) { return contracted, nil }})
	if e != nil {
		t.Fatal(e)
	}
	owner := model.ID{0xa1}
	assign := issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: current.Revision, IssueID: current.ID, Kind: "assign", Owner: &owner}
	commits := len(f.store.commits)
	_, e = svc.Act(context.Background(), f.writer, assign)
	var fault *model.Fault
	if !errors.As(e, &fault) || fault.Code != model.Unsupported || fault.SafeDetail != issues.DetailNeedsContracted || len(f.store.commits) != commits {
		t.Fatalf("assign before contraction: %v", e)
	}
	f.clock.at = 100
	if _, e = svc.Act(context.Background(), f.writer, issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: current.Revision, IssueID: current.ID, Kind: "resolve", Reason: "r"}); e != nil {
		t.Fatalf("resolve must not need contraction: %v", e)
	}
	contracted = true
	current = f.issueFor(1)
	assign.CommandID, assign.ExpectedVersion = model.NewID(), current.Revision
	if got, e := svc.Act(context.Background(), f.writer, assign); e != nil || got.Owner == nil {
		t.Fatalf("assign after contraction: %v", e)
	}
}

// D94: the format marker is raised BEFORE the first owner or link record is committed (never for a refused write or for
// an action that writes no D92 record), and a marker that cannot be written refuses the write: nothing is committed.
func TestIssueRecordsRaiseTheFormatMarkerFirstAndRefuseWithoutIt(t *testing.T) {
	f := newFx(t)
	f.apply(f.ev(1, f.A, 50))
	current := f.issueFor(1)
	var marks, commitsAtMark int
	var markErr error
	svc, e := issues.New(issues.Deps{Store: f.store, Authorizer: f.app.Auth, Graphs: f.graphs, Fence: f.fence, Policy: f.policy, Clock: f.clock,
		Regression: issues.RegressionPolicy{MinOccurrences: 1}, Contracted: func(context.Context, model.ID) (bool, error) { return true, nil },
		RecordFormat: func(context.Context) error { marks++; commitsAtMark = len(f.store.commits); return markErr }})
	if e != nil {
		t.Fatal(e)
	}
	f.clock.at = 100
	if _, e = svc.Act(context.Background(), f.writer, issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: current.Revision, IssueID: current.ID, Kind: "resolve", Reason: "r"}); e != nil || marks != 0 {
		t.Fatalf("an action that writes no D92 record raised the marker: marks %d, %v", marks, e)
	}
	current = f.issueFor(1)
	owner := model.ID{0xa1}
	assign := issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: current.Revision, IssueID: current.ID, Kind: "assign", Owner: &owner}
	markErr = model.Fail(model.Unavailable)
	commits := len(f.store.commits)
	if _, e = svc.Act(context.Background(), f.writer, assign); e == nil || marks != 1 || len(f.store.commits) != commits {
		t.Fatalf("an assign whose marker could not be written: marks %d, commits %d -> %d, %v", marks, commits, len(f.store.commits), e)
	}
	markErr = nil
	if got, e := svc.Act(context.Background(), f.writer, assign); e != nil || got.Owner == nil || marks != 2 || commitsAtMark != commits {
		t.Fatalf("assign with the marker: marks %d, commits at the mark %d (want %d), %v", marks, commitsAtMark, commits, e)
	}
}
