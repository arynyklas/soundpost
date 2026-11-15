// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
)

// issueEnv is the human issue-action surface over the real stack: the real
// control store and auth, the REAL issues.Service the node binds
// (App.NewIssueActions) behind the real C11 routes. Only the issue's evidence
// is seeded, through the lifecycle's own system door (ApplyThrough), exactly as
// the producer does.
type issueEnv struct {
	*actEnv
	svc *issues.Service
}

func newIssueEnv(t *testing.T) *issueEnv {
	t.Helper()
	e := &issueEnv{actEnv: newActEnv(t)}
	var err error
	if e.svc, err = e.app.NewIssueActions(wallClock{}); err != nil {
		t.Fatal(err)
	}
	e.actions.BindIssues(e.svc)
	return e
}

// seed lands one occurrence of a new fingerprint and returns the issue it made.
func (e *issueEnv) seed(org, project model.ID, fingerprint byte) model.ID {
	e.t.Helper()
	system, err := e.app.Auth.AuthorizeSystem(e.ctx, org, []model.ID{project}, auth.IssuesWrite)
	if err != nil {
		e.t.Fatal(err)
	}
	at := model.UnixNano(time.Now().Add(-time.Hour).UnixNano())
	group := model.NewID()
	ev := issues.Evidence{OccurrenceID: model.NewID(), RecordID: model.NewID(), Origin: model.Cursor{Group: group, Index: 1}, GroupingVersion: 1, Fingerprint: model.Hash{fingerprint},
		EventTime: at, ArrivalTime: at + 1, Ancestry: "unknown", Freshness: "fresh", Ordinal: 1}
	if err = e.svc.ApplyThrough(e.ctx, system, model.Cursor{Group: group, Index: 1}, []issues.Evidence{ev}); err != nil {
		e.t.Fatal(err)
	}
	book, err := e.app.Control.IssueBook(e.ctx, system, project)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, gi := range book.Issues {
		if gi.Fingerprint == (model.Hash{fingerprint}) {
			return gi.ID
		}
	}
	e.t.Fatal("seeded issue not found")
	return model.ID{}
}

func uitoa(n uint64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// issueAct posts an issue action under a fresh command ID and returns it.
func (e *issueEnv) issueAct(who person, org, project, issue model.ID, kind string, expected uint64, payload map[string]any) (int, []byte, model.ID) {
	e.t.Helper()
	if payload == nil {
		payload = map[string]any{"reason": "issue action over HTTP"}
	}
	command := model.NewID()
	status, raw := e.retry(who, org, project, issue, command, kind, expected, payload)
	return status, raw, command
}

func (e *issueEnv) retry(who person, org, project, issue, command model.ID, kind string, expected uint64, payload map[string]any) (int, []byte) {
	e.t.Helper()
	return e.post(who, "/api/v1/actions", actBody{"org": org.String(), "command_id": command.String(), "expected_version": uitoa(expected), "project_id": project.String(), "target_id": issue.String(),
		"entity_kind": "issue", "kind": kind, "payload": payload})
}

type conflictBody struct {
	Code           string `json:"code"`
	Detail         string `json:"detail"`
	CurrentVersion string `json:"current_version"`
}

// audits returns the control audit rows of one action.
func (e *issueEnv) audits(action string) (out []model.ControlAudit) {
	e.t.Helper()
	if err := e.app.Control.View(e.ctx, func(st model.ControlState) error {
		for _, a := range st.Audits {
			if a.Action == action {
				out = append(out, a)
			}
		}
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func (e *issueEnv) committed(status int, raw []byte, workflow string, revision string) httpapi.ActionResponse {
	e.t.Helper()
	r := e.respond(status, raw)
	if r.State != httpapi.ActionCommitted || r.EntityKind != httpapi.EntityIssue || r.Issue == nil || r.Incident != nil || r.Revision == nil || r.Issue.Workflow != workflow || uitoa(uint64(r.Issue.Revision)) != revision || uitoa(uint64(*r.Revision)) != revision {
		e.t.Fatalf("committed issue answer %s/%s: %+v", workflow, revision, r)
	}
	return r
}

// A person with issues.write (or an organization administrator) resolves,
// ignores, unignores and reopens an issue through the real action route; the
// answer is the issue exactly as the lifecycle committed it, the actor is the
// caller, a stale revision is a typed 409 with the current revision, and a retry
// of a command ID answers the first result.
func TestIssueActionsOverHTTP(t *testing.T) {
	e := newIssueEnv(t)
	p1 := model.NewID()
	org := e.org("issue actions org", p1)
	admin := e.user(org, "admin-issue@example.test")
	gina := e.user(org, "gina-issue@example.test")   // issues.write on p1
	erin := e.user(org, "erin-issue@example.test")   // incidents.write on p1
	frank := e.user(org, "frank-issue@example.test") // telemetry.read on p1
	hank := e.user(org, "hank-issue@example.test")   // policy.write on p1
	e.admin(org, admin)
	e.grant(org, gina, p1, true, auth.IssuesWrite)
	e.grant(org, erin, p1, true, auth.IncidentsWrite)
	e.grant(org, frank, p1, true, auth.Read)
	e.grant(org, hank, p1, true, auth.PolicyWrite)
	issue := e.seed(org, p1, 1)

	// Resolve as gina: committed, human actor, revision 2, a resolution boundary.
	status, raw, command := e.issueAct(gina, org, p1, issue, "resolve", 1, map[string]any{"reason": "fixed in the next release"})
	r := e.committed(status, raw, "resolved", "2")
	if r.Issue.ID != issue || r.Issue.ResolutionTime == nil {
		t.Fatalf("resolve answer: %+v", r.Issue)
	}
	resolve := e.audits("issues.resolve")
	if len(resolve) != 1 || resolve[0].Principal != gina.ID || resolve[0].Reason != "fixed in the next release" || resolve[0].ID != command {
		t.Fatalf("the resolve audit must name the person who acted: %+v", resolve)
	}

	// A retry of the same command ID answers the first result and acts once.
	status, raw = e.retry(gina, org, p1, issue, command, "resolve", 1, map[string]any{"reason": "fixed in the next release"})
	e.committed(status, raw, "resolved", "2")
	if got := e.audits("issues.resolve"); len(got) != 1 {
		t.Fatalf("a retried command audited twice: %+v", got)
	}

	// A stale revision is a typed 409 carrying the revision the issue is at.
	status, raw, _ = e.issueAct(gina, org, p1, issue, "reopen", 1, nil)
	var conflict conflictBody
	if status != http.StatusConflict || json.Unmarshal(raw, &conflict) != nil || conflict.Code != "conflict" || conflict.Detail != "issue_version_conflict" || conflict.CurrentVersion != "2" {
		t.Fatalf("stale revision: %d %s", status, raw)
	}

	// Reopen (gina), ignore (the administrator acts as a person with no grant of
	// their own), unignore (gina): each moves the revision by one.
	status, raw, _ = e.issueAct(gina, org, p1, issue, "reopen", 2, nil)
	e.committed(status, raw, "open", "3")
	status, raw, _ = e.issueAct(admin, org, p1, issue, "ignore", 3, nil)
	e.committed(status, raw, "ignored", "4")
	if got := e.audits("issues.ignore"); len(got) != 1 || got[0].Principal != admin.ID {
		t.Fatalf("an administrator's action must name the administrator: %+v", got)
	}
	status, raw, _ = e.issueAct(gina, org, p1, issue, "unignore", 4, nil)
	e.committed(status, raw, "open", "5")

	// A transition the workflow forbids at the revision the caller saw is a 409
	// that says so (the revision did not move), not a version conflict.
	status, raw, _ = e.issueAct(gina, org, p1, issue, "reopen", 5, nil)
	if status != http.StatusConflict || json.Unmarshal(raw, &conflict) != nil || conflict.Detail != "issue_state_conflict" || conflict.CurrentVersion != "5" {
		t.Fatalf("forbidden transition: %d %s", status, raw)
	}

	// Anyone without issues.write (and no administration) gets the one denial of a
	// missing project, never a hint about the issue.
	var baseline string
	for name, who := range map[string]person{"incidents.write": erin, "telemetry.read": frank, "policy.write": hank} {
		status, raw, _ = e.issueAct(who, org, p1, issue, "resolve", 5, nil)
		if status != http.StatusNotFound {
			t.Fatalf("%s must not act on an issue: %d %s", name, status, raw)
		}
		if got := denial(t, status, raw); baseline == "" {
			baseline = got
		} else if got != baseline {
			t.Fatalf("%s is distinguishable: %s vs %s", name, got, baseline)
		}
	}
	// issues.write on one project reaches nothing on another.
	p2 := model.NewID()
	e.cmd(org, "create_project", auth.AdminPayload{ID: p2, Name: "second"})
	if status, raw, _ = e.issueAct(gina, org, p2, issue, "resolve", 5, nil); status != http.StatusNotFound {
		t.Fatalf("issues.write is project-scoped: %d %s", status, raw)
	}
	// An issue of another project is not found, not a conflict.
	other := e.seed(org, p2, 9)
	if status, raw, _ = e.issueAct(admin, org, p1, other, "resolve", 1, nil); status != http.StatusNotFound {
		t.Fatalf("an issue of another project: %d %s", status, raw)
	}

	// Payload discipline: a field the kind does not take is refused, and the
	// issue-only fields are refused on an incident action.
	migration := map[string]any{"id": model.NewID().String(), "to": model.NewID().String(), "grouping_version": 2, "fingerprint": model.Hash{7}.String()}
	for name, tc := range map[string]struct {
		kind    string
		payload map[string]any
	}{
		"owner on resolve":     {"resolve", map[string]any{"reason": "x", "owner": gina.ID.String()}},
		"until on ignore":      {"ignore", map[string]any{"reason": "x", "until": "1"}},
		"boundary on ignore":   {"ignore", map[string]any{"reason": "x", "resolution_boundary": "1"}},
		"frontier on reopen":   {"reopen", map[string]any{"reason": "x", "fixed_frontier": []string{model.NewID().String()}}},
		"migration on resolve": {"resolve", map[string]any{"reason": "x", "migration": migration}},
		"no migration":         {"grouping_migration", map[string]any{"reason": "x"}},
		"no reason":            {"resolve", map[string]any{"reason": ""}},
	} {
		if status, raw, _ = e.issueAct(admin, org, p1, issue, tc.kind, 5, tc.payload); status != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
	}
	one, _, _ := e.open(org, p1, incidents.SeverityMinor)
	bad := act(org, p1, one, "ack", 1, map[string]any{"resolution_boundary": "1"})
	if status, raw = e.post(admin, "/api/v1/actions", bad); status != http.StatusBadRequest {
		t.Fatalf("issue-only field on an incident action: %d %s", status, raw)
	}

	// Revocation applies at once.
	e.grant(org, gina, p1, false)
	if status, raw, _ = e.issueAct(gina, org, p1, issue, "ignore", 5, nil); status != http.StatusNotFound {
		t.Fatalf("a revoked grant must not act: %d %s", status, raw)
	}
}

// The grouping migration needs issues.write AND policy.write (or administration):
// the person who holds both migrates under their own name, the person who holds
// only one gets the one denial, and the migration is audited and idempotent.
func TestIssueGroupingMigrationOverHTTP(t *testing.T) {
	e := newIssueEnv(t)
	p1 := model.NewID()
	org := e.org("migration org", p1)
	admin := e.user(org, "admin-mig@example.test")
	gina := e.user(org, "gina-mig@example.test") // issues.write
	hank := e.user(org, "hank-mig@example.test") // policy.write
	june := e.user(org, "june-mig@example.test") // issues.write + policy.write
	e.admin(org, admin)
	e.grant(org, gina, p1, true, auth.IssuesWrite)
	e.grant(org, hank, p1, true, auth.PolicyWrite)
	e.grant(org, june, p1, true, auth.IssuesWrite, auth.PolicyWrite)
	issue := e.seed(org, p1, 1)
	migration := func(to model.ID, fp byte) map[string]any {
		return map[string]any{"reason": "regroup under grouping v2", "migration": map[string]any{"id": model.NewID().String(), "to": to.String(), "grouping_version": 2, "fingerprint": model.Hash{fp}.String()}}
	}

	for name, who := range map[string]person{"issues.write only": gina, "policy.write only": hank} {
		if status, raw, _ := e.issueAct(who, org, p1, issue, "grouping_migration", 1, migration(model.NewID(), 5)); status != http.StatusNotFound {
			t.Fatalf("%s must not migrate: %d %s", name, status, raw)
		}
	}
	if got := e.audits("issues.grouping_migration"); len(got) != 0 {
		t.Fatalf("a refused migration left an audit: %+v", got)
	}

	to := model.NewID()
	payload := migration(to, 5)
	status, raw, command := e.issueAct(june, org, p1, issue, "grouping_migration", 1, payload)
	r := e.committed(status, raw, "open", "2")
	if len(r.Issue.MigrationLinks) != 1 {
		t.Fatalf("the migrated issue carries the link: %+v", r.Issue)
	}
	got := e.audits("issues.grouping_migration")
	if len(got) != 1 || got[0].Principal != june.ID || got[0].Reason != "regroup under grouping v2" || got[0].Targets[0] != issue || got[0].Targets[1] != to {
		t.Fatalf("the migration audit must name the person who migrated: %+v", got)
	}
	// The new issue exists under the new grouping version, open at revision 1.
	system, err := e.app.Auth.AuthorizeSystem(e.ctx, org, []model.ID{p1}, auth.IssuesWrite)
	if err != nil {
		t.Fatal(err)
	}
	moved, err := e.svc.Get(e.ctx, system, p1, to)
	if err != nil || moved.GroupingVersion != 2 || moved.Revision != 1 || moved.Workflow != "open" {
		t.Fatalf("migrated issue: %+v %v", moved, err)
	}

	// A retry of the same command answers the committed issue and migrates once.
	status, raw = e.retry(june, org, p1, issue, command, "grouping_migration", 1, payload)
	if r = e.committed(status, raw, "open", "2"); len(r.Issue.MigrationLinks) != 1 {
		t.Fatalf("retried migration: %+v", r.Issue)
	}
	if got = e.audits("issues.grouping_migration"); len(got) != 1 {
		t.Fatalf("a retried migration audited twice: %+v", got)
	}

	// The administrator migrates another issue with no grant of their own, and a
	// migration onto an existing issue is a conflict, never a merge.
	second := e.seed(org, p1, 2)
	status, raw, _ = e.issueAct(admin, org, p1, second, "grouping_migration", 1, migration(model.NewID(), 6))
	e.committed(status, raw, "open", "2")
	if got = e.audits("issues.grouping_migration"); len(got) != 2 || got[1].Principal != admin.ID {
		t.Fatalf("the administrator's migration: %+v", got)
	}
	third := e.seed(org, p1, 3)
	if status, raw, _ = e.issueAct(admin, org, p1, third, "grouping_migration", 1, migration(to, 7)); status != http.StatusConflict {
		t.Fatalf("a migration onto an existing issue: %d %s", status, raw)
	}
	// A stale source revision is a conflict that names the current revision.
	var conflict conflictBody
	status, raw, _ = e.issueAct(admin, org, p1, third, "grouping_migration", 5, migration(model.NewID(), 8))
	if status != http.StatusConflict || json.Unmarshal(raw, &conflict) != nil || conflict.Detail != "issue_version_conflict" || conflict.CurrentVersion != "1" {
		t.Fatalf("stale source revision: %d %s", status, raw)
	}
	// Revoking policy.write ends the right at once.
	e.grant(org, june, p1, true, auth.IssuesWrite)
	if status, raw, _ = e.issueAct(june, org, p1, third, "grouping_migration", 1, migration(model.NewID(), 9)); status != http.StatusNotFound {
		t.Fatalf("a revoked policy.write must not migrate: %d %s", status, raw)
	}
}

// A project whose deletion saga is fencing denies issue actions (retryable, never
// success); once the fence is complete the project is usable again.
func TestIssueActionsAreDeniedWhileADeletionFences(t *testing.T) {
	e := newIssueEnv(t)
	p1 := model.NewID()
	org := e.org("fence org", p1)
	admin := e.user(org, "admin-fence@example.test")
	e.admin(org, admin)
	issue := e.seed(org, p1, 1)

	// A real deletion saga over the project's errors of a far past range (so the
	// seeded evidence is not erased), begun through control and left fencing: no
	// data slot has recorded its barrier yet.
	adminScope, err := e.app.Auth.Authorize(e.ctx, e.actor.Cred, org, []model.ID{p1}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	now := model.UnixNano(time.Now().UnixNano())
	payload, _ := json.Marshal(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{p1}, Signals: []model.Kind{model.ErrorKind}, Start: 1, End: 1000, Reason: "fence the issues", At: now,
		PhysicalDeadline: now + model.UnixNano(24*time.Hour), BackupDeadline: now + model.UnixNano(30*24*time.Hour)})
	var revision model.Revision
	if err = e.app.Control.View(e.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	op := model.NewID()
	if _, err = e.app.Control.Transact(e.ctx, adminScope, control.Command{CommandID: op, ExpectedRevision: revision, Kind: string(control.KindDeleteScope), Payload: payload}); err != nil {
		t.Fatal(err)
	}
	status, raw, _ := e.issueAct(admin, org, p1, issue, "resolve", 1, nil)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("a fencing project must deny the action (retryable): %d %s", status, raw)
	}
	var f model.Fault
	if json.Unmarshal(raw, &f) != nil || f.SafeDetail != "deletion_fencing" || !f.Retryable {
		t.Fatalf("fence denial: %s", raw)
	}
	if got := e.audits("issues.resolve"); len(got) != 0 {
		t.Fatalf("a denied action audited: %+v", got)
	}
	// Another project of the same organization is not fenced by it.
	p2 := model.NewID()
	e.cmd(org, "create_project", auth.AdminPayload{ID: p2, Name: "bystander"})
	bystander := e.seed(org, p2, 4)
	status, raw, _ = e.issueAct(admin, org, p2, bystander, "resolve", 1, nil)
	e.committed(status, raw, "resolved", "2")

	// Once the fence is complete the project is usable again.
	barriers := make([]model.Cursor, model.DeleteSlots)
	for i := range barriers {
		barriers[i] = model.Cursor{Group: model.NewID(), Index: model.Uint64(i + 1)}
	}
	if _, err = e.app.Control.RecordBarriers(e.ctx, op, barriers); err != nil {
		t.Fatal(err)
	}
	if _, err = e.app.Control.CompleteDeletion(e.ctx, op, now, nil); err != nil {
		t.Fatal(err)
	}
	status, raw, _ = e.issueAct(admin, org, p1, issue, "resolve", 1, nil)
	e.committed(status, raw, "resolved", "2")
}

// Resolve may name the releases that contain the fix and an explicit boundary:
// the frontier must be releases of this project's graph (read under the caller's
// own scope), and a release the project does not have is refused, not recorded.
func TestIssueResolveNamesTheFixedFrontier(t *testing.T) {
	e := newIssueEnv(t)
	p1 := model.NewID()
	org := e.org("frontier org", p1)
	gina := e.user(org, "gina-frontier@example.test")
	e.grant(org, gina, p1, true, auth.IssuesWrite)
	issue := e.seed(org, p1, 1)

	scope, err := e.app.Auth.Authorize(e.ctx, e.actor.Cred, org, []model.ID{p1}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	var revision model.Revision
	if err = e.app.Control.View(e.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	fix := model.NewID()
	if _, err = e.app.Releases.Register(e.ctx, scope, model.Release{ID: fix, Org: org, Project: p1, BuildID: model.NewID(), BuildTime: 1, Parents: []model.ID{}, DisplayLabel: "v2"}, revision, model.NewID()); err != nil {
		t.Fatal(err)
	}

	// A release the project does not have is refused and nothing is recorded.
	status, raw, _ := e.issueAct(gina, org, p1, issue, "resolve", 1, map[string]any{"reason": "fixed", "fixed_frontier": []string{model.NewID().String()}})
	if status != http.StatusBadRequest {
		t.Fatalf("an unknown release in the frontier: %d %s", status, raw)
	}
	if got := e.audits("issues.resolve"); len(got) != 0 {
		t.Fatalf("a refused resolve audited: %+v", got)
	}
	// The boundary may not lie in the future.
	future := model.Int64(time.Now().Add(time.Hour).UnixNano())
	if status, raw, _ = e.issueAct(gina, org, p1, issue, "resolve", 1, map[string]any{"reason": "fixed", "resolution_boundary": future}); status != http.StatusBadRequest {
		t.Fatalf("a future boundary: %d %s", status, raw)
	}

	boundary := model.Int64(time.Now().Add(-30 * time.Minute).UnixNano())
	status, raw, _ = e.issueAct(gina, org, p1, issue, "resolve", 1, map[string]any{"reason": "fixed in v2", "fixed_frontier": []string{fix.String()}, "resolution_boundary": boundary})
	r := e.committed(status, raw, "resolved", "2")
	if len(r.Issue.FixedDescendants) != 1 || r.Issue.FixedDescendants[0] != fix || r.Issue.ResolutionTime == nil || *r.Issue.ResolutionTime != boundary {
		t.Fatalf("the frontier and boundary the caller named: %+v", r.Issue)
	}
}
