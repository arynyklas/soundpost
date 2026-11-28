// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
)

// member creates an organization member with the given project grants, logs them
// in over the real session path and returns their credential.
func (n *workerNode) member(email string, permissions ...auth.Permission) (model.ID, auth.Credential) {
	n.t.Helper()
	id := model.NewID()
	n.command("create_user", auth.AdminPayload{ID: id, Email: email, Password: "issue actions member password"})
	n.command("membership", auth.AdminPayload{UserID: id, Enabled: true})
	ps := make([]string, len(permissions))
	for i, p := range permissions {
		ps[i] = string(p)
	}
	n.command("grant", auth.AdminPayload{UserID: id, ProjectID: n.project, Permissions: ps, Enabled: true})
	login, err := n.app.Auth.Login(n.ctx, email, "issue actions member password", "")
	if err != nil {
		n.t.Fatal(err)
	}
	cred, err := n.app.Auth.Authenticate(n.ctx, login.Token)
	if err != nil {
		n.t.Fatal(err)
	}
	return id, cred
}

func (n *workerNode) scopeOf(cred auth.Credential, permission auth.Permission) auth.Scope {
	n.t.Helper()
	s, err := n.app.Auth.Authorize(n.ctx, cred, n.org, []model.ID{n.project}, permission)
	if err != nil {
		n.t.Fatal(err)
	}
	return s
}

func issueRequest(project, issue model.ID, kind httpapi.ActionKind, expected uint64, payload httpapi.ActionPayload) httpapi.ActionRequest {
	return httpapi.ActionRequest{CommandID: model.NewID(), ExpectedVersion: model.Uint64(expected), ProjectID: project, TargetID: issue, EntityKind: httpapi.EntityIssue, Kind: kind, Payload: payload}
}

func migrationPayload(to model.ID, fp byte) httpapi.ActionPayload {
	return httpapi.ActionPayload{Reason: "regroup under grouping v2", Migration: &httpapi.MigrationPayload{ID: model.NewID(), To: to, GroupingVersion: 2, Fingerprint: model.Hash{fp}}}
}

// An error ingested through a source credential becomes an issue through the
// real producer; a person then resolves, ignores and reopens it through the
// node's own action surface (App.Actions bound by BindIssueActions), and the
// grouping migration is refused to every scope that does not hold BOTH
// issues.write and policy.write, below the HTTP route that would filter first.
func TestHumanIssueActionsOverTheProducedIssue(t *testing.T) {
	r := newIssueRig(t)
	r.ingest("TypeError", 5, false, true)
	r.tick(r.workers())
	snap := r.snapshot()
	if len(snap.Issues) != 1 {
		t.Fatalf("setup: issues %+v", snap.Issues)
	}
	issue := snap.Issues[0].ID

	admin := r.admin()
	if err := r.app.BindIssueActions(); err != nil {
		t.Fatal(err)
	}

	// The organization administrator acts as a person: resolve, reopen, ignore.
	resolved, err := r.app.Actions.Act(r.ctx, admin, issueRequest(r.project, issue, httpapi.ActionResolve, 1, httpapi.ActionPayload{Reason: "fixed"}))
	if err != nil || resolved.State != httpapi.ActionCommitted || resolved.Issue == nil || resolved.Issue.Workflow != "resolved" || resolved.Issue.Revision != 2 {
		t.Fatalf("resolve: %+v %v", resolved, err)
	}
	if got := r.snapshot().Issues[0]; got.Workflow != "resolved" || got.Revision != 2 {
		t.Fatalf("the committed issue: %+v", got)
	}
	var actor model.ID
	if err = r.app.Control.View(r.ctx, func(st model.ControlState) error {
		for _, a := range st.Audits {
			if a.Action == "issues.resolve" {
				actor = a.Principal
			}
		}
		return nil
	}); err != nil || actor != r.user || auth.IsSystemPrincipal(actor) {
		t.Fatalf("the resolve audit actor is %s, want the person %s (%v)", actor, r.user, err)
	}
	if _, err = r.app.Actions.Act(r.ctx, admin, issueRequest(r.project, issue, httpapi.ActionReopen, 2, httpapi.ActionPayload{Reason: "still happening"})); err != nil {
		t.Fatal(err)
	}

	// The runner's organization-administrator scope is no actor of this surface.
	runner := r.system(auth.OrgAdmin)
	if _, err = r.app.Actions.Act(r.ctx, runner, issueRequest(r.project, issue, httpapi.ActionIgnore, 3, httpapi.ActionPayload{Reason: "runner"})); issueFault(err) != model.Forbidden {
		t.Fatalf("the runner's org.admin scope acted on an issue: %v", err)
	}
	if got := r.snapshot().Issues[0]; got.Workflow != "open" || got.Revision != 3 {
		t.Fatalf("the runner changed the issue: %+v", got)
	}

	// Migration below the route: issues.write alone and policy.write alone are
	// refused by the lifecycle itself; both together migrate under their own name.
	ginaID, gina := r.member("gina-issues@example.test", auth.IssuesWrite)
	_, hank := r.member("hank-issues@example.test", auth.PolicyWrite)
	juneID, june := r.member("june-issues@example.test", auth.IssuesWrite, auth.PolicyWrite)
	to := model.NewID()
	if _, err = r.app.Actions.Act(r.ctx, r.scopeOf(gina, auth.IssuesWrite), issueRequest(r.project, issue, httpapi.ActionGroupMigration, 3, migrationPayload(to, 5))); err == nil {
		t.Fatal("issues.write alone migrated")
	}
	if _, err = r.app.Actions.Act(r.ctx, r.scopeOf(hank, auth.PolicyWrite), issueRequest(r.project, issue, httpapi.ActionGroupMigration, 3, migrationPayload(to, 5))); err == nil {
		t.Fatal("policy.write alone migrated")
	}
	if len(r.snapshot().Issues) != 1 {
		t.Fatalf("a refused migration changed the book: %+v", r.snapshot().Issues)
	}
	// Direct to the lifecycle, bypassing the C11 handler: the same refusal.
	svc, err := r.app.NewIssueActions(r.clock)
	if err != nil {
		t.Fatal(err)
	}
	direct := issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: 3, IssueID: issue, Kind: "grouping_migration", Reason: "direct",
		Migration: &model.GroupingMigration{ID: model.NewID(), Org: r.org, Project: r.project, From: issue, To: to, FromRevision: 3, GroupingVersion: 2, Fingerprint: model.Hash{5}, Reason: "direct", At: 1}}
	if _, err = svc.Act(r.ctx, r.scopeOf(gina, auth.IssuesWrite), direct); err == nil {
		t.Fatal("the lifecycle migrated for issues.write alone")
	}

	migrated, err := r.app.Actions.Act(r.ctx, r.scopeOf(june, auth.IssuesWrite), issueRequest(r.project, issue, httpapi.ActionGroupMigration, 3, migrationPayload(to, 5)))
	if err != nil || migrated.State != httpapi.ActionCommitted || migrated.Issue == nil || len(migrated.Issue.MigrationLinks) != 1 {
		t.Fatalf("migration: %+v %v", migrated, err)
	}
	snap = r.snapshot()
	if len(snap.Issues) != 2 {
		t.Fatalf("the migration must add the new issue: %+v", snap.Issues)
	}
	var migrationActor model.ID
	if err = r.app.Control.View(r.ctx, func(st model.ControlState) error {
		for _, a := range st.Audits {
			if a.Action == "issues.grouping_migration" {
				migrationActor = a.Principal
			}
		}
		return nil
	}); err != nil || migrationActor != juneID || migrationActor == ginaID {
		t.Fatalf("the migration audit actor is %s, want %s (%v)", migrationActor, juneID, err)
	}

	// The evidence the producer committed is untouched by the migration: the
	// occurrence stays on the original issue.
	for _, gi := range snap.Issues {
		if gi.ID == issue && len(gi.Occurrences) != 1 {
			t.Fatalf("the migration rewrote history: %+v", gi)
		}
	}
	// The producer keeps working after human actions (the ledger is one history).
	r.ingest("RangeError", 6, true, false)
	r.tick(r.workers())
	if got := len(r.snapshot().Issues); got != 3 {
		t.Fatalf("issues after more evidence: %d", got)
	}
}

func issueFault(err error) model.Code {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.Code
	}
	return ""
}

// The control store admits the issue lifecycle writes only to the scopes the
// decision names: the runner's org.admin scope commits nothing there, and a
// migration needs a person (never the runner) holding both grants.
func TestIssueControlWritesRefuseTheRunnerAsAnActor(t *testing.T) {
	r := newIssueRig(t)
	r.ingest("TypeError", 5, false, true)
	r.tick(r.workers())
	issue := r.snapshot().Issues[0].ID
	to := model.NewID()
	payload, err := json.Marshal(model.ReleaseCommand{Operation: "grouping_migration", At: 1, RequestID: model.NewID(), Migration: &model.GroupingMigration{ID: model.NewID(), Org: r.org, Project: r.project, From: issue, To: to, FromRevision: 1, GroupingVersion: 2, Fingerprint: model.Hash{5}, Reason: "runner", At: 1}})
	if err != nil {
		t.Fatal(err)
	}
	for name, scope := range map[string]auth.Scope{"org.admin": r.system(auth.OrgAdmin), "issues.write": r.system(auth.IssuesWrite)} {
		if _, err = r.app.Control.TransactIssues(r.ctx, scope, control.Command{CommandID: model.NewID(), Kind: string(control.KindApplyIssueEvidence), Payload: payload}); err == nil {
			t.Fatalf("the runner's %s scope committed a grouping migration", name)
		}
		if err = r.app.Control.AuthorizePolicyWrite(r.ctx, scope, r.project); err == nil {
			t.Fatalf("the runner's %s scope holds policy.write", name)
		}
	}
	// A commit that is valid in every respect except who sends it: the scope's own
	// principal, organization and policy epoch, the book's current revision.
	runnerAdmin := r.system(auth.OrgAdmin)
	commit, err := json.Marshal(control.IssueCommand{Operation: "commit", Project: r.project, ExpectedRevision: r.snapshot().Revision, Audits: []model.ControlAudit{{ID: model.NewID(), Principal: auth.SystemPrincipal(r.org), Action: "issues.resolve", Reason: "runner", Time: 1, Org: r.org.String(), PolicyEpoch: runnerAdmin.PolicyEpoch(), Targets: []model.ID{issue}, Outcome: model.AuditAllowed}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.app.Control.TransactIssues(r.ctx, runnerAdmin, control.Command{CommandID: control.IssueCommandID(commit), Kind: string(control.KindApplyIssueEvidence), Payload: commit}); issueFault(err) != model.Forbidden {
		t.Fatalf("the runner's org.admin scope wrote the issue book: %v", err)
	}
	if got := r.snapshot().Issues[0]; got.Workflow != "open" || got.Revision != 1 {
		t.Fatalf("the issue changed: %+v", got)
	}
}
