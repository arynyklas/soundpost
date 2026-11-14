// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package releases_test

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/releases"
	"reflect"
	"testing"
)

type releaseFixture struct {
	app          *appcore.App
	org, project model.ID
	scope        auth.Scope
	token        string
	dir          string
}

func setupReleaseFixture(t *testing.T) *releaseFixture {
	t.Helper()
	f := &releaseFixture{dir: t.TempDir(), org: model.NewID(), project: model.NewID()}
	var e error
	f.app, e = appcore.Open(f.dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if f.app != nil {
			f.app.Close()
		}
	})
	ctx := context.Background()
	bootstrap, e := f.app.Control.BootstrapToken()
	if e != nil {
		t.Fatal(e)
	}
	session, e := f.app.Auth.Bootstrap(ctx, bootstrap, "release@example.test", "release fixture password 2026")
	if e != nil {
		t.Fatal(e)
	}
	f.token = session.Token
	actor, e := f.app.Auth.Authenticate(ctx, f.token)
	if e != nil {
		t.Fatal(e)
	}
	for _, cmd := range []struct {
		kind string
		p    auth.AdminPayload
	}{{"create_org", auth.AdminPayload{Name: "releases"}}, {"create_project", auth.AdminPayload{ID: f.project, Name: "application"}}} {
		cmd.p.Reason = "release behavior fixture"
		raw, e := json.Marshal(cmd.p)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: f.revision(t), OrgID: f.org, Kind: cmd.kind, Payload: raw}); e != nil {
			t.Fatal(e)
		}
	}
	f.scope, e = f.app.Auth.Authorize(ctx, actor, f.org, nil, auth.OrgAdmin)
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *releaseFixture) revision(t *testing.T) model.Revision {
	t.Helper()
	var revision model.Revision
	if e := f.app.Control.View(context.Background(), func(st model.ControlState) error { revision = st.Revision; return nil }); e != nil {
		t.Fatal(e)
	}
	return revision
}
func (f *releaseFixture) restart(t *testing.T) {
	t.Helper()
	if e := f.app.Close(); e != nil {
		t.Fatal(e)
	}
	f.app = nil
	var e error
	f.app, e = appcore.Open(f.dir)
	if e != nil {
		t.Fatal(e)
	}
	actor, e := f.app.Auth.Authenticate(context.Background(), f.token)
	if e != nil {
		t.Fatal(e)
	}
	f.scope, e = f.app.Auth.Authorize(context.Background(), actor, f.org, nil, auth.OrgAdmin)
	if e != nil {
		t.Fatal(e)
	}
}

func TestReleaseRestart(t *testing.T) {
	f := setupReleaseFixture(t)
	ctx := context.Background()
	root := releases.Release{ID: model.NewID(), Org: f.org, Project: f.project, BuildID: model.NewID(), BuildTime: 17, DisplayLabel: "v9"}
	command := model.NewID()
	first, e := f.app.Releases.Register(ctx, f.scope, root, f.revision(t), command)
	if e != nil {
		t.Fatal(e)
	}
	if first.Revision != 1 {
		t.Fatalf("entity revision %v", first.Revision)
	}
	occurrence := model.ErrorOccurrence{Class: "Error", Mechanism: "manual", Build: root.BuildID, Release: &root.ID, Frames: []model.Frame{{Module: "app", Function: "run", Artifact: "app.go", Line: 1, InApp: true}}}
	originalHash, e := issues.Fingerprint(1, f.org, f.project, occurrence)
	if e != nil {
		t.Fatal(e)
	}
	child := releases.Release{ID: model.NewID(), Org: f.org, Project: f.project, BuildID: model.NewID(), BuildTime: 3, Parents: []model.ID{root.ID}, DebugArtifacts: []model.ReleaseDebugArtifact{{ArtifactID: model.NewID(), DebugID: "build-debug", SHA256: model.Hash{1}}}, DisplayLabel: "v10"}
	child, e = f.app.Releases.Register(ctx, f.scope, child, f.revision(t), model.NewID())
	if e != nil {
		t.Fatal(e)
	}
	first.DisplayLabel = "friendly name"
	renamed, e := f.app.Releases.Register(ctx, f.scope, first, f.revision(t), model.NewID())
	if e != nil {
		t.Fatal(e)
	}
	if renamed.Revision != 2 {
		t.Fatal("label edit did not increment entity revision")
	}
	if _, e = f.app.Releases.Register(ctx, f.scope, renamed, 0, model.NewID()); e == nil {
		t.Fatal("stale control revision committed")
	}
	before := f.revision(t)
	for _, mutation := range []func(*releases.Release){func(r *releases.Release) { r.BuildID = model.NewID() }, func(r *releases.Release) { r.BuildTime++ }, func(r *releases.Release) { r.Parents = []model.ID{model.NewID()} }, func(r *releases.Release) {
		r.DebugArtifacts = []model.ReleaseDebugArtifact{{ArtifactID: model.NewID(), DebugID: "different", SHA256: model.Hash{2}}}
	}, func(r *releases.Release) { r.Revision = 1 }} {
		attempt := renamed
		mutation(&attempt)
		if _, e = f.app.Releases.Register(ctx, f.scope, attempt, before, model.NewID()); e == nil {
			t.Fatal("immutable/stale release edit committed")
		}
		if f.revision(t) != before {
			t.Fatal("rejected graph edit mutated durable state")
		}
	}
	// Unknown parents may be registered, but completing a cycle may not commit.
	a, b := model.NewID(), model.NewID()
	if _, e = f.app.Releases.Register(ctx, f.scope, releases.Release{ID: a, Org: f.org, Project: f.project, BuildID: model.NewID(), Parents: []model.ID{b}}, f.revision(t), model.NewID()); e != nil {
		t.Fatal(e)
	}
	if _, e = f.app.Releases.Register(ctx, f.scope, releases.Release{ID: b, Org: f.org, Project: f.project, BuildID: model.NewID(), Parents: []model.ID{a}}, f.revision(t), model.NewID()); e == nil {
		t.Fatal("cycle committed")
	}
	foreign := renamed
	foreign.Org = model.NewID()
	if _, e = f.app.Releases.Register(ctx, f.scope, foreign, f.revision(t), model.NewID()); e == nil {
		t.Fatal("caller org label authorized write")
	}
	foreign = renamed
	foreign.Project = model.NewID()
	if _, e = f.app.Releases.Register(ctx, f.scope, foreign, f.revision(t), model.NewID()); e == nil {
		t.Fatal("foreign project write committed")
	}
	if _, e = f.app.Releases.Register(ctx, auth.Scope{}, renamed, f.revision(t), model.NewID()); e == nil {
		t.Fatal("forged scope accepted")
	}
	f.restart(t)
	got, e := f.app.Releases.Get(ctx, f.scope, f.project, root.ID)
	if e != nil || !reflect.DeepEqual(got, renamed) {
		t.Fatalf("release lost identity across restart: %#v %v", got, e)
	}
	occurrence.Build = got.BuildID
	occurrence.Release = &got.ID
	afterHash, e := issues.Fingerprint(1, f.org, f.project, occurrence)
	if e != nil || afterHash != originalHash {
		t.Fatal("rename/restart changed grouping identity")
	}
	graph, e := f.app.Releases.Graph(ctx, f.scope, f.project)
	if e != nil {
		t.Fatal(e)
	}
	if releases.Relation(graph, root.ID, child.ID) != releases.Ancestor {
		t.Fatal("restart changed ancestry")
	}
	replay, e := f.app.Releases.Register(ctx, f.scope, root, 0, command)
	if e != nil || replay.Revision != first.Revision || replay.DisplayLabel != "v9" {
		t.Fatalf("command replay changed original response: %#v %v", replay, e)
	}
	// A different store must not see either handlers' state or releases.
	other, e := appcore.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if _, e = other.Releases.Get(ctx, f.scope, f.project, root.ID); e == nil {
		t.Fatal("foreign store accepted another authority's scope")
	}
}

func TestGroupingMigrationAudit(t *testing.T) {
	f := setupReleaseFixture(t)
	ctx := context.Background()
	old := model.GroupingIssue{ID: model.NewID(), Org: f.org, Project: f.project, GroupingVersion: 1, Fingerprint: model.Hash{1}, Workflow: "resolved", Revision: 4, Occurrences: []model.GroupingEvidence{{OccurrenceID: model.NewID(), RecordID: model.NewID(), Origin: model.Cursor{Group: model.NewID(), Index: 8}, EventTime: 9, ArrivalTime: 12}}}
	resolutionTime := model.UnixNano(20)
	old.ResolutionTime = &resolutionTime
	old.ResolutionFrontier = []model.ID{model.NewID()}
	old.FixedDescendants = []model.ID{model.NewID()}
	old.LateHistory = []model.GroupingEvidence{{OccurrenceID: model.NewID(), RecordID: model.NewID(), Origin: model.Cursor{Group: model.NewID(), Index: 7}, EventTime: 8, ArrivalTime: 23}}
	// Existing committed lifecycle state is the fixture prerequisite; the migration itself must use Transact.
	if e := f.app.Control.Update(ctx, func(st *model.ControlState) error {
		if st.GroupingIssues == nil {
			st.GroupingIssues = map[string]model.GroupingIssue{}
		}
		st.GroupingIssues[model.ReleaseScopeKey(old.Org, old.Project, old.ID)] = old
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	migration := model.GroupingMigration{ID: model.NewID(), Org: f.org, Project: f.project, From: old.ID, To: model.NewID(), FromRevision: old.Revision, GroupingVersion: 2, Fingerprint: model.Hash{2}, Reason: "approved safe grouping version", At: 25}
	command := model.NewID()
	result, e := f.app.Releases.MigrateGrouping(ctx, f.scope, migration, f.revision(t), command)
	if e != nil {
		t.Fatal(e)
	}
	if result.To != migration.To {
		t.Fatal("migration lost explicit target")
	}
	stale := migration
	stale.ID, stale.To = model.NewID(), model.NewID()
	beforeStale := f.revision(t)
	_, staleError := f.app.Releases.MigrateGrouping(ctx, f.scope, stale, beforeStale, model.NewID())
	var staleFault *model.Fault
	if !errors.As(staleError, &staleFault) || staleFault.Code != model.Conflict {
		t.Fatalf("stale source revision with a fresh target got %v", staleError)
	}
	if f.revision(t) != beforeStale {
		t.Fatal("stale source migration committed state")
	}
	f.restart(t)
	if _, e = f.app.Releases.MigrateGrouping(ctx, f.scope, migration, 0, command); e != nil {
		t.Fatalf("migration replay: %v", e)
	}
	addressable, e := f.app.Releases.GroupingIssue(ctx, f.scope, f.project, old.ID)
	if e != nil || !reflect.DeepEqual(addressable.Occurrences, old.Occurrences) || addressable.Workflow != "resolved" {
		t.Fatalf("old issue not addressable after restart: %v", e)
	}
	if _, e = f.app.Releases.GroupingIssue(ctx, f.scope, model.NewID(), old.ID); e == nil {
		t.Fatal("wrong project disclosed historical issue")
	}
	if e = f.app.Control.View(ctx, func(st model.ControlState) error {
		prior := st.GroupingIssues[model.ReleaseScopeKey(f.org, f.project, old.ID)]
		next := st.GroupingIssues[model.ReleaseScopeKey(f.org, f.project, migration.To)]
		if !reflect.DeepEqual(prior.Occurrences, old.Occurrences) || prior.Workflow != "resolved" || prior.GroupingVersion != 1 {
			t.Fatal("migration rewrote old issue/history")
		}
		if len(prior.MigrationLinks) != 1 || len(next.MigrationLinks) != 1 || next.Workflow != "open" || len(next.Occurrences) != 0 {
			t.Fatal("migration silently merged or lost links")
		}
		prior.MigrationLinks = nil
		prior.Revision = old.Revision
		if !reflect.DeepEqual(prior, old) {
			t.Fatal("migration altered prior lifecycle/frontier/history")
		}
		if len(st.GroupingMigrations) != 1 {
			t.Fatal("retry duplicated migration")
		}
		count := 0
		for _, audit := range st.Audits {
			if audit.Action == "issues.grouping_migration" {
				count++
				if audit.Principal != f.scope.PrincipalID() || audit.RequestID != command || audit.Reason != migration.Reason || audit.Outcome != model.AuditAllowed {
					t.Fatal("migration audit lacks committed actor/command/reason")
				}
			}
		}
		if count != 1 {
			t.Fatalf("migration audit count %d", count)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	collision := migration
	collision.ID = model.NewID()
	collision.FromRevision = old.Revision + 1
	if _, e = f.app.Releases.MigrateGrouping(ctx, f.scope, collision, f.revision(t), model.NewID()); e == nil {
		t.Fatal("existing target silently merged")
	}
}

func TestReleaseRequiresActualAdminPermission(t *testing.T) {
	f := setupReleaseFixture(t)
	ctx := context.Background()
	actor, e := f.app.Auth.Authenticate(ctx, f.token)
	if e != nil {
		t.Fatal(e)
	}
	readerID := model.NewID()
	for _, cmd := range []struct {
		kind string
		p    auth.AdminPayload
	}{
		{"create_user", auth.AdminPayload{ID: readerID, Email: "reader@example.test", Password: "reader fixture password 2026"}},
		{"membership", auth.AdminPayload{UserID: readerID, Enabled: true}},
		{"grant", auth.AdminPayload{UserID: readerID, ProjectID: f.project, Permissions: []string{"telemetry.read", "issues.write"}, Enabled: true}},
	} {
		cmd.p.Reason = "permission fixture"
		payload, e := json.Marshal(cmd.p)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: f.revision(t), OrgID: f.org, Kind: cmd.kind, Payload: payload}); e != nil {
			t.Fatal(e)
		}
	}
	login, e := f.app.Auth.Login(ctx, "reader@example.test", "reader fixture password 2026", "")
	if e != nil {
		t.Fatal(e)
	}
	reader, e := f.app.Auth.Authenticate(ctx, login.Token)
	if e != nil {
		t.Fatal(e)
	}
	scope, e := f.app.Auth.Authorize(ctx, reader, f.org, []model.ID{f.project}, auth.Permission("issues.write"))
	if e != nil {
		t.Fatal(e)
	}
	release := releases.Release{ID: model.NewID(), Org: f.org, Project: f.project, BuildID: model.NewID()}
	if _, e = f.app.Releases.Register(ctx, scope, release, f.revision(t), model.NewID()); e == nil {
		t.Fatal("issues.write became admin release mutation")
	}
	if _, e = f.app.Releases.Graph(ctx, scope, f.project); e == nil {
		t.Fatal("issues.write became admin metadata access")
	}
	if _, e = f.app.Releases.Register(ctx, f.scope, release, f.revision(t), model.NewID()); e == nil {
		t.Fatal("stale pre-policy-change scope remained authorized")
	}
}
