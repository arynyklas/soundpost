// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

type deployFixture struct {
	*cacheFixture
	release, env model.ID
}

// newDeployFixture has one project with an active source policy that lists an environment, and one
// registered release.
func newDeployFixture(t *testing.T) *deployFixture {
	t.Helper()
	d := &deployFixture{cacheFixture: newCacheFixture(t), release: model.NewID(), env: model.NewID()}
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{model.NewID()}, Environments: []model.ID{d.env}, Builds: []model.ID{model.NewID()}, Instances: []string{"i"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 7}, MaxBytes: 1 << 20, MaxSeries: 100}
	if _, err := d.service.OnboardSource(d.ctx, d.actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: d.org, Project: d.project, Source: model.NewID(), Expires: model.UnixNano(d.at().Add(time.Hour).UnixNano()), Policy: policy, Reason: "deploy fixture"}); err != nil {
		t.Fatal(err)
	}
	d.registerRelease(d.org, d.project, d.release)
	return d
}

func (d *deployFixture) registerRelease(org, project, release model.ID) {
	d.t.Helper()
	if err := d.store.Update(d.ctx, func(st *control.State) error {
		if st.Releases == nil {
			st.Releases = map[string]model.Release{}
		}
		st.Releases[model.ReleaseScopeKey(org, project, release)] = model.Release{ID: release, Org: org, Project: project, BuildID: model.NewID(), BuildTime: 5, DisplayLabel: "v1"}
		return nil
	}); err != nil {
		d.t.Fatal(err)
	}
}

func (d *deployFixture) adminScope(c auth.Credential, project model.ID) auth.Scope {
	d.t.Helper()
	s, err := d.service.Authorize(d.ctx, c, d.org, []model.ID{project}, auth.OrgAdmin)
	if err != nil {
		d.t.Fatal(err)
	}
	return s
}

func (d *deployFixture) record(c auth.Credential, command, release, env model.ID, at int64) (auth.DeployItem, error) {
	return d.service.RecordDeploy(d.ctx, d.adminScope(c, d.project), auth.DeployRecord{CommandID: command, Org: d.org, Project: d.project, Release: release, Environment: env, DeployedAt: at})
}

func (d *deployFixture) epoch() uint64 {
	var e uint64
	_ = d.store.View(d.ctx, func(st control.State) error { e = st.Orgs[d.org.String()].Epoch; return nil })
	return e
}

func TestRecordDeployKeepsTheEarliestTimeCountsRedeploysAndIsIdempotent(t *testing.T) {
	d := newDeployFixture(t)
	base := d.at().UnixNano()

	first, err := d.record(d.actor, model.NewID(), d.release, d.env, base-int64(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if first.First != model.Int64(base-int64(time.Hour)) || first.Last != first.First || first.Count != 1 || first.ProjectID != d.project || first.ReleaseID != d.release || first.Env != d.env {
		t.Fatalf("first: %+v", first)
	}
	// An earlier time moves the first, a later one the last; every recording counts.
	if got, err := d.record(d.actor, model.NewID(), d.release, d.env, base-int64(2*time.Hour)); err != nil || got.First != model.Int64(base-int64(2*time.Hour)) || got.Last != first.Last || got.Count != 2 {
		t.Fatalf("earlier: %+v %v", got, err)
	}
	cmd := model.NewID()
	third, err := d.record(d.actor, cmd, d.release, d.env, 0) // server clock
	if err != nil || third.Last != model.Int64(base) || third.First != model.Int64(base-int64(2*time.Hour)) || third.Count != 3 {
		t.Fatalf("server clock: %+v %v", third, err)
	}
	// The same command again: the same marker, no second count, no second audit.
	if got, err := d.record(d.actor, cmd, d.release, d.env, 0); err != nil || got.Count != 3 {
		t.Fatalf("replay: %+v %v", got, err)
	}
	// The same command id with other content is a conflict, another principal's replay is not found.
	if _, err := d.record(d.actor, cmd, d.release, d.env, base-int64(time.Minute)); code(err) != model.Conflict {
		t.Fatalf("replay with other content: %v", err)
	}
	other, _ := d.reader("deploy-other@example.test", auth.Read)
	d.cmd("org_admin", auth.AdminPayload{UserID: d.userOf(other), Enabled: true})
	if _, err := d.service.RecordDeploy(d.ctx, d.adminScope(other, d.project), auth.DeployRecord{CommandID: cmd, Org: d.org, Project: d.project, Release: d.release, Environment: d.env}); code(err) != model.NotFound {
		t.Fatalf("another administrator replaying the command: %v", err)
	}
	audits := 0
	_ = d.store.View(d.ctx, func(st control.State) error {
		for _, a := range st.Audits {
			if a.Action == "releases.deploy" {
				audits++
				if len(a.Targets) != 4 || a.Outcome != model.AuditAllowed {
					t.Errorf("audit: %+v", a)
				}
			}
		}
		return nil
	})
	if audits != 3 {
		t.Fatalf("audits: %d, want 3", audits)
	}
	if _, err := d.record(d.actor, model.NewID(), d.release, d.env, base); err != nil {
		t.Fatal(err)
	}
}

func TestRecordDeployDoesNotMoveThePolicyEpoch(t *testing.T) {
	d := newDeployFixture(t)
	epoch := d.epoch()
	for i := range 3 {
		if _, err := d.record(d.actor, model.NewID(), d.release, d.env, int64(i+1)); err != nil {
			t.Fatal(err)
		}
	}
	if got := d.epoch(); got != epoch {
		t.Fatalf("epoch %d -> %d: recording a deploy moved the organization's policy epoch", epoch, got)
	}
}

// userOf is the user ID of a credential created by reader.
func (d *deployFixture) userOf(c auth.Credential) model.ID {
	d.t.Helper()
	s, err := d.service.Authorize(d.ctx, c, d.org, []model.ID{d.project}, auth.Read)
	if err != nil {
		d.t.Fatal(err)
	}
	return s.PrincipalID()
}

func TestRecordDeployRefusals(t *testing.T) {
	d := newDeployFixture(t)
	now := d.at().UnixNano()
	if _, err := d.record(d.actor, model.NewID(), d.release, model.NewID(), now); code(err) != model.Invalid || detailOf(err) != auth.DeployEnvironmentUnknown {
		t.Fatalf("an environment no active source policy lists: %v", err)
	}
	if _, err := d.record(d.actor, model.NewID(), model.NewID(), d.env, now); code(err) != model.NotFound {
		t.Fatalf("a release that does not exist: %v", err)
	}
	if _, err := d.record(d.actor, model.NewID(), d.release, d.env, now+int64(auth.DeployFutureSkew)+int64(time.Second)); code(err) != model.Invalid || detailOf(err) != auth.DeployTimeInvalid {
		t.Fatalf("a time later than now + 5 minutes: %v", err)
	}
	if _, err := d.record(d.actor, model.NewID(), d.release, d.env, now+int64(auth.DeployFutureSkew)-int64(time.Second)); err != nil {
		t.Fatalf("a time within the skew: %v", err)
	}
	if _, err := d.record(d.actor, model.NewID(), d.release, d.env, -1); code(err) != model.Invalid {
		t.Fatalf("a negative time: %v", err)
	}
	if _, err := d.record(d.actor, model.ID{}, d.release, d.env, now); code(err) != model.Invalid {
		t.Fatalf("no command id: %v", err)
	}
	// A release of another project is not this project's release.
	p2 := model.NewID()
	d.cmd("create_project", auth.AdminPayload{ID: p2, Name: "second"})
	foreign := model.NewID()
	d.registerRelease(d.org, p2, foreign)
	if _, err := d.record(d.actor, model.NewID(), foreign, d.env, now); code(err) != model.NotFound {
		t.Fatalf("a release of another project: %v", err)
	}
	// An environment of another project's source policy is not this project's.
	if _, err := d.service.RecordDeploy(d.ctx, d.adminScope(d.actor, p2), auth.DeployRecord{CommandID: model.NewID(), Org: d.org, Project: p2, Release: foreign, Environment: d.env}); code(err) != model.Invalid {
		t.Fatalf("another project's environment: %v", err)
	}
}

func TestRecordDeployNeedsOrganizationAdministration(t *testing.T) {
	d := newDeployFixture(t)
	reader, _ := d.reader("deploy-reader@example.test", auth.Read, auth.IncidentsWrite)
	if _, err := d.service.Authorize(d.ctx, reader, d.org, []model.ID{d.project}, auth.OrgAdmin); code(err) != model.NotFound {
		t.Fatalf("a reader derived an administrator scope: %v", err)
	}
	// A read scope handed to the transition is refused, not trusted.
	readScope := d.scope(reader, auth.Read)
	if _, err := d.service.RecordDeploy(d.ctx, readScope, auth.DeployRecord{CommandID: model.NewID(), Org: d.org, Project: d.project, Release: d.release, Environment: d.env}); code(err) != model.Forbidden {
		t.Fatalf("a read scope recorded a deploy: %v", err)
	}
	// The administrator scope of one project is not a scope for another project or organization.
	p2 := model.NewID()
	d.cmd("create_project", auth.AdminPayload{ID: p2, Name: "second"})
	adminScope := d.adminScope(d.actor, d.project)
	if _, err := d.service.RecordDeploy(d.ctx, adminScope, auth.DeployRecord{CommandID: model.NewID(), Org: d.org, Project: p2, Release: d.release, Environment: d.env}); code(err) != model.Forbidden {
		t.Fatalf("a scope of another project: %v", err)
	}
	other := d.otherOrg()
	if _, err := d.service.RecordDeploy(d.ctx, adminScope, auth.DeployRecord{CommandID: model.NewID(), Org: other, Project: d.project, Release: d.release, Environment: d.env}); code(err) != model.Forbidden {
		t.Fatalf("a scope of another organization: %v", err)
	}
	// A scope derived before the administrator lost the role is refused by the transition itself.
	d.cmd("org_admin", auth.AdminPayload{UserID: d.session.User, Enabled: false})
	if _, err := d.service.RecordDeploy(d.ctx, adminScope, auth.DeployRecord{CommandID: model.NewID(), Org: d.org, Project: d.project, Release: d.release, Environment: d.env}); err == nil {
		t.Fatal("a revoked administrator recorded a deploy")
	}
}

func TestDeployMarkerQuotaRefusesAndDropsNothing(t *testing.T) {
	d := newDeployFixture(t)
	if _, err := d.record(d.actor, model.NewID(), d.release, d.env, 100); err != nil {
		t.Fatal(err)
	}
	// Fill the project to the bound with markers of other releases.
	if err := d.store.Update(d.ctx, func(st *control.State) error {
		o := st.Orgs[d.org.String()]
		for i := range auth.MaxDeployMarkersPerProject - 1 {
			o.Settings[auth.DeployKey(d.project, model.NewID(), model.NewID())] = []byte(fmt.Sprintf(`{"first":%d,"last":%d,"count":1}`, 1000+i, 1000+i))
		}
		st.Orgs[d.org.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Markers of another project do not count against this one.
	other := model.NewID()
	d.cmd("create_project", auth.AdminPayload{ID: other, Name: "other"})
	if err := d.store.Update(d.ctx, func(st *control.State) error {
		o := st.Orgs[d.org.String()]
		for range 10 {
			o.Settings[auth.DeployKey(other, model.NewID(), model.NewID())] = []byte(`{"first":1,"last":1,"count":1}`)
		}
		st.Orgs[d.org.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The bound is reached by one more new (release, environment); an existing one still counts up.
	second := model.NewID()
	d.registerRelease(d.org, d.project, second)
	if _, err := d.record(d.actor, model.NewID(), second, d.env, 200); err == nil || code(err) != model.Quota || detailOf(err) != auth.DeployMarkerFull {
		// 4095 + the first = 4096 already: the next new marker is over the bound.
		t.Fatalf("a marker over the bound: %v", err)
	}
	if got, err := d.record(d.actor, model.NewID(), d.release, d.env, 300); err != nil || got.Count != 2 {
		t.Fatalf("an existing marker still counts redeploys at the bound: %+v %v", got, err)
	}
	items, err := d.service.ListDeploys(d.ctx, d.scope(d.actor, auth.OrgAdmin), []model.ID{d.project}, model.ID{})
	if err != nil || len(items) != auth.MaxDeployMarkersPerProject {
		t.Fatalf("nothing was dropped: %d %v", len(items), err)
	}
}

func TestListDeploysIsScopedToTheReadersProjectsAndOrganization(t *testing.T) {
	d := newDeployFixture(t)
	p2 := model.NewID()
	d.cmd("create_project", auth.AdminPayload{ID: p2, Name: "second"})
	if _, err := d.record(d.actor, model.NewID(), d.release, d.env, 100); err != nil {
		t.Fatal(err)
	}
	// A marker of the second project (written directly: the fixture's environment is not its).
	if err := d.store.Update(d.ctx, func(st *control.State) error {
		o := st.Orgs[d.org.String()]
		o.Settings[auth.DeployKey(p2, model.NewID(), model.NewID())] = []byte(`{"first":5,"last":6,"count":1}`)
		st.Orgs[d.org.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reader, _ := d.reader("deploy-list@example.test", auth.Read)
	items, err := d.service.ListDeploys(d.ctx, d.scope(reader, auth.Read), []model.ID{d.project}, model.ID{})
	if err != nil || len(items) != 1 || items[0].ProjectID != d.project || items[0].Env != d.env || items[0].Count != 1 {
		t.Fatalf("a reader lists the markers of its project: %+v %v", items, err)
	}
	// A project outside the scope is the one not-found, whatever the caller asks.
	if _, err := d.service.ListDeploys(d.ctx, d.scope(reader, auth.Read), []model.ID{d.project, p2}, model.ID{}); code(err) != model.NotFound {
		t.Fatalf("a project outside the scope: %v", err)
	}
	if _, err := d.service.Authorize(d.ctx, reader, d.org, []model.ID{p2}, auth.Read); code(err) != model.NotFound {
		t.Fatalf("authorize for a project without a grant: %v", err)
	}
	// A release filter; a release without a marker has no item.
	if items, err = d.service.ListDeploys(d.ctx, d.scope(reader, auth.Read), []model.ID{d.project}, model.NewID()); err != nil || len(items) != 0 {
		t.Fatalf("a release without markers: %+v %v", items, err)
	}
	// Another organization's reader cannot derive a scope for this organization at all, and a scope of
	// another organization lists nothing of this one.
	otherOrg := d.otherOrg()
	if _, err := d.service.Authorize(d.ctx, reader, otherOrg, []model.ID{d.project}, auth.Read); code(err) != model.NotFound {
		t.Fatalf("a reader of org A in org B: %v", err)
	}
	// A retired project's markers are not listed.
	if err := d.store.Update(d.ctx, func(st *control.State) error {
		o := st.Orgs[d.org.String()]
		delete(o.Projects, p2.String())
		st.Orgs[d.org.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if items, err = d.service.ListDeploys(d.ctx, d.scope(d.actor, auth.OrgAdmin), []model.ID{d.project}, model.ID{}); err != nil || len(items) != 1 {
		t.Fatalf("after retirement: %+v %v", items, err)
	}
	// Listing refuses a scope that is not this service's or covers no project.
	if _, err := d.service.ListDeploys(d.ctx, auth.Scope{}, []model.ID{d.project}, model.ID{}); err == nil {
		t.Fatal("the zero scope listed deploys")
	}
	if _, err := d.service.ListDeploys(d.ctx, d.scope(reader, auth.Read), nil, model.ID{}); err == nil {
		t.Fatalf("no projects: %v", err)
	}
}
