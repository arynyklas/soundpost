// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
)

// kindsWorld is one organization over the REAL control store, real incidents, jobs and releases services: a reader (telemetry.read)
// and an organization admin on the projects p and sibling, and a third project p3 that holds nothing.
type kindsWorld struct {
	*jobEnv
	w                 *jobWorld
	p3                model.ID
	admin             person
	inv               *httpapi.Investigator
	reader, adminP    auth.Scope // reader: p only; adminP: p and sibling
	adminOne, adminP3 auth.Scope
}

func newKindsWorld(t *testing.T) *kindsWorld {
	t.Helper()
	e, w := newJobEnvWorld(t)
	k := &kindsWorld{jobEnv: e, w: w, p3: model.NewID()}
	e.cmd(w.org, "create_project", auth.AdminPayload{ID: k.p3, Name: "project"})
	k.admin = e.user(w.org, "kinds-admin@example.test")
	e.cmd(w.org, "org_admin", auth.AdminPayload{UserID: k.admin.ID, Enabled: true})
	k.refresh()
	var err error
	if k.inv, err = httpapi.NewInvestigator(e.app.Auth, &fakeDiscovery{}, &fakeLinks{}); err != nil {
		t.Fatal(err)
	}
	k.inv.WithHealth(e.app.Control)
	// The node binds the issue lifecycle behind the issue kind (App.BindIssueActions): project readers are served through it.
	issueSvc, err := e.app.NewIssueActions(wallClock{})
	if err != nil {
		t.Fatal(err)
	}
	k.inv.WithIssues(issueSvc)
	return k
}

// refresh re-derives every scope the world holds: a committed grant or record changes the policy epoch, and a scope derived before
// it is refused as stale.
func (k *kindsWorld) refresh() {
	k.t.Helper()
	var err error
	if k.reader, err = k.scope(k.w.reader, k.w.org, k.w.project, auth.Read); err != nil {
		k.t.Fatal(err)
	}
	if k.w.write, err = k.scope(k.w.writer, k.w.org, k.w.project, auth.PolicyWrite); err != nil {
		k.t.Fatal(err)
	}
	authorize := func(projects ...model.ID) auth.Scope {
		s, err := k.app.Auth.Authorize(k.ctx, k.admin.Cred, k.w.org, projects, auth.OrgAdmin)
		if err != nil {
			k.t.Fatal(err)
		}
		return s
	}
	k.adminP, k.adminOne, k.adminP3 = authorize(k.w.project, k.w.sibling), authorize(k.w.project), authorize(k.p3)
}

func (k *kindsWorld) open(project model.ID, severity incidents.Severity) model.ID {
	k.t.Helper()
	incident := model.NewID()
	scope, err := k.app.Auth.Authorize(k.ctx, k.admin.Cred, k.w.org, []model.ID{project}, auth.OrgAdmin)
	if err != nil {
		k.t.Fatal(err)
	}
	if _, err = k.app.Incidents.Act(k.ctx, scope, incidents.Action{CommandID: model.NewID(), Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Target: incidents.Target{Org: k.w.org, Project: project, Incident: incident},
		Impact: &incidents.Impact{Condition: model.NewID(), Episode: model.NewID(), Severity: severity, State: incidents.ConditionFiring, Freshness: incidents.FreshnessFresh}}, 0); err != nil {
		k.t.Fatal(err)
	}
	return incident
}

func (k *kindsWorld) resolve(project, incident model.ID) {
	k.t.Helper()
	scope, err := k.app.Auth.Authorize(k.ctx, k.admin.Cred, k.w.org, []model.ID{project}, auth.OrgAdmin)
	if err != nil {
		k.t.Fatal(err)
	}
	if _, err = k.app.Incidents.Act(k.ctx, scope, incidents.Action{CommandID: model.NewID(), ExpectedVersion: 1, Type: incidents.TypeResolve, Origin: incidents.OriginHuman, Reason: "fixed", Target: incidents.Target{Org: k.w.org, Project: project, Incident: incident}}, 0); err != nil {
		k.t.Fatal(err)
	}
}

func (k *kindsWorld) release(project model.ID) model.ID {
	k.t.Helper()
	var revision model.Revision
	if err := k.app.Control.View(k.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		k.t.Fatal(err)
	}
	scope, err := k.app.Auth.Authorize(k.ctx, k.admin.Cred, k.w.org, []model.ID{project}, auth.OrgAdmin)
	if err != nil {
		k.t.Fatal(err)
	}
	id := model.NewID()
	if _, err = k.app.Releases.Register(k.ctx, scope, model.Release{ID: id, Org: k.w.org, Project: project, BuildID: model.NewID(), BuildTime: 7, Parents: []model.ID{}, DisplayLabel: "SECRET-LABEL-v1",
		DebugArtifacts: []model.ReleaseDebugArtifact{{ArtifactID: model.NewID(), DebugID: "debug-v1", SHA256: model.HashCanonical([]byte("v1"))}}}, revision, model.NewID()); err != nil {
		k.t.Fatal(err)
	}
	return id
}

// issue commits one grouping issue record straight into the control state, like the control package's own fixtures: the lifecycle that
// authors it needs the issues runner.
func (k *kindsWorld) issue(project model.ID, compacted bool) model.ID {
	k.t.Helper()
	ev := func(n uint64) model.GroupingEvidence {
		return model.GroupingEvidence{OccurrenceID: model.NewID(), RecordID: model.NewID(), Origin: model.Cursor{Group: model.ID{0xe1}, Index: model.Uint64(n)}, GroupingVersion: 3, Fingerprint: model.Hash{9},
			EventTime: model.UnixNano(1000 + n), ArrivalTime: model.UnixNano(2000 + n), Ancestry: "unknown", Ordinal: model.Uint64(n), Freshness: "fresh"}
	}
	gi := model.GroupingIssue{ID: model.NewID(), Org: k.w.org, Project: project, GroupingVersion: 3, Fingerprint: model.Hash{9}, Workflow: "open", Revision: 4,
		Occurrences: []model.GroupingEvidence{ev(1), ev(2)}, LateHistory: []model.GroupingEvidence{ev(3)},
		ResolutionFrontier: []model.ID{}, ObservedReleases: []model.ID{}, FixedDescendants: []model.ID{}, MigrationLinks: []model.ID{}}
	if compacted {
		gi.Compacted = &model.GroupingCompaction{Count: 5, FirstEvent: 1, LastEvent: 8, FirstArrival: 2, LastArrival: 9}
	}
	if err := k.app.Control.Update(k.ctx, func(st *control.State) error {
		if st.GroupingIssues == nil {
			st.GroupingIssues = map[string]model.GroupingIssue{}
		}
		st.GroupingIssues[model.ReleaseScopeKey(k.w.org, project, gi.ID)] = gi
		if st.IssueBooks == nil {
			st.IssueBooks = map[string]json.RawMessage{}
		}
		if _, ok := st.IssueBooks[k.w.org.String()+":"+project.String()]; !ok {
			// A book of the project's own: the issue lifecycle (the reader path) refuses one that is not.
			book, err := json.Marshal(control.IssueBook{Org: k.w.org, Project: project})
			if err != nil {
				return err
			}
			st.IssueBooks[k.w.org.String()+":"+project.String()] = book
		}
		return nil
	}); err != nil {
		k.t.Fatal(err)
	}
	return gi.ID
}

var kindsWindow = query.TimeRange{Start: 10, End: 20}

func (k *kindsWorld) read(inv *httpapi.Investigator, scope auth.Scope, kind httpapi.InvestigationKind, target *model.ID, limit uint32, projects ...model.ID) (httpapi.InvestigationView, error) {
	return inv.Investigate(k.ctx, scope, httpapi.InvestigationRequest{Kind: kind, Projects: projects, Target: target, Window: kindsWindow, Limit: limit})
}

func TestInvestigateServesQueueIncidentIssueReleaseAndJob(t *testing.T) {
	k := newKindsWorld(t)
	p := k.w.project
	major := k.open(p, incidents.SeverityMajor)
	critical := k.open(p, incidents.SeverityCritical)
	minor := k.open(p, incidents.SeverityMinor)
	k.resolve(p, minor)
	k.open(k.w.sibling, incidents.SeverityMajor)
	k.refresh()
	k.seedJourney(k.w)
	rel := k.release(p)
	iss := k.issue(p, true)
	k.refresh()

	// Queue: only the requested project, open first, then severity; the resolved one last.
	v, err := k.read(k.inv, k.reader, httpapi.KindQueue, nil, 10, p)
	if err != nil || v.State != httpapi.StateReady || v.Kind != httpapi.KindQueue || v.Org != k.w.org || v.More || len(v.Queue) != 3 {
		t.Fatalf("queue: %+v %v", v, err)
	}
	for n, want := range []struct {
		id         model.ID
		status     string
		severity   string
		versionMin model.Uint64
	}{{critical, "open", "critical", 1}, {major, "open", "major", 1}, {minor, "resolved", "minor", 2}} {
		got := v.Queue[n]
		if got.ID != want.id || got.Status != want.status || got.Severity != want.severity || got.Version < want.versionMin || got.ProjectID != p {
			t.Fatalf("queue[%d] = %+v, want %+v", n, got, want)
		}
	}

	// Incident, job: the one targeted record under the reader's scope.
	v, err = k.read(k.inv, k.reader, httpapi.KindIncident, &major, 10, p)
	if err != nil || v.State != httpapi.StateReady || v.Incident == nil || v.Incident.ID != major || v.Incident.Status != "open" || v.Incident.Severity != "major" || v.Incident.Version != 1 || v.Incident.ProjectID != p || len(v.Queue) != 0 {
		t.Fatalf("incident: %+v %v", v, err)
	}
	job := jobJourney
	v, err = k.read(k.inv, k.reader, httpapi.KindJob, &job, 10, p)
	if err != nil || v.State != httpapi.StateReady || v.Job == nil || v.Job.ID != job || v.Job.ProjectID != p || v.Job.Version != 7 || v.Job.Runs != 2 || v.Job.Attempts != 4 {
		t.Fatalf("job: %+v %v", v, err)
	}

	// Release and issue: the organization-admin registries.
	v, err = k.read(k.inv, k.adminOne, httpapi.KindRelease, &rel, 10, p)
	if err != nil || v.State != httpapi.StateReady || v.Release == nil || v.Release.ID != rel || v.Release.ProjectID != p || v.Release.BuildTime != 7 || v.Release.Revision == 0 || len(v.Release.Parents) != 0 || v.Release.DebugArtifacts != 1 {
		t.Fatalf("release: %+v %v", v, err)
	}
	if raw, _ := json.Marshal(v); strings.Contains(string(raw), "SECRET-LABEL") {
		t.Fatalf("the summary leaked the caller-authored label: %s", raw)
	}
	v, err = k.read(k.inv, k.adminOne, httpapi.KindIssue, &iss, 10, p)
	if err != nil || v.State != httpapi.StateIncomplete || v.Reason != httpapi.ReasonEvidenceCompacted || v.Issue == nil || v.Issue.ID != iss || v.Issue.Workflow != "open" || v.Issue.GroupingVersion != 3 || v.Issue.Revision != 4 ||
		v.Issue.Occurrences != 7 || v.Issue.LateHistory != 1 || !v.Issue.Compacted {
		t.Fatalf("issue: %+v %v", v, err)
	}
	// Wire names the web parser reads.
	raw, _ := json.Marshal(v)
	for _, name := range []string{`"issue":{"project_id"`, `"issue_id"`, `"grouping_version"`, `"occurrences"`, `"late_history"`, `"compacted"`} {
		if !strings.Contains(string(raw), name) {
			t.Fatalf("wire lacks %s: %s", name, raw)
		}
	}
}

func TestInvestigateReleaseAndIssueHonourTheirGates(t *testing.T) {
	k := newKindsWorld(t)
	p := k.w.project
	rel, iss := k.release(p), k.issue(p, false)
	k.refresh()
	// Release records stay organization administration: a project reader is told so, a real and a guessed target alike.
	target := rel
	v, err := k.read(k.inv, k.reader, httpapi.KindRelease, &target, 10, p)
	if err != nil || v.State != httpapi.StateNotAvailable || v.Reason != httpapi.ReasonReleaseRecordsAdmin || v.Release != nil {
		t.Fatalf("release for a project reader: %+v %v", v, err)
	}
	guess := model.NewID()
	if g, err := k.read(k.inv, k.reader, httpapi.KindRelease, &guess, 10, p); err != nil || g.Reason != httpapi.ReasonReleaseRecordsAdmin || g.State != httpapi.StateNotAvailable {
		t.Fatalf("release guessed target for a reader: %+v %v", g, err)
	}
	// An error issue is served to a project reader from the issue lifecycle (D92): the summary of her own project's issue, and the
	// one NotFound for a target that is not in it.
	target = iss
	v, err = k.read(k.inv, k.reader, httpapi.KindIssue, &target, 10, p)
	if err != nil || v.State != httpapi.StateReady || v.Issue == nil || v.Issue.ID != iss || v.Issue.ProjectID != p || v.Issue.Revision != 4 || v.Issue.Occurrences != 2 || v.Issue.LateHistory != 1 {
		t.Fatalf("issue for a project reader: %+v %v", v, err)
	}
	if g, err := k.read(k.inv, k.reader, httpapi.KindIssue, &guess, 10, p); faultCode(err) != model.NotFound || g.Issue != nil {
		t.Fatalf("issue guessed target for a reader: %+v %v", g, err)
	}
	// Without the lifecycle bound (an installation that never ran BindIssueActions) the reader is told the view is not built, and
	// the administrator is still served from the registry.
	bare, err := httpapi.NewInvestigator(k.app.Auth, &fakeDiscovery{}, &fakeLinks{})
	if err != nil {
		t.Fatal(err)
	}
	bare.WithHealth(k.app.Control)
	if g, err := k.read(bare, k.reader, httpapi.KindIssue, &target, 10, p); err != nil || g.State != httpapi.StateNotAvailable || g.Reason != httpapi.ReasonIssueEvidenceAbsent || g.Issue != nil {
		t.Fatalf("issue for a reader without the lifecycle: %+v %v", g, err)
	}
	if g, err := k.read(bare, k.adminOne, httpapi.KindIssue, &target, 10, p); err != nil || g.State != httpapi.StateReady || g.Issue == nil {
		t.Fatalf("issue for an administrator without the lifecycle: %+v %v", g, err)
	}
}

// leakyOwner is a labelled double of an owner read that does NOT validate the scope (it answers with a fixed internal admin scope), to
// prove the investigation itself checks every requested project against the caller's scope before reading anything.
type leakyOwner struct {
	*control.Store
	admin auth.Scope
}

func (l leakyOwner) Incident(ctx context.Context, _ auth.Scope, project, id model.ID) (control.IncidentRecord, bool, error) {
	return l.Store.Incident(ctx, l.admin, project, id)
}
func (l leakyOwner) Incidents(ctx context.Context, _ auth.Scope, project model.ID) ([]control.IncidentRecord, error) {
	return l.Store.Incidents(ctx, l.admin, project)
}
func (l leakyOwner) JobDetail(ctx context.Context, _ auth.Scope, project, job model.ID) (control.JobEntry, bool, error) {
	return l.Store.JobDetail(ctx, l.admin, project, job)
}

// stubSources is the SourceLister of investigators that never read sources.
type stubSources struct{}

func (stubSources) VisibleSources(context.Context, auth.Scope) ([]auth.VisibleSource, error) {
	return nil, nil
}
func (stubSources) VisibleServices(context.Context, auth.Scope) ([]auth.VisibleService, error) {
	return nil, nil
}

func TestInvestigateKindRefusesForeignScopeAsOneNotFound(t *testing.T) {
	k := newKindsWorld(t)
	p, sibling := k.w.project, k.w.sibling
	k.open(p, incidents.SeverityMajor)
	sibInc := k.open(sibling, incidents.SeverityMajor)
	k.refresh()
	k.seedJourney(k.w)
	k.release(p)
	k.issue(p, false)
	sibRel, sibIss := k.release(sibling), k.issue(sibling, false)
	// A user of another organization, with its own readable project.
	pO := model.NewID()
	orgO := k.org("kinds other org", pO)
	other := k.user(orgO, "kinds-other@example.test")
	k.grant(orgO, other, pO, true, auth.Read)
	k.refresh()
	otherScope, err := k.scope(other, orgO, pO, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	// The second investigator's owner reads do not validate the scope at all: only the investigation's own check stands in the way.
	leaky, err := httpapi.NewInvestigator(k.app.Auth, &fakeDiscovery{}, &fakeLinks{})
	if err != nil {
		t.Fatal(err)
	}
	leaky.WithHealth(leakyOwner{Store: k.app.Control, admin: k.adminP})

	guess := model.NewID()
	type probe struct {
		name    string
		scope   auth.Scope
		project model.ID
		target  func(kind httpapi.InvestigationKind) *model.ID
	}
	// The target a kind asks for: guessed, or a real record of the sibling project.
	siblings := map[httpapi.InvestigationKind]model.ID{httpapi.KindIncident: sibInc, httpapi.KindRelease: sibRel, httpapi.KindIssue: sibIss, httpapi.KindJob: guess}
	probes := []probe{
		{"project outside the scope", k.reader, sibling, func(kind httpapi.InvestigationKind) *model.ID { id := siblings[kind]; return &id }},
		{"another organization's scope", otherScope, p, func(kind httpapi.InvestigationKind) *model.ID { return &guess }},
		{"a sibling project's record asked under this project", k.adminOne, p, func(kind httpapi.InvestigationKind) *model.ID { id := siblings[kind]; return &id }},
		{"a guessed record", k.adminOne, p, func(kind httpapi.InvestigationKind) *model.ID { return &guess }},
	}
	var first string
	for _, inv := range []*httpapi.Investigator{k.inv, leaky} {
		for _, kind := range []httpapi.InvestigationKind{httpapi.KindQueue, httpapi.KindIncident, httpapi.KindIssue, httpapi.KindRelease, httpapi.KindJob} {
			for _, pr := range probes {
				var target *model.ID
				if kind != httpapi.KindQueue {
					target = pr.target(kind)
				} else if pr.name != "project outside the scope" && pr.name != "another organization's scope" {
					continue // a queue has no target to guess
				}
				v, err := k.read(inv, pr.scope, kind, target, 10, pr.project)
				if faultCode(err) != model.NotFound {
					t.Fatalf("%s / %s: want the one not-found, got %+v %v", kind, pr.name, v, err)
				}
				if v.Queue != nil || v.Incident != nil || v.Issue != nil || v.Release != nil || v.Job != nil || v.State != "" {
					t.Fatalf("%s / %s: a refused read carried a view: %+v", kind, pr.name, v)
				}
				if first == "" {
					first = err.Error()
				} else if err.Error() != first {
					t.Fatalf("%s / %s: refusal %q is distinguishable from %q", kind, pr.name, err.Error(), first)
				}
			}
		}
	}
	// Scope comes first: an unwired owner does not turn a foreign project into a "not available" answer either.
	bare, err := httpapi.NewInvestigator(k.app.Auth, &fakeDiscovery{}, &fakeLinks{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = k.read(bare, k.reader, httpapi.KindQueue, nil, 10, sibling); faultCode(err) != model.NotFound {
		t.Fatalf("an unwired owner answered a foreign project: %v", err)
	}
}

func TestInvestigateKindWithoutOwnerIsNotAvailableNeverEmpty(t *testing.T) {
	k := newKindsWorld(t)
	p := k.w.project
	inc := k.open(p, incidents.SeverityMajor)
	k.refresh()
	k.seedJourney(k.w)
	rel, iss := k.release(p), k.issue(p, false)
	k.refresh()
	job := jobJourney
	bare, err := httpapi.NewInvestigator(k.app.Auth, &fakeDiscovery{}, &fakeLinks{})
	if err != nil {
		t.Fatal(err)
	}
	// A health source that is not the control store provides no records either.
	healthOnly, err := httpapi.NewInvestigator(k.app.Auth, &fakeDiscovery{}, &fakeLinks{})
	if err != nil {
		t.Fatal(err)
	}
	healthOnly.WithHealth(&conditionHealth{HealthSource: k.app.Control})
	want := map[httpapi.InvestigationKind]struct {
		target *model.ID
		scope  auth.Scope
		reason string
	}{
		httpapi.KindQueue:    {nil, k.reader, httpapi.ReasonIncidentSourceNotWired},
		httpapi.KindIncident: {&inc, k.reader, httpapi.ReasonIncidentSourceNotWired},
		httpapi.KindJob:      {&job, k.reader, httpapi.ReasonJobServiceNotWired},
		httpapi.KindRelease:  {&rel, k.adminOne, httpapi.ReasonReleasesNotBuilt},
		httpapi.KindIssue:    {&iss, k.adminOne, httpapi.ReasonIssueEvidenceAbsent},
	}
	for _, inv := range []*httpapi.Investigator{bare, healthOnly} {
		for kind, c := range want {
			v, err := k.read(inv, c.scope, kind, c.target, 10, p)
			if err != nil || v.State != httpapi.StateNotAvailable || v.Reason != c.reason || len(v.Sections) != 1 || v.Sections[0].State != httpapi.StateNotAvailable || v.Sections[0].Reason != c.reason {
				t.Fatalf("%s: %+v %v", kind, v, err)
			}
			if v.Queue != nil || v.Incident != nil || v.Issue != nil || v.Release != nil || v.Job != nil {
				t.Fatalf("%s: an unwired owner still carried content: %+v", kind, v)
			}
		}
	}
	// The control store passed to WithHealth is what wires them.
	if v, err := k.read(k.inv, k.reader, httpapi.KindQueue, nil, 10, p); err != nil || v.State != httpapi.StateReady {
		t.Fatalf("wired: %+v %v", v, err)
	}
}

func TestInvestigateKindsBoundedAndTruthfulTruncation(t *testing.T) {
	k := newKindsWorld(t)
	p, sibling := k.w.project, k.w.sibling
	a := k.open(p, incidents.SeverityCritical)
	b := k.open(p, incidents.SeverityMajor)
	k.open(sibling, incidents.SeverityMinor)

	// Fewer than the page: whole answer, More false. Exactly the page: still whole. One short: truncated and says so.
	for limit, want := range map[uint32]struct {
		n    int
		more bool
	}{1: {1, true}, 2: {2, true}, 3: {3, false}, 200: {3, false}} {
		v, err := k.read(k.inv, k.adminP, httpapi.KindQueue, nil, limit, p, sibling)
		if err != nil || v.State != httpapi.StateReady || len(v.Queue) != want.n || v.More != want.more {
			t.Fatalf("limit %d: %d entries more=%v (%+v) %v", limit, len(v.Queue), v.More, v.State, err)
		}
	}
	// The kept entries are the head of the deterministic order, never an arbitrary subset.
	v, err := k.read(k.inv, k.adminP, httpapi.KindQueue, nil, 2, p, sibling)
	if err != nil || v.Queue[0].ID != a || v.Queue[1].ID != b {
		t.Fatalf("truncated queue is not the head of the order: %+v %v", v.Queue, err)
	}
	// Past the maximum is invalid, not clamped.
	if _, err = k.read(k.inv, k.adminP, httpapi.KindQueue, nil, httpapi.MaxInvestigationLimit+1, p); faultCode(err) != model.Invalid {
		t.Fatalf("over-limit request: %v", err)
	}
	// A project with no incidents is an empty queue, which is not a ready one, and not truncated.
	v, err = k.read(k.inv, k.adminP3, httpapi.KindQueue, nil, 10, k.p3)
	if err != nil || v.State != httpapi.StateEmpty || len(v.Queue) != 0 || v.More {
		t.Fatalf("empty queue: %+v %v", v, err)
	}
}

// eraseBefore erases everything in the project up to now through a real completed range deletion.
func (k *kindsWorld) eraseBefore(project model.ID) {
	k.t.Helper()
	orgScope, err := k.app.Auth.Authorize(k.ctx, k.admin.Cred, k.w.org, nil, auth.OrgAdmin)
	if err != nil {
		k.t.Fatal(err)
	}
	now := model.UnixNano(time.Now().UnixNano())
	raw, err := json.Marshal(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{project}, Signals: []model.Kind{model.Metric},
		Start: now - model.UnixNano(time.Hour), End: now, At: now, Reason: "fixture", PhysicalDeadline: now + 1, BackupDeadline: now + 2})
	if err != nil {
		k.t.Fatal(err)
	}
	var revision model.Revision
	if err = k.app.Control.View(k.ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
		k.t.Fatal(err)
	}
	op := model.NewID()
	if _, err = k.app.Control.Transact(k.ctx, orgScope, control.Command{CommandID: op, ExpectedRevision: revision, Kind: string(control.KindDeleteScope), Payload: raw}); err != nil {
		k.t.Fatal(err)
	}
	var barriers []model.Cursor
	for slot := range uint16(model.DeleteSlots) {
		barriers = append(barriers, model.Cursor{Group: model.ID{byte(slot + 1)}, Index: 1})
	}
	if _, err = k.app.Control.RecordBarriers(k.ctx, op, barriers); err != nil {
		k.t.Fatal(err)
	}
	if _, err = k.app.Control.CompleteDeletion(k.ctx, op, now, nil); err != nil {
		k.t.Fatal(err)
	}
}

func TestInvestigateKindsSkipErasedIncidents(t *testing.T) {
	k := newKindsWorld(t)
	p := k.w.project
	erased := k.open(p, incidents.SeverityMajor)
	k.eraseBefore(p)
	live := k.open(p, incidents.SeverityCritical)
	k.refresh()
	if rec, found, err := k.app.Control.Incident(k.ctx, k.reader, p, erased); err != nil || !found || !rec.Erased() {
		t.Fatalf("fixture: the first incident is not erased: %+v %v %v", rec, found, err)
	}
	v, err := k.read(k.inv, k.reader, httpapi.KindQueue, nil, 10, p)
	if err != nil || len(v.Queue) != 1 || v.Queue[0].ID != live {
		t.Fatalf("the queue must list only the live incident: %+v %v", v.Queue, err)
	}
	if v, err = k.read(k.inv, k.reader, httpapi.KindIncident, &erased, 10, p); faultCode(err) != model.NotFound || v.Incident != nil {
		t.Fatalf("an erased incident must be the one not-found: %+v %v", v, err)
	}
	if v, err = k.read(k.inv, k.reader, httpapi.KindIncident, &live, 10, p); err != nil || v.Incident == nil || v.Incident.ID != live {
		t.Fatalf("the live incident: %+v %v", v, err)
	}
}

func TestInvestigateRecordKindsNeedTheirTargetAndQueueForbidsOne(t *testing.T) {
	inv, err := httpapi.NewInvestigator(stubSources{}, &fakeDiscovery{}, &fakeLinks{})
	if err != nil {
		t.Fatal(err)
	}
	p, target, zero := model.NewID(), model.NewID(), model.ID{}
	for _, kind := range []httpapi.InvestigationKind{httpapi.KindIncident, httpapi.KindIssue, httpapi.KindRelease, httpapi.KindJob} {
		for name, tgt := range map[string]*model.ID{"missing": nil, "zero": &zero} {
			_, err := inv.Investigate(context.Background(), auth.Scope{}, httpapi.InvestigationRequest{Kind: kind, Projects: []model.ID{p}, Target: tgt, Window: kindsWindow, Limit: 10})
			if faultCode(err) != model.Invalid {
				t.Fatalf("%s with a %s target: %v", kind, name, err)
			}
		}
	}
	if _, err = inv.Investigate(context.Background(), auth.Scope{}, httpapi.InvestigationRequest{Kind: httpapi.KindQueue, Projects: []model.ID{p}, Target: &target, Window: kindsWindow, Limit: 10}); faultCode(err) != model.Invalid {
		t.Fatalf("a queue with a target: %v", err)
	}
}
