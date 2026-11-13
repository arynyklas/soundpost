// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/httpapi"
	"soundpost/internal/incidents"
	"soundpost/internal/issues"
	"soundpost/internal/model"
	"soundpost/internal/releases"
	"soundpost/internal/replica"
)

// issueRig is a worker node with a real source credential that ingests error
// occurrences through the real ingest service (credential -> grant -> Admit).
type issueRig struct {
	*workerNode
	source, producer model.ID
	resource         model.Resource
	admit            func(model.Batch) (model.Receipt, error)
}

func newIssueRig(t *testing.T) *issueRig {
	t.Helper()
	n := newWorkerNode(t)
	r := &issueRig{workerNode: n, source: model.NewID(), producer: model.NewID()}
	service, environment, build := model.NewID(), model.NewID(), model.NewID()
	r.resource = model.Resource{Service: service, Environment: environment, Build: build, Instance: "opaque-instance", Labels: model.Labels{}}
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.ErrorKind},
		Resources:     model.ResourceRegistry{Services: []model.ID{service}, Environments: []model.ID{environment}, Builds: []model.ID{build}, Instances: []string{"opaque-instance"}},
		RetentionDays: map[model.Kind]uint32{model.ErrorKind: 30}, MaxBytes: 64 << 20, MaxSeries: 100}
	issued, err := n.app.Auth.OnboardSource(n.ctx, n.actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: n.org, Project: n.project, Source: r.source,
		Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "issue producer"})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := n.app.Auth.AuthenticateSource(n.ctx, issued.Credential, "", false)
	if err != nil {
		t.Fatal(err)
	}
	r.admit = func(b model.Batch) (model.Receipt, error) {
		g, err := n.app.Ingest.ResolveSource(n.ctx, cred, b)
		if err != nil {
			return model.Receipt{}, err
		}
		return n.app.Ingest.Admit(n.ctx, g, b)
	}
	return r
}

func (r *issueRig) record(class string, observed model.UnixNano, handled, fatal bool, occurrence model.ID) model.Record {
	return model.Record{ID: model.NewID(), Kind: model.ErrorKind, ObservedAt: observed, Resource: r.resource,
		Payload: model.Payload{Error: &model.ErrorOccurrence{Occurrence: occurrence, Class: class, Mechanism: "manual", Build: r.resource.Build, Handled: handled, Fatal: fatal, Frames: []model.Frame{}}}}
}

// ingestBatch admits one batch of records (one journal cursor).
func (r *issueRig) ingestBatch(records ...model.Record) {
	r.t.Helper()
	b := model.Batch{Version: 1, Project: r.project, Source: r.source, Producer: r.producer, ID: model.NewID(), PolicyRevision: 1, Records: records}
	var err error
	if b.RouteSlot, err = model.OwnerSlot(r.org, r.project, r.source, r.producer, records[0]); err != nil {
		r.t.Fatal(err)
	}
	if _, err = r.admit(b); err != nil {
		r.t.Fatal(err)
	}
}

func (r *issueRig) ingest(class string, observed model.UnixNano, handled, fatal bool) model.ID {
	r.t.Helper()
	occurrence := model.NewID()
	r.ingestBatch(r.record(class, observed, handled, fatal, occurrence))
	return occurrence
}

func (r *issueRig) system(permission auth.Permission) auth.Scope {
	r.t.Helper()
	s, err := r.app.Auth.AuthorizeSystem(r.ctx, r.org, []model.ID{r.project}, permission)
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

func (r *issueRig) snapshot() control.IssueSnapshot {
	r.t.Helper()
	s, err := r.app.Control.IssueBook(r.ctx, r.system(auth.IssuesWrite), r.project)
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

func (r *issueRig) incidentRecords() []control.IncidentRecord {
	r.t.Helper()
	list, err := r.app.Control.Incidents(r.ctx, r.admin(), r.project)
	if err != nil {
		r.t.Fatal(err)
	}
	return list
}

func (r *issueRig) producers() func(*appcore.WorkerConfig) {
	return func(c *appcore.WorkerConfig) {
		c.Producers = []appcore.Producer{r.app.IssueProducerWithClock(r.clock), r.app.IncidentProducerWithClock(r.clock)}
	}
}

func (r *issueRig) workers(extra ...func(*appcore.WorkerConfig)) *appcore.Workers {
	r.t.Helper()
	w, err := r.app.NewWorkers(r.config(func(c *appcore.WorkerConfig) {
		r.producers()(c)
		for _, e := range extra {
			e(c)
		}
	}))
	if err != nil {
		r.t.Fatal(err)
	}
	return w
}

func sumCheckpoints(s control.IssueSnapshot) (sum model.Uint64) {
	for _, v := range s.Checkpoints {
		sum += v
	}
	return sum
}

// idsInOneSlot returns n occurrence IDs that route to the same owner slot, so
// batches of them share one data group.
func (r *issueRig) idsInOneSlot(n int) []model.ID {
	r.t.Helper()
	slot := func(id model.ID) uint16 {
		s, err := model.OwnerSlot(r.org, r.project, r.source, r.producer, r.record("X", 1, true, false, id))
		if err != nil {
			r.t.Fatal(err)
		}
		return s
	}
	want := slot(model.NewID())
	var out []model.ID
	for len(out) < n {
		if id := model.NewID(); slot(id) == want {
			out = append(out, id)
		}
	}
	return out
}

func onlyCheckpoint(t *testing.T, s control.IssueSnapshot) model.Uint64 {
	t.Helper()
	if len(s.Checkpoints) != 1 {
		t.Fatalf("checkpoints = %v, want exactly one data group", s.Checkpoints)
	}
	for _, v := range s.Checkpoints {
		return v
	}
	return 0
}

// The whole pipeline: an error ingested through a source credential becomes an
// issue and, once, an incident, with no human session and no seed route; the
// actor of the committed incident is the organization's system principal.
func TestProducerIngestedErrorBecomesIssueAndIncident(t *testing.T) {
	r := newIssueRig(t)
	occurrence := r.ingest("TypeError", 5, false, true)

	// Without producers a served process does nothing with the evidence.
	bare, err := r.app.NewWorkers(r.config(nil))
	if err != nil {
		t.Fatal(err)
	}
	if rep := r.tick(bare); rep.Produced != 0 {
		t.Fatalf("producers off: %+v", rep)
	}
	if got := r.snapshot(); len(got.Issues) != 0 || len(r.incidentRecords()) != 0 {
		t.Fatalf("something produced without producers: %+v", got)
	}

	w := r.workers()
	first := r.tick(w)
	if first.Produced != 2 {
		t.Fatalf("first tick produced %d, want 1 occurrence + 1 incident: %+v", first.Produced, first)
	}
	snap := r.snapshot()
	if len(snap.Issues) != 1 || len(snap.Issues[0].Occurrences) != 1 || snap.Issues[0].Occurrences[0].OccurrenceID != occurrence || snap.Issues[0].Workflow != "open" {
		t.Fatalf("issue state: %+v", snap.Issues)
	}
	checkpoint := onlyCheckpoint(t, snap)
	if checkpoint == 0 || snap.Issues[0].Occurrences[0].Origin.Index != checkpoint {
		t.Fatalf("checkpoint %d does not cover the applied cursor %+v", checkpoint, snap.Issues[0].Occurrences[0].Origin)
	}
	records := r.incidentRecords()
	if len(records) != 1 {
		t.Fatalf("incidents = %d, want 1", len(records))
	}
	view, err := r.app.Actions.GetIncident(r.ctx, r.admin(), r.project, records[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if view.Status != "open" || view.Severity != "critical" || !view.SourceFiring || view.Version != 1 {
		t.Fatalf("incident view: %+v", view)
	}
	for _, l := range view.Links {
		if l.Kind == incidents.LinkIssue {
			t.Fatalf("the incident carries an issue link: %+v", view.Links)
		}
	}
	if len(view.Timeline) != 1 || view.Timeline[0].Type != "open" || view.Timeline[0].Origin != "system" || view.Timeline[0].Actor != auth.SystemPrincipal(r.org) {
		t.Fatalf("incident timeline: %+v", view.Timeline)
	}
	var audited bool
	if err = r.app.Control.View(r.ctx, func(st model.ControlState) error {
		for _, a := range st.Audits {
			if a.Action == "incidents.open" {
				audited = a.Principal == auth.SystemPrincipal(r.org) && a.Org == r.org.String()
			}
		}
		return nil
	}); err != nil || !audited {
		t.Fatalf("the incident audit actor is not the system principal (err %v)", err)
	}
	queue, err := r.app.Actions.Queue(r.ctx, r.admin(), httpapi.QueueRequest{Projects: []model.ID{r.project}, Limit: 10})
	if err != nil || len(queue.Entries) != 1 || queue.Entries[0].ID != records[0].ID {
		t.Fatalf("queue: %v %+v", err, queue.Entries)
	}

	// A second pass adds nothing.
	revision := snap.Revision
	second := r.tick(w)
	if second.Produced != 0 {
		t.Fatalf("second tick produced %d: %+v", second.Produced, second)
	}
	again := r.snapshot()
	if again.Revision != revision || len(r.incidentRecords()) != 1 {
		t.Fatalf("second tick changed state: revision %d -> %d", revision, again.Revision)
	}
	if v, err := r.app.Incidents.Get(r.ctx, r.admin(), r.project, records[0].ID); err != nil || v.Version != 1 || v.Status != incidents.StatusOpen {
		t.Fatalf("incident after second tick: %v %+v", err, v)
	}
}

// Same fingerprint, same issue, no second incident; another class, another issue
// and incident; a handled error is a minor impact.
func TestProducerGroupsByFingerprintAndOpensOneIncidentPerIssue(t *testing.T) {
	r := newIssueRig(t)
	r.ingest("TypeError", 5, true, false)
	r.ingest("TypeError", 6, true, false)
	r.ingest("RangeError", 7, true, false)
	r.tick(r.workers())
	snap := r.snapshot()
	if len(snap.Issues) != 2 {
		t.Fatalf("issues = %d, want 2", len(snap.Issues))
	}
	counts := map[int]int{}
	for _, i := range snap.Issues {
		counts[len(i.Occurrences)]++
	}
	if counts[2] != 1 || counts[1] != 1 {
		t.Fatalf("occurrences per issue: %v", counts)
	}
	records := r.incidentRecords()
	if len(records) != 2 {
		t.Fatalf("incidents = %d, want one per issue", len(records))
	}
	for _, rec := range records {
		v, err := r.app.Actions.GetIncident(r.ctx, r.admin(), r.project, rec.ID)
		if err != nil || v.Severity != "minor" {
			t.Fatalf("severity: %v %+v", err, v)
		}
	}
	// An unhandled non-fatal error is major.
	r.ingest("OtherError", 8, false, false)
	r.tick(r.workers())
	major := 0
	for _, rec := range r.incidentRecords() {
		if v, err := r.app.Actions.GetIncident(r.ctx, r.admin(), r.project, rec.ID); err == nil && v.Severity == "major" {
			major++
		}
	}
	if major != 1 {
		t.Fatalf("major incidents = %d", major)
	}
}

// The same occurrence sent again in a new batch (a client retry with a new batch
// ID) must not wedge the producer: it is the same occurrence, applied once.
func TestProducerSameOccurrenceInAnotherBatchDoesNotWedge(t *testing.T) {
	r := newIssueRig(t)
	occurrence := model.NewID()
	r.ingestBatch(r.record("TypeError", 5, true, false, occurrence))
	r.ingestBatch(r.record("TypeError", 5, true, false, occurrence))
	r.ingestBatch(r.record("TypeError", 6, true, false, model.NewID()))
	w := r.workers()
	rep := r.tick(w)
	if rep.Produced != 3 { // two distinct occurrences + one incident
		t.Fatalf("produced %d: %+v", rep.Produced, rep)
	}
	snap := r.snapshot()
	if len(snap.Issues) != 1 || len(snap.Issues[0].Occurrences) != 2 {
		t.Fatalf("issues: %+v", snap.Issues)
	}
	first := sumCheckpoints(snap)
	r.ingestBatch(r.record("TypeError", 7, true, false, occurrence))
	if rep = r.tick(w); rep.Produced != 0 {
		t.Fatalf("a repeated occurrence produced: %+v", rep)
	}
	if next := sumCheckpoints(r.snapshot()); next <= first {
		t.Fatalf("the checkpoint did not move past the repeated occurrence: %d -> %d", first, next)
	}
}

// A call is bounded: three batches of 300 occurrences are applied two batches
// (whole cursors) at a time, resuming strictly after the checkpoint.
func TestProducerIsBoundedPerCallAndResumesAfterCheckpoint(t *testing.T) {
	r := newIssueRig(t)
	ids := r.idsInOneSlot(900)
	for b := range 3 {
		records := make([]model.Record, 0, 300)
		for i := range 300 {
			records = append(records, r.record("TypeError", model.UnixNano(10+b*1000+i), true, false, ids[b*300+i]))
		}
		r.ingestBatch(records...)
	}
	w := r.workers()
	first := r.tick(w)
	if first.Produced != 600+1 {
		t.Fatalf("first tick produced %d, want 600 occurrences + 1 incident", first.Produced)
	}
	snap := r.snapshot()
	if len(snap.Issues) != 1 || len(snap.Issues[0].Occurrences) != 600 {
		t.Fatalf("after the first tick: %d occurrences", len(snap.Issues[0].Occurrences))
	}
	mid := onlyCheckpoint(t, snap)
	second := r.tick(w)
	if second.Produced != 300 {
		t.Fatalf("second tick produced %d, want the remaining 300", second.Produced)
	}
	snap = r.snapshot()
	if len(snap.Issues[0].Occurrences) != 900 || onlyCheckpoint(t, snap) <= mid {
		t.Fatalf("after the second tick: %d occurrences, checkpoint %d -> %d", len(snap.Issues[0].Occurrences), mid, onlyCheckpoint(t, snap))
	}
	if third := r.tick(w); third.Produced != 0 {
		t.Fatalf("third tick: %+v", third)
	}
}

type allowFence struct{}

func (allowFence) Admit(context.Context, auth.Scope, model.ID) error { return nil }

type allowPolicy struct{}

func (allowPolicy) AuthorizePolicyWrite(context.Context, auth.Scope, model.ID) error { return nil }

type adminGraphs struct{ r *issueRig }

func (g adminGraphs) Graph(ctx context.Context, _ auth.Scope, project model.ID) (releases.Graph, error) {
	return g.r.app.Releases.Graph(ctx, g.r.admin(), project)
}

type constClock model.UnixNano

func (c constClock) Now() model.UnixNano { return model.UnixNano(c) }

// A regression (resolved, then seen again after the boundary) is a new episode
// with its own incident; the first stays one.
func TestProducerRegressionOpensANewEpisodeIncident(t *testing.T) {
	r := newIssueRig(t)
	r.ingest("TypeError", 5, true, false)
	w := r.workers()
	r.tick(w)
	first := r.incidentRecords()
	if len(first) != 1 {
		t.Fatalf("incidents = %d", len(first))
	}
	store, err := issues.NewControlStore(r.app.Control)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := issues.New(issues.Deps{Store: store, Authorizer: r.app.Auth, Graphs: adminGraphs{r}, Fence: allowFence{}, Policy: allowPolicy{}, Clock: constClock(1000), Regression: issues.RegressionPolicy{MinOccurrences: 1}})
	if err != nil {
		t.Fatal(err)
	}
	issue := r.snapshot().Issues[0]
	if _, err = svc.Act(r.ctx, r.system(auth.IssuesWrite), issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: issue.Revision, IssueID: issue.ID, Kind: "resolve", Reason: "fixed", ResolutionBoundary: 500}); err != nil {
		t.Fatal(err)
	}
	if rep := r.tick(w); rep.Produced != 0 {
		t.Fatalf("a resolved issue produced: %+v", rep)
	}
	r.ingest("TypeError", 2000, true, false)
	rep := r.tick(w)
	if rep.Produced != 2 {
		t.Fatalf("regression produced %d, want 1 occurrence + 1 incident: %+v", rep.Produced, rep)
	}
	if got := r.snapshot().Issues[0]; got.Workflow != "open" {
		t.Fatalf("the issue was not reopened: %s", got.Workflow)
	}
	records := r.incidentRecords()
	if len(records) != 2 || records[0].ID == records[1].ID {
		t.Fatalf("incidents after the regression: %d", len(records))
	}
	if rep = r.tick(w); rep.Produced != 0 || len(r.incidentRecords()) != 2 {
		t.Fatalf("a repeat after the regression produced: %+v", rep)
	}
}

// A node that is not the leader produces nothing, and a pass whose lease the
// control group no longer recognizes produces nothing (the producer re-proves
// the lease itself).
func TestProducerLeaderGating(t *testing.T) {
	r := newIssueRig(t)
	r.ingest("TypeError", 5, false, true)
	fence := r.fence()
	fence.notLeader.Store(true)
	w := r.workers(func(c *appcore.WorkerConfig) { c.Fence = fence })
	for range 3 {
		if rep := w.Tick(r.ctx); rep.Leader || rep.Produced != 0 || len(rep.Errors) != 0 {
			t.Fatalf("a non-leader produced: %+v", rep)
		}
	}
	if got := r.snapshot(); len(got.Issues) != 0 || len(r.incidentRecords()) != 0 {
		t.Fatal("a non-leader committed state")
	}
}

// staleLease hands the workers a lease the control group never issued while the
// runner's own re-proof stays quiet, so only the producer's check can stop it.
type staleLease struct{ inner appcore.LeaderFence }

func (s staleLease) Fence(ctx context.Context) (replica.FenceToken, error) {
	t, err := s.inner.Fence(ctx)
	if err != nil {
		return t, err
	}
	var bad replica.FenceToken
	return bad, nil
}
func (s staleLease) ValidateFence(context.Context, replica.FenceToken) error { return nil }

func TestProducerRefusesAnUnprovenLease(t *testing.T) {
	r := newIssueRig(t)
	r.ingest("TypeError", 5, false, true)
	w := r.workers(func(c *appcore.WorkerConfig) { c.Fence = staleLease{r.app.Control.ReplicaGroup()} })
	rep := w.Tick(r.ctx)
	if rep.Produced != 0 || len(rep.Errors) == 0 {
		t.Fatalf("a producer acted under a lease the control group does not hold: %+v", rep)
	}
	if got := r.snapshot(); len(got.Issues) != 0 || len(r.incidentRecords()) != 0 {
		t.Fatal("state committed under an unproven lease")
	}
}

// Nothing is produced for a retired project or organization; the evidence is
// still there afterwards, so it was the retirement that stopped it.
func TestProducerNothingForRetiredProjectOrOrganization(t *testing.T) {
	for name, key := range map[string]string{"project": "project", "organization": "org"} {
		t.Run(name, func(t *testing.T) {
			r := newIssueRig(t)
			r.ingest("TypeError", 5, false, true)
			retire := func(on bool) {
				if err := r.app.Control.Update(r.ctx, func(st *model.ControlState) error {
					if key == "project" {
						k := r.org.String() + ":" + r.project.String()
						if st.RetiredProjects == nil {
							st.RetiredProjects = map[string]model.ID{}
						}
						if on {
							st.RetiredProjects[k] = model.NewID()
						} else {
							delete(st.RetiredProjects, k)
						}
						return nil
					}
					if st.RetiredOrgs == nil {
						st.RetiredOrgs = map[string]model.ID{}
					}
					if on {
						st.RetiredOrgs[r.org.String()] = model.NewID()
					} else {
						delete(st.RetiredOrgs, r.org.String())
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			w := r.workers()
			retire(true)
			if rep := w.Tick(r.ctx); rep.Produced != 0 {
				t.Fatalf("produced for a retired %s: %+v", name, rep)
			}
			retire(false)
			if got := r.snapshot(); len(got.Issues) != 0 || len(r.incidentRecords()) != 0 {
				t.Fatalf("state committed for a retired %s", name)
			}
			if rep := r.tick(w); rep.Produced != 2 {
				t.Fatalf("after reinstating the %s: %+v", name, rep)
			}
		})
	}
}

// The producer's scopes are the runner's: issues.write for the ledger,
// org.admin for incidents, and the issue ledger refuses a scope without
// issues.write.
func TestProducerScopeRoles(t *testing.T) {
	r := newIssueRig(t)
	r.ingest("TypeError", 5, false, true)
	r.tick(r.workers())
	store, err := issues.NewControlStore(r.app.Control)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []auth.Permission{auth.Read, auth.IssuesWrite, auth.OrgAdmin} {
		if _, err = store.Load(r.ctx, r.system(p), r.project); err != nil && p != auth.OrgAdmin {
			t.Fatalf("%s: %v", p, err)
		}
	}
	read := r.system(auth.Read)
	cmd, _ := json.Marshal(control.IssueCommand{Operation: "commit", Project: r.project, ExpectedRevision: r.snapshot().Revision, Checkpoint: &control.IssueCheckpoint{Group: model.NewID(), Index: 1}})
	if _, err = r.app.Control.Transact(r.ctx, read, control.Command{CommandID: model.NewID(), ExpectedRevision: r.currentRevision(), Kind: string(control.KindApplyIssueEvidence), Payload: cmd}); err == nil {
		t.Fatal("a read-only system scope committed to the issue ledger")
	}
}

func (r *issueRig) currentRevision() model.Revision {
	var revision model.Revision
	if err := r.app.Control.View(r.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		r.t.Fatal(err)
	}
	return revision
}
