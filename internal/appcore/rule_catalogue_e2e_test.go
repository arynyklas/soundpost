// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
	"github.com/arynyklas/soundpost/internal/rules"
	"github.com/arynyklas/soundpost/internal/storage"
)

// ruleRig is a worker node served over the rule route: an administrator
// authors rules over HTTP, a real metric source ingests data through the
// production ingest path, and the workers run over the node with a recording
// Sender and the test clock. Nothing is injected into the rule path: what the
// workers evaluate is what the route committed.
type ruleRig struct {
	*workerNode
	srv      *httptest.Server
	session  auth.Session
	source   model.ID
	secret   string
	resource model.Resource
	admit    func(model.Batch) (model.Receipt, error)
}

func newRuleRig(t *testing.T) *ruleRig {
	t.Helper()
	n := newWorkerNode(t)
	r := &ruleRig{workerNode: n, source: model.NewID()}
	service, environment, build := model.NewID(), model.NewID(), model.NewID()
	r.resource = model.Resource{Service: service, Environment: environment, Build: build, Instance: "rules-1", Labels: model.Labels{}}
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric},
		Resources:     model.ResourceRegistry{Services: []model.ID{service}, Environments: []model.ID{environment}, Builds: []model.ID{build}, Instances: []string{"rules-1"}},
		Labels:        map[string][]string{"job": {"api"}, "env": {"prod"}},
		RetentionDays: map[model.Kind]uint32{model.Metric: 7}, MaxBytes: 64 << 20, MaxSeries: 1000}
	issued, err := n.app.Auth.OnboardSource(n.ctx, n.actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: n.org, Project: n.project, Source: r.source,
		Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "rule catalogue e2e"})
	if err != nil {
		t.Fatal(err)
	}
	r.secret = issued.Credential
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
	if r.session, err = n.app.Auth.Login(n.ctx, "workers@example.test", "worker wiring password 2026", ""); err != nil {
		t.Fatal(err)
	}
	r.srv = httptest.NewTLSServer(httpapi.NewServer("", n.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterPolicyRoutes(mux, n.app.Auth, n.app.Policies)
	}).Handler)
	t.Cleanup(r.srv.Close)
	return r
}

// lbl builds a label set from name, value pairs.
func lbl(pairs ...string) model.Labels {
	out := model.Labels{}
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, model.Label{Name: pairs[i], Value: pairs[i+1]})
	}
	return out
}

// put admits one metric sample through the production ingest path.
func (r *ruleRig) put(name string, labels model.Labels, at model.UnixNano, value float64) {
	r.t.Helper()
	bits := model.FloatBits(math.Float64bits(value))
	producer := model.ID{0xd1}
	record := model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: at, Resource: r.resource,
		Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: labels, SampleKind: "float", Value: &bits, Unit: "1", Type: "gauge"}}}
	slot, err := model.OwnerSlot(r.org, r.project, r.source, producer, record)
	if err != nil {
		r.t.Fatal(err)
	}
	batch := model.Batch{Version: 1, Project: r.project, Source: r.source, Producer: producer, ID: model.NewID(), PolicyRevision: 1, RouteSlot: slot, Records: []model.Record{record}}
	if _, err = r.admit(batch); err != nil {
		r.t.Fatal(err)
	}
}

// post is one request to the rule route as the logged-in administrator.
func (r *ruleRig) post(body map[string]any) (int, []byte) {
	r.t.Helper()
	body["org"], body["project_id"] = r.org.String(), r.project.String()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", r.srv.URL+"/api/v1/rules", bytes.NewReader(raw))
	req.Header.Set("Cookie", "__Host-soundpost="+r.session.Token)
	req.Header.Set("X-CSRF-Token", r.session.CSRF)
	req.Header.Set("Origin", r.srv.URL)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.srv.Client().Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// save authors one rule over the route and returns its ID and committed revision.
func (r *ruleRig) save(id model.ID, expected uint64, spec map[string]any) httpapi.RuleView {
	r.t.Helper()
	status, raw := r.post(map[string]any{"operation": "save", "command_id": model.NewID().String(), "rule_id": id.String(),
		"expected_revision": strconv.FormatUint(expected, 10), "reason": "served-node e2e", "rule": spec})
	var answer httpapi.RuleWriteAnswer
	if err := json.Unmarshal(raw, &answer); status != http.StatusOK || err != nil {
		r.t.Fatalf("save over the route: %d %v %s", status, err, raw)
	}
	return answer.Rule
}

func (r *ruleRig) alertSpec(expression string) map[string]any {
	return map[string]any{"kind": "alert", "profile": "promql-prometheus-3.13.5", "feature_set": r.feature, "expression": expression, "interval_seconds": 60, "severity": "critical"}
}

// deliverySender records every delivery the workers hand it.
type deliverySender struct {
	mu   sync.Mutex
	sent []notify.Delivery
}

func (s *deliverySender) Send(_ context.Context, _ auth.Scope, d notify.Delivery) (notify.Outcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, d)
	return notify.Outcome{Kind: notify.OutcomeAccepted, ProviderID: "provider-" + strconv.Itoa(len(s.sent))}, nil
}

func (s *deliverySender) deliveries() []notify.Delivery {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]notify.Delivery(nil), s.sent...)
}

func (r *ruleRig) conditionIDs() map[model.ID]bool {
	r.t.Helper()
	ids := map[model.ID]bool{}
	if err := r.app.Control.View(r.ctx, func(st model.ControlState) error {
		for key := range st.ConditionBooks {
			// The key is "org:project:condition".
			parts := strings.Split(key, ":")
			id, err := model.ParseID(parts[len(parts)-1])
			if len(parts) != 3 || err != nil {
				r.t.Fatalf("condition key %q", key)
			}
			ids[id] = true
		}
		return nil
	}); err != nil {
		r.t.Fatal(err)
	}
	return ids
}

// A served node evaluates the rules an administrator saved over the route, and
// only those: the route commits the definition to control state, the workers
// list it from there (RuleCatalogue is the node's RuleSource), the scheduler
// evaluates it against the data the node ingested, a firing series opens a
// condition that the conditions consumer applies, the org routing decides a
// notification to the organization's enabled destination and the delivery worker
// hands it to the sender exactly once. A rule whose expression the data does not
// satisfy opens nothing; a retired rule is no longer evaluated; a new version of
// a rule is evaluated under its own version.
func TestServedNodeEvaluatesRulesAuthoredOverTheRouteAndNotifies(t *testing.T) {
	r := newRuleRig(t)
	for _, v := range []float64{10, 10, 10} {
		r.put("queue_depth", lbl("job", "api"), workerGrid-model.UnixNano(20*time.Second), v)
	}
	catalogue, err := r.app.RuleCatalogue()
	if err != nil {
		t.Fatal(err)
	}
	sender := &deliverySender{}
	w, err := r.app.NewWorkers(r.config(func(c *appcore.WorkerConfig) {
		c.Rules = catalogue
		c.Sender = sender
		c.Routing = r.app.OrgRouting()
	}))
	if err != nil {
		t.Fatal(err)
	}
	// With nothing authored a pass evaluates nothing.
	if rep := r.tick(w); rep.Evaluated != 0 || rep.Consumed != 0 || len(sender.deliveries()) != 0 {
		t.Fatalf("a pass over an empty catalogue: %+v", rep)
	}

	firing, quiet := model.NewID(), model.NewID()
	viewFiring := r.save(firing, 0, r.alertSpec("queue_depth > 5"))
	viewQuiet := r.save(quiet, 0, r.alertSpec("queue_depth > 50"))
	if viewFiring.Version != 1 || viewFiring.Revision != 1 || viewQuiet.Version != 1 {
		t.Fatalf("saved views: %+v %+v", viewFiring, viewQuiet)
	}

	rep := r.tick(w)
	if rep.Evaluated != 2 || rep.Consumed != 1 || rep.Submitted == 0 || rep.Attempted != 1 {
		t.Fatalf("the pass after the rules were saved: %+v", rep)
	}
	for id, version := range map[model.ID]model.Revision{firing: 1, quiet: 1} {
		book, found := r.book(rules.Rule{ID: id, Project: r.project})
		if !found || book.Head != version || len(book.Versions) != 1 || book.Versions[0].Last == nil || book.Versions[0].Last.At != workerGrid {
			t.Fatalf("rule %s: no evaluation committed at the grid point %d: found=%v %+v", id, workerGrid, found, book)
		}
	}
	sent := sender.deliveries()
	conditions := r.conditionIDs()
	if len(sent) != 1 || len(conditions) != 1 || sent[0].Template.Entity.Kind != notify.EntityCondition || !conditions[sent[0].Template.Entity.ID] ||
		sent[0].Key.Recipient == nil || *sent[0].Key.Recipient != r.dest || sent[0].Template.Project != r.project {
		t.Fatalf("deliveries %+v for conditions %v: want one condition notification to the destination", sent, conditions)
	}
	if accepted := r.deliveries(control.DeliveryAccepted); len(accepted) != 1 {
		t.Fatalf("accepted deliveries: %+v", accepted)
	}
	// The same pass again changes nothing.
	r.clock.v.Add(int64(time.Second))
	if again := r.tick(w); again.Evaluated != 0 || len(sender.deliveries()) != 1 {
		t.Fatalf("a repeated pass: %+v, %d deliveries", again, len(sender.deliveries()))
	}

	// A retired rule stops at the next pass; the other keeps its grid.
	status, raw := r.post(map[string]any{"operation": "retire", "command_id": model.NewID().String(), "rule_id": firing.String(), "expected_revision": "1", "reason": "stop it"})
	if status != http.StatusOK {
		t.Fatalf("retire: %d %s", status, raw)
	}
	r.clock.v.Add(int64(time.Minute))
	if rep = r.tick(w); rep.Evaluated != 1 {
		t.Fatalf("the pass after a retirement evaluated %d rules, want 1", rep.Evaluated)
	}
	if book, _ := r.book(rules.Rule{ID: firing, Project: r.project}); len(book.Versions) != 1 || book.Versions[0].Last.At != workerGrid {
		t.Fatalf("a retired rule was evaluated again: %+v", book)
	}
	if book, _ := r.book(rules.Rule{ID: quiet, Project: r.project}); book.Versions[0].Last.At != workerGrid+model.UnixNano(time.Minute) {
		t.Fatalf("the other rule did not advance: %+v", book)
	}

	// A new version is evaluated under its own number, and now the data satisfies it.
	updated := r.save(quiet, 1, r.alertSpec("queue_depth > 0"))
	if updated.Version != 2 || updated.Revision != 2 {
		t.Fatalf("updated view: %+v", updated)
	}
	r.clock.v.Add(int64(time.Minute))
	rep = r.tick(w)
	if rep.Evaluated != 1 || rep.Consumed != 1 || len(sender.deliveries()) != 2 {
		t.Fatalf("the pass after the update: %+v, %d deliveries", rep, len(sender.deliveries()))
	}
	if book, _ := r.book(rules.Rule{ID: quiet, Project: r.project}); book.Head != 2 {
		t.Fatalf("the new version was not evaluated: %+v", book)
	}
	if conditions = r.conditionIDs(); len(conditions) != 2 {
		t.Fatalf("conditions after the update: %v", conditions)
	}
}

// stored lists the observation times of every stored sample of a metric.
func (r *ruleRig) stored(name string) []model.UnixNano {
	r.t.Helper()
	scope, err := r.app.Auth.Authorize(r.ctx, r.actor, r.org, []model.ID{r.project}, auth.Read)
	if err != nil {
		r.t.Fatal(err)
	}
	rows, err := r.app.Storage.Scan(r.ctx, scope, storage.ScanRequest{Projects: []model.ID{r.project}, Signal: model.Metric, Start: math.MinInt64, End: math.MaxInt64})
	if err != nil {
		r.t.Fatal(err)
	}
	defer rows.Close()
	var out []model.UnixNano
	for {
		page, err := rows.Next(r.ctx)
		if err == io.EOF {
			return out
		}
		if err != nil {
			r.t.Fatal(err)
		}
		for i := range page.Len() {
			if m := page.Values[i].Metric; m != nil && m.Name == name {
				out = append(out, page.ObservedTimes[i])
			}
		}
	}
}

// A recording rule saved over the route records through the node's recording
// source: the save is checked against the source's label policy, the evaluation
// derives the sample under the source's producer identity, the output worker
// admits it through the ordinary ingest path under the source credential, and the
// stored sample is there exactly once however often the passes repeat.
func TestServedNodeRecordsARuleThroughTheRecordingSource(t *testing.T) {
	r := newRuleRig(t)
	r.put("queue_depth", lbl("job", "api"), workerGrid-model.UnixNano(20*time.Second), 7)
	source, err := r.app.NewRecordingSource(r.ctx, r.secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.app.NewRecordingSource(r.ctx, "not-a-source-credential"); err == nil {
		t.Fatal("a recording source accepted a credential that is not one")
	}
	catalogue, err := r.app.RuleCatalogue(rules.WithRecordingSource(source))
	if err != nil {
		t.Fatal(err)
	}
	r.app.Policies.UseRecordingSource(source)
	t.Cleanup(func() { r.app.Policies.UseRecordingSource(nil) })
	spec := func(labels ...map[string]string) map[string]any {
		s := r.alertSpec("sum by (job) (queue_depth)")
		s["kind"], s["record_name"] = "recording", "job:queue_depth:sum"
		delete(s, "severity")
		if len(labels) > 0 {
			s["labels"] = labels
		}
		return s
	}
	// A label the source policy does not enumerate is refused at save.
	status, raw := r.post(map[string]any{"operation": "save", "command_id": model.NewID().String(), "rule_id": model.NewID().String(), "expected_revision": "0", "reason": "x",
		"rule": spec(map[string]string{"name": "env", "value": "staging"})})
	if status != http.StatusBadRequest {
		t.Fatalf("a label outside the source policy: %d %s", status, raw)
	}
	rule := model.NewID()
	r.save(rule, 0, spec(map[string]string{"name": "env", "value": "prod"}))

	w, err := r.app.NewWorkers(r.config(func(c *appcore.WorkerConfig) {
		c.Rules = catalogue
		c.Admission = source
		c.Producer = source.Producer
	}))
	if err != nil {
		t.Fatal(err)
	}
	rep := r.tick(w)
	if rep.Evaluated != 1 || rep.Finalized != 1 {
		t.Fatalf("the pass after the rule was saved: %+v", rep)
	}
	if got := r.stored("job:queue_depth:sum"); len(got) != 1 || got[0] != workerGrid {
		t.Fatalf("recorded samples: %v, want exactly one at %d", got, workerGrid)
	}
	r.clock.v.Add(int64(time.Second))
	if again := r.tick(w); again.Evaluated != 0 || again.Finalized != 0 {
		t.Fatalf("a repeated pass: %+v", again)
	}
	if got := r.stored("job:queue_depth:sum"); len(got) != 1 {
		t.Fatalf("a repeated pass recorded again: %v", got)
	}
	out, err := r.app.Control.RuleOutputs(r.ctx, r.adminFor(r.project), r.project, rule, control.RulePhaseFinalized, 0)
	if err != nil || len(out) != 1 || out[0].Receipt == nil {
		t.Fatalf("finalized outputs: %+v %v", out, err)
	}
}

// Without a recording source the recording stage is off and a recording rule
// cannot be saved: nothing is admitted on a node that was not given the
// credential.
func TestServedNodeWithoutARecordingSourceRefusesRecordingRules(t *testing.T) {
	r := newRuleRig(t)
	s := r.alertSpec("sum by (job) (queue_depth)")
	s["kind"], s["record_name"] = "recording", "job:queue_depth:sum"
	delete(s, "severity")
	status, raw := r.post(map[string]any{"operation": "save", "command_id": model.NewID().String(), "rule_id": model.NewID().String(), "expected_revision": "0", "reason": "x", "rule": s})
	if status != http.StatusBadRequest || !bytes.Contains(raw, []byte(rules.ReasonRecordingSourceUnavailable)) {
		t.Fatalf("a recording rule on a node with no recording source: %d %s", status, raw)
	}
}
