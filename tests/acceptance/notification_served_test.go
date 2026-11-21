// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package acceptance

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// servedPipeline is what a serving process runs on the node, and nothing else:
// the real HTTP routes (appcore.App.Register) and the leader-only background
// workers (appcore.NewWorkers over appcore.Producers, the production
// notification routing and the delivery worker). The journeys below never call an
// issue, incident or policy API by hand: evidence enters through the ingest wire,
// and issues, incidents, policy decisions, deliveries and the owner-cutover mode
// are all produced by the worker passes. Only the operator's cutover commands, the
// provider (a recording Sender behind the committed interface) and the clock (the
// worker's Clock seam) are the test's.
type servedPipeline struct {
	n   *accNode
	srv *httptest.Server
	// tls serves the same routes over TLS: session-authenticated routes (rule
	// authoring) need the console's cookie and are refused over plain HTTP.
	tls     *httptest.Server
	workers *appcore.Workers
	// viewToken is a service credential with policy.write on the project: what the
	// console's cutover page reads the view with.
	viewToken string
}

func (n *accNode) serve() *servedPipeline { return n.serveWith(nil) }

// serveWith is serve with the worker configuration adjusted by extra (the rule
// catalogue of the condition journey).
func (n *accNode) serveWith(extra func(*appcore.WorkerConfig)) *servedPipeline {
	n.t.Helper()
	mux := http.NewServeMux()
	n.app.Register(mux)
	srv := httptest.NewServer(mux)
	n.t.Cleanup(srv.Close)
	tlsSrv := httptest.NewTLSServer(mux)
	n.t.Cleanup(tlsSrv.Close)
	cfg := appcore.WorkerConfig{
		Producers: n.app.Producers(),
		Routing:   n.app.OrgRouting(),
		Sender:    n.prov,
		Clock:     n.clock,
	}
	if extra != nil {
		extra(&cfg)
	}
	w, err := n.app.NewWorkers(cfg)
	if err != nil {
		n.t.Fatal(err)
	}
	if err = n.app.Auth.DrainSourceFences(n.ctx); err != nil {
		n.t.Fatal("source fences:", err)
	}
	issued, err := n.app.Auth.IssueServerToken(n.ctx, n.cred, n.org, n.user, []model.ID{n.project}, []auth.Permission{auth.PolicyWrite}, time.Now().Add(time.Hour).Unix(), "cutover view")
	if err != nil {
		n.t.Fatal("view credential:", err)
	}
	return &servedPipeline{n: n, srv: srv, tls: tlsSrv, workers: w, viewToken: issued.Token}
}

// ingestError sends one fatal error occurrence through the real ingest route with
// the source credential and returns the durable receipt.
func (s *servedPipeline) ingestError(class string) model.Receipt {
	n := s.n
	n.t.Helper()
	record := model.Record{ID: model.NewID(), Kind: model.ErrorKind, ObservedAt: n.clock.Now(), Resource: n.resource,
		Payload: model.Payload{Error: &model.ErrorOccurrence{Occurrence: model.NewID(), Class: class, Mechanism: "manual", Build: n.resource.Build, Fatal: true, Frames: []model.Frame{}}}}
	producer := model.NewID()
	slot, err := model.OwnerSlot(n.org, n.project, n.source, producer, record)
	if err != nil {
		n.t.Fatal(err)
	}
	batch := model.Batch{Version: 1, Project: n.project, Source: n.source, Producer: producer, ID: model.NewID(), PolicyRevision: n.version, RouteSlot: slot, Records: []model.Record{record}}
	body, err := json.Marshal(batch)
	if err != nil {
		n.t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, s.srv.URL+"/ingest/v1/batches", bytes.NewReader(body))
	if err != nil {
		n.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+n.issued)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		n.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var receipt model.Receipt
	if resp.StatusCode != http.StatusOK || json.Unmarshal(raw, &receipt) != nil || receipt.BatchID != batch.ID {
		n.t.Fatalf("ingest %q: %d %s", class, resp.StatusCode, raw)
	}
	return receipt
}

// pass is one worker pass at the clock's instant. A stage failure is a test failure.
func (s *servedPipeline) pass() appcore.PassReport {
	s.n.t.Helper()
	var rep appcore.PassReport
	// A leadership change (a killed voter, a transfer) can leave a pass without the
	// lease for a moment; the lease is awaited, a stage failure is never tolerated.
	for range 100 {
		if rep = s.workers.Tick(s.n.ctx); rep.Leader {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !rep.Leader || len(rep.Errors) != 0 {
		s.n.t.Fatalf("worker pass: leader=%v deposed=%v errors=%+v", rep.Leader, rep.Deposed, rep.Errors)
	}
	return rep
}

// passUntil runs worker passes (a few seconds of the worker's clock each) until
// done, and fails with what is missing when it does not happen.
func (s *servedPipeline) passUntil(what string, done func() bool) {
	s.n.t.Helper()
	for range 200 {
		s.pass()
		if done() {
			return
		}
		s.n.clock.add(2 * sec)
		time.Sleep(10 * time.Millisecond)
	}
	s.n.t.Fatalf("the worker passes never produced %s", what)
}

// view reads the cutover view of the project through the real route, with a
// service credential that holds policy.write on the project.
func (s *servedPipeline) view() control.CutoverView {
	n := s.n
	n.t.Helper()
	body, err := json.Marshal(map[string]any{"org": n.org.String(), "project_id": n.project.String()})
	if err != nil {
		n.t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, s.srv.URL+"/api/v1/cutover", bytes.NewReader(body))
	if err != nil {
		n.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+s.viewToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		n.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var v control.CutoverView
	if resp.StatusCode != http.StatusOK || json.Unmarshal(raw, &v) != nil {
		n.t.Fatalf("cutover view: %d %s", resp.StatusCode, raw)
	}
	return v
}

// incidentCount is how many incidents the project has: all of them opened by the
// incident producer from issue episodes.
func (n *accNode) incidentCount() int {
	n.t.Helper()
	recs, err := n.app.Control.Incidents(n.ctx, n.scope(), n.project)
	if err != nil {
		n.t.Fatal(err)
	}
	return len(recs)
}

// deliveriesOf counts the project's delivery records of a kind, by phase.
func (n *accNode) deliveriesOf(kind notify.Kind) map[string]int {
	n.t.Helper()
	out := map[string]int{}
	for _, r := range n.records() {
		if r.Kind == string(kind) {
			out[r.Phase]++
		}
	}
	return out
}

// step commits one operator cutover command; the modes follow in the next worker
// pass (appcore.Workers syncs them), never by a call from the test.
func (n *accNode) step(phase notify.CutoverPhase, mods ...func(*notify.BarrierEvidence)) notify.CutoverState {
	n.t.Helper()
	s, err := n.cut.AdvanceCutover(n.ctx, n.scope(), n.command(phase, mods...))
	if err != nil {
		n.t.Fatalf("advance to %s: %v", phase, err)
	}
	n.clock.add(30 * sec)
	return s
}

func TestNotificationCutoverThroughTheServedPipeline(t *testing.T) {
	eachServedLayout(t, servedPipelineCutover)
}

// servedPipelineCutover is the ownership journey of TestNotificationCutover
// (shadow, quiescing_old, barrier_verified, new_active, rollback_quiescing,
// old_active) with the evidence flowing the way it does in a served node: fatal
// errors posted to the ingest route -> admission -> issue producer -> incident
// producer -> the production notification routing -> policy decision -> delivery
// outbox -> delivery worker -> provider. The barrier's source frontier is the
// durable receipt cursor the ingest route returned, and it can only verify once the
// issue producer itself has committed its checkpoint up to that cursor.
func servedPipelineCutover(t *testing.T, n *accNode) {
	s := n.serve()

	// The old owner's episode: a fatal error already durable when the cutover starts.
	old := s.ingestError("PaymentFailed")
	n.frontierCursor = old.Cursor

	// Shadow: the product decides what it would send and sends nothing.
	n.step(notify.CutoverShadow)
	s.passUntil("the shadow decision for the old owner's episode", func() bool {
		return n.incidentCount() == 1 && n.deliveriesOf(notify.KindOpen)[control.DeliverySuppressed] == 1
	})
	for _, r := range n.records() {
		// The in-app queue entry is not an external send; every external delivery
		// decided in shadow is recorded and suppressed.
		if r.Kind != string(notify.KindQueue) && r.Phase != control.DeliverySuppressed {
			t.Fatalf("shadow: delivery %s/%s is %s, want suppressed", r.Kind, r.Subject, r.Phase)
		}
	}
	if got := n.prov.snapshot(); len(got) != 0 {
		t.Fatalf("the shadow sent %v", n.prov.kinds())
	}
	n.assertOneOwner(n.old)

	// The view shows the shadow: the old owner owns notifications, the opening the
	// product decided is recorded and unsent, and the history boundary begins.
	v := s.view()
	if v.Cutover == nil || v.Cutover.Phase != control.CutoverShadow || !v.Shadow.Observing || v.Shadow.Decisions != 1 || v.Shadow.ByKind[string(notify.KindOpen)] != 1 || len(v.Shadow.Recent) != 1 ||
		v.Shadow.Recent[0].Kind != string(notify.KindOpen) || len(v.History.Spans) != 1 || v.History.Spans[0].Side != control.HistorySideLegacy || v.History.Spans[0].To != 0 {
		t.Fatalf("the shadow view: %+v", v)
	}
	shadowID := v.Shadow.Recent[0].ID

	n.step(notify.CutoverQuiescingOld)
	s.pass()
	st := n.step(notify.CutoverBarrierVerified)
	if len(st.ActiveOwners) != 0 {
		t.Fatalf("barrier_verified has active owners %v", st.ActiveOwners)
	}
	s.pass()
	if got := n.prov.snapshot(); len(got) != 0 {
		t.Fatalf("a worker pass in barrier_verified sent %v", n.prov.kinds())
	}

	// New owner: the policy's own rule for the end of a shadow applies. What the
	// episode had suppressed while the product only watched is reevaluated ONCE, as one
	// current_state update; the old owner's opening is never re-announced.
	n.step(notify.CutoverNewActive)
	n.assertOneOwner(n.nw)
	s.passUntil("the end-of-shadow current-state update", func() bool { return len(n.prov.snapshot()) >= 1 })
	s.pass()
	s.pass()
	if kinds := n.prov.kinds(); !slices.Equal(kinds, []string{string(notify.KindCurrent)}) {
		t.Fatalf("the activation sent %v, want exactly one current_state (never the old owner's opening again)", kinds)
	}
	baseline := len(n.prov.snapshot())
	v = s.view()
	last := v.History.Spans[len(v.History.Spans)-1]
	if v.Shadow.Observing || v.Cutover.Phase != control.CutoverNewActive || last.Side != control.HistorySideProduct || last.To != 0 || last.Owner == nil || *last.Owner != n.nw ||
		v.Shadow.Decisions != 1 || v.Shadow.Recent[0].ID != shadowID {
		t.Fatalf("the view after the activation: %+v", v)
	}

	// A genuinely new episode (a second fatal error, another class) is the new
	// owner's to announce, once.
	s.ingestError("InventoryTimeout")
	s.passUntil("the new owner's opening for the second episode", func() bool { return len(n.prov.snapshot()) == baseline+1 })
	s.pass()
	s.pass()
	if kinds := n.prov.kinds(); len(kinds) != baseline+1 || kinds[len(kinds)-1] != string(notify.KindOpen) {
		t.Fatalf("the new owner did not announce the second episode exactly once: %v", kinds)
	}
	if n.incidentCount() != 2 {
		t.Fatalf("%d incidents, want 2 (one per episode)", n.incidentCount())
	}
	sent, incidentsSoFar := len(n.prov.snapshot()), 2

	// Three voters: the leader of every group dies while the new owner is active. The
	// surviving voters elect another, the journey carries on through it, the episode
	// that was already announced is not announced again, and a new one is announced
	// exactly once.
	if n.layout == layoutCluster {
		s = n.loseTheLeader()
		for range 3 {
			s.pass()
		}
		if len(n.prov.snapshot()) != sent {
			t.Fatalf("the new leader re-sent what was already announced: %v", n.prov.kinds())
		}
		s.ingestError("CheckoutLatency")
		s.passUntil("the new leader's opening for the next episode", func() bool { return len(n.prov.snapshot()) == sent+1 })
		s.pass()
		s.pass()
		if kinds := n.prov.kinds(); len(kinds) != sent+1 || kinds[len(kinds)-1] != string(notify.KindOpen) {
			t.Fatalf("the new leader did not announce the next episode exactly once: %v", kinds)
		}
		n.assertOneOwner(n.nw)
		sent, incidentsSoFar = len(n.prov.snapshot()), 3
		if n.incidentCount() != incidentsSoFar {
			t.Fatalf("%d incidents after the leader change, want %d", n.incidentCount(), incidentsSoFar)
		}
	}

	// Rollback: the new owner no longer sends; a further episode is decided and suppressed.
	n.step(notify.CutoverRollbackQuiescing)
	n.assertOneOwner()
	s.ingestError("SearchIndexStale")
	s.passUntil("the next incident", func() bool { return n.incidentCount() == incidentsSoFar+1 })
	s.pass()
	if len(n.prov.snapshot()) != sent {
		t.Fatalf("a send went out during rollback_quiescing: %v", n.prov.kinds())
	}
	n.clock.add(3 * 60 * sec)
	n.step(notify.CutoverOldActive)
	n.assertOneOwner(n.old)
	s.pass()
	s.pass()
	if len(n.prov.snapshot()) != sent {
		t.Fatalf("a send went out after the old owner was reactivated: %v", n.prov.kinds())
	}

	// The view tells the whole story: the product owned notifications between the
	// activation and the rollback, the history spans are contiguous, and the two
	// openings decided while it only watched are its shadow decisions.
	v = s.view()
	var sides []string
	for i, sp := range v.History.Spans {
		sides = append(sides, sp.Side)
		if i+1 < len(v.History.Spans) && (sp.To == 0 || sp.To != v.History.Spans[i+1].From) {
			t.Fatalf("history spans are not contiguous: %+v", v.History.Spans)
		}
	}
	wantSides := []string{control.HistorySideLegacy, control.HistorySideLegacy, control.HistorySideHandover, control.HistorySideProduct, control.HistorySideHandover, control.HistorySideLegacy}
	if v.Cutover.Phase != control.CutoverOldActive || !slices.Equal(sides, wantSides) || v.History.Spans[len(v.History.Spans)-1].To != 0 ||
		v.Shadow.Decisions != 2 || v.Shadow.ByKind[string(notify.KindOpen)] != 2 || len(v.Cutover.Timeline) != 6 {
		t.Fatalf("the view at the end of the journey: %+v", v)
	}

	// Everything was produced by the product itself: the incidents were opened by the
	// system runner, never by a person or a test call.
	var audits []string
	_ = n.app.Control.View(n.ctx, func(cs control.State) error {
		for _, a := range cs.Audits {
			if a.Principal == auth.SystemPrincipal(n.org) {
				audits = append(audits, a.Action)
			}
		}
		return nil
	})
	if !slices.Contains(audits, "incidents.open") {
		t.Fatalf("no incident opening audited as the system runner: %v", audits)
	}
	recs, err := n.app.Control.Incidents(n.ctx, n.scope(), n.project)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range recs {
		var is incidents.State
		if err = json.Unmarshal(rec.State, &is); err != nil || is.Status != incidents.StatusOpen {
			t.Fatalf("incident %s: %v %+v", rec.ID, err, is)
		}
	}
	t.Logf("served pipeline on %s: provider sends %v; owners at the end %v", n.layout, n.prov.kinds(), n.mustCutState().ActiveOwners)
}

func (n *accNode) mustCutState() notify.CutoverState {
	s, ok := n.cutState()
	if !ok {
		n.t.Fatal("no cutover")
	}
	return s
}
