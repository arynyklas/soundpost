// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/incidents"
	"soundpost/internal/model"
	"soundpost/internal/notify"
)

// TestNotificationOutage is the whole-product outage drill against an ACTUAL
// external observer: tests/acceptance/observer is built and run as a separate
// operating-system process with its own credentials and its own storage path.
// The product (the real node, its HTTP heartbeat endpoints and its notification
// worker) is stopped while the observer keeps running; the observer must notice
// the missing heartbeats within its configured interval and deliver to an
// authorized test destination (a loopback receiver); when the product comes back
// the outage and its failed delivery attempt are still in the observer's record and
// no retroactive backlog is announced as a new emergency.
//
// WHAT THIS DOES NOT SHOW. The observer runs on the same host as the product, so
// it is NOT an independent failure domain: a host, power or network failure that
// takes the product down takes this observer down with it. The test shows that a
// separate process with separate state and credentials keeps working while the
// product is stopped; the independence of the failure domain is NOT demonstrated by
// this fixture. A real deployment needs a separately provisioned host, network
// path, credentials and schedule (docs/operations/external-deadman.md). No real
// SMTP, Telegram or webhook provider is contacted: the destination is a loopback
// receiver the observer was explicitly authorized for.
func TestNotificationOutage(t *testing.T) {
	n := newAccNode(t)
	s := n.activate()
	n.assertOneOwner(n.nw)
	_ = s

	const (
		interval = 200 * time.Millisecond
		missing  = 1500 * time.Millisecond
	)
	pollToken := n.issueObserverToken()
	deliveryToken := "OBSERVER-DELIVERY-CREDENTIAL-5f2a"
	recv := newReceiver(t, deliveryToken, 1)
	hb := newHeartbeat(t, n, pollToken)
	loop := newWorkerLoop(n)
	loop.attach(hb)
	hb.start()
	loop.start()
	t.Cleanup(func() { loop.stop(); hb.stop() })

	// A real incident the product announces before anything fails.
	incidentID, episode := model.ID{0x56}, model.ID{0xec}
	subject := subjectOf(incidentID)
	n.addRecipient(subject)
	opened := n.incidentAction(incidents.Action{CommandID: model.ID{0xd1}, Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Target: incidents.Target{Incident: incidentID},
		Impact: &incidents.Impact{Condition: model.ID{0xc4}, Episode: episode, Severity: incidents.SeverityMajor, State: incidents.ConditionFiring, Freshness: incidents.FreshnessFresh}})
	n.submit(subject, n.evidenceOf(opened))
	waitFor(t, 10*time.Second, "the product to announce the opening", func() bool { return slices.Equal(n.prov.kinds(), []string{"open"}) })

	// The observer: a separate process.
	bin := buildObserver(t)
	obsDir := t.TempDir()
	if obsDir == n.dir {
		t.Fatal("the observer shares the product's storage path")
	}
	// An unauthorized or non-test destination is refused before the observer ever runs.
	for name, args := range map[string][]string{
		"a destination that is not on the authorized list":  {"-destination", recv.URL(), "-test-allow-loopback"},
		"a loopback destination without the test allowance": {"-destination", recv.URL(), "-authorized-destination", recv.Host()},
	} {
		cmd := exec.Command(bin, append([]string{"-state", t.TempDir(), "-poll", "product=" + hb.url("product")}, args...)...)
		cmd.Env = append(os.Environ(), "OBSERVER_POLL_TOKEN="+pollToken, "OBSERVER_DELIVERY_TOKEN="+deliveryToken)
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("%s: the observer started (%s)", name, out)
		}
	}
	obs := startObserver(t, bin, obsDir, pollToken, deliveryToken, []string{
		"-id", "deadman-fixture",
		"-poll", "product=" + hb.url("product") + ",ingest=" + hb.url("ingest") + ",notification=" + hb.url("notification"),
		"-interval", interval.String(), "-missing-after", missing.String(), "-timeout", "400ms",
		"-destination", recv.URL(), "-authorized-destination", recv.Host(), "-test-allow-loopback",
	})
	waitFor(t, 15*time.Second, "the observer to be armed on all three heartbeats", func() bool {
		st, err := obs.state()
		if err != nil || !st.Armed {
			return false
		}
		for _, c := range st.Components {
			if c.Status != "ok" {
				return false
			}
		}
		return len(st.Components) == 3
	})
	time.Sleep(3 * interval)
	if got := recv.requests(); len(got) != 0 {
		t.Fatalf("the observer alerted while the product was healthy: %v", got)
	}

	// A decision the product takes just before it dies: committed, not yet sent.
	loop.stop()
	worse := n.incidentAction(incidents.Action{CommandID: model.ID{0xd2}, Type: incidents.TypeImpact, Origin: incidents.OriginSystem, Target: incidents.Target{Incident: incidentID}, ExpectedVersion: opened.Version,
		Impact: &incidents.Impact{Condition: model.ID{0xc4}, Episode: episode, Severity: incidents.SeverityCritical, State: incidents.ConditionFiring, Freshness: incidents.FreshnessFresh}})
	n.submit(subject, n.evidenceOf(worse))
	var pendingID model.ID
	for _, r := range n.records() {
		if r.Kind == string(notify.KindWorseImpact) && r.Phase == control.DeliveryPending {
			pendingID = r.ID
		}
	}
	if pendingID == (model.ID{}) {
		t.Fatal("the pending worse-impact delivery was not committed")
	}
	sentBefore := len(n.prov.snapshot())

	// The whole product goes away: heartbeat endpoints, the notification worker, the node.
	stoppedAt := time.Now()
	hb.stop()
	if err := n.app.Close(); err != nil {
		t.Fatal(err)
	}
	n.app = nil

	// The observer keeps running and detects every missing heartbeat within its interval.
	waitFor(t, 20*time.Second, "the observer to alert on all three missing heartbeats", func() bool {
		st, err := obs.state()
		if err != nil || len(st.Outages) != 3 {
			return false
		}
		for _, o := range st.Outages {
			if !o.Alerted {
				return false
			}
		}
		return true
	})
	st, err := obs.state()
	if err != nil {
		t.Fatal(err)
	}
	components := map[string]bool{}
	for _, o := range st.Outages {
		components[o.Component] = true
		gap := time.Duration(o.DetectedNS - o.LastOKNS)
		if gap < missing || gap > missing+3*interval+700*time.Millisecond {
			t.Errorf("%s: detected %v after its last healthy heartbeat, want within [%v, %v]", o.Component, gap, missing, missing+3*interval+700*time.Millisecond)
		}
		if o.DetectedNS < stoppedAt.UnixNano() || o.LastOKNS > stoppedAt.UnixNano() {
			t.Errorf("%s: the outage (%d) is not after the stop (%d): a false alarm or a missed one", o.Component, o.DetectedNS, stoppedAt.UnixNano())
		}
		if time.Duration(o.DetectedNS-stoppedAt.UnixNano()) > missing+3*interval+700*time.Millisecond {
			t.Errorf("%s: detected %v after the stop", o.Component, time.Duration(o.DetectedNS-stoppedAt.UnixNano()))
		}
	}
	if !components["product"] || !components["ingest"] || !components["notification"] {
		t.Fatalf("outages for %v, want product, ingest and notification", components)
	}
	if st.LastCycle <= stoppedAt.UnixNano() {
		t.Fatal("the observer stopped with the product")
	}
	failed, delivered := 0, 0
	for _, o := range st.Outages {
		for _, a := range o.Attempts {
			if a.Kind != "alert" {
				continue
			}
			if a.Status == http.StatusServiceUnavailable {
				failed++
			} else if a.Status == http.StatusOK {
				delivered++
			}
		}
	}
	if failed != 1 || delivered != 3 {
		t.Fatalf("alert attempts: %d failed with 503 and %d delivered, want 1 and 3", failed, delivered)
	}
	got := recv.requests()
	seen := map[string]bool{}
	for _, r := range got {
		if r.Kind != "alert" || r.Observer != "deadman-fixture" || r.Status != http.StatusOK {
			continue
		}
		seen[r.Component] = true
	}
	if len(seen) != 3 {
		t.Fatalf("the destination accepted alerts for %v (all requests: %+v)", seen, got)
	}

	// The product comes back. Its own history is intact; the observer's record is not erased.
	n.open()
	n.authenticate()
	if n.issued != "" {
		var e error
		if n.srcCred, e = n.app.Auth.AuthenticateSource(n.ctx, n.issued, "", false); e != nil {
			t.Fatal(e)
		}
	}
	n.build()
	n.clock.atLeast(model.UnixNano(time.Now().UnixNano()))
	hb.start()
	loop.start() // the notification worker is part of the product: it restarts with it
	waitFor(t, 20*time.Second, "the observer to see the product again and send its recovery notices", func() bool {
		st, err := obs.state()
		if err != nil || len(st.Outages) != 3 {
			return false
		}
		for _, o := range st.Outages {
			if o.RecoveredNS == 0 || !o.Recovery {
				return false
			}
		}
		return true
	})
	st, err = obs.state()
	if err != nil {
		t.Fatal(err)
	}
	failedAfter := 0
	for _, o := range st.Outages {
		for _, a := range o.Attempts {
			if a.Kind == "alert" && a.Status == http.StatusServiceUnavailable {
				failedAfter++
			}
		}
		if o.DetectedNS == 0 || !o.Alerted {
			t.Fatalf("recovery erased the outage record: %+v", o)
		}
	}
	if failedAfter != 1 {
		t.Fatalf("the failed attempt was erased by the recovery: %d left", failedAfter)
	}
	recoveries := 0
	alerts := map[string]int{}
	for _, r := range recv.requests() {
		if r.Status != http.StatusOK {
			continue
		}
		switch r.Kind {
		case "recovery":
			recoveries++
		case "alert":
			alerts[r.Component]++
		}
	}
	if recoveries != 3 || alerts["product"] != 1 || alerts["ingest"] != 1 || alerts["notification"] != 1 {
		t.Fatalf("after the recovery the destination saw %d recovery notices and alerts %v: a recovery is one notice per outage, never a second emergency", recoveries, alerts)
	}

	// The observer is a separate process with its own state: killing it hard and starting it
	// again keeps the record and repeats no accepted alert.
	obs.kill()
	before := len(recv.requests())
	obs = startObserver(t, bin, obsDir, pollToken, deliveryToken, obs.args)
	time.Sleep(6 * interval)
	restarted, err := obs.state()
	if err != nil || len(restarted.Outages) != 3 || restarted.StartedNS != st.StartedNS {
		t.Fatalf("the observer lost its record across a restart: %+v %v", restarted, err)
	}
	if len(recv.requests()) != before {
		t.Fatalf("a restarted observer repeated notices already accepted: %d -> %d requests", before, len(recv.requests()))
	}

	// The product's side of the outage: the delivery committed before it died is sent
	// once under its ORIGINAL ID (the outbox's contract), nothing is invented for the
	// outage, and evidence that merely arrives late, or as a backfill, announces nothing.
	waitFor(t, 15*time.Second, "the pending delivery to be sent after the recovery", func() bool { return n.prov.count(pendingID) == 1 })
	loop.stop()
	if len(n.prov.snapshot()) != sentBefore+1 {
		t.Fatalf("after the recovery the provider saw %v: only the pre-outage delivery may be sent", n.prov.kinds())
	}
	if rec := n.recordOf(pendingID); rec.Phase != control.DeliveryAccepted || len(rec.Attempts) != 1 {
		t.Fatalf("the pre-outage delivery after the recovery: %+v", rec)
	}
	late := n.issueLate()
	for name, want := range map[string]bool{"late live evidence": false, "backfill": false, "explicit operator replay": true, "current live evidence": true} {
		if got := late[name]; got != want {
			t.Errorf("%s produced a deliverable notification: %v, want %v", name, got, want)
		}
	}

	// The observer's last proof is what the product's barrier is given: fresh while it runs,
	// an UNKNOWN state once it does not.
	n.clock.atLeast(model.UnixNano(time.Now().UnixNano()))
	n.advance(notify.CutoverRollbackQuiescing)
	n.clock.add(3 * 60 * sec)
	n.clock.atLeast(model.UnixNano(time.Now().UnixNano()))
	alive, _ := obs.state()
	n.advance(notify.CutoverOldActive, func(e *notify.BarrierEvidence) { e.Observer.ObservedAt = model.UnixNano(alive.LastCycle) })
	n.advance(notify.CutoverQuiescingOld)
	obs.kill()
	dead, _ := obs.state()
	n.clock.add(20 * 60 * sec)
	_, err = n.cut.AdvanceCutover(n.ctx, n.scope(), n.command(notify.CutoverBarrierVerified, func(e *notify.BarrierEvidence) { e.Observer.ObservedAt = model.UnixNano(dead.LastCycle) }))
	var barrier *notify.BarrierError
	if !errors.As(err, &barrier) || !slices.Contains(barrier.Checks, "observer_stale") {
		t.Fatalf("a barrier was verified against an observer that stopped proving itself: %v", err)
	}
	t.Logf("outage drill: %d outages detected %v after the last healthy heartbeat each; %d failed + %d accepted alert attempts; %d recovery notices; observer restart kept its record", len(st.Outages),
		time.Duration(st.Outages[0].DetectedNS-st.Outages[0].LastOKNS), failed, delivered, recoveries)
}

// issueLate submits four evidence batches for four fresh issues: late live
// evidence (its window closed long before), a backfill, an explicit operator replay
// of the same late window, and current live evidence; it reports which of them
// produced a deliverable notification.
func (n *accNode) issueLate() map[string]bool {
	n.t.Helper()
	out := map[string]bool{}
	now := n.clock.Now()
	oldWindow := (now - 30*60*sec) / notify.ErrorWindow * notify.ErrorWindow
	currentWindow := now / notify.ErrorWindow * notify.ErrorWindow
	cases := []struct {
		name   string
		window model.UnixNano
		mode   notify.Mode
	}{
		{"late live evidence", oldWindow, notify.ModeLive},
		{"backfill", oldWindow, notify.ModeBackfill},
		{"explicit operator replay", oldWindow, notify.ModeOperatorReplay},
		{"current live evidence", currentWindow, notify.ModeLive},
	}
	for i, c := range cases {
		subject := notify.Entity{Kind: notify.EntityIssue, ID: model.ID{0x90, byte(i)}}
		n.addRecipient(subject)
		var occurrences []model.ID
		for k := range 25 {
			occurrences = append(occurrences, model.ID{0x91, byte(i), byte(k)})
		}
		ev := n.event(notify.EventIssue, fmt.Sprintf("late|%d", i))
		ev.Entity = &subject
		ev.Mode = c.mode
		ev.Issue = &notify.IssueEvidence{WindowStart: c.window, Occurrences: occurrences, Freshness: notify.FreshnessFresh,
			Denominator: &notify.Denominator{Name: "http_operations", WindowStart: c.window, Operations: 100, Complete: true}}
		sub := n.submit(subject, ev)
		for _, in := range sub.Intents {
			if in.Eligible() && in.Key.Kind == notify.KindOpen {
				out[c.name] = true
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// The product's heartbeat endpoints, served from the real node.

func (n *accNode) issueObserverToken() string {
	n.t.Helper()
	issued, err := n.app.Auth.IssueServerToken(n.ctx, n.cred, n.org, n.user, []model.ID{n.project}, []auth.Permission{auth.Read}, time.Now().Add(time.Hour).Unix(), "deadman observer")
	if err != nil {
		n.t.Fatal("observer credential:", err)
	}
	return issued.Token
}

type heartbeat struct {
	t     *testing.T
	n     *accNode
	token string
	addr  string
	mu    sync.Mutex
	srv   *http.Server
	seq   atomic.Uint64
	pass  atomic.Int64
}

func newHeartbeat(t *testing.T, n *accNode, token string) *heartbeat {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return &heartbeat{t: t, n: n, token: token, addr: addr}
}

func (h *heartbeat) url(component string) string {
	return "http://" + h.addr + "/heartbeat/" + component
}

func (h *heartbeat) start() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.srv != nil {
		return
	}
	var ln net.Listener
	var err error
	for range 50 {
		if ln, err = net.Listen("tcp", h.addr); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		h.t.Fatal(err)
	}
	mux := http.NewServeMux()
	for _, c := range []string{"product", "ingest", "notification"} {
		mux.HandleFunc("/heartbeat/"+c, h.handler(c))
	}
	h.srv = &http.Server{Handler: mux}
	go h.srv.Serve(ln)
}

func (h *heartbeat) stop() {
	h.mu.Lock()
	srv := h.srv
	h.srv = nil
	h.mu.Unlock()
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = srv.Close()
	}
}

// handler answers one component's heartbeat from real node state. 200 means the
// component works: product = the control group answers a quorum round; ingest = a
// canary sample was admitted through the production C03 path and acknowledged;
// notification = the worker completed a pass recently.
func (h *heartbeat) handler(component string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fail := func(code int) { w.WriteHeader(code) }
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" || h.n.app == nil {
			fail(http.StatusUnauthorized)
			return
		}
		app := h.n.app
		cred, err := app.Auth.Authenticate(r.Context(), token)
		if err != nil {
			fail(http.StatusUnauthorized)
			return
		}
		if _, err = app.Auth.Authorize(r.Context(), cred, h.n.org, []model.ID{h.n.project}, auth.Read); err != nil {
			fail(http.StatusForbidden)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 300*time.Millisecond)
		defer cancel()
		switch component {
		case "product":
			if _, err = app.Control.ReplicaGroup().Fence(ctx); err != nil {
				fail(http.StatusServiceUnavailable)
				return
			}
		case "ingest":
			record := canaryRecord(h.n.resource, model.UnixNano(time.Now().UnixNano()), float64(h.seq.Load()))
			producer := model.ID{0xd1}
			slot, e := model.OwnerSlot(h.n.org, h.n.project, h.n.source, producer, record)
			if e != nil {
				fail(http.StatusServiceUnavailable)
				return
			}
			batch := model.Batch{Version: 1, Project: h.n.project, Source: h.n.source, Producer: producer, ID: model.NewID(), PolicyRevision: 1, RouteSlot: slot, Records: []model.Record{record}}
			grant, e := app.Ingest.ResolveSource(ctx, h.n.srcCred, batch)
			if e == nil {
				_, e = app.Ingest.Admit(ctx, grant, batch)
			}
			if e != nil {
				fail(http.StatusServiceUnavailable)
				return
			}
		case "notification":
			if time.Since(time.Unix(0, h.pass.Load())) > 2*time.Second {
				fail(http.StatusServiceUnavailable)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"component": component, "ok": true, "seq": h.seq.Add(1), "at_ns": time.Now().UnixNano()})
	}
}

// workerLoop is the product's notification worker: one pass every 50 ms. Each
// completed pass is the notification pipeline's heartbeat.
type workerLoop struct {
	n      *accNode
	cancel context.CancelFunc
	wg     sync.WaitGroup
	hb     *heartbeat
}

func newWorkerLoop(n *accNode) *workerLoop { return &workerLoop{n: n} }

func (l *workerLoop) attach(h *heartbeat) { l.hb = h }

func (l *workerLoop) start() {
	if l.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	l.cancel = cancel
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			app := l.n.app
			if app == nil {
				continue
			}
			scope, err := app.Auth.Authorize(ctx, l.n.cred, l.n.org, []model.ID{l.n.project}, auth.OrgAdmin)
			if err != nil {
				continue
			}
			lease, err := app.Control.ReplicaGroup().Fence(ctx)
			if err != nil {
				continue
			}
			l.n.clock.add(sec / 20)
			if _, err = l.n.w.RunOnce(ctx, scope, l.n.clock.Now(), lease); err == nil && l.hb != nil {
				l.hb.pass.Store(time.Now().UnixNano())
			}
		}
	}()
}

func (l *workerLoop) stop() {
	if l.cancel != nil {
		l.cancel()
		l.wg.Wait()
		l.cancel = nil
	}
}

// ---------------------------------------------------------------------------
// The destination the observer is authorized for: a loopback receiver.

type received struct {
	Kind      string `json:"kind"`
	Observer  string `json:"observer"`
	Component string `json:"component"`
	Outage    string `json:"outage"`
	Idem      string `json:"-"`
	Status    int    `json:"-"`
}

type receiver struct {
	srv   *httptest.Server
	mu    sync.Mutex
	reqs  []received
	fail  int
	token string
}

// newReceiver starts a loopback destination that fails its first failFirst
// requests with 503 and then accepts.
func newReceiver(t *testing.T, token string, failFirst int) *receiver {
	r := &receiver{fail: failFirst, token: token}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body received
		_ = json.NewDecoder(req.Body).Decode(&body)
		body.Idem = req.Header.Get("Idempotency-Key")
		r.mu.Lock()
		defer r.mu.Unlock()
		switch {
		case req.Header.Get("Authorization") != "Bearer "+r.token:
			body.Status = http.StatusUnauthorized
		case r.fail > 0:
			r.fail--
			body.Status = http.StatusServiceUnavailable
		default:
			body.Status = http.StatusOK
		}
		r.reqs = append(r.reqs, body)
		w.WriteHeader(body.Status)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) URL() string  { return r.srv.URL + "/notify" }
func (r *receiver) Host() string { return strings.TrimPrefix(r.srv.URL, "http://") }
func (r *receiver) requests() []received {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.reqs)
}

// ---------------------------------------------------------------------------
// The observer process.

type obsAttempt struct {
	N      int    `json:"n"`
	AtNS   int64  `json:"at_ns"`
	Kind   string `json:"kind"`
	Status int    `json:"status"`
	Error  string `json:"error"`
}
type obsOutage struct {
	ID          string       `json:"id"`
	Component   string       `json:"component"`
	LastOKNS    int64        `json:"last_ok_ns"`
	DetectedNS  int64        `json:"detected_ns"`
	RecoveredNS int64        `json:"recovered_ns"`
	Alerted     bool         `json:"alerted"`
	Recovery    bool         `json:"recovery_notified"`
	Attempts    []obsAttempt `json:"attempts"`
}
type obsComponent struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}
type obsState struct {
	Observer   string         `json:"observer"`
	StartedNS  int64          `json:"started_ns"`
	LastCycle  int64          `json:"last_cycle_ns"`
	Armed      bool           `json:"armed"`
	Components []obsComponent `json:"components"`
	Outages    []obsOutage    `json:"outages"`
}

type observerProc struct {
	t    *testing.T
	cmd  *exec.Cmd
	dir  string
	args []string
	out  bytes.Buffer
	done chan struct{}
}

func (o *observerProc) state() (obsState, error) {
	var st obsState
	raw, err := os.ReadFile(filepath.Join(o.dir, "state.json"))
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(raw, &st)
}

// kill is SIGKILL: no shutdown handler runs.
func (o *observerProc) kill() {
	if o.cmd.Process != nil {
		_ = o.cmd.Process.Signal(syscall.SIGKILL)
		<-o.done
	}
}

// moduleRoot finds the directory of go.mod above the test's working directory.
func moduleRoot(t *testing.T) string {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err = os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = parent
	}
}

var observerBinary struct {
	once sync.Once
	path string
	err  error
}

// buildObserver compiles the observer program once with the toolchain that runs the
// tests.
func buildObserver(t *testing.T) string {
	t.Helper()
	observerBinary.once.Do(func() {
		dir, err := os.MkdirTemp("", "soundpost-observer-")
		if err != nil {
			observerBinary.err = err
			return
		}
		observerBinary.path = filepath.Join(dir, "observer")
		cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", observerBinary.path, "./tests/acceptance/observer")
		cmd.Dir = moduleRoot(t)
		if out, err := cmd.CombinedOutput(); err != nil {
			observerBinary.err = fmt.Errorf("building the observer: %v\n%s", err, out)
		}
	})
	if observerBinary.err != nil {
		t.Fatal(observerBinary.err)
	}
	return observerBinary.path
}

// startObserver runs the observer as a separate process whose environment holds only
// its own two credentials.
func startObserver(t *testing.T, bin, dir, pollToken, deliveryToken string, args []string) *observerProc {
	t.Helper()
	o := &observerProc{t: t, dir: dir, args: args, done: make(chan struct{})}
	o.cmd = exec.Command(bin, append([]string{"-state", dir}, args...)...)
	o.cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "OBSERVER_POLL_TOKEN=" + pollToken, "OBSERVER_DELIVERY_TOKEN=" + deliveryToken}
	o.cmd.Stdout, o.cmd.Stderr = &o.out, &o.out
	if err := o.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = o.cmd.Wait(); close(o.done) }()
	t.Cleanup(func() {
		select {
		case <-o.done:
		default:
			_ = o.cmd.Process.Signal(syscall.SIGKILL)
			<-o.done
		}
		if strings.Contains(o.out.String(), pollToken) || strings.Contains(o.out.String(), deliveryToken) {
			t.Error("the observer logged a credential")
		}
	})
	return o
}

func waitFor(t *testing.T, limit time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for %s", limit, what)
}
