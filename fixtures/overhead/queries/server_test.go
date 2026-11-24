// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/rules"
)

func testServer(t *testing.T) (*server, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	events, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { events.Close() })
	s := &server{out: dir, faultDir: filepath.Join(dir, "fault"), events: events, faultWait: 2 * time.Second}
	if err := os.MkdirAll(s.faultDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.controlHandler("tok", make(chan struct{})))
	t.Cleanup(ts.Close)
	return s, ts
}

func control(t *testing.T, ts *httptest.Server, method, path, token string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, nil)
	if token != "" {
		req.Header.Set("X-Harness-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func TestParseSlots(t *testing.T) {
	got, err := parseSlots("0-3,7,3,40-41")
	if err != nil || len(got) != 7 || got[0] != 0 || got[3] != 3 || got[4] != 7 || got[6] != 41 {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"", "x", "5-2", "0-64", "-1", "1,,2", "1-"} {
		if _, err := parseSlots(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// fakeFaultConsumer plays the soundpost_faults consumer of <fault dir>/close-groups: it takes the file, removes it and answers in
// close-groups.result, as cmd/soundpost/faultcontrol.go does, and records what it was asked.
func fakeFaultConsumer(t *testing.T, dir string, answer func(slots []string) string) (asked func() [][]string, stop func()) {
	t.Helper()
	var mu sync.Mutex
	var requests [][]string
	quit, finished := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		for {
			select {
			case <-quit:
				return
			case <-time.After(10 * time.Millisecond):
			}
			raw, err := os.ReadFile(filepath.Join(dir, "close-groups"))
			if err != nil {
				continue
			}
			os.Remove(filepath.Join(dir, "close-groups"))
			slots := strings.Split(string(raw), ",")
			mu.Lock()
			requests = append(requests, slots)
			mu.Unlock()
			os.WriteFile(filepath.Join(dir, "close-groups.result"), []byte(answer(slots)), 0o600)
		}
	}()
	return func() [][]string { mu.Lock(); defer mu.Unlock(); return append([][]string(nil), requests...) }, func() { close(quit); <-finished }
}

func TestControlCloseGroupsDrivesTheFaultDirectory(t *testing.T) {
	s, ts := testServer(t)
	// a stale answer of an earlier request must not satisfy this one
	os.WriteFile(filepath.Join(s.faultDir, "close-groups.result"), []byte("ok 999"), 0o600)
	asked, stop := fakeFaultConsumer(t, s.faultDir, func(slots []string) string {
		if len(slots) == 1 && slots[0] == "5" {
			return "error injected"
		}
		return "ok " + strconv.Itoa(len(slots))
	})
	defer stop()

	if code, _ := control(t, ts, "POST", "/fault/close-groups?slots=0-31", ""); code != http.StatusForbidden {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := control(t, ts, "POST", "/fault/close-groups?slots=0-99", "tok"); code != http.StatusBadRequest {
		t.Fatalf("bad slots: %d", code)
	}
	code, raw := control(t, ts, "POST", "/fault/close-groups?slots=0-31", "tok")
	var e Event
	if code != 200 || json.Unmarshal(raw, &e) != nil || e.Event != "shard_loss" || e.Mode != "slots 0-31" || e.Note != "closed 32" {
		t.Fatalf("shard loss %d: %s", code, raw)
	}
	got := asked()
	if len(got) != 1 || len(got[0]) != 32 || got[0][0] != "0" || got[0][31] != "31" {
		t.Fatalf("the product was asked %v", got)
	}
	if _, err := os.Stat(filepath.Join(s.faultDir, "close-groups.tmp")); err == nil {
		t.Fatal("the temporary request file was left behind")
	}
	// a comma list; the product's own error is reported, not swallowed
	if code, raw = control(t, ts, "POST", "/fault/close-groups?slots=5", "tok"); code != http.StatusBadGateway || !strings.Contains(string(raw), "error injected") {
		t.Fatalf("product error %d: %s", code, raw)
	}
	events, _ := os.ReadFile(filepath.Join(s.out, "events.jsonl"))
	lines := strings.Split(strings.TrimSpace(string(events)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"note":"closed 32"`) || !strings.Contains(lines[1], `"note":"error injected"`) {
		t.Fatalf("events: %s", events)
	}
}

func TestControlCloseGroupsNoAnswerIsAnError(t *testing.T) {
	s, ts := testServer(t)
	s.faultWait = 300 * time.Millisecond
	code, raw := control(t, ts, "POST", "/fault/close-groups?slots=0-31", "tok")
	if code != http.StatusGatewayTimeout || !strings.Contains(string(raw), "did not answer") {
		t.Fatalf("%d: %s", code, raw)
	}
}

func TestBundleStreamsTheFaultFiles(t *testing.T) {
	s, ts := testServer(t)
	write := func(path, text string) { os.WriteFile(path, []byte(text), 0o644) }
	write(filepath.Join(s.out, "server-series.jsonl"), "{}\n")
	write(filepath.Join(s.out, "events.jsonl"), "{}\n")
	write(filepath.Join(s.out, "net-series.jsonl"), "{\"t_ms\":1}\n")
	write(filepath.Join(s.faultDir, "rules.jsonl"), strings.Repeat("{\"k\":\"e\"}\n", 1000))
	write(filepath.Join(s.faultDir, "scans.jsonl"), "{\"req\":\"x\"}\n")
	code, raw := control(t, ts, "GET", "/bundle", "tok")
	if code != 200 {
		t.Fatalf("%d", code)
	}
	files := map[string]string{}
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(tr)
		files[h.Name] = string(body)
	}
	for _, name := range []string{"server-series.jsonl", "events.jsonl", "net-series.jsonl", "rules.jsonl", "scans.jsonl"} {
		if _, ok := files[name]; !ok {
			t.Errorf("%s missing from the bundle (%d files)", name, len(files))
		}
	}
	if n := strings.Count(files["rules.jsonl"], "\n"); n != 1000 {
		t.Errorf("rules.jsonl has %d lines", n)
	}
	if _, ok := files["host.json"]; ok {
		t.Error("a file that does not exist was bundled")
	}
}

func TestWebhookPKIServesTheReceiverAddress(t *testing.T) {
	ips := []net.IP{net.ParseIP("10.20.30.40"), net.ParseIP("10.20.30.41")}
	caPEM, certPEM, keyPEM, err := webhookPKI(ips, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || len(keyPEM) == 0 {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("CA is not PEM")
	}
	for _, name := range []string{"10.20.30.40", "10.20.30.41"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Errorf("leaf does not verify for %s: %v", name, err)
		}
	}
	if leaf.NotAfter.Sub(time.Now()) < 48*time.Hour {
		t.Errorf("leaf expires in %s: it must outlast a 24 h run and its preload", leaf.NotAfter.Sub(time.Now()))
	}
	otherCA, _, _, _ := webhookPKI(ips, time.Now())
	other := x509.NewCertPool()
	other.AppendCertsFromPEM(otherCA)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: other, DNSName: "10.20.30.40"}); err == nil {
		t.Error("the leaf verifies against another CA")
	}
}

func TestWebhookTarget(t *testing.T) {
	if ip, listen, err := webhookTarget("https://10.1.2.3:9443/hook", "10.1.2.3:9443"); err != nil || ip.String() != "10.1.2.3" || listen.String() != "10.1.2.3" {
		t.Fatalf("%v %v %v", ip, listen, err)
	}
	if ip, _, err := webhookTarget("https://100.64.1.2:9443", "0.0.0.0:9443"); err != nil || ip.String() != "100.64.1.2" {
		t.Fatalf("CGNAT: %v %v", ip, err)
	}
	for _, bad := range [][2]string{
		{"http://10.1.2.3:9443", "10.1.2.3:9443"},      // not https
		{"https://example.test:9443", "10.1.2.3:9443"}, // not an address
		{"https://8.8.8.8:9443", "10.1.2.3:9443"},      // not private: the egress allow-list could never hold it
		{"https://127.0.0.1:9443", "10.1.2.3:9443"},    // loopback is never allowed
		{"https://10.1.2.3:9443", "receiver:9443"},
	} {
		if _, _, err := webhookTarget(bad[0], bad[1]); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

// testPlan is a plan with the profiles the product advertises (the embedded registry), as provision would pick them.
func testPlan(t *testing.T) *Plan {
	t.Helper()
	reg, err := rules.DefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	var advertised []httpapi.RuleProfile
	for _, p := range reg.Profiles() {
		entry := httpapi.RuleProfile{ID: p.ID, FeatureSets: []string{}}
		for _, f := range p.FeatureSets {
			entry.FeatureSets = append(entry.FeatureSets, f.ID)
		}
		advertised = append(advertised, entry)
	}
	plan := &Plan{Config: DefaultConfig()}
	plan.PromProfile, plan.PromFeatureSet, plan.LogProfile, plan.LogFeatureSet, err = pickProfiles(advertised)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// The 100 save bodies are what the product's route accepts: they decode strictly into its own request type, have the shape the route
// requires of a save, and every expression passes the save-time check (parses under the pinned profile and is an instant vector).
func TestRuleSaveRequestsAreWhatTheRouteAccepts(t *testing.T) {
	plan := testPlan(t)
	if plan.PromProfile != "promql-prometheus-3.13.5" || !strings.HasPrefix(plan.LogProfile, "logql-") || plan.PromFeatureSet == "" || plan.LogFeatureSet == "" {
		t.Fatalf("profiles: %+v", plan)
	}
	reg, _ := rules.DefaultRegistry()
	classes := map[string]int{}
	ids, commands := map[model.ID]bool{}, map[model.ID]bool{}
	for p := range plan.Config.Projects {
		req, pr := ruleSaveRequest(plan, p)
		raw, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		var decoded httpapi.RuleRequest
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&decoded); err != nil {
			t.Fatalf("project %d: %v\n%s", p, err, raw)
		}
		// validRuleShape of a save
		if decoded.Org == (model.ID{}) || decoded.Project == (model.ID{}) || decoded.Operation != httpapi.RuleSave || decoded.CommandID == (model.ID{}) || decoded.RuleID == (model.ID{}) ||
			decoded.ExpectedRevision == nil || *decoded.ExpectedRevision != 0 || decoded.Reason == "" || decoded.Rule == nil || decoded.Replay != nil {
			t.Fatalf("project %d: not the shape of a save: %s", p, raw)
		}
		spec := decoded.Rule
		rule := rules.Rule{ID: decoded.RuleID, Project: decoded.Project, Version: 1, Kind: rules.Kind(spec.Kind), Profile: spec.Profile, FeatureSet: spec.FeatureSet, Expression: spec.Expression,
			Interval: time.Duration(spec.IntervalSeconds) * time.Second, MissingData: rules.MissingData(spec.MissingData), Severity: spec.Severity}
		if err := rule.Check(reg); err != nil {
			t.Fatalf("project %d (%s) %q: the product would refuse it: %v", p, pr.Class, spec.Expression, err)
		}
		if pr.Project != p || pr.Rule != RuleID(plan.Config.Seed, p) || pr.Class != RuleClass(p) || pr.Expression != spec.Expression || pr.IntervalSeconds != spec.IntervalSeconds {
			t.Fatalf("project %d: plan rule %+v does not describe the body", p, pr)
		}
		wantLang := "promql"
		if pr.Class == RuleFiringLog {
			wantLang = "logql"
		}
		if pr.Language != wantLang || !strings.HasPrefix(spec.Profile, wantLang+"-") {
			t.Fatalf("project %d: language %s, profile %s", p, pr.Language, spec.Profile)
		}
		if want := map[bool]uint32{true: 30, false: 60}[pr.Class == RuleFlip]; spec.IntervalSeconds != want {
			t.Fatalf("project %d (%s): interval %d", p, pr.Class, spec.IntervalSeconds)
		}
		if spec.Kind != "alert" || spec.Severity != "warning" {
			t.Fatalf("project %d: %+v", p, spec)
		}
		again, _ := ruleSaveRequest(plan, p)
		if again.CommandID != req.CommandID || again.RuleID != req.RuleID {
			t.Fatalf("project %d: the command id is not stable, a retry would not be idempotent", p)
		}
		classes[pr.Class]++
		ids[req.RuleID], commands[req.CommandID] = true, true
	}
	if len(ids) != 100 || len(commands) != 100 {
		t.Fatalf("%d rule ids, %d command ids", len(ids), len(commands))
	}
	if classes[RuleFlip] != 3 || classes[RuleFiringMetric]+classes[RuleFiringLog]+classes[RuleHealthyMetric]+classes[RuleHealthyHeavy] != 97 || classes[RuleFiringLog] < 20 || classes[RuleHealthyHeavy] < 20 {
		t.Fatalf("classes: %v", classes)
	}
}

func TestDestinationPayloadIsWhatTheAdminCommandAccepts(t *testing.T) {
	cfg := DefaultConfig()
	w := PlanWebhook{URL: "https://10.1.2.3:9443/hook", Secret: strings.Repeat("ab", 32)}
	command, p := destinationPayload(cfg, 3, w)
	again, p2 := destinationPayload(cfg, 3, w)
	other, p3 := destinationPayload(cfg, 4, w)
	if command != again || p.ID != p2.ID || command == other || p.ID == p3.ID || command == (model.ID{}) || p.ID == (model.ID{}) {
		t.Fatal("destination identity is not stable per organization")
	}
	if len(p.Secret) < 16 || len(p.Secret) > 256 {
		t.Fatalf("secret of %d bytes", len(p.Secret))
	}
	var dc auth.DestinationConfig
	dec := json.NewDecoder(bytes.NewReader(p.Config))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&dc); err != nil || dc.Type != "webhook" || dc.Endpoint != w.URL || !dc.Enabled {
		t.Fatalf("%+v %v", dc, err)
	}
}

// A fake of the rules route over TLS: the list advertises profiles, the first save answers 409 (a stale precondition), the retry commits.
func TestProvisionRuleCallsAgainstAFakeRoute(t *testing.T) {
	plan := testPlan(t)
	var mu sync.Mutex
	saves, conflicts := 0, 0
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req httpapi.RuleRequest
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if r.URL.Path != "/api/v1/rules" || dec.Decode(&req) != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch req.Operation {
		case httpapi.RuleList:
			json.NewEncoder(w).Encode(httpapi.RuleListAnswer{Org: req.Org, Project: req.Project, CanAuthor: true, Profiles: []httpapi.RuleProfile{
				{ID: "promql-prometheus-3.1.0", FeatureSets: []string{"a"}}, {ID: plan.PromProfile, FeatureSets: []string{plan.PromFeatureSet, "z"}}, {ID: plan.LogProfile, FeatureSets: []string{plan.LogFeatureSet}}}})
		case httpapi.RuleSave:
			if conflicts == 0 {
				conflicts++
				http.Error(w, `{"error":"conflict"}`, http.StatusConflict)
				return
			}
			saves++
			json.NewEncoder(w).Encode(httpapi.RuleWriteAnswer{State: httpapi.ActionCommitted, Rule: httpapi.RuleView{RuleID: req.RuleID, Revision: 1, Version: 1, Rule: *req.Rule}})
		default:
			http.Error(w, "operation", http.StatusBadRequest)
		}
	}))
	defer ts.Close()
	s := &server{addr: strings.TrimPrefix(ts.URL, "https://"), client: ts.Client()}
	pj := NewProject(plan.Config, 0)
	prom, promFS, logp, logFS, err := pickProfiles(s.ruleProfiles(pj))
	if err != nil || prom != plan.PromProfile || promFS != plan.PromFeatureSet || logp != plan.LogProfile || logFS != plan.LogFeatureSet {
		t.Fatalf("%q %q %q %q %v", prom, promFS, logp, logFS, err)
	}
	req, _ := ruleSaveRequest(plan, 0)
	s.saveRule(req, 0)
	if saves != 1 || conflicts != 1 {
		t.Fatalf("saves %d, conflicts %d", saves, conflicts)
	}
}
