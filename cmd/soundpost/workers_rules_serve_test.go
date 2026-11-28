// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify/providers"
)

func workerSettingsOf(t *testing.T, args ...string) (workerSettings, error) {
	t.Helper()
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	opts := addWorkerFlags(f)
	if err := f.Parse(args); err != nil {
		t.Fatal(err)
	}
	return opts.settings("127.0.0.1:8443", t.TempDir())
}

// The credential of the node's recording source is read from a file (never a
// flag value, which a process listing shows): one non-empty line, surrounding
// whitespace trimmed; anything else fails startup with a static reason that does
// not echo the file.
func TestRecordingSourceCredentialIsReadFromAFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if s, err := workerSettingsOf(t); err != nil || s.recordingSecret != "" {
		t.Fatalf("no flag: %+v %v", s, err)
	}
	if s, err := workerSettingsOf(t, "--recording-source-credential-file", write("ok", "  spk_secret-0123456789abcdef \n")); err != nil || s.recordingSecret != "spk_secret-0123456789abcdef" {
		t.Fatalf("a credential file: %+v %v", s, err)
	}
	for name, path := range map[string]string{
		"unreadable": filepath.Join(dir, "missing"),
		"empty":      write("empty", " \n"),
		"two lines":  write("two", "SECRETLINEONE\nSECRETLINETWO\n"),
	} {
		_, err := workerSettingsOf(t, "--recording-source-credential-file", path)
		if err == nil || strings.Contains(err.Error(), "SECRETLINE") || !strings.HasPrefix(err.Error(), "--recording-source-credential-file:") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A node whose recording source credential is not one refuses to start the
// workers, with a static reason: it never runs half-configured, and the
// credential is not echoed.
func TestStartWorkersRefusesARecordingCredentialThatIsNotASource(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	settings, err := workerSettingsOf(t)
	if err != nil {
		t.Fatal(err)
	}
	settings.recordingSecret = "NOT-A-SOURCE-CREDENTIAL-1234567890"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = startWorkers(ctx, app, settings, nil)
	if err == nil || !strings.Contains(err.Error(), "recording source") || strings.Contains(err.Error(), "NOT-A-SOURCE") {
		t.Fatalf("a credential that is not a source: %v", err)
	}
}

// The acceptance of 11.01-W1 on the real serve path: a served process (the
// re-executed real main) evaluates a rule an administrator saved over
// POST /api/v1/rules, opens its condition, routes it to the organization's
// destination and delivers a signed webhook to a TLS receiver; nobody is logged
// in after the rule was saved, and the runner's work is audited as system:runner
// while the rule's authoring is audited as the administrator.
func TestServeEvaluatesARuleSavedOverTheRouteAndDeliversItsCondition(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes and signals")
	}
	ip := privateAddress(t)
	work := t.TempDir()
	caPath := filepath.Join(work, "receiver-ca.pem")
	hookURL, posts := webhookReceiver(t, ip, caPath)
	dir := filepath.Join(work, "data")
	port := freePort(t)
	listen := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	cmd, lines, errOut := serveChild(t, "--data-dir", dir, "--listen", listen, "--worker-interval", "100ms",
		"--public-origin", "https://soundpost.example.test", "--notify-egress-allow", netip.PrefixFrom(ip, 32).String(), "--notify-ca-file", caPath)
	defer cmd.Process.Kill()
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range lines {
		}
	}()
	var client *http.Client
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if pemBytes, err := os.ReadFile(filepath.Join(dir, "server.crt")); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pemBytes) {
				jar, _ := cookiejar.New(nil)
				client = &http.Client{Jar: jar, Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
				if resp, err := client.Get("https://" + listen + "/readyz"); err == nil {
					resp.Body.Close()
					if resp.StatusCode == 200 {
						break
					}
				}
			}
		}
		client = nil
		time.Sleep(200 * time.Millisecond)
	}
	if client == nil {
		t.Fatalf("serve never became ready; stderr:\n%s", errOut.String())
	}
	a := &api{t: t, base: "https://" + listen, client: client}

	token, err := os.ReadFile(filepath.Join(dir, "bootstrap.token"))
	if err != nil {
		t.Fatal(err)
	}
	password := "serve rules acceptance password 2026"
	code, raw := a.do("POST", "/api/v1/bootstrap", map[string]string{"Token": strings.TrimSpace(string(token)), "Email": "owner@example.test", "Password": password}, nil)
	var session struct {
		CSRF string `json:"csrf"`
	}
	if code != 200 || json.Unmarshal(raw, &session) != nil {
		t.Fatalf("bootstrap %d: %s", code, raw)
	}
	a.csrf = session.CSRF
	org, project, dest := model.NewID(), model.NewID(), model.NewID()
	a.command(org, "create_org", auth.AdminPayload{Name: "serve rules acceptance"})
	a.command(org, "create_project", auth.AdminPayload{ID: project, Name: "serve rules acceptance project"})
	secret := "serve rules acceptance webhook secret 0123456789"
	destination, _ := json.Marshal(auth.DestinationConfig{Type: "webhook", Endpoint: hookURL, Enabled: true})
	a.command(org, "destination", auth.AdminPayload{ID: dest, Config: destination, Secret: secret})
	if got := posts(); len(got) != 0 {
		t.Fatalf("a delivery before any rule exists: %d", len(got))
	}

	// Author the rule over the route: the list advertises the pinned feature set,
	// the save commits the definition.
	code, raw = a.do("POST", "/api/v1/rules", map[string]any{"org": org, "project_id": project, "operation": "list"}, nil)
	var listed httpapi.RuleListAnswer
	if code != 200 || json.Unmarshal(raw, &listed) != nil || !listed.CanAuthor || len(listed.Rules) != 0 {
		t.Fatalf("rule list %d: %s", code, raw)
	}
	featureSet := ""
	for _, p := range listed.Profiles {
		if p.ID == "promql-prometheus-3.13.5" && len(p.FeatureSets) > 0 {
			featureSet = p.FeatureSets[0]
		}
	}
	if featureSet == "" {
		t.Fatalf("no feature set advertised: %s", raw)
	}
	rule := model.NewID()
	code, raw = a.do("POST", "/api/v1/rules", map[string]any{"org": org, "project_id": project, "operation": "save", "command_id": model.NewID(), "rule_id": rule, "expected_revision": "0", "reason": "serve acceptance",
		"rule": map[string]any{"kind": "alert", "profile": "promql-prometheus-3.13.5", "feature_set": featureSet, "expression": "vector(1)", "interval_seconds": 60, "severity": "critical"}}, nil)
	if code != 200 {
		t.Fatalf("rule save %d: %s", code, raw)
	}
	if code, raw = a.do("POST", "/api/v1/logout", nil, nil); code >= 300 {
		t.Fatalf("logout %d: %s", code, raw)
	}
	a.csrf = ""

	var post webhookPost
	for deadline = time.Now().Add(90 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if got := posts(); len(got) > 0 {
			post = got[0]
			break
		}
	}
	if post.body == nil {
		t.Fatalf("no notification reached the receiver; stderr:\n%s", errOut.String())
	}
	ts, _ := strconv.ParseInt(post.header.Get(providers.HeaderTimestamp), 10, 64)
	if want := providers.Sign([]byte(secret), ts, post.header.Get(providers.HeaderDeliveryID), post.body); post.header.Get(providers.HeaderSignature) != want {
		t.Fatal("the delivery's signature does not verify with the destination secret")
	}
	var body struct {
		Org    model.ID `json:"org_id"`
		Entity struct {
			Kind string `json:"kind"`
		} `json:"entity"`
	}
	if err = json.Unmarshal(post.body, &body); err != nil || body.Org != org || body.Entity.Kind != "condition" {
		t.Fatalf("the notification is not about a condition of the organization: %s (%v)", post.body, err)
	}

	code, raw = a.do("POST", "/api/v1/login", map[string]string{"Email": "owner@example.test", "Password": password}, nil)
	if code != 200 || json.Unmarshal(raw, &session) != nil {
		t.Fatalf("login %d: %s", code, raw)
	}
	a.csrf = session.CSRF
	code, raw = a.do("POST", "/api/v1/admin/read", map[string]any{"kind": "audit", "org_id": org}, nil)
	if code != 200 {
		t.Fatalf("audit read %d: %s", code, raw)
	}
	var audit struct {
		Audits []struct {
			Principal model.ID `json:"principal"`
			Action    string   `json:"action"`
		} `json:"audits"`
	}
	if err = json.Unmarshal(raw, &audit); err != nil {
		t.Fatalf("audit %s: %v", raw, err)
	}
	authored, delivered := false, false
	for _, e := range audit.Audits {
		authored = authored || e.Action == "rules.define" && !auth.IsSystemPrincipal(e.Principal)
		delivered = delivered || strings.HasPrefix(e.Action, "notify.delivery.") && e.Principal == auth.SystemPrincipal(org)
	}
	if !authored || !delivered {
		t.Fatalf("authored by the administrator=%v, delivered by %s=%v: %v", authored, auth.SystemRunner, delivered, audit.Audits)
	}
	if err = cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-drained:
	case <-time.After(30 * time.Second):
		t.Fatalf("serve did not stop after SIGINT; stderr:\n%s", errOut.String())
	}
	if err = cmd.Wait(); err != nil {
		t.Fatalf("serve did not exit cleanly: %v\n%s", err, errOut.String())
	}
}
