// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"io/fs"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
	"github.com/arynyklas/soundpost/profiles"
)

// [10.16-W1] The scrape smoke over a NON-loopback address, through the real
// `soundpost serve` child process: the exporter listens on a private address of
// this host (never 127.0.0.1: the egress policy has no loopback exception), the
// configuration lifts exactly that /32, and the scraped sample is read back
// through the real query engine after serve stopped. The negative leg removes
// the allow prefix and proves the default policy refuses the same exporter.

const (
	nlToken  = "CANARY-nonloopback-bearer-71c2d9"
	nlMetric = "nonloopback_temp"
)

// privateHostAddr returns a private (RFC 1918) IPv4 address of this host that
// the scrape egress policy can admit with an allow prefix.
func privateHostAddr(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip := ipn.IP.To4(); ip != nil && ip.IsPrivate() {
			return ip.String()
		}
	}
	t.Skip("no private non-loopback IPv4 address on this host (set up a veth/second address to run the non-loopback scrape smoke)")
	return ""
}

type nlExporter struct {
	mu       sync.Mutex
	ok, deny int
	srv      *http.Server
	url      string
}

func newNLExporter(t *testing.T, ip string) *nlExporter {
	t.Helper()
	ln, err := net.Listen("tcp4", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	e := &nlExporter{url: "http://" + ln.Addr().String() + "/metrics"}
	e.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		defer e.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+nlToken {
			e.deny++
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		e.ok++
		w.Header().Set("Content-Type", "application/openmetrics-text; version=1.0.0; charset=utf-8")
		w.Write([]byte("# TYPE " + nlMetric + " gauge\n" + nlMetric + "{job=\"api\"} 73\n# EOF\n"))
	})}
	go e.srv.Serve(ln)
	t.Cleanup(func() { e.srv.Close() })
	return e
}

func (e *nlExporter) counts() (ok, deny int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.ok, e.deny
}

type nlNode struct {
	data, config, secrets string
	project               model.ID
	owner                 model.ID
	session               string
	org                   model.ID
}

// provisionNLNode builds a data directory with an owner, a project, an
// onboarded source and the private secrets/config files for one target at url.
func provisionNLNode(t *testing.T, url string, allow []string) nlNode {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	n := nlNode{data: filepath.Join(root, "data"), secrets: filepath.Join(root, "secrets"), config: filepath.Join(root, "scrape.json")}
	app, err := appcore.Open(n.data)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	token, err := app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := app.Auth.Bootstrap(ctx, token, "nl-owner@example.test", "non-loopback fixture password 2026")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := app.Auth.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	org, source := model.NewID(), model.NewID()
	n.org = org
	n.project, n.owner, n.session = model.NewID(), session.User, session.Token
	command := func(kind string, p auth.AdminPayload) {
		var rev model.Revision
		app.Control.View(ctx, func(st model.ControlState) error { rev = st.Revision; return nil })
		p.Reason = "non-loopback smoke"
		raw, _ := json.Marshal(p)
		if _, err := app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: org, Kind: kind, Payload: raw}); err != nil {
			t.Fatalf("admin %s: %v", kind, err)
		}
	}
	command("create_org", auth.AdminPayload{Name: "nl"})
	command("create_project", auth.AdminPayload{ID: n.project, Name: "nl"})
	command("membership", auth.AdminPayload{UserID: n.owner, Enabled: true})
	command("grant", auth.AdminPayload{UserID: n.owner, ProjectID: n.project, Permissions: []string{string(auth.Read)}, Enabled: true})
	res := model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "inst-nl"}
	issued, err := app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{
		CommandID: model.NewID(), Org: org, Project: n.project, Source: source,
		Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()),
		Policy: model.SourcePolicy{
			Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric},
			Resources:     model.ResourceRegistry{Services: []model.ID{res.Service}, Environments: []model.ID{res.Environment}, Builds: []model.ID{res.Build}, Instances: []string{res.Instance}},
			Labels:        map[string][]string{"job": {"api"}},
			RetentionDays: map[model.Kind]uint32{model.Metric: 7}, MaxBytes: 64 << 20, MaxSeries: 1000,
		},
		Reason: "non-loopback smoke",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(n.secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{"source-token": issued.Credential, "exporter-token": nlToken} {
		if err = os.WriteFile(filepath.Join(n.secrets, name), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	target := map[string]any{
		"alias": "nonloopback", "url": url, "interval": "1s", "timeout": "1s", "max_bytes": 1 << 20,
		"egress": map[string]any{"allow_prefixes": allow},
		"auth":   "bearer", "secret": "exporter-token",
		"source": map[string]any{
			"project": n.project.String(), "source": source.String(), "producer": model.ID{0xaa, 9}.String(), "policy_revision": 1,
			"credential_secret": "source-token",
			"resource":          map[string]any{"service": res.Service.String(), "environment": res.Environment.String(), "build": res.Build.String(), "instance": res.Instance},
		},
	}
	raw, err := json.Marshal(map[string]any{"version": 1, "targets": []any{target}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(n.config, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return n
}

// runServe starts the real serve child over the node, calls during while it
// runs, then stops it with SIGINT and requires a clean exit.
func (n nlNode) runServe(t *testing.T, during func()) {
	t.Helper()
	cmd, lines, errOut := serveChild(t, "--data-dir", n.data, "--listen", "127.0.0.1:0", "--scrape-config", n.config, "--scrape-secrets-dir", n.secrets)
	defer cmd.Process.Kill()
	started := false
	deadline := time.After(40 * time.Second)
wait:
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				break wait
			}
			if line == "scrape: 1 target(s) started" {
				started = true
				break wait
			}
		case <-deadline:
			break wait
		}
	}
	if !started {
		t.Fatalf("serve never reported its scrapers started; stderr:\n%s", errOut.String())
	}
	during()
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for range lines {
		}
		done <- cmd.Wait()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve did not exit cleanly: %v\n%s", err, errOut.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("serve did not stop after SIGINT; stderr:\n%s", errOut.String())
	}
	for _, leak := range []string{n.config, n.secrets, nlToken} {
		if strings.Contains(errOut.String(), leak) {
			t.Errorf("serve printed %q", leak)
		}
	}
}

// queryNL reopens the stopped node and returns the float values of the metric.
func (n nlNode) queryNL(t *testing.T) []float64 {
	t.Helper()
	ctx := context.Background()
	app, err := appcore.Open(n.data)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	actor, err := app.Auth.Authenticate(ctx, n.session)
	if err != nil {
		t.Fatal(err)
	}
	org := n.org
	scope, err := app.Auth.Authorize(ctx, actor, org, []model.ID{n.project}, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	files, err := profiles.Query()
	if err != nil {
		t.Fatal(err)
	}
	const profileID = "promql-prometheus-3.13.5"
	rawProfile, err := fs.ReadFile(files, profileID+".json")
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		FeatureSets []struct {
			ID string `json:"id"`
		} `json:"feature_sets"`
	}
	if json.Unmarshal(rawProfile, &p) != nil || len(p.FeatureSets) == 0 {
		t.Fatal("no feature set")
	}
	at := model.UnixNano(time.Now().Add(2 * time.Second).Truncate(time.Millisecond).UnixNano())
	res, err := app.Query.Execute(ctx, scope, query.Request{
		Language: query.LanguagePromQL, Profile: profileID, FeatureSet: p.FeatureSets[0].ID, Expression: nlMetric,
		Evaluation: query.Evaluation{Instant: true, Time: at}, Projects: []model.ID{n.project},
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	var out []float64
	for _, pr := range res.Projects {
		if pr.Failure != nil {
			t.Fatalf("query failure: %+v", pr.Failure)
		}
		if pr.Value == nil {
			continue
		}
		for _, el := range pr.Value.Vector {
			if el.Sample.Float != nil {
				out = append(out, math.Float64frombits(uint64(*el.Sample.Float)))
			}
		}
	}
	return out
}

func TestServeScrapesANonLoopbackExporterIntoTheRealQueryPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes and signals")
	}
	ip := privateHostAddr(t)
	exp := newNLExporter(t, ip)
	if host, _, _ := net.SplitHostPort(strings.TrimPrefix(exp.url, "http://")); net.ParseIP(host).IsLoopback() {
		t.Fatal("the exporter must not be on loopback")
	}
	n := provisionNLNode(t, exp.url, []string{ip + "/32"})
	n.runServe(t, func() {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if ok, _ := exp.counts(); ok >= 2 {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Error("the exporter was not scraped by serve over the non-loopback address")
	})
	if _, deny := exp.counts(); deny != 0 {
		t.Fatalf("%d requests carried the wrong bearer", deny)
	}
	if got := n.queryNL(t); len(got) != 1 || got[0] != 73 {
		t.Fatalf("the scraped sample is not queryable after serve: %v", got)
	}
}

// Without the allow prefix the same exporter is refused by the default egress
// policy before any request: serve never contacts it and nothing is admitted.
func TestServeDoesNotScrapeANonLoopbackExporterWithoutAnAllowPrefix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes and signals")
	}
	exp := newNLExporter(t, privateHostAddr(t))
	n := provisionNLNode(t, exp.url, []string{})
	n.runServe(t, func() { time.Sleep(4 * time.Second) })
	if ok, deny := exp.counts(); ok != 0 || deny != 0 {
		t.Fatalf("the default egress policy let serve reach a private exporter: ok=%d deny=%d", ok, deny)
	}
	if got := n.queryNL(t); len(got) != 0 {
		t.Fatalf("unexpected sample %v", got)
	}
}
