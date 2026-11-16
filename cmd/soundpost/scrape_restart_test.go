// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
	"github.com/arynyklas/soundpost/internal/sources"
	"github.com/arynyklas/soundpost/profiles"
)

// [07.03#9 / 10.16-W2] The stale-marker state survives a restart of the real
// `soundpost serve`: a real serve child scrapes a NON-loopback exporter that
// exposes two series, is killed (SIGKILL: no shutdown path runs), the exporter
// drops one series while the node is down, and the restarted serve (same
// --data-dir) admits the stale marker of the dropped series on its first cycle.
// The marker is read back through the real query engine: the dropped series is
// no longer returned, while before the restart it still was.

const (
	rsKeepMetric = "restart_keep"
	rsGoneMetric = "restart_gone"
)

// rsExporter is a bearer-protected OpenMetrics exporter on a private address
// whose exposition the test changes.
type rsExporter struct {
	mu   sync.Mutex
	body string
	ok   int
	srv  *http.Server
	url  string
}

func newRSExporter(t *testing.T, ip string, body string) *rsExporter {
	t.Helper()
	ln, err := net.Listen("tcp4", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	e := &rsExporter{body: body, url: "http://" + ln.Addr().String() + "/metrics"}
	e.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		defer e.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+nlToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		e.ok++
		w.Header().Set("Content-Type", "application/openmetrics-text; version=1.0.0; charset=utf-8")
		w.Write([]byte(e.body))
	})}
	go e.srv.Serve(ln)
	t.Cleanup(func() { e.srv.Close() })
	return e
}

func (e *rsExporter) set(body string) { e.mu.Lock(); e.body = body; e.mu.Unlock() }

func (e *rsExporter) scrapes() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.ok
}

func (e *rsExporter) waitScrapes(t *testing.T, n int, what string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if e.scrapes() >= n {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s: the exporter was scraped %d times, want %d", what, e.scrapes(), n)
}

func rsBody(keep, gone string) string {
	s := "# TYPE " + rsKeepMetric + " gauge\n" + rsKeepMetric + "{job=\"api\"} " + keep + "\n"
	if gone != "" {
		s += "# TYPE " + rsGoneMetric + " gauge\n" + rsGoneMetric + "{job=\"api\"} " + gone + "\n"
	}
	return s + "# EOF\n"
}

// enableStaleMarkers adds the on_disappear stale policy to the target of the
// provisioned configuration file.
func enableStaleMarkers(t *testing.T, config string) {
	t.Helper()
	raw, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["targets"].([]any)[0].(map[string]any)["stale"] = map[string]any{"on_disappear": true}
	if raw, err = json.Marshal(doc); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(config, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// killServe starts the real serve child over the node, calls during while it
// runs and then kills it with SIGKILL: the process gets no chance to flush or
// persist anything it had not already made durable.
func (n nlNode) killServe(t *testing.T, during func()) {
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
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for range lines {
		}
		cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not die after SIGKILL")
	}
}

// queryRestart reopens the stopped node and returns the float values of the
// instant vector of expr, evaluated just after now.
func (n nlNode) queryRestart(t *testing.T, expr string) []float64 {
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
	scope, err := app.Auth.Authorize(ctx, actor, n.org, []model.ID{n.project}, auth.Read)
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
		Language: query.LanguagePromQL, Profile: profileID, FeatureSet: p.FeatureSets[0].ID, Expression: expr,
		Evaluation: query.Evaluation{Instant: true, Time: at}, Projects: []model.ID{n.project},
	})
	if err != nil {
		t.Fatalf("query %s: %v", expr, err)
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

func TestServeKeepsTheStaleMarkerStateAcrossAKilledRestart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes and signals")
	}
	ip := privateHostAddr(t)
	exp := newRSExporter(t, ip, rsBody("1", "7"))
	n := provisionNLNode(t, exp.url, []string{ip + "/32"})
	enableStaleMarkers(t, n.config)
	statePath := filepath.Join(n.data, "scrape-state", "nonloopback.scrape-state.json")

	// First process: both series are scraped and admitted; the state file names both.
	n.killServe(t, func() {
		exp.waitScrapes(t, 3, "first process")
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if raw, err := os.ReadFile(statePath); err == nil && strings.Contains(string(raw), rsGoneMetric) && strings.Contains(string(raw), rsKeepMetric) {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Error("the state file under the data directory never named both scraped series")
	})
	before := exp.scrapes()
	if got := n.queryRestart(t, rsGoneMetric); len(got) != 1 || got[0] != 7 {
		t.Fatalf("before the restart %s: %v, want the scraped 7", rsGoneMetric, got)
	}

	// The exporter drops one series while the node is down.
	exp.set(rsBody("5", ""))
	n.runServe(t, func() { exp.waitScrapes(t, before+3, "restarted process") })

	if got := n.queryRestart(t, rsGoneMetric); len(got) != 0 {
		t.Fatalf("the series that vanished while the node was down is still returned after the restart: %v (its stale marker was lost with the process)", got)
	}
	if got := n.queryRestart(t, rsKeepMetric); len(got) != 1 || got[0] != 5 {
		t.Fatalf("the series that stayed: %v, want the new 5", got)
	}

	// The state lives in a private subdirectory of the data directory.
	for path, want := range map[string]os.FileMode{filepath.Dir(statePath): 0o700, statePath: 0o600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Errorf("%s: %v %v, want mode %v", filepath.Base(path), info, err, want)
		}
	}
	if raw, err := os.ReadFile(statePath); err != nil || strings.Contains(string(raw), rsGoneMetric) || !strings.Contains(string(raw), rsKeepMetric) {
		t.Errorf("the committed state after the restart: %s %v", raw, err)
	}
}

// The state directory is the data directory's own subdirectory; a state path
// that cannot be created is a static startup reason, not a silent memory-only run.
func TestScrapeStateDirectoryIsUnderTheDataDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	f.String("data-dir", "", "private durable directory")
	o := addScrapeFlags(f)
	config, secrets := scrapeCmdFiles(t, "https://exporter.example.test/metrics", nil)
	data := filepath.Join(t.TempDir(), "data")
	if err := f.Parse([]string{"--data-dir", data, "--scrape-config", config, "--scrape-secrets-dir", secrets}); err != nil {
		t.Fatal(err)
	}
	s, err := o.settings()
	if err != nil || s.stateDir != filepath.Join(data, "scrape-state") {
		t.Fatalf("state directory %q %v, want it under the data directory", s.stateDir, err)
	}
	// settings() creates nothing: a refused configuration leaves the data directory untouched.
	if _, err := os.Stat(data); err == nil {
		t.Fatal("settings() created the data directory")
	}

	// start opens the private state directory under the node's data directory
	app, err := appcore.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	host, err := s.start(context.Background(), app)
	if err != nil || host == nil {
		t.Fatalf("%v %v", host, err)
	}
	host.Close()
	if info, err := os.Stat(s.stateDir); err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("state directory: %v %v", info, err)
	}

	// a state directory that cannot be created refuses the start, typed
	blocked := s
	file := filepath.Join(data, "not-a-directory")
	if err = os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	blocked.stateDir = filepath.Join(file, "scrape-state")
	if _, err = blocked.start(context.Background(), app); err == nil {
		t.Fatal("a state directory under a regular file was accepted")
	}
	var se *sources.ScrapeStateError
	if !errors.As(err, &se) || scrapeFailureNotice(err) != "scrape: state_unavailable" {
		t.Fatalf("start error %v, notice %q", err, scrapeFailureNotice(err))
	}
	if strings.Contains(scrapeFailureNotice(err), blocked.stateDir) {
		t.Fatal("the notice names a path")
	}
}
