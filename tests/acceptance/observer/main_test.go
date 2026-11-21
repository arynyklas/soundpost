// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func env(poll, deliv string) func(string) string {
	return func(k string) string {
		switch k {
		case "OBSERVER_POLL_TOKEN":
			return poll
		case "OBSERVER_DELIVERY_TOKEN":
			return deliv
		}
		return ""
	}
}

func baseArgs(extra ...string) []string {
	return append([]string{"-state", "/s", "-interval", "10ms", "-missing-after", "50ms", "-timeout", "200ms",
		"-destination", "https://10.1.2.3:9443/notify", "-authorized-destination", "10.1.2.3:9443"}, extra...)
}

// The observer polls the product's own /readyz without any heartbeat contract and without a poll credential, delivers to a
// private destination only when the operator allowed private destinations, and still refuses a loopback one.
func TestParseReadyzPrivateAndCredentials(t *testing.T) {
	if _, err := parseArgs(baseArgs("-poll-readyz", "node-1=https://10.0.0.1:8443"), env("", "d")); err == nil || !strings.Contains(err.Error(), "-allow-private-destination") {
		t.Fatalf("a private destination without the operator allowance: %v", err)
	}
	c, err := parseArgs(baseArgs("-allow-private-destination", "-poll-readyz", "node-1=https://10.0.0.1:8443,node-2=https://10.0.0.2:8443"), env("", "d"))
	if err != nil {
		t.Fatalf("readyz polls need no poll credential: %v", err)
	}
	if len(c.polls) != 2 || !c.readyz["node-1"] || !c.readyz["node-2"] {
		t.Fatalf("polls %v readyz %v", c.polls, c.readyz)
	}
	if _, err = parseArgs(baseArgs("-allow-private-destination", "-poll", "product=https://x.example/h"), env("", "d")); err == nil {
		t.Fatal("a heartbeat-contract poll without the poll credential was accepted")
	}
	if _, err = parseArgs(baseArgs("-allow-private-destination", "-poll-readyz", "node-1=http://10.0.0.1:8443"), env("", "d")); err == nil {
		t.Fatal("a plain-http readyz origin was accepted")
	}
	if _, err = parseArgs(baseArgs("-allow-private-destination", "-poll-readyz", "node-1=https://10.0.0.1:8443/readyz"), env("", "d")); err == nil {
		t.Fatal("a readyz origin with a path was accepted")
	}
	if _, err = parseArgs(baseArgs("-allow-private-destination", "-poll", "a=https://x/h", "-poll-readyz", "a=https://10.0.0.1:8443"), env("p", "d")); err == nil {
		t.Fatal("one component polled twice was accepted")
	}
	if _, err = parseArgs(baseArgs("-allow-private-destination", "-poll-readyz", "n=https://10.0.0.1:8443"), env("", "")); err == nil {
		t.Fatal("no delivery credential was accepted")
	}
	loop := []string{"-state", "/s", "-poll-readyz", "n=https://10.0.0.1:8443", "-destination", "http://127.0.0.1:9/n", "-authorized-destination", "127.0.0.1:9", "-allow-private-destination"}
	if _, err = parseArgs(loop, env("", "d")); err == nil {
		t.Fatal("-allow-private-destination permitted a loopback destination")
	}
	if _, err = parseArgs(append(loop, "-test-allow-loopback"), env("", "d")); err != nil {
		t.Fatalf("the test allowance still permits loopback: %v", err)
	}
}

func pemOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// pollReadyz is a heartbeat only for 200 with ready=true over a verified certificate; every other answer is none.
func TestPollReadyzAnswers(t *testing.T) {
	var status atomic.Int32
	var body atomic.Value
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" || r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	defer srv.Close()
	c := config{timeout: time.Second, caFile: pemOf(t, srv)}
	client, err := newClient(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		status int
		body   string
		ok     bool
		seq    uint64
	}{
		{"ready with a cursor", 200, `{"ready":true,"version":"v","applied_cursor":{"group":"g","index":"42"},"role":"leader"}`, true, 42},
		{"ready without a cursor", 200, `{"ready":true}`, true, 0},
		{"not ready is a 503", 503, `{"ready":false,"reason":"no_quorum"}`, false, 0},
		{"200 that says not ready", 200, `{"ready":false}`, false, 0},
		{"200 with a body that is not readiness", 200, `<html>proxy</html>`, false, 0},
		{"200 with an empty body", 200, ``, false, 0},
	} {
		status.Store(int32(tc.status))
		body.Store(tc.body)
		seq, ok := pollReadyz(context.Background(), client, srv.URL)
		if ok != tc.ok || seq != tc.seq {
			t.Errorf("%s: got (%d, %v), want (%d, %v)", tc.name, seq, ok, tc.seq, tc.ok)
		}
	}
	// Verification is never disabled: without the run's root the same healthy answer is no heartbeat.
	status.Store(200)
	body.Store(`{"ready":true}`)
	untrusted, err := newClient(config{timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pollReadyz(context.Background(), untrusted, srv.URL); ok {
		t.Fatal("a certificate no configured root vouches for was accepted")
	}
	if _, err = newClient(config{timeout: time.Second, caFile: filepath.Join(t.TempDir(), "missing.pem")}); err == nil {
		t.Fatal("an unreadable -ca-file was accepted")
	}
	garbage := filepath.Join(t.TempDir(), "g.pem")
	_ = os.WriteFile(garbage, []byte("not a certificate"), 0o600)
	if _, err = newClient(config{timeout: time.Second, caFile: garbage}); err == nil {
		t.Fatal("a -ca-file with no certificate was accepted")
	}
	srv.Close()
	if _, ok := pollReadyz(context.Background(), client, srv.URL); ok {
		t.Fatal("a stopped node answered a heartbeat")
	}
}

// One cycle loop over a real readyz peer: healthy polling opens nothing; a stopped peer opens exactly one outage and one alert;
// the peer back closes it with exactly one recovery notice.
func TestCycleReadyzOutageAndRecovery(t *testing.T) {
	var up atomic.Bool
	up.Store(true)
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"ready":false,"reason":"no_quorum"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ready":true,"applied_cursor":{"group":"g","index":"7"}}`))
	}))
	defer peer.Close()
	var alerts, recoveries atomic.Int32
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer deliv" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		switch {
		case strings.Contains(string(raw), `"kind":"alert"`):
			alerts.Add(1)
		case strings.Contains(string(raw), `"kind":"recovery"`):
			recoveries.Add(1)
		}
	}))
	defer dest.Close()
	c := config{id: "t", state: t.TempDir(), polls: map[string]string{"node-1": peer.URL}, readyz: map[string]bool{"node-1": true},
		interval: 10 * time.Millisecond, missing: 60 * time.Millisecond, timeout: time.Second, destination: dest.URL, maxAttempts: 3, delivToken: "deliv", caFile: pemOf(t, peer)}
	client, err := newClient(c)
	if err != nil {
		t.Fatal(err)
	}
	st, err := load(c)
	if err != nil {
		t.Fatal(err)
	}
	run := func(d time.Duration) {
		for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(c.interval) {
			cycle(context.Background(), c, client, st)
		}
	}
	run(200 * time.Millisecond)
	if len(st.Outages) != 0 || !st.Armed || st.Components[0].Status != "ok" || st.Components[0].LastSeq != 7 {
		t.Fatalf("healthy polling: %+v", st)
	}
	up.Store(false)
	run(300 * time.Millisecond)
	if len(st.Outages) != 1 || !st.Outages[0].Alerted || alerts.Load() != 1 || st.Components[0].Status != "missing" {
		t.Fatalf("stopped peer: outages %d alerts %d status %s", len(st.Outages), alerts.Load(), st.Components[0].Status)
	}
	up.Store(true)
	run(200 * time.Millisecond)
	if !st.Outages[0].Recovery || recoveries.Load() != 1 || alerts.Load() != 1 || len(st.Outages) != 1 {
		t.Fatalf("recovered peer: recovery %v recoveries %d alerts %d outages %d", st.Outages[0].Recovery, recoveries.Load(), alerts.Load(), len(st.Outages))
	}
}

// A destination that is down for minutes still gets the alert: retries back off (1 s, 2 s, 4 s, ... capped), so the attempt budget covers the
// outage instead of being spent in the first seconds; the attempts are spaced exactly so, and the alert is delivered once the destination is back.
func TestDeliveryRetriesBackOffAndOutlastADestinationOutage(t *testing.T) {
	var up atomic.Bool
	var hits atomic.Int32
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if !up.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer dest.Close()
	c := config{id: "t", state: t.TempDir(), interval: time.Second, retryCap: 8 * time.Second, maxAttempts: 20, timeout: time.Second, destination: dest.URL, delivToken: "d"}
	o := &Outage{ID: "o1", Component: "node-1", DetectedNS: 1}
	client := &http.Client{Timeout: time.Second}
	const sec = int64(time.Second)
	start := int64(1_000_000_000_000)
	// Down for the first 40 simulated seconds, ticked once a second like the observer's cycle.
	for s := int64(0); s < 40; s++ {
		deliver(context.Background(), c, client, o, start+s*sec)
	}
	var at []int64
	for _, a := range o.Attempts {
		at = append(at, (a.AtNS-start)/sec)
	}
	want := []int64{0, 1, 3, 7, 15, 23, 31, 39}
	if len(at) != len(want) {
		t.Fatalf("attempts at %v, want %v", at, want)
	}
	for i := range want {
		if at[i] != want[i] {
			t.Fatalf("attempts at %v, want %v (1 s, then doubling, capped at 8 s)", at, want)
		}
	}
	if o.Alerted {
		t.Fatal("alerted while the destination was down")
	}
	up.Store(true)
	for s := int64(40); s < 60 && !o.Alerted; s++ {
		deliver(context.Background(), c, client, o, start+s*sec)
	}
	if !o.Alerted {
		t.Fatalf("the alert never reached the destination after it came back (%d attempts)", len(o.Attempts))
	}
	before := hits.Load()
	for s := int64(60); s < 80; s++ {
		deliver(context.Background(), c, client, o, start+s*sec)
	}
	if hits.Load() != before {
		t.Fatal("an accepted alert was sent again")
	}
}
