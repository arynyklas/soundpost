// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

func countLines(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		n++
	}
	return n
}

// TestPreloadAndSteadyAgainstAFakeIngest runs both phases of the role over TLS against a fake of the ingest route: the preload takes the
// target bytes per signal and writes its summary, the steady stream sends the mix and the control samples, and the refusal of the slots a
// lost shard owned is counted and never aborts the run.
func TestPreloadAndSteadyAgainstAFakeIngest(t *testing.T) {
	if testing.Short() {
		t.Skip("network phases take about half a minute")
	}
	cfg := DefaultConfig()
	creds := map[string]string{} // project id -> credential
	plan := Plan{Config: cfg}
	for p := range cfg.Projects {
		cred := fmt.Sprintf("cred-%d", p)
		creds[NewProject(cfg, p).Project.String()] = cred
		plan.Sources = append(plan.Sources, PlanSource{Project: p, Credential: cred})
	}
	var lost atomic.Bool
	var mu sync.Mutex
	var bodyBytes int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var b model.Batch
		if r.URL.Path != ingestPath || r.Method != http.MethodPost || r.Header.Get("User-Agent") != ingestUserAgent || json.Unmarshal(raw, &b) != nil || r.Header.Get("Authorization") != "Bearer "+creds[b.Project.String()] {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if lost.Load() && b.RouteSlot < 32 {
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, `{"code":"unavailable","retryable":true}`)
			return
		}
		mu.Lock()
		bodyBytes += int64(len(raw))
		mu.Unlock()
		rc, _ := json.Marshal(model.Receipt{Version: 1, BatchID: b.ID, Hash: model.Hash{1}, Cursor: model.Cursor{Group: model.ID{1}, Index: 1}, SignalDeadlines: []model.SignalDeadline{}})
		w.Write(rc)
	}))
	defer srv.Close()
	plan.Addr = srv.Listener.Addr().String()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	must(os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600), "ca")
	out := filepath.Join(dir, "run")

	const target = 128 << 20
	span := SteadyS * time.Second
	pcfg := cfg
	pcfg.Epoch = PreloadEpoch
	var plans []sigPlan
	for _, sig := range PreloadSignals {
		plans = append(plans, calibrate(pcfg, sig, target, time.Now().Add(-span), span, 4))
	}
	runPreload(pcfg, plan, ca, out, plans, target, 8, 4)

	var sum PreloadSummary
	raw, err := os.ReadFile(filepath.Join(out, FilePreloadSummary))
	if err != nil || json.Unmarshal(raw, &sum) != nil {
		t.Fatalf("preload summary: %v", err)
	}
	var total, batches int64
	for _, sig := range PreloadSignals {
		s := sum.Signals[sig]
		if s.EncodedBytes < target || s.EncodedBytes > target+2<<20 || s.Batches == 0 || s.Records == 0 {
			t.Fatalf("%s: %+v", sig, s)
		}
		if r := time.Duration(s.EventEndNS - s.EventStartNS); r < 23*time.Hour+30*time.Minute || r > 24*time.Hour+30*time.Minute {
			t.Fatalf("%s: event range %s", sig, r)
		}
		total += s.EncodedBytes
		batches += s.Batches
	}
	mu.Lock()
	got := bodyBytes
	mu.Unlock()
	if got != total {
		t.Fatalf("server took %d body bytes, the summary says %d ACKed", got, total)
	}
	if sum.EventEndNS > sum.StartUnixMS*1e6 || sum.EventEndNS < sum.StartUnixMS*1e6-int64(time.Hour) || sum.Refused != 0 || sum.Transport != 0 {
		t.Fatalf("summary %d..%d start %d refused %d transport %d", sum.EventStartNS, sum.EventEndNS, sum.StartUnixMS, sum.Refused, sum.Transport)
	}
	for p, slots := range sum.SlotsByProject {
		if len(slots) == 0 || slots[0] > 31 {
			t.Fatalf("project %d holds no record in slots 0..31: %v", p, slots)
		}
	}
	if len(sum.TraceSamples) < cfg.Projects*(preloadSampleTraces-2) {
		t.Fatalf("%d trace samples", len(sum.TraceSamples))
	}
	if n := countLines(t, filepath.Join(out, FilePreloadAcks)); int64(n) != batches+1 {
		t.Fatalf("%d acks lines for %d batches", n, batches)
	}

	// steady: 14 s, the shard lost 5 s in
	t0 := time.Now().Add(3 * time.Second)
	time.AfterFunc(time.Until(t0.Add(5*time.Second)), func() { lost.Store(true) })
	runSteady(cfg, plan, ca, out, t0, 0, 14*time.Second, IngestRate)
	var is IngestSummary
	raw, err = os.ReadFile(filepath.Join(out, FileIngestSummary))
	if err != nil || json.Unmarshal(raw, &is) != nil {
		t.Fatalf("load summary: %v", err)
	}
	// at most 100 + 40 windows of the mix start inside the 14 s (j = 0; j = 1 for the projects whose phase is below 4 s) and a window's batches
	// are spread over the 10 s after its flush, so those past the end of the run are not sent; control samples at 0 s (project 97) and 10 s (project 98)
	if m, s := is.RecordsSent["metric"], is.RecordsSent["span"]; m < 400 || m > 140*6 || s < 100 || s > 140*2 || is.RecordsSent["control"] != 2 {
		t.Fatalf("sent %v", is.RecordsSent)
	}
	if is.Refused == 0 || is.RefusedBy["503"] != is.Refused || is.Acked == 0 || is.Acked+is.Refused != is.Sent || is.Transport != 0 || is.Shed != 0 {
		t.Fatalf("summary %+v", is)
	}
	if is.T0UnixMS != t0.UnixMilli() || is.DurationS != 14 || is.Rate != IngestRate || is.BytesAcked == 0 {
		t.Fatalf("summary %+v", is)
	}
	if n := countLines(t, filepath.Join(out, FileIngestAcks)); int64(n) != is.Sent+is.Shed+1 {
		t.Fatalf("%d acks lines for %d requests", n, is.Sent)
	}
}
