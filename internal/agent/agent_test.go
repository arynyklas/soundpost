// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"soundpost/internal/ingest"
	"soundpost/internal/model"
	"soundpost/internal/sources"
)

const (
	testToken  = "sp_src_TOKEN-CANARY-0123456789"
	canaryBody = "password reset requested by erin token=BODY-CANARY"
)

type ingestFake struct {
	t        *testing.T
	srv      *httptest.Server
	policy   model.SourcePolicy
	id       sources.Identity
	mu       sync.Mutex
	down     bool
	seen     map[model.ID][]byte
	receipts map[model.ID]model.Receipt
	records  []model.Record
	raw      bytes.Buffer // every request body
	headers  []http.Header
	index    uint64
}

func scalar(t testing.TB, lit string) model.Scalar {
	t.Helper()
	var s model.Scalar
	if err := json.Unmarshal([]byte(lit), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func templates(t testing.TB) []model.LogTemplate {
	return []model.LogTemplate{{ID: "svc.started", Revision: 1, Line: "service started unit {unit}", Severity: "info", Fields: []model.TemplateField{
		{Name: "unit", Type: "string", MaxBytes: 16, Sensitivity: "metadata", Values: []model.Scalar{scalar(t, `"alpha"`), scalar(t, `"beta"`)}},
	}}}
}

func testIDs() (resource model.Resource, id sources.Identity) {
	resource = model.Resource{Service: model.ID{1}, Environment: model.ID{2}, Build: model.ID{3}, Instance: "host-1", Labels: model.Labels{}}
	return resource, sources.Identity{Org: model.ID{0x21}, Project: model.ID{0x22}, Source: model.ID{0x23}}
}

// newIngestFake is a TLS server with the C03 route contract the agent relies
// on: bearer authentication, strict batch decoding, the SAME record validation
// the server applies, route-slot checking and receipts that deduplicate a
// retried batch.
func newIngestFake(t *testing.T) *ingestFake {
	t.Helper()
	res, id := testIDs()
	f := &ingestFake{t: t, id: id, seen: map[model.ID][]byte{}, receipts: map[model.ID]model.Receipt{}}
	f.policy = model.SourcePolicy{
		Revision: 1, Enabled: true, Class: "structured",
		Kinds:     []model.Kind{model.Metric, model.Log, model.CapabilityKind, model.Loss},
		Templates: templates(t),
		Resources: model.ResourceRegistry{Services: []model.ID{res.Service}, Environments: []model.ID{res.Environment}, Builds: []model.ID{res.Build}, Instances: []string{res.Instance}},
		Labels: map[string][]string{
			"source": {"app", "denied"},
			"mode":   {"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"},
			"state":  {"total", "available", "free", "buffers", "cached", "swap_total", "swap_free", "size", "current", "limit", "swap_current"},
			"window": {"1m", "5m", "15m"},
			"mount":  {"data"},
		},
		RetentionDays: map[model.Kind]uint32{model.Metric: 7, model.Log: 7, model.CapabilityKind: 7, model.Loss: 7}, MaxBytes: 1 << 30, MaxSeries: 10000,
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *ingestFake) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fault := func(status int, code model.Code) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(model.Fail(code))
	}
	f.headers = append(f.headers, r.Header.Clone())
	if r.URL.Path != "/ingest/v1/batches" || r.Method != http.MethodPost {
		fault(404, model.NotFound)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+testToken || r.Header.Get("Cookie") != "" {
		fault(403, model.Forbidden)
		return
	}
	if f.down {
		fault(503, model.Unavailable)
		return
	}
	var body bytes.Buffer
	b, err := ingest.Decode(teeReader(r, &body), r.Header.Get("Content-Encoding"))
	f.raw.Write(body.Bytes())
	if err != nil {
		fault(422, model.Invalid)
		return
	}
	if b.Project != f.id.Project || b.Source != f.id.Source || b.PolicyRevision != 1 {
		fault(403, model.Forbidden)
		return
	}
	canonical, _ := model.CanonicalJSON(b)
	for i := range b.Records {
		rec := &b.Records[i]
		if err := model.ValidateRecord(rec, f.policy); err != nil {
			f.t.Errorf("server validation refused a %s record: %v", rec.Kind, err)
			fault(422, model.Invalid)
			return
		}
		slot, err := model.OwnerSlot(f.id.Org, b.Project, b.Source, b.Producer, *rec)
		if err != nil || slot != b.RouteSlot {
			f.t.Errorf("route slot mismatch for a %s record", rec.Kind)
			fault(422, model.Invalid)
			return
		}
	}
	if old, ok := f.seen[b.ID]; ok {
		if string(old) != string(canonical) {
			fault(409, model.Conflict)
			return
		}
		json.NewEncoder(w).Encode(f.receipts[b.ID])
		return
	}
	f.index++
	rc := model.Receipt{Version: 1, BatchID: b.ID, Hash: model.HashCanonical(canonical), Cursor: model.Cursor{Group: model.ID{9}, Index: model.Uint64(f.index)}}
	f.seen[b.ID], f.receipts[b.ID] = canonical, rc
	f.records = append(f.records, b.Records...)
	json.NewEncoder(w).Encode(rc)
}

type teeBody struct {
	r *http.Request
	b *bytes.Buffer
}

func teeReader(r *http.Request, b *bytes.Buffer) *teeBody { return &teeBody{r: r, b: b} }
func (t *teeBody) Read(p []byte) (int, error) {
	n, err := t.r.Body.Read(p)
	t.b.Write(p[:n])
	return n, err
}

func (f *ingestFake) setDown(v bool) { f.mu.Lock(); f.down = v; f.mu.Unlock() }

func (f *ingestFake) ofKind(k model.Kind) []model.Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []model.Record
	for _, r := range f.records {
		if r.Kind == k {
			out = append(out, r)
		}
	}
	return out
}

func (f *ingestFake) everything() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.raw.String()
}

// writeCA stores the test server's certificate as the agent's trust root.
func writeCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func baseConfig(t *testing.T, f *ingestFake, logs ...LogConfig) (Config, string) {
	t.Helper()
	dir := t.TempDir()
	cred := filepath.Join(dir, "credential")
	if err := os.WriteFile(cred, []byte(testToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	res, id := testIDs()
	return Config{
		Version: 1, Server: f.srv.URL, CAFile: writeCA(t, f.srv), CredentialFile: cred, StateDir: state,
		Org: id.Org.String(), Project: id.Project.String(), Source: id.Source.String(), PolicyRevision: 1,
		Resource: ResourceConfig{ServiceID: res.Service.String(), EnvironmentID: res.Environment.String(), BuildID: res.Build.String(), Instance: res.Instance},
		Host:     &HostConfig{Interval: Duration(time.Second), Allow: []string{"cpu", "memory", "load", "filesystem", "process_count"}, Filesystems: []FilesystemConfig{{Alias: "data", Path: dir}}},
		Logs:     logs,
	}, state
}

func fileLog(t *testing.T, name, path string) LogConfig {
	return LogConfig{SourcePolicy: sources.SourcePolicy{
		Name: name, Kind: sources.KindFile, Class: sources.ClassStructured,
		Labels:    model.Labels{{Name: "source", Value: map[string]string{"app": "app", "denied": "denied"}[name]}},
		Templates: templates(t), File: &sources.FileSpec{Path: path, StartAt: sources.StartBeginning},
	}}
}

func appendLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		fmt.Fprintln(f, l)
	}
}

func everyByte(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			raw, _ := os.ReadFile(p)
			b.Write(raw)
		}
		return nil
	})
	return b.String()
}

func capabilityByMethod(recs []model.Record) map[string]*model.Capability {
	out := map[string]*model.Capability{}
	for _, r := range recs {
		c := r.Payload.Capability
		out[c.Method] = c // the latest record of a method wins
	}
	return out
}

func busy(d time.Duration) {
	end := time.Now().Add(d)
	var wg sync.WaitGroup
	for range runtime.NumCPU() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			x := 1
			for time.Now().Before(end) {
				for range 10000 {
					x = x*3 + 1
				}
			}
			_ = x
		}()
	}
	wg.Wait()
}

func cpuBusy(recs []model.Record) (busySeconds, idleSeconds float64, found bool) {
	for _, r := range recs {
		m := r.Payload.Metric
		if m == nil || m.Name != "host_cpu_seconds_total" || len(m.Labels) != 1 {
			continue
		}
		v := floatOf(m)
		found = true
		if m.Labels[0].Value == "idle" || m.Labels[0].Value == "iowait" {
			idleSeconds += v
		} else {
			busySeconds += v
		}
	}
	return
}

func TestAgentCycleOverHTTPS(t *testing.T) {
	f := newIngestFake(t)
	dir := t.TempDir()
	app := filepath.Join(dir, "app.log")
	appendLines(t, app, "service started unit alpha", canaryBody, "service started unit beta")
	denied := filepath.Join(dir, "denied.log")
	appendLines(t, denied, "service started unit alpha")
	deniable := runtime.GOOS != "windows" && os.Geteuid() != 0
	if deniable {
		if err := os.Chmod(denied, 0); err != nil {
			t.Fatal(err)
		}
	}
	cfg, state := baseConfig(t, f, fileLog(t, "app", app), fileLog(t, "denied", denied))
	var logs bytes.Buffer
	a, err := New(cfg, slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	if err != nil {
		t.Fatal(err)
	}

	rep := a.Cycle(context.Background())
	if rep.Host.Err != nil || !rep.Host.Ran || rep.Host.Samples == 0 || rep.Host.Admitted != rep.Host.Batches || rep.Host.Batches == 0 {
		t.Fatalf("host: %+v", rep.Host)
	}
	if !rep.CapabilitiesSent || rep.CapabilitiesFailed {
		t.Fatalf("capabilities: %+v", rep)
	}
	var appRep, deniedRep SourceReport
	for _, s := range rep.Sources {
		switch s.Name {
		case "app":
			appRep = s
		case "denied":
			deniedRep = s
		}
	}
	if appRep.Err != nil || appRep.Result.Admitted != 2 || appRep.Result.Scanned != 3 || appRep.Status != sources.StatusSupported {
		t.Fatalf("app source: %+v", appRep)
	}

	// logs: only the two registered messages crossed the wire, as typed fields
	appLines := func() []string {
		var out []string
		for _, r := range f.ofKind(model.Log) {
			if l := r.Payload.Log; len(l.StreamLabels) == 1 && l.StreamLabels[0].Value == "app" {
				out = append(out, l.Line)
			}
		}
		return out
	}
	lines := appLines()
	if strings.Join(lines, "|") != "service started unit alpha|service started unit beta" {
		t.Fatalf("admitted lines %q", lines)
	}

	// host metrics: values are real, the filesystem is named by alias only
	metrics := f.ofKind(model.Metric)
	names := map[string]int{}
	for _, r := range metrics {
		names[r.Payload.Metric.Name]++
	}
	for _, want := range []string{"host_cpu_seconds_total", "host_memory_bytes", "host_filesystem_bytes", "host_processes_total", "host_cpu_logical_count"} {
		if names[want] == 0 {
			t.Errorf("metric %s missing (have %v)", want, names)
		}
	}
	if runtime.GOOS == "linux" && names["host_load_average"] != 3 {
		t.Errorf("load average samples %d, want 3", names["host_load_average"])
	}
	wire := f.everything()
	if strings.Contains(wire, dir) || strings.Contains(wire, "denied.log") || strings.Contains(wire, "app.log") {
		t.Fatal("a path crossed the wire")
	}

	// capabilities: supported, policy-denied and permission-denied states are
	// explicit records, never silence and never zero samples
	caps := capabilityByMethod(f.ofKind(model.CapabilityKind))
	if c := caps["cpu:procfs_stat"]; runtime.GOOS == "linux" && (c == nil || c.Status != "supported" || c.Reason != "ok") {
		t.Fatalf("cpu capability %+v", c)
	}
	if c := caps["cgroup:policy"]; c == nil || c.Status != "denied" || c.Reason != "policy" || c.Coverage.Frames != "unknown" {
		t.Fatalf("a group outside the host policy must be an explicit denial: %+v", c)
	}
	if c := caps["file_tail:app"]; c == nil || c.Status != "supported" || c.Signal != model.Log || c.Coverage.Frames != "complete" {
		t.Fatalf("app source capability %+v", c)
	}
	if deniable {
		if deniedRep.Err == nil || deniedRep.Status != sources.StatusDenied || deniedRep.Reason != sources.ReasonPermission {
			t.Fatalf("denied source: %+v", deniedRep)
		}
		if c := caps["file_tail:denied"]; c == nil || c.Status != "denied" || c.Reason != "permission_denied" || c.Coverage.Frames != "unknown" {
			t.Fatalf("denied source capability %+v", c)
		}
		if n := len(f.ofKind(model.Loss)); n != 0 {
			t.Fatalf("permission denial reported as loss: %d", n)
		}
	}

	// privacy: neither the rejected message body, nor the credential, nor a
	// path appears in what was sent, logged or persisted
	if rep.Failed() != deniable {
		t.Fatalf("Failed() = %v with deniable=%v", rep.Failed(), deniable)
	}
	for place, text := range map[string]string{"wire": wire, "agent logs": logs.String(), "state dir": everyByte(t, state)} {
		for _, secret := range []string{"BODY-CANARY", "password reset", "erin", testToken, "TOKEN-CANARY"} {
			if strings.Contains(text, secret) {
				t.Fatalf("%s contains %q", place, secret)
			}
		}
	}
	if !strings.Contains(logs.String(), `"unknown_or_denied"`) {
		t.Fatalf("agent produced no host log line: %s", logs.String())
	}
	for _, h := range f.headers {
		if h.Get("Authorization") != "Bearer "+testToken || h.Get("Cookie") != "" || h.Get("User-Agent") != "soundpost-agent" {
			t.Fatalf("request headers %v", h)
		}
	}

	// a second cycle: real CPU work shows as a counter delta, new lines are
	// read exactly once
	first := metricsOf(f, "host_cpu_seconds_total")
	before, _, ok := cpuBusy(first)
	if !ok {
		t.Fatal("no cpu counter in the first cycle")
	}
	appendLines(t, app, "service started unit beta")
	busy(400 * time.Millisecond)
	a.Cycle(context.Background())
	second := metricsOf(f, "host_cpu_seconds_total")[len(first):]
	after, _, ok := cpuBusy(second)
	if !ok || len(second) != len(first) {
		t.Fatalf("second cycle cpu samples %d, first %d", len(second), len(first))
	}
	if after-before < 0.15 {
		t.Fatalf("cpu busy seconds grew by %.3f over a 400ms all-core spin: the collector is not reading real counters", after-before)
	}
	lines = appLines()
	if len(lines) != 3 || lines[2] != "service started unit beta" {
		t.Fatalf("second cycle lines %q", lines)
	}
	if strings.Contains(logs.String(), "BODY-CANARY") {
		t.Fatal("canary appeared in later logs")
	}
}

func metricsOf(f *ingestFake, name string) []model.Record {
	var out []model.Record
	for _, r := range f.ofKind(model.Metric) {
		if r.Payload.Metric.Name == name {
			out = append(out, r)
		}
	}
	return out
}

func floatOf(m *model.MetricPoint) float64 {
	return math.Float64frombits(uint64(*m.Value))
}

// A host batch refused by an unavailable server is not retried from a spool
// (host samples are point-in-time) but is reported as a loss once the server
// accepts data again.
func TestAgentHostLossIsReportedAfterOutage(t *testing.T) {
	f := newIngestFake(t)
	cfg, _ := baseConfig(t, f)
	a, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.setDown(true)
	rep := a.Cycle(context.Background())
	if rep.Host.Err == nil || rep.Host.Admitted != 0 || !rep.CapabilitiesFailed || len(f.ofKind(model.Metric)) != 0 {
		t.Fatalf("outage cycle: %+v", rep)
	}
	lostSamples := rep.Host.Samples
	f.setDown(false)
	rep = a.Cycle(context.Background())
	if rep.Host.Err != nil || rep.Host.Admitted == 0 {
		t.Fatalf("recovery cycle: %+v", rep.Host)
	}
	losses := f.ofKind(model.Loss)
	if len(losses) != 1 {
		t.Fatalf("loss records %d, want exactly 1", len(losses))
	}
	l := losses[0].Payload.Loss
	if l.Signal != model.Metric || l.Reason != "transport" || int(l.Count) != lostSamples || l.End < l.Start {
		t.Fatalf("loss %+v, want %d lost samples", l, lostSamples)
	}
	// reported once, not on every later cycle
	a.Cycle(context.Background())
	if n := len(f.ofKind(model.Loss)); n != 1 {
		t.Fatalf("loss repeated: %d", n)
	}
}
