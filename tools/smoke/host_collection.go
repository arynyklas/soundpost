// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"soundpost/internal/agent"
	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
	"soundpost/internal/sources"
	"soundpost/internal/storage"
)

// The host-collection smoke starts a real node (control Raft, auth, C03
// admission, C05 storage behind the real HTTPS ingest route), runs the REAL
// agent logic against it on this host, produces real CPU load, a real
// filesystem change, real child processes and controlled registered events,
// and asserts what the node STORED: observed deltas, exact template lines, no
// unregistered content anywhere, and explicit capability states for a
// policy-denied group and a permission-denied source. Rows that cannot run
// here are listed with their reason in the report, never skipped silently.

const (
	hcBodyCanary    = "operator typed password=hunter2-BODY-CANARY"
	hcJournalCanary = "operator typed token=JOURNAL-CANARY-4711"
	hcSyslogCanary  = "Failed password for root SYSLOG-CANARY"
)

type hcReport struct {
	Smoke    string                       `json:"smoke"`
	RunID    string                       `json:"run_id"`
	OS       string                       `json:"os"`
	Arch     string                       `json:"arch"`
	Observed map[string]float64           `json:"observed"`
	Rows     map[string]string            `json:"rows"`
	NotRun   map[string]string            `json:"not_run"`
	Counters map[string]map[string]uint64 `json:"checkpoint_counters"`
}

func hcFail(stage string, actual, expected int) error {
	return &smokeFailure{Smoke: "host_collection", Stage: stage, Code: "assertion", Actual: actual, Expected: expected}
}

// hcAckLoss wraps the real ingest handler. When armed it forwards the next log
// batch to the real handler (so it is durably admitted) and then drops the
// connection without answering: the agent never sees the receipt.
type hcAckLoss struct {
	inner   http.Handler
	armed   atomic.Bool
	dropped atomic.Int64
}

func (h *hcAckLoss) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ingest/v1/batches" || !h.armed.Load() {
		h.inner.ServeHTTP(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		h.inner.ServeHTTP(w, r)
		return
	}
	var probe struct {
		Records []struct {
			Kind string `json:"kind"`
		} `json:"records"`
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if json.Unmarshal(body, &probe) != nil || len(probe.Records) == 0 || probe.Records[0].Kind != "log" || !h.armed.CompareAndSwap(true, false) {
		h.inner.ServeHTTP(w, r)
		return
	}
	rec := httptest.NewRecorder()
	h.inner.ServeHTTP(rec, r) // admitted for real
	if rec.Code != 200 {
		h.dropped.Store(-1)
	} else {
		h.dropped.Add(1)
	}
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			conn.Close()
		}
	}
}

type hcNode struct {
	app      *appcore.App
	server   *httptest.Server
	loss     *hcAckLoss
	org      model.ID
	project  model.ID
	source   model.ID
	cred     string
	resource model.Resource
	session  auth.Session
	token    string
}

func hcTemplates() []model.LogTemplate {
	scalar := func(lit string) model.Scalar {
		var s model.Scalar
		if err := s.UnmarshalJSON([]byte(lit)); err != nil {
			panic(err)
		}
		return s
	}
	return []model.LogTemplate{
		{ID: "service.started", Revision: 1, Line: "service started unit {unit}", Severity: "info", Fields: []model.TemplateField{
			{Name: "unit", Type: "string", MaxBytes: 16, Sensitivity: "metadata", Values: []model.Scalar{scalar(`"alpha"`), scalar(`"beta"`), scalar(`"gamma"`)}},
		}},
		{ID: "request.status", Revision: 1, Line: "request status {status}", Severity: "warn", Fields: []model.TemplateField{
			{Name: "status", Type: "int64", MaxBytes: 8, Sensitivity: "metadata", Values: []model.Scalar{scalar(`200`), scalar(`503`)}},
		}},
		{ID: "smoke.event", Revision: 1, Line: "soundpost smoke event {event}", Severity: "info", Fields: []model.TemplateField{
			{Name: "event", Type: "string", MaxBytes: 16, Sensitivity: "metadata", Values: []model.Scalar{scalar(`"ready"`), scalar(`"degraded"`), scalar(`"recovered"`)}},
		}},
	}
}

func hcStartNode(work string) (*hcNode, error) {
	app, err := appcore.Open(filepath.Join(work, "node"))
	if err != nil {
		return nil, err
	}
	n := &hcNode{app: app, org: model.NewID(), project: model.NewID(), source: model.NewID()}
	n.loss = &hcAckLoss{inner: httpapi.NewServer("", app.Auth, nil, app.Register).Handler}
	n.server = httptest.NewTLSServer(n.loss)
	client := n.server.Client()
	client.Jar, _ = cookiejar.New(nil)
	child := &smokeChild{client: client, address: childAddress{URL: n.server.URL}}
	boot, err := app.Control.BootstrapToken()
	if err != nil {
		return nil, err
	}
	status, raw, err := child.call("/api/v1/bootstrap", map[string]string{"Token": boot, "Email": "host-collection@example.test", "Password": "host collection smoke password 2026"}, "", "")
	if err = requireSmokeResponse("hc_bootstrap", status, 200, raw, err); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &n.session); err != nil {
		return nil, err
	}
	u, err := url.Parse(n.server.URL)
	if err != nil {
		return nil, err
	}
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == "__Host-soundpost" {
			n.token = c.Value
		}
	}
	if n.token == "" {
		return nil, errors.New("session cookie missing")
	}
	admin := func(kind string, p auth.AdminPayload) error {
		status, raw, err := child.organizationsRead(n.session.CSRF)
		if err = requireSmokeResponse("hc_admin_revision", status, 200, raw, err); err != nil {
			return err
		}
		var view auth.AdminView
		if err = json.Unmarshal(raw, &view); err != nil {
			return err
		}
		p.Reason = "host collection smoke"
		payload, err := json.Marshal(p)
		if err != nil {
			return err
		}
		status, raw, err = child.call("/api/v1/admin/commands", auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: view.Revision, OrgID: n.org, Kind: kind, Payload: payload}, n.session.CSRF, "")
		return requireSmokeResponse("hc_admin_"+kind, status, 200, raw, err)
	}
	if err = admin("create_org", auth.AdminPayload{Name: "host-collection"}); err != nil {
		return nil, err
	}
	if err = admin("create_project", auth.AdminPayload{ID: n.project, Name: "host-collection"}); err != nil {
		return nil, err
	}
	if err = admin("membership", auth.AdminPayload{UserID: n.session.User, Enabled: true}); err != nil {
		return nil, err
	}
	if err = admin("grant", auth.AdminPayload{UserID: n.session.User, ProjectID: n.project, Enabled: true, Permissions: []string{string(auth.Read)}}); err != nil {
		return nil, err
	}
	n.resource = model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "smoke-host", Labels: model.Labels{}}
	pol := model.SourcePolicy{
		Revision: 1, Enabled: true, Class: "structured",
		Kinds:     []model.Kind{model.Metric, model.Log, model.CapabilityKind, model.Loss},
		Templates: hcTemplates(),
		Resources: model.ResourceRegistry{Services: []model.ID{n.resource.Service}, Environments: []model.ID{n.resource.Environment}, Builds: []model.ID{n.resource.Build}, Instances: []string{n.resource.Instance}},
		Labels: map[string][]string{
			"source": {"app", "syslog", "journal", "denied"},
			"mode":   {"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"},
			"state":  {"total", "available", "free", "buffers", "cached", "swap_total", "swap_free", "size", "current", "limit", "swap_current"},
			"window": {"1m", "5m", "15m"},
			"mount":  {"data"},
		},
		RetentionDays: map[model.Kind]uint32{model.Metric: 7, model.Log: 7, model.CapabilityKind: 7, model.Loss: 7}, MaxBytes: 1 << 30, MaxSeries: 10000,
	}
	status, raw, err = child.call("/api/v1/sources", auth.SourceOnboarding{CommandID: model.NewID(), Org: n.org, Project: n.project, Source: n.source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: pol, Reason: "host collection smoke"}, n.session.CSRF, "")
	if err = requireSmokeResponse("hc_onboard", status, 200, raw, err); err != nil {
		return nil, err
	}
	var issued auth.SourceOnboarded
	if err = json.Unmarshal(raw, &issued); err != nil {
		return nil, err
	}
	n.cred = issued.Credential
	return n, nil
}

func (n *hcNode) close() {
	if n.server != nil {
		n.server.Close()
	}
	if n.app != nil {
		n.app.Close()
	}
}

// hcStored is one stored row.
type hcStored struct {
	at      model.UnixNano
	origin  model.ID
	payload model.Payload
	project model.ID
}

func (n *hcNode) scan(kind model.Kind) ([]hcStored, error) {
	ctx := context.Background()
	cred, err := n.app.Auth.Authenticate(ctx, n.token)
	if err != nil {
		return nil, err
	}
	scope, err := n.app.Auth.Authorize(ctx, cred, n.org, []model.ID{n.project}, auth.Read)
	if err != nil {
		return nil, err
	}
	it, err := n.app.Storage.Scan(ctx, scope, storage.ScanRequest{Projects: []model.ID{n.project}, Signal: kind, Start: math.MinInt64, End: math.MaxInt64})
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []hcStored
	for {
		page, err := it.Next(ctx)
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		for i := range page.Len() {
			out = append(out, hcStored{at: page.ObservedTimes[i], payload: page.Values[i], project: page.Projects[i]})
		}
	}
}

func hcFloat(m *model.MetricPoint) float64 { return math.Float64frombits(uint64(*m.Value)) }

// hcSeries returns the stored samples of a metric as observed-time -> labels -> value.
func hcSeries(rows []hcStored, name string) map[model.UnixNano]map[string]float64 {
	out := map[model.UnixNano]map[string]float64{}
	for _, r := range rows {
		m := r.payload.Metric
		if m == nil || m.Name != name {
			continue
		}
		var parts []string
		for _, l := range m.Labels {
			parts = append(parts, l.Name+"="+l.Value)
		}
		if out[r.at] == nil {
			out[r.at] = map[string]float64{}
		}
		out[r.at][strings.Join(parts, ",")] = hcFloat(m)
	}
	return out
}

func hcTimes(s map[model.UnixNano]map[string]float64) []model.UnixNano {
	var ts []model.UnixNano
	for t := range s {
		ts = append(ts, t)
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	return ts
}

func hcBurn(d time.Duration) {
	end := time.Now().Add(d)
	var wg sync.WaitGroup
	for range runtime.NumCPU() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			x := 1
			for time.Now().Before(end) {
				for range 20000 {
					x = x*3 + 1
				}
			}
			if x == 42 {
				fmt.Fprint(io.Discard, x)
			}
		}()
	}
	wg.Wait()
}

func hcWriteFile(path string, size int) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	chunk := make([]byte, 1<<20)
	if _, err := rand.Read(chunk); err != nil {
		f.Close()
		return err
	}
	for written := 0; written < size; written += len(chunk) {
		if _, err := f.Write(chunk); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func hcAppend(path string, lines ...string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := fmt.Fprintln(f, l); err != nil {
			return err
		}
	}
	return nil
}

// hcJournal says whether the real systemd journal can be used here and why not.
func hcJournal(ident string) (usable bool, reason string) {
	journalctl, err := exec.LookPath("journalctl")
	if err != nil {
		return false, "journalctl is not installed"
	}
	if _, err := exec.LookPath("logger"); err != nil {
		return false, "logger is not installed"
	}
	cmd := exec.Command(journalctl, "--no-pager", "--quiet", "--lines=1", "--output=json", "SYSLOG_IDENTIFIER="+ident)
	cmd.Env = []string{"LC_ALL=C"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return false, "journalctl exited with an error"
	}
	if s := strings.ToLower(stderr.String()); strings.Contains(s, "insufficient permissions") || strings.Contains(s, "not seeing messages") {
		return false, "journalctl reports insufficient permissions (not root, not in the adm/systemd-journal groups)"
	}
	return true, ""
}

func hcLogger(ident, message string) error {
	return exec.Command("logger", "-t", ident, "-p", "user.info", "--", message).Run()
}

// hcWaitJournal waits until the journal shows n entries for the identifier.
func hcWaitJournal(ident string, n int) bool {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		cmd := exec.Command("journalctl", "--no-pager", "--quiet", "--output=cat", "SYSLOG_IDENTIFIER="+ident)
		cmd.Env = []string{"LC_ALL=C"}
		out, _ := cmd.Output()
		if len(bytes.Split(bytes.TrimSpace(out), []byte("\n"))) >= n && len(bytes.TrimSpace(out)) > 0 {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// RunHostCollection is `host-collection`.
func RunHostCollection(args []string) (result error) {
	stage := "hc_flags"
	defer func() { result = annotateSmokeFailure("host_collection", stage, model.ID{}, result) }()
	flags := flag.NewFlagSet("host-collection", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	artifact := flags.String("artifact-dir", "", "sanitized artifact directory")
	binary := flags.String("agent-binary", "", "optional compiled soundpost-agent to run once as a separate process")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *artifact == "" {
		return errors.New("artifact directory required")
	}
	if err := os.MkdirAll(*artifact, 0700); err != nil {
		return err
	}
	runID := model.NewID()
	report := hcReport{Smoke: "host_collection", RunID: runID.String(), OS: runtime.GOOS, Arch: runtime.GOARCH,
		Observed: map[string]float64{}, Rows: map[string]string{}, NotRun: map[string]string{}, Counters: map[string]map[string]uint64{}}

	stage = "hc_workdir"
	work, err := os.MkdirTemp("", "soundpost-host-collection-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	stage = "hc_node"
	node, err := hcStartNode(work)
	if err != nil {
		return err
	}
	defer node.close()

	// ---- sources: file, syslog file, real journal, a denied file
	dataDir := filepath.Join(work, "data")
	srcDir := filepath.Join(work, "logs")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(srcDir, 0700); err != nil {
		return err
	}
	appLog := filepath.Join(srcDir, "app.log")
	if err := hcAppend(appLog, "service started unit alpha", hcBodyCanary, "request status 503"); err != nil {
		return err
	}
	syslogFile := filepath.Join(srcDir, "syslog")
	stamp := time.Now().Format("Jan _2 15:04:05")
	if err := hcAppend(syslogFile,
		stamp+" smoke-host soundpostsmoke[100]: service started unit beta",
		stamp+" smoke-host soundpostsmoke[100]: "+hcSyslogCanary,
		stamp+" smoke-host sshd[200]: service started unit alpha"); err != nil {
		return err
	}
	deniedLog := filepath.Join(srcDir, "denied.log")
	if err := hcAppend(deniedLog, "service started unit alpha"); err != nil {
		return err
	}
	deniable := runtime.GOOS != "windows" && os.Geteuid() != 0
	if deniable {
		if err := os.Chmod(deniedLog, 0); err != nil {
			return err
		}
	} else {
		report.NotRun["denied_source_by_os_permission"] = "running as root or on Windows: chmod 000 does not deny the reader; only the policy-denied group row is asserted"
	}
	ident := "soundpost-smoke-" + hex.EncodeToString(runID[:4])
	journalOK, journalWhy := hcJournal(ident)
	if journalOK {
		if err := hcLogger(ident, "soundpost smoke event ready"); err != nil {
			journalOK, journalWhy = false, "logger could not write to the journal"
		} else if err := hcLogger(ident, hcJournalCanary); err != nil {
			journalOK, journalWhy = false, "logger could not write to the journal"
		} else if !hcWaitJournal(ident, 2) {
			journalOK, journalWhy = false, "journal entries did not become readable in time"
		}
	}
	if !journalOK {
		report.NotRun["journal"] = journalWhy
	}

	labels := func(v string) model.Labels { return model.Labels{{Name: "source", Value: v}} }
	logs := []agent.LogConfig{
		{SourcePolicy: sources.SourcePolicy{Name: "app", Kind: sources.KindFile, Class: sources.ClassStructured, Labels: labels("app"), Templates: hcTemplates(), File: &sources.FileSpec{Path: appLog, StartAt: sources.StartBeginning}}},
		{SourcePolicy: sources.SourcePolicy{Name: "syslog", Kind: sources.KindSyslog, Class: sources.ClassStructured, Labels: labels("syslog"), Templates: hcTemplates(), Syslog: &sources.SyslogSpec{Path: syslogFile, Tags: []string{"soundpostsmoke"}, StartAt: sources.StartBeginning}}},
	}
	if journalOK {
		logs = append(logs, agent.LogConfig{SourcePolicy: sources.SourcePolicy{Name: "journal", Kind: sources.KindJournal, Class: sources.ClassStructured, Labels: labels("journal"), Templates: hcTemplates(), Journal: &sources.JournalSpec{Identifiers: []string{ident}, StartAt: sources.StartBeginning}}})
	}
	if deniable {
		logs = append(logs, agent.LogConfig{SourcePolicy: sources.SourcePolicy{Name: "denied", Kind: sources.KindFile, Class: sources.ClassStructured, Labels: labels("denied"), Templates: hcTemplates(), File: &sources.FileSpec{Path: deniedLog, StartAt: sources.StartBeginning}}})
	}

	// ---- agent configuration (credential and CA are in the private work dir)
	stage = "hc_config"
	secrets := filepath.Join(work, "secrets")
	if err := os.MkdirAll(secrets, 0700); err != nil {
		return err
	}
	credFile := filepath.Join(secrets, "credential")
	if err := os.WriteFile(credFile, []byte(node.cred+"\n"), 0600); err != nil {
		return err
	}
	caFile := filepath.Join(secrets, "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: node.server.Certificate().Raw}), 0600); err != nil {
		return err
	}
	cfg := agent.Config{
		Version: 1, Server: node.server.URL, CAFile: caFile, CredentialFile: credFile, StateDir: filepath.Join(work, "agent-state"),
		Org: node.org.String(), Project: node.project.String(), Source: node.source.String(), PolicyRevision: 1,
		Resource: agent.ResourceConfig{ServiceID: node.resource.Service.String(), EnvironmentID: node.resource.Environment.String(), BuildID: node.resource.Build.String(), Instance: node.resource.Instance},
		Host: &agent.HostConfig{Interval: agent.Duration(time.Second), Allow: []string{"cpu", "memory", "load", "filesystem", "process_count"},
			Filesystems: []agent.FilesystemConfig{{Alias: "data", Path: dataDir}}},
		Logs: logs,
	}
	var agentLog bytes.Buffer
	a, err := agent.New(cfg, slog.New(slog.NewJSONHandler(&agentLog, nil)))
	if err != nil {
		return err
	}
	ctx := context.Background()

	// ---- cycle A: baseline
	stage = "hc_cycle_a"
	repA := a.Cycle(ctx)
	if repA.Host.Err != nil || repA.Host.Admitted == 0 {
		return hcFail("hc_cycle_a_host", repA.Host.Admitted, 1)
	}
	time.Sleep(300 * time.Millisecond)

	// ---- real work between the cycles
	stage = "hc_workload"
	started := time.Now()
	hcBurn(700 * time.Millisecond)
	if err := hcWriteFile(filepath.Join(dataDir, "ballast.bin"), 32<<20); err != nil {
		return err
	}
	var children []*exec.Cmd
	processesRun := runtime.GOOS != "windows"
	if processesRun {
		for range 40 {
			c := exec.Command("sleep", "120")
			if err := c.Start(); err != nil {
				processesRun = false
				report.NotRun["process_count_delta"] = "sleep could not be started"
				break
			}
			children = append(children, c)
		}
	} else {
		report.NotRun["process_count_delta"] = "child processes are started with sleep(1), which this OS does not have"
	}
	defer func() {
		for _, c := range children {
			c.Process.Kill()
			c.Wait()
		}
	}()
	if err := hcAppend(appLog, "service started unit beta", "request status 200"); err != nil {
		return err
	}
	if err := hcAppend(syslogFile, stamp+" smoke-host soundpostsmoke[100]: request status 503"); err != nil {
		return err
	}
	if journalOK {
		if err := hcLogger(ident, "soundpost smoke event degraded"); err != nil {
			return err
		}
		hcWaitJournal(ident, 3)
	}
	elapsed := time.Since(started)

	// ---- cycle B: the response to the first log batch is lost (it is durably
	// admitted, the agent never sees the receipt)
	stage = "hc_cycle_b_ack_loss"
	node.loss.armed.Store(true)
	repB := a.Cycle(ctx)
	if node.loss.dropped.Load() != 1 {
		return hcFail("hc_ack_loss_drill_armed", int(node.loss.dropped.Load()), 1)
	}
	lostAck := 0
	for _, s := range repB.Sources {
		if s.Err != nil && s.Name != "denied" {
			lostAck++
		}
	}
	if lostAck != 1 {
		return hcFail("hc_ack_loss_surfaced", lostAck, 1)
	}

	// ---- cycle C: the pending range is resubmitted unchanged
	stage = "hc_cycle_c"
	if err := hcAppend(appLog, "service started unit gamma"); err != nil {
		return err
	}
	repC := a.Cycle(ctx)
	for _, s := range repC.Sources {
		if s.Err != nil && s.Name != "denied" {
			return hcFail("hc_cycle_c_source_"+s.Name, 1, 0)
		}
	}
	repD := a.Cycle(ctx) // drains the line appended before cycle C
	for _, s := range repD.Sources {
		if s.Err != nil && s.Name != "denied" {
			return hcFail("hc_cycle_d_source_"+s.Name, 1, 0)
		}
	}

	// ---- assertions on what the node STORED
	stage = "hc_read_back"
	metrics, err := node.scan(model.Metric)
	if err != nil {
		return err
	}
	cpu := hcSeries(metrics, "host_cpu_seconds_total")
	ts := hcTimes(cpu)
	if len(ts) < 3 {
		return hcFail("hc_cpu_cycles_stored", len(ts), 3)
	}
	busy := func(s map[string]float64) (b, total float64) {
		for k, v := range s {
			total += v
			if k != "mode=idle" && k != "mode=iowait" {
				b += v
			}
		}
		return
	}
	busyA, totalA := busy(cpu[ts[0]])
	busyB, totalB := busy(cpu[ts[1]])
	cores := float64(runtime.NumCPU())
	report.Observed["cpu_busy_seconds_delta"] = busyB - busyA
	report.Observed["cpu_total_seconds_delta"] = totalB - totalA
	report.Observed["workload_wall_seconds"] = elapsed.Seconds()
	report.Observed["logical_cpus"] = cores
	if busyB-busyA < 0.25*0.7 { // a 700ms all-core spin: far more than this on any machine
		return hcFail("hc_cpu_load_visible", int((busyB-busyA)*1000), 175)
	}
	if totalB-totalA < 0.5*cores*elapsed.Seconds() {
		return hcFail("hc_cpu_counters_track_wall_time", int((totalB-totalA)*1000), int(0.5*cores*elapsed.Seconds()*1000))
	}
	report.Rows["cpu_load_delta"] = "asserted from stored host_cpu_seconds_total"

	fsBytes := hcSeries(metrics, "host_filesystem_bytes")
	fsT := hcTimes(fsBytes)
	if len(fsT) < 3 {
		return hcFail("hc_filesystem_cycles_stored", len(fsT), 3)
	}
	freeA, freeB := fsBytes[fsT[0]]["mount=data,state=free"], fsBytes[fsT[1]]["mount=data,state=free"]
	report.Observed["filesystem_free_bytes_delta"] = freeB - freeA
	if fsBytes[fsT[0]]["mount=data,state=size"] != fsBytes[fsT[1]]["mount=data,state=size"] || fsBytes[fsT[0]]["mount=data,state=size"] <= 0 {
		return hcFail("hc_filesystem_size_stable", 0, 1)
	}
	if freeA-freeB < 16<<20 {
		return hcFail("hc_filesystem_change_visible", int((freeA-freeB)/(1<<20)), 16)
	}
	report.Rows["filesystem_change"] = "asserted: a 32 MiB write lowered stored free bytes of alias data by at least 16 MiB"

	procs := hcSeries(metrics, "host_processes_total")
	pT := hcTimes(procs)
	if len(pT) < 2 {
		return hcFail("hc_process_cycles_stored", len(pT), 2)
	}
	if processesRun {
		delta := procs[pT[1]][""] - procs[pT[0]][""]
		report.Observed["process_count_delta"] = delta
		// 40 children are started; the bound is half of that so that processes
		// of other work on a busy host exiting meanwhile cannot fail the row
		if delta < 20 {
			return hcFail("hc_process_count_visible", int(delta), 20)
		}
		report.Rows["process_count_delta"] = "asserted: forty started children raised the stored process count by at least twenty"
	}
	mem := hcSeries(metrics, "host_memory_bytes")
	mT := hcTimes(mem)
	if len(mT) < 2 || mem[mT[0]]["state=total"] <= 0 || mem[mT[0]]["state=total"] != mem[mT[1]]["state=total"] || mem[mT[1]]["state=available"] > mem[mT[1]]["state=total"] || mem[mT[1]]["state=available"] <= 0 {
		return hcFail("hc_memory_consistent", len(mT), 2)
	}
	if runtime.GOOS == "linux" {
		la := hcSeries(metrics, "host_load_average")
		if len(la) == 0 {
			return hcFail("hc_load_average_stored", 0, 1)
		}
	}
	// no zero stands in for a missing source: cgroup was not allowed by the
	// policy, so no cgroup sample exists at all
	for _, r := range metrics {
		if strings.HasPrefix(r.payload.Metric.Name, "host_cgroup_") {
			return hcFail("hc_policy_denied_group_has_no_samples", 1, 0)
		}
	}

	// logs: exactly the registered lines, once each, per source
	logRows, err := node.scan(model.Log)
	if err != nil {
		return err
	}
	got := map[string][]string{}
	for _, r := range logRows {
		l := r.payload.Log
		var src string
		for _, lb := range l.StreamLabels {
			if lb.Name == "source" {
				src = lb.Value
			}
		}
		got[src] = append(got[src], l.TemplateID+"|"+l.Line)
	}
	for k := range got {
		sort.Strings(got[k])
	}
	want := map[string][]string{
		"app":    {"request.status|request status 200", "request.status|request status 503", "service.started|service started unit alpha", "service.started|service started unit beta", "service.started|service started unit gamma"},
		"syslog": {"request.status|request status 503", "service.started|service started unit beta"},
	}
	if journalOK {
		want["journal"] = []string{"smoke.event|soundpost smoke event degraded", "smoke.event|soundpost smoke event ready"}
	}
	for src, lines := range want {
		sort.Strings(lines)
		if strings.Join(got[src], "\n") != strings.Join(lines, "\n") {
			return hcFail("hc_logs_exact_"+src, len(got[src]), len(lines))
		}
		report.Rows["logs_"+src] = fmt.Sprintf("asserted: %d registered lines stored exactly once as typed template fields", len(lines))
	}
	if len(got) != len(want) {
		return hcFail("hc_no_other_log_source", len(got), len(want))
	}
	report.Rows["ack_loss_no_duplicate"] = "asserted: the first log batch was admitted but its receipt was dropped; its lines are stored exactly once after the retry"

	// capabilities: explicit states
	capRows, err := node.scan(model.CapabilityKind)
	if err != nil {
		return err
	}
	latest := map[string]*model.Capability{}
	latestAt := map[string]model.UnixNano{}
	for _, r := range capRows {
		c := r.payload.Capability
		if r.at >= latestAt[c.Method] {
			latest[c.Method], latestAt[c.Method] = c, r.at
		}
	}
	if c := latest["cgroup:policy"]; c == nil || c.Status != "denied" || c.Reason != "policy" {
		return hcFail("hc_policy_denied_capability", 0, 1)
	}
	report.Rows["policy_denied_capability"] = "asserted: cgroup group not allowed -> stored capability denied/policy and no samples"
	if c := latest["file_tail:app"]; c == nil || c.Status != "supported" {
		return hcFail("hc_supported_source_capability", 0, 1)
	}
	if deniable {
		c := latest["file_tail:denied"]
		if c == nil || c.Status != "denied" || c.Reason != "permission_denied" || c.Coverage.Frames != "unknown" {
			return hcFail("hc_denied_source_capability", 0, 1)
		}
		report.Rows["denied_source_capability"] = "asserted: an unreadable file source is a stored capability denied/permission_denied"
	}
	for _, want := range []string{"syslog_file:syslog"} {
		if c := latest[want]; c == nil || c.Status != "supported" {
			return hcFail("hc_capability_"+want, 0, 1)
		}
	}
	if journalOK {
		if c := latest["journalctl:journal"]; c == nil || c.Status != "supported" {
			return hcFail("hc_journal_capability", 0, 1)
		}
	}
	if lossRows, err := node.scan(model.Loss); err != nil || len(lossRows) != 0 {
		return hcFail("hc_no_false_loss", len(lossRows), 0)
	}

	// privacy: no unregistered content in anything stored, logged or checkpointed
	stage = "hc_privacy"
	var everything bytes.Buffer
	for _, kind := range []model.Kind{model.Metric, model.Log, model.CapabilityKind, model.Loss} {
		rows, err := node.scan(kind)
		if err != nil {
			return err
		}
		for _, r := range rows {
			raw, err := model.CanonicalJSON(model.Record{ID: model.NewID(), Kind: kind, ObservedAt: r.at, Resource: node.resource, Payload: r.payload})
			if err != nil {
				return err
			}
			everything.Write(raw)
		}
	}
	state := filepath.Join(work, "agent-state")
	checkpoints := ""
	entries, _ := os.ReadDir(state)
	for _, e := range entries {
		raw, _ := os.ReadFile(filepath.Join(state, e.Name()))
		checkpoints += string(raw)
		if strings.HasSuffix(e.Name(), ".checkpoint.json") {
			var cp sources.Checkpoint
			var file struct {
				Checkpoint json.RawMessage `json:"checkpoint"`
			}
			if json.Unmarshal(raw, &file) == nil && json.Unmarshal(file.Checkpoint, &cp) == nil {
				report.Counters[cp.Source] = cp.Counters
			}
		}
	}
	for place, text := range map[string]string{"node storage": everything.String(), "agent logs": agentLog.String(), "agent state": checkpoints} {
		for _, canary := range []string{"hunter2", "BODY-CANARY", "JOURNAL-CANARY", "SYSLOG-CANARY", "password", node.cred} {
			if strings.Contains(text, canary) {
				return hcFail("hc_privacy_"+strings.ReplaceAll(place, " ", "_"), 1, 0)
			}
		}
	}
	for src, wantDrops := range map[string]uint64{"app": 1, "syslog": 2} { // syslog: unknown template + unapproved tag
		if report.Counters[src][sources.DropUnknownTemplate]+report.Counters[src][sources.DropUnapprovedSource] != wantDrops {
			return hcFail("hc_unknown_counted_"+src, int(report.Counters[src][sources.DropUnknownTemplate]+report.Counters[src][sources.DropUnapprovedSource]), int(wantDrops))
		}
	}
	if journalOK && report.Counters["journal"][sources.DropUnknownTemplate] != 1 {
		return hcFail("hc_unknown_counted_journal", int(report.Counters["journal"][sources.DropUnknownTemplate]), 1)
	}
	unregistered := 2 // the file and the syslog source
	if journalOK {
		unregistered++
	}
	report.Rows["unregistered_content_absent"] = fmt.Sprintf("asserted: %d unregistered messages (file, syslog%s) appear nowhere in storage, agent logs or agent state; each was counted by reason", unregistered, map[bool]string{true: ", journal", false: ""}[journalOK])

	// ---- optional: the compiled binary as a separate process
	if *binary != "" {
		stage = "hc_binary"
		cfg2 := cfg
		cfg2.StateDir = filepath.Join(work, "agent-state-binary")
		cfg2.Logs = nil
		for _, l := range cfg.Logs {
			if l.Name != "denied" {
				cfg2.Logs = append(cfg2.Logs, l)
			}
		}
		// fresh state: the binary re-reads the sources from the beginning
		// under its own producer; only its exit status and silence are asserted
		raw, err := json.Marshal(cfg2)
		if err != nil {
			return err
		}
		cfgFile := filepath.Join(secrets, "agent.json")
		if err := os.WriteFile(cfgFile, raw, 0600); err != nil {
			return err
		}
		cmd := exec.Command(*binary, "-config", cfgFile, "-once")
		cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		cmd.Stdout = io.Discard
		err = cmd.Run()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			return err
		}
		if code != 0 {
			return hcFail("hc_binary_exit_code", code, 0)
		}
		for _, canary := range []string{"hunter2", "BODY-CANARY", "JOURNAL-CANARY", node.cred} {
			if strings.Contains(stderr.String(), canary) {
				return hcFail("hc_binary_stderr_privacy", 1, 0)
			}
		}
		report.Rows["agent_binary_once"] = "asserted: the compiled agent ran one cycle against the node in its own process and exited 0 and its stderr carries no unregistered content or credential"
	} else {
		report.NotRun["agent_binary_once"] = "no --agent-binary given: only the in-process agent logic ran"
	}

	report.Rows["host_os"] = runtime.GOOS + "/" + runtime.GOARCH
	if runtime.GOOS != "linux" {
		report.NotRun["linux_cgroup_and_load"] = "not Linux"
	}
	report.NotRun["other_operating_systems"] = "this run covers " + runtime.GOOS + " only; every other OS needs its own run, and macOS has never been run"
	stage = "hc_artifact"
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*artifact, "host-collection.json"), append(out, '\n'), 0600); err != nil {
		return err
	}
	fmt.Println("host-collection: PASS (see host-collection.json)")
	return nil
}
