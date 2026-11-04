// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	bolt "go.etcd.io/bbolt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
	"strings"
	"time"
)

type childAddress struct {
	URL         string               `json:"url"`
	Certificate string               `json:"certificate"`
	Failure     *childStartupFailure `json:"failure,omitempty"`
}
type childStartupFailure struct {
	Stage string `json:"stage"`
	Code  string `json:"code"`
}

func runDurableChild(args []string) (result error) {
	stage := "child_flags"
	defer func() {
		if result != nil {
			_ = json.NewEncoder(os.Stdout).Encode(childAddress{Failure: &childStartupFailure{Stage: stage, Code: classifySmokeError(result)}})
		}
	}()
	f := flag.NewFlagSet("durable-child", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	dir := f.String("data-dir", "", "")
	if e := f.Parse(args); e != nil {
		return e
	}
	stage = "child_appcore_open"
	app, e := appcore.Open(*dir)
	if e != nil {
		return e
	}
	defer app.Close()
	stage = "child_https_start"
	server := httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, app.Register).Handler)
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go app.RunFences(ctx)
	stage = "child_startup_metadata"
	if e = json.NewEncoder(os.Stdout).Encode(childAddress{URL: server.URL, Certificate: base64.RawStdEncoding.EncodeToString(server.Certificate().Raw)}); e != nil {
		return e
	}
	select {}
}

type smokeChild struct {
	cmd     *exec.Cmd
	client  *http.Client
	address childAddress
}

func startDurableChild(dir string) (child *smokeChild, result error) {
	stage := "child_executable"
	defer func() { result = annotateSmokeFailure("drill", stage, model.ID{}, result) }()
	exe, e := os.Executable()
	if e != nil {
		return nil, e
	}
	cmd := exec.Command(exe, "durable-child", "--data-dir", dir)
	stage = "child_stdout_pipe"
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		return nil, e
	}
	cmd.Stderr = io.Discard
	stage = "child_process_start"
	if e = cmd.Start(); e != nil {
		return nil, e
	}
	fail := func(err error) (*smokeChild, error) { cmd.Process.Kill(); cmd.Wait(); return nil, err }
	type startupRead struct {
		line []byte
		err  error
	}
	line := make(chan startupRead, 1)
	go func() { b, e := bufio.NewReader(stdout).ReadBytes('\n'); line <- startupRead{line: b, err: e} }()
	var address childAddress
	stage = "child_startup_line"
	select {
	case read := <-line:
		if read.err != nil && len(read.line) == 0 {
			return fail(read.err)
		}
		if json.Unmarshal(read.line, &address) != nil {
			return fail(&smokeFailure{Stage: stage, Code: "decode"})
		}
		if address.Failure != nil {
			return fail(&smokeFailure{Stage: address.Failure.Stage, Code: address.Failure.Code})
		}
	case <-time.After(30 * time.Second):
		return fail(&smokeFailure{Stage: stage, Code: "timeout"})
	}
	stage = "child_certificate_decode"
	der, e := base64.RawStdEncoding.DecodeString(address.Certificate)
	if e != nil {
		return fail(e)
	}
	stage = "child_certificate_parse"
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		return fail(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}, Jar: jar, Timeout: 15 * time.Second}
	return &smokeChild{cmd: cmd, client: client, address: address}, nil
}
func (c *smokeChild) kill() error {
	if c == nil || c.cmd == nil || c.cmd.Process == nil {
		return nil
	}
	e := c.cmd.Process.Kill()
	c.cmd.Wait()
	c.cmd.Process = nil
	return e
}
func (c *smokeChild) call(path string, v any, csrf, source string) (int, []byte, error) {
	raw, e := json.Marshal(v)
	if e != nil {
		return 0, nil, e
	}
	r, e := http.NewRequest("POST", c.address.URL+path, bytes.NewReader(raw))
	if e != nil {
		return 0, nil, e
	}
	r.Header.Set("Content-Type", "application/json")
	client := c.client
	if source != "" {
		r.Header.Set("Authorization", "Bearer "+source)
		copyClient := *client
		copyClient.Jar = nil
		client = &copyClient
	} else {
		r.Header.Set("Origin", c.address.URL)
		r.Header.Set("X-CSRF-Token", csrf)
	}
	resp, e := client.Do(r)
	if e != nil {
		return 0, nil, e
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, e
}

// Organization discovery is an instance selector. It has no organization ID;
// supplying a zero ID would fail C01 marshaling before an HTTP request exists.
func (c *smokeChild) organizationsRead(csrf string) (int, []byte, error) {
	request := struct {
		Kind string `json:"kind"`
	}{Kind: "organizations"}
	return c.call("/api/v1/admin/read", request, csrf, "")
}
func runDurable(args []string, name string) (result error) {
	stage := "drill_flags"
	defer func() { result = annotateSmokeFailure("drill", stage, model.ID{}, result) }()
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	artifact := f.String("artifact-dir", "", "sanitized artifacts")
	if e := f.Parse(args); e != nil {
		return e
	}
	if *artifact == "" {
		return errors.New("artifact directory required")
	}
	stage = "drill_artifact_directory"
	if e := os.MkdirAll(*artifact, 0700); e != nil {
		return e
	}
	stage = "drill_fixture_directory"
	dir, e := os.MkdirTemp("", "soundpost-durable-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(dir)
	stage = "drill_child_start"
	child, e := startDurableChild(dir)
	if e != nil {
		return e
	}
	defer func() { child.kill() }()
	stage = "drill_bootstrap_token"
	bootstrap, e := os.ReadFile(filepath.Join(dir, "bootstrap.token"))
	if e != nil {
		return e
	}
	stage = "drill_bootstrap_http"
	status, raw, e := child.call("/api/v1/bootstrap", map[string]string{"Token": string(bootstrap), "Email": "durable@example.test", "Password": "durable smoke password 2026"}, "", "")
	if e = requireSmokeResponse("bootstrap", status, 200, raw, e); e != nil {
		return e
	}
	stage = "drill_bootstrap_session_decode"
	var session auth.Session
	if e = json.Unmarshal(raw, &session); e != nil {
		return e
	}
	org, project, source := model.NewID(), model.NewID(), model.NewID()
	admin := func(kind string, p auth.AdminPayload) error {
		stage = "drill_admin_" + kind + "_revision_read"
		status, raw, e := child.organizationsRead(session.CSRF)
		if e = requireSmokeResponse("admin_"+kind+"_revision_read", status, 200, raw, e); e != nil {
			return e
		}
		stage = "drill_admin_" + kind + "_view_decode"
		var view auth.AdminView
		if e = json.Unmarshal(raw, &view); e != nil {
			return e
		}
		p.Reason = "durability smoke"
		payload, _ := json.Marshal(p)
		stage = "drill_admin_" + kind + "_command"
		status, raw, e = child.call("/api/v1/admin/commands", auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: view.Revision, OrgID: org, Kind: kind, Payload: payload}, session.CSRF, "")
		if e = requireSmokeResponse("admin_"+kind+"_command", status, 200, raw, e); e != nil {
			return e
		}
		return nil
	}
	if e = admin("create_org", auth.AdminPayload{Name: "generic"}); e != nil {
		return e
	}
	if e = admin("create_project", auth.AdminPayload{ID: project, Name: "generic"}); e != nil {
		return e
	}
	var approved model.Scalar
	json.Unmarshal([]byte(`503`), &approved)
	serviceID, environmentID, buildID := model.NewID(), model.NewID(), model.NewID()
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric, model.Log, model.ErrorKind}, Resources: model.ResourceRegistry{Services: []model.ID{serviceID}, Environments: []model.ID{environmentID}, Builds: []model.ID{buildID}, Instances: []string{"instance"}}, Templates: []model.LogTemplate{{ID: "failed", Revision: 1, Line: "operation failed: {status}", Severity: "error", Fields: []model.TemplateField{{Name: "status", Type: "int64", MaxBytes: 16, Sensitivity: "metadata", Values: []model.Scalar{approved}}}}}, RetentionDays: map[model.Kind]uint32{model.Metric: 30, model.Log: 14, model.ErrorKind: 30}, MaxBytes: 1 << 30, MaxSeries: 1000}
	stage = "drill_source_onboard"
	status, raw, e = child.call("/api/v1/sources", auth.SourceOnboarding{CommandID: model.NewID(), Org: org, Project: project, Source: source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "durability smoke"}, session.CSRF, "")
	if e = requireSmokeResponse("source_onboard", status, 200, raw, e); e != nil {
		return e
	}
	stage = "drill_source_descriptor_decode"
	var issued auth.SourceOnboarded
	if e = json.Unmarshal(raw, &issued); e != nil {
		return e
	}
	resource := model.Resource{Service: serviceID, Environment: environmentID, Build: buildID, Instance: "instance", Labels: model.Labels{}}
	histogram := &model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Schema: 0, ZeroThreshold: model.FloatBits(0), Sum: model.FloatBits(0), Count: 9007199254740993, ZeroCount: 9007199254740993, ResetHint: "unknown"}}
	b := model.Batch{Version: 1, Project: project, Source: source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: 9007199254740993, Resource: resource, Payload: model.Payload{Metric: &model.MetricPoint{Name: "request_count", Labels: model.Labels{}, SampleKind: "integer_histogram", Histogram: histogram, Unit: "1", Type: "histogram"}}}}}
	b.RouteSlot, _ = model.OwnerSlot(org, project, source, b.Producer, b.Records[0])
	stage = "drill_first_append"
	status, raw, e = child.call("/ingest/v1/batches", b, "", issued.Credential)
	if e = requireSmokeResponse("first_append", status, 200, raw, e); e != nil {
		return e
	}
	stage = "drill_first_receipt_decode"
	var original model.Receipt
	if e = json.Unmarshal(raw, &original); e != nil {
		return e
	}
	// An observed HTTP ACK precedes an unconditional real child process kill.
	stage = "drill_post_ack_kill"
	if e = child.kill(); e != nil {
		return e
	}
	stage = "drill_child_restart"
	child, e = startDurableChild(dir)
	if e != nil {
		return e
	}
	stage = "drill_retry_append"
	status, raw, e = child.call("/ingest/v1/batches", b, "", issued.Credential)
	if e = requireSmokeResponse("retry_append", status, 200, raw, e); e != nil {
		return e
	}
	stage = "drill_retry_receipt_decode"
	var retry model.Receipt
	if e = json.Unmarshal(raw, &retry); e != nil {
		return e
	}
	stage = "drill_retry_receipt_compare"
	before, _ := model.CanonicalJSON(original)
	after, _ := model.CanonicalJSON(retry)
	if !bytes.Equal(before, after) {
		return errors.New("original receipt changed")
	}
	q := model.ReceiptRequest{Source: source, Producer: b.Producer, RouteSlot: b.RouteSlot, BatchID: b.ID, OriginalHash: original.Hash}
	stage = "drill_historical_lookup"
	status, raw, e = child.call("/ingest/v1/receipts", q, "", issued.Credential)
	if e = requireSmokeResponse("historical_lookup", status, 200, raw, e); e != nil {
		return e
	}
	stage = "drill_historical_decode"
	var historical model.Receipt
	if e = json.Unmarshal(raw, &historical); e != nil {
		return e
	}
	if !historical.Historical {
		return &smokeFailure{Stage: stage, Code: "historical_marker"}
	}
	stage = "drill_historical_receipt_compare"
	historical.Historical = false
	after, _ = model.CanonicalJSON(historical)
	if !bytes.Equal(before, after) {
		return errors.New("historical receipt changed")
	}
	b.Records[0].Payload.Metric.Histogram.Integer.Count++
	b.Records[0].Payload.Metric.Histogram.Integer.ZeroCount++
	stage = "drill_conflicting_retry"
	status, raw, e = child.call("/ingest/v1/batches", b, "", issued.Credential)
	if e = requireSmokeResponse("conflicting_retry", status, 409, raw, e); e != nil {
		return e
	}
	const canary = "SOUNDPOST_FORBIDDEN_BODY_CANARY_2026"
	var forbidden model.Scalar
	json.Unmarshal([]byte(`"`+canary+`"`), &forbidden)
	logBatch := model.Batch{Version: 1, Project: project, Source: source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Log, ObservedAt: 1, Resource: resource, Payload: model.Payload{Log: &model.LogRecord{TemplateID: "failed", TemplateRevision: 1, Fields: map[string]model.Scalar{"status": approved, "body": forbidden}, Line: canary, StreamLabels: model.Labels{}, Metadata: map[string]model.Scalar{"body": forbidden}, SourceClass: "structured"}}}}}
	logBatch.RouteSlot, _ = model.OwnerSlot(org, project, source, logBatch.Producer, logBatch.Records[0])
	stage = "drill_safe_log_append"
	status, raw, e = child.call("/ingest/v1/batches", logBatch, "", issued.Credential)
	if e = requireSmokeResponse("safe_log_append", status, 200, raw, e); e != nil {
		return e
	}
	if bytes.Contains(raw, []byte(canary)) {
		return &smokeFailure{Stage: stage, Code: "content_leak"}
	}
	logBatch.ID = model.NewID()
	logBatch.Records[0].Payload.Log.TemplateID = canary
	stage = "drill_unknown_template"
	status, raw, e = child.call("/ingest/v1/batches", logBatch, "", issued.Credential)
	if e = requireSmokeResponse("unknown_template", status, 422, raw, e); e != nil {
		return e
	}
	if bytes.Contains(raw, []byte(canary)) {
		return &smokeFailure{Stage: stage, Code: "content_leak"}
	}
	stage = "drill_atomic_privacy"
	if e = checkAtomicPrivacy(child, issued.Credential, org, resource, logBatch, canary); e != nil {
		return e
	}
	stage = "drill_final_child_kill"
	if e = child.kill(); e != nil {
		return e
	}
	exact, safeLine := false, false
	logicalRecords := 0
	stage = "drill_data_open"
	db, e := bolt.Open(filepath.Join(dir, "data", "apply.db"), 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if e != nil {
		return e
	}
	stage = "drill_data_read"
	e = db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("batches")).ForEach(func(_, raw []byte) error {
			var records []model.Record
			if json.Unmarshal(raw, &records) != nil {
				return errors.New("typed records unavailable")
			}
			logicalRecords += len(records)
			for _, r := range records {
				if r.Kind == model.Metric {
					exact = r.Payload.Metric.Histogram.Integer.Count == 9007199254740993 && r.ObservedAt == 9007199254740993
				}
				if r.Kind == model.Log {
					safeLine = r.Payload.Log.Line == "operation failed: 503" && len(r.Payload.Log.Fields) == 1 && len(r.Payload.Log.Metadata) == 0
				}
			}
			return nil
		})
	})
	db.Close()
	stage = "drill_data_assert"
	if e != nil {
		return e
	}
	if !exact {
		return &smokeFailure{Stage: stage, Code: "exact_value"}
	}
	if !safeLine {
		return &smokeFailure{Stage: stage, Code: "immutable_line"}
	}
	if logicalRecords != 2 {
		return &smokeFailure{Stage: stage, Code: "record_count"}
	}
	stage = "drill_control_reopen"
	authority, e := control.Open(dir)
	if e != nil {
		return e
	}
	stage = "drill_consumption_read"
	e = authority.View(context.Background(), func(st control.State) error {
		if len(st.Reservations) != 2 {
			return errors.New("rejected batch reserved quota")
		}
		for _, reservation := range st.Reservations {
			if reservation.State != "consumed" || reservation.Cursor == nil {
				return errors.New("durable consumption missing")
			}
		}
		return nil
	})
	authority.Close()
	if e != nil {
		return e
	}
	stage = "drill_canary_scan"
	if e = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if bytes.Contains(b, []byte(canary)) {
			return errors.New("privacy canary persisted")
		}
		return nil
	}); e != nil {
		return e
	}
	stage = "drill_artifact_encode"
	artifactJSON, _ := json.MarshalIndent(map[string]any{"version": 1, "observed_http_ack": true, "force_kill_restart": true, "original_receipt": true, "historical_receipt": true, "conflicting_retry_status": 409, "integer_count": "9007199254740993", "timestamp_ns": "9007199254740993", "immutable_line": true, "privacy_canary_absent": true, "forbidden_fields_rejected": true, "mixed_slot_rejected": true, "gzip_expansion_rejected": true, "atomic_zero_admission": true, "durable_reservations": 2, "retained_records": logicalRecords, "mode": "single-non-HA", "qualification": "process-crash-only-not-power-loss"}, "", "  ")
	stage = "drill_artifact_write"
	return os.WriteFile(filepath.Join(*artifact, strings.TrimSpace(name)+".json"), artifactJSON, 0600)
}
