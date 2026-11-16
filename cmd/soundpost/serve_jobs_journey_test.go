// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/jobs"
	"github.com/arynyklas/soundpost/internal/model"
)

// jjRelay is a TCP relay between the SDK and the served node. While it is down it
// accepts and drops every connection at once (the path to the product refuses) and
// cuts the ones in flight; while it is up it forwards bytes untouched, so the TLS
// session of the SDK still ends at the served node.
type jjRelay struct {
	ln     net.Listener
	target string

	mu    sync.Mutex
	down  bool
	conns map[net.Conn]struct{}

	refused, relayed atomic.Int64
}

func newJJRelay(t *testing.T, target string) *jjRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &jjRelay{ln: ln, target: target, conns: map[net.Conn]struct{}{}}
	go r.accept()
	t.Cleanup(func() { r.ln.Close(); r.setDown(true) })
	return r
}

func (r *jjRelay) addr() string { return r.ln.Addr().String() }

// setDown(true) refuses new connections and resets the open ones; setDown(false) restores the path.
func (r *jjRelay) setDown(down bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.down = down
	if down {
		for c := range r.conns {
			c.Close()
		}
		clear(r.conns)
	}
}

func (r *jjRelay) accept() {
	for {
		client, err := r.ln.Accept()
		if err != nil {
			return
		}
		r.mu.Lock()
		if r.down {
			r.mu.Unlock()
			r.refused.Add(1)
			client.Close()
			continue
		}
		server, err := net.DialTimeout("tcp", r.target, 5*time.Second)
		if err != nil {
			r.mu.Unlock()
			r.refused.Add(1)
			client.Close()
			continue
		}
		r.conns[client], r.conns[server] = struct{}{}, struct{}{}
		r.mu.Unlock()
		r.relayed.Add(1)
		go func() {
			var wg sync.WaitGroup
			wg.Add(2)
			pipe := func(dst, src net.Conn) {
				defer wg.Done()
				_, _ = io.Copy(dst, src)
				dst.Close()
				src.Close()
			}
			go pipe(server, client)
			go pipe(client, server)
			wg.Wait()
			r.mu.Lock()
			delete(r.conns, client)
			delete(r.conns, server)
			r.mu.Unlock()
		}()
	}
}

// jjServe is one served node (the re-executed real main) on a fixed data directory and address.
type jjServe struct {
	t       *testing.T
	dir     string
	listen  string
	cmd     *exec.Cmd
	drained chan struct{}
	errOut  *lockedBuf
	// interval is the node's --worker-interval.
	interval string
}

func (s *jjServe) start() {
	s.t.Helper()
	cmd, lines, errOut := serveChild(s.t, "--data-dir", s.dir, "--listen", s.listen, "--worker-interval", s.interval)
	s.cmd, s.errOut, s.drained = cmd, errOut, make(chan struct{})
	go func() {
		defer close(s.drained)
		for range lines {
		}
	}()
}

// client waits until the node is ready and returns a client (a fresh cookie jar) that trusts the node's own certificate as it is now.
func (s *jjServe) client() *http.Client {
	s.t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if pemBytes, err := os.ReadFile(filepath.Join(s.dir, "server.crt")); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pemBytes) {
				jar, _ := cookiejar.New(nil)
				c := &http.Client{Jar: jar, Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, DisableKeepAlives: true}}
				if resp, err := c.Get("https://" + s.listen + "/readyz"); err == nil {
					resp.Body.Close()
					if resp.StatusCode == 200 {
						return c
					}
				}
			}
		}
		select {
		case <-s.drained:
			s.t.Fatalf("serve exited before it was ready; stderr:\n%s", s.errOut.String())
		case <-time.After(200 * time.Millisecond):
		}
	}
	s.t.Fatalf("serve never became ready; stderr:\n%s", s.errOut.String())
	return nil
}

func (s *jjServe) api(c *http.Client) *api {
	return &api{t: s.t, base: "https://" + s.listen, client: c}
}

// kill is kill -9: no shutdown, nothing flushed by the process.
func (s *jjServe) kill() {
	s.t.Helper()
	if err := s.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		s.t.Fatal(err)
	}
	select {
	case <-s.drained:
	case <-time.After(30 * time.Second):
		s.t.Fatal("serve did not die after SIGKILL")
	}
	_ = s.cmd.Wait()
}

// interrupt is the operator's graceful stop; the node must exit cleanly.
func (s *jjServe) interrupt() {
	s.t.Helper()
	if err := s.cmd.Process.Signal(syscall.SIGINT); err != nil {
		s.t.Fatal(err)
	}
	select {
	case <-s.drained:
	case <-time.After(30 * time.Second):
		s.t.Fatalf("serve did not stop after SIGINT; stderr:\n%s", s.errOut.String())
	}
	if err := s.cmd.Wait(); err != nil {
		s.t.Fatalf("serve did not exit cleanly: %v\n%s", err, s.errOut.String())
	}
}

// jjSDK runs one mode of the scheduler fixture (a real Python process using the real SDK).
func jjSDK(t *testing.T, python, config, spool string, job model.ID, scheduled model.UnixNano, mode, run string) (out string, exit int, stderr string) {
	t.Helper()
	src, err := filepath.Abs(filepath.Join("..", "..", "sdk", "python", "src"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, filepath.Join("testdata", "sdk_scheduled_job.py"), mode)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+src, "PYTHONDONTWRITEBYTECODE=1", "SOUNDPOST_SDK_CONFIG="+config, "SOUNDPOST_SDK_JOB="+job.String(), "SOUNDPOST_SDK_SPOOL="+spool,
		"SOUNDPOST_SDK_SCHEDULED_NS="+strconv.FormatInt(int64(scheduled), 10), "SOUNDPOST_SDK_RUN="+run)
	var stdout, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &errBuf
	err = cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		exit = exitErr.ExitCode()
	default:
		t.Fatalf("scheduler fixture %s: %v", mode, err)
	}
	return stdout.String(), exit, errBuf.String()
}

func jjLastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

// jjView reads one job (and one run of it) through the real read route.
func jjView(a *api, org, project, job model.ID, run string) (int, httpapi.JobView, []byte) {
	a.t.Helper()
	body := map[string]any{"org": org, "project": project, "job": job}
	if run != "" {
		body["run"] = run
	}
	code, raw := a.do("POST", "/api/v1/jobs/view", body, nil)
	var view httpapi.JobView
	if code == 200 {
		if err := json.Unmarshal(raw, &view); err != nil {
			a.t.Fatalf("job view %s: %v", raw, err)
		}
	}
	return code, view, raw
}

// jjDefinitions lists the project's catalogue through the real route.
func jjDefinitions(a *api, org, project model.ID) (int, httpapi.JobDefinitionListAnswer, []byte) {
	a.t.Helper()
	code, raw := a.do("POST", "/api/v1/jobs/definitions", map[string]any{"org": org, "project_id": project, "operation": "list"}, nil)
	var list httpapi.JobDefinitionListAnswer
	if code == 200 {
		if err := json.Unmarshal(raw, &list); err != nil {
			a.t.Fatalf("definitions %s: %v", raw, err)
		}
	}
	return code, list, raw
}

// jjCommand is one admin command that rides out revision races. The expected revision is the whole control state's, which the served
// node's own runner commits to as well, and create_user hashes its password before it compares, so a command can lose several times
// in a row (api.command gives up after eight). A 409 is a race exactly when the revision moved since the command read it; the same
// revision twice means the command itself was refused.
func jjCommand(a *api, org model.ID, kind string, payload auth.AdminPayload) {
	a.t.Helper()
	payload.Reason = "serve job journey"
	body, _ := json.Marshal(payload)
	deadline := time.Now().Add(60 * time.Second)
	var refused model.Revision
	var refusedBody []byte
	for {
		code, raw := a.do("POST", "/api/v1/admin/read", map[string]any{"kind": "organizations"}, nil)
		var read struct {
			Revision model.Revision `json:"revision"`
		}
		if code != 200 || json.Unmarshal(raw, &read) != nil {
			a.t.Fatalf("admin read %d: %s", code, raw)
		}
		if refusedBody != nil && refused == read.Revision {
			a.t.Fatalf("%s: 409 %s (the revision did not move, so this is no revision race)", kind, refusedBody)
		}
		code, raw = a.do("POST", "/api/v1/admin/commands", map[string]any{"command_id": model.NewID(), "expected_revision": read.Revision, "org_id": org, "kind": kind, "payload": json.RawMessage(body)}, nil)
		if code == 409 && time.Now().Before(deadline) {
			refused, refusedBody = read.Revision, raw
			continue
		}
		if code >= 300 {
			a.t.Fatalf("%s: %d %s", kind, code, raw)
		}
		return
	}
}

func jjLogin(t *testing.T, a *api, email, password string) {
	t.Helper()
	code, raw := a.do("POST", "/api/v1/login", map[string]string{"Email": email, "Password": password, "Code": ""}, nil)
	var session struct {
		CSRF string `json:"csrf"`
	}
	if code != 200 || json.Unmarshal(raw, &session) != nil {
		t.Fatalf("login %s: %d %s", email, code, raw)
	}
	a.csrf = session.CSRF
}

func jjUntil(t *testing.T, within time.Duration, what string, step func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(within)
	last := ""
	for {
		ok, why := step()
		if ok {
			return
		}
		last = why
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen within %s; last state: %s", what, within, last)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// jjRecovered holds the verdict the journey must reach, in the same words after every restart.
func jjRecovered(t *testing.T, when string, view httpapi.JobView, key string, scheduled model.UnixNano, first, retry, errorID model.ID) {
	t.Helper()
	h := view.Health
	if view.Health == nil || h.Status != jobs.StatusSucceeded || !h.Complete || !slices.Contains(h.Reasons, jobs.ReasonRunRecovered) || h.Evidence.Occurrence != key {
		t.Fatalf("%s: the retry must recover the scheduled run (succeeded, complete, %s, occurrence %s): %+v", when, jobs.ReasonRunRecovered, key, view.Health)
	}
	if view.Observer == nil || view.Observer.State != "fresh" || !view.Observer.ExpectedSchedule {
		t.Fatalf("%s: the schedule observer must be fresh: %+v", when, view.Observer)
	}
	if view.TotalRuns != 1 || view.TotalAttempts != 2 || view.LatestOccurrence != key || len(view.Runs) != 1 {
		t.Fatalf("%s: exactly one scheduled run of two attempts under %s: runs=%d attempts=%d latest=%s", when, key, view.TotalRuns, view.TotalAttempts, view.LatestOccurrence)
	}
	run := view.Runs[0]
	if !run.Occurrence.Scheduled || run.Occurrence.Key != key || run.Occurrence.At == nil || *run.Occurrence.At != scheduled || run.AttemptCount != 2 || run.FailedAttempts != 1 || !run.Recovered || run.Status != jobs.RunRecovered || !run.BasisOfHealth {
		t.Fatalf("%s: the run is the scheduled occurrence, recovered after one failed attempt: %+v", when, run)
	}
	if view.Run == nil || len(view.Run.Attempts) != 2 {
		t.Fatalf("%s: run detail: %+v", when, view.Run)
	}
	one, two := view.Run.Attempts[0], view.Run.Attempts[1]
	if one.ID != first || one.Ordinal != 1 || one.Effective != jobs.AttemptFailed || one.Terminal == nil || one.CauseError == nil || *one.CauseError != errorID || one.EventsAccepted != 2 || one.Final {
		t.Fatalf("%s: attempt 1 must stay failed with its captured error as the cause, 2 events: %+v", when, one)
	}
	if two.ID != retry || two.Ordinal != 2 || two.Effective != jobs.AttemptSucceeded || two.EventsAccepted != 2 || !two.Final {
		t.Fatalf("%s: attempt 2 must be the succeeded final attempt, 2 events: %+v", when, two)
	}
	for _, a := range view.Run.Attempts {
		if a.Effective == jobs.AttemptStarted {
			t.Fatalf("%s: an attempt is left started: %+v", when, a)
		}
	}
}

// TestServeJobDurableRetryJourney is the 06.03#11 smoke on the real process boundary: a real `soundpost serve`
// (the re-executed real main), the real Python SDK in a scheduler fixture process (two processes sharing one
// encrypted spool), a TCP relay that really drops and restores the exporter's path, and two real restarts of
// the node on the same data directory. A scheduled job's first attempt fails while the path is down and nothing
// is delivered; the node restarts; the path is restored and the retry (same run, same occurrence) delivers the
// recovered events and its own; the job reads succeeded, recovered, complete, with attempt 1 still failed and no
// attempt counted twice, before and after a second restart.
func TestServeJobDurableRetryJourney(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes and signals")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not on PATH: the journey drives the real Python SDK")
	}
	work := t.TempDir()
	// Provisioning is a run of admin commands against one control revision, and the node's own runner commits to the same state. A slow
	// runner (the restart below makes it fast) keeps the revision still long enough for the slow password hash of create_user under -race.
	node := &jjServe{t: t, dir: filepath.Join(work, "data"), listen: net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t))), interval: "20s"}
	node.start()
	t.Cleanup(func() {
		if node.cmd != nil && node.cmd.ProcessState == nil {
			_ = node.cmd.Process.Kill()
		}
	})
	relay := newJJRelay(t, node.listen)
	relay.setDown(true)

	// 1. Provision as the bootstrap administrator: an organization, a project, an author (policy.write) and a reader (telemetry.read).
	admin := node.api(node.client())
	token, err := os.ReadFile(filepath.Join(node.dir, "bootstrap.token"))
	if err != nil {
		t.Fatal(err)
	}
	adminPassword := "serve journey admin password 2026"
	code, raw := admin.do("POST", "/api/v1/bootstrap", map[string]string{"Token": strings.TrimSpace(string(token)), "Email": "owner@example.test", "Password": adminPassword}, nil)
	var session struct {
		CSRF string `json:"csrf"`
	}
	if code != 200 || json.Unmarshal(raw, &session) != nil {
		t.Fatalf("bootstrap %d: %s", code, raw)
	}
	admin.csrf = session.CSRF
	org, project, source := model.NewID(), model.NewID(), model.NewID()
	jjCommand(admin, org, "create_org", auth.AdminPayload{Name: "serve job journey"})
	jjCommand(admin, org, "create_project", auth.AdminPayload{ID: project, Name: "serve job journey project"})
	author, reader := model.NewID(), model.NewID()
	authorPassword, readerPassword := "serve journey author password 2026", "serve journey reader password 2026"
	for _, u := range []struct {
		id       model.ID
		email    string
		password string
		perm     auth.Permission
	}{{author, "author@example.test", authorPassword, auth.PolicyWrite}, {reader, "reader@example.test", readerPassword, auth.Read}} {
		jjCommand(admin, org, "create_user", auth.AdminPayload{ID: u.id, Email: u.email, Password: u.password})
		jjCommand(admin, org, "membership", auth.AdminPayload{UserID: u.id, Enabled: true})
		jjCommand(admin, org, "grant", auth.AdminPayload{UserID: u.id, ProjectID: project, Permissions: []string{string(u.perm)}, Enabled: true})
	}

	// A job source onboarded for the SDK: job attempts, the errors a failed attempt captures and the SDK's own loss counters.
	service, environment, build := model.NewID(), model.NewID(), model.NewID()
	policy := map[string]any{"revision": "1", "enabled": true, "class": "structured", "kinds": []string{"job_attempt", "error", "loss"}, "templates": []any{},
		"resources": map[string]any{"service_id": []model.ID{service}, "environment_id": []model.ID{environment}, "build_id": []model.ID{build}, "instance_pseudonym": []string{"opaque-instance"}},
		"labels":    map[string]any{}, "operations": []string{}, "dependencies": []string{}, "codes": []string{},
		"retention_days": map[string]int{"job_attempt": 7, "error": 7, "loss": 7}, "max_bytes": "1048576", "max_series": "1000", "replay": false, "expires_ns": "0"}
	code, raw = admin.do("POST", "/api/v1/sources", map[string]any{"command_id": model.NewID(), "org": org, "project": project, "source": source, "browser": false, "origins": []string{},
		"expires_ns": strconv.FormatInt(time.Now().Add(24*time.Hour).UnixNano(), 10), "policy": policy, "reason": "serve job journey"}, nil)
	var onboarded map[string]json.RawMessage
	if code != 200 || json.Unmarshal(raw, &onboarded) != nil || onboarded["credential"] == nil || onboarded["policy"] == nil || onboarded["trusted_keys"] == nil || onboarded["descriptor"] == nil {
		t.Fatalf("source onboarding %d: %s", code, raw)
	}
	var credential string
	if err = json.Unmarshal(onboarded["credential"], &credential); err != nil || credential == "" {
		t.Fatalf("credential %s: %v", onboarded["credential"], err)
	}
	config := filepath.Join(work, "sdk.json")
	writeSDKConfig := func() {
		t.Helper()
		doc := map[string]any{"org": org, "project": project, "source": source, "credential": credential, "build": build, "endpoint": "https://" + relay.addr() + "/ingest/v1/batches",
			"policy": onboarded["policy"], "trusted_keys": onboarded["trusted_keys"], "descriptor": onboarded["descriptor"],
			"resource": map[string]any{"service_id": service, "environment_id": environment, "build_id": build, "instance_pseudonym": "opaque-instance", "labels": []any{}},
			"ca_file":  filepath.Join(node.dir, "server.crt")}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(config, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeSDKConfig()

	// The scheduled job: hourly, its latest occurrence 20 minutes ago (late enough that the product's attestation, the newest
	// event time less its 15 minute allowance, reaches it; early enough that no later occurrence falls due during the test).
	scheduled := model.UnixNano(time.Now().UTC().Add(-20 * time.Minute).Truncate(time.Minute).UnixNano())
	key := jobs.OccurrenceKey("UTC", scheduled, 0)
	job := model.NewID()
	authorAPI := node.api(node.client())
	jjLogin(t, authorAPI, "author@example.test", authorPassword)
	cron := strconv.Itoa(time.Unix(0, int64(scheduled)).UTC().Minute()) + " * * * *"
	definition := map[string]any{"revision": "1", "effective_from_ns": strconv.FormatInt(time.Now().Add(-24*time.Hour).UnixNano(), 10), "schedule": map[string]string{"cron": cron, "timezone": "UTC"},
		"grace_ns": "60000000000", "max_runtime_ns": "0", "observer_stale_after_ns": "20000000000", "overlap": "allow"}
	code, raw = authorAPI.do("POST", "/api/v1/jobs/definitions", map[string]any{"org": org, "project_id": project, "operation": "save", "command_id": model.NewID(), "job_id": job,
		"expected_revision": "0", "reason": "serve job journey schedule", "definition": definition}, nil)
	if code != 200 {
		t.Fatalf("saving the job definition: %d %s", code, raw)
	}
	readerAPI := node.api(node.client())
	jjLogin(t, readerAPI, "reader@example.test", readerPassword)
	if code, list, raw := jjDefinitions(readerAPI, org, project); code != 200 || len(list.Jobs) != 1 || list.Jobs[0].JobID != job || list.CanAuthor {
		t.Fatalf("the reader must see the authored definition and not author: %d %s", code, raw)
	}

	// 3a. Phase A: the exporter's path is down. The scheduler fixture runs attempt 1 (it raises), cannot deliver and dies at once.
	spool := filepath.Join(work, "spool.bin")
	out, exit, stderr := jjSDK(t, python, config, spool, job, scheduled, "crash", "")
	if exit != 137 {
		t.Fatalf("the first scheduler process must die abruptly (exit 137), got %d\nstdout: %s\nstderr: %s", exit, out, stderr)
	}
	var first struct {
		Run, Occurrence, FailedAttempt, Error string
		ScheduledNS                           int64
		Pending                               int
	}
	var crashed map[string]any
	if err = json.Unmarshal([]byte(jjLastLine(out)), &crashed); err != nil {
		t.Fatalf("crash output %q: %v", out, err)
	}
	first.Run, _ = crashed["run"].(string)
	first.Occurrence, _ = crashed["occurrence"].(string)
	first.FailedAttempt, _ = crashed["failed_attempt"].(string)
	first.Error, _ = crashed["error"].(string)
	if p, ok := crashed["pending"].(float64); ok {
		first.Pending = int(p)
	}
	if first.Run == "" || first.FailedAttempt == "" || first.Error == "" || first.Pending == 0 {
		t.Fatalf("the first process must report its run, failed attempt, error and pending events: %q", out)
	}
	if first.Occurrence != key {
		t.Fatalf("the SDK emitted %q, want the scheduled form jobs.OccurrenceKey = %q (never manual.<run>)", first.Occurrence, key)
	}
	if relay.refused.Load() == 0 || relay.relayed.Load() != 0 {
		t.Fatalf("the exporter must have hit the dead path: refused=%d relayed=%d", relay.refused.Load(), relay.relayed.Load())
	}
	runID, err := model.ParseID(first.Run)
	if err != nil {
		t.Fatal(err)
	}
	failedAttempt, _ := model.ParseID(first.FailedAttempt)
	errorID, _ := model.ParseID(first.Error)
	// Nothing was delivered, so the product must not show a success, a failure or a started attempt. The real route answers either 404 (the
	// runner has not yet entered the catalogue's job into the job books: no job state at all) or 200 with the job as the catalogue defines it
	// and no evidence: unknown (never succeeded), incomplete, no run and no attempt. Which one depends on whether a runner pass has seen the
	// definition, so both are the truthful "nothing received".
	notDelivered := func(when string) {
		t.Helper()
		code, view, raw := jjView(readerAPI, org, project, job, "")
		if code == 404 {
			t.Logf("%s: job read 404 (no job state yet): %s", when, raw)
			if code2, _, raw2 := jjView(readerAPI, org, project, job, first.Run); code2 != 404 {
				t.Fatalf("%s: the product answers for run %s it never received: %d %s", when, first.Run, code2, raw2)
			}
			return
		}
		if code != 200 || view.Health == nil {
			t.Fatalf("%s: job read %d: %s", when, code, raw)
		}
		if h := view.Health; h.Status != jobs.StatusUnknown || h.Complete || !slices.Contains(h.Reasons, jobs.ReasonNoEvidence) || h.Evidence.Run != nil || h.Evidence.Attempt != nil {
			t.Fatalf("%s: the product must read the job unknown for want of evidence, never a verdict for a run it never received: %s", when, raw)
		}
		if view.TotalRuns != 0 || view.TotalAttempts != 0 || len(view.Runs) != 0 || view.LatestOccurrence != "" {
			t.Fatalf("%s: the product shows a run it never received: %s", when, raw)
		}
		t.Logf("%s: job read %d: state=%s status=%s reasons=%v", when, code, view.State, view.Health.Status, view.Health.Reasons)
		if code2, _, raw2 := jjView(readerAPI, org, project, job, first.Run); code2 == 200 {
			t.Fatalf("%s: the product answers for run %s it never received: %s", when, first.Run, raw2)
		}
	}
	notDelivered("path down, before the restart")

	// 3b. Phase B: kill -9 the node while the path is still down and start it again on the same data directory.
	certBefore, _ := os.ReadFile(filepath.Join(node.dir, "server.crt"))
	node.kill()
	node.interval = "100ms" // the restarted node's runner passes quickly: the journey now waits on its verdicts
	node.start()
	node.client() // ready
	certAfter, _ := os.ReadFile(filepath.Join(node.dir, "server.crt"))
	t.Logf("restart 1: server.crt unchanged=%v", string(certBefore) == string(certAfter))
	// Control persistence: the account and the definition survived the kill; sessions are not assumed to.
	readerAPI = node.api(node.client())
	jjLogin(t, readerAPI, "reader@example.test", readerPassword)
	if code, list, raw := jjDefinitions(readerAPI, org, project); code != 200 || len(list.Jobs) != 1 || list.Jobs[0].JobID != job || list.Jobs[0].Definition.Schedule == nil || list.Jobs[0].Definition.Schedule.Cron != cron {
		t.Fatalf("the job definition did not survive the restart: %d %s", code, raw)
	}
	notDelivered("path down, after restart 1")

	// 3c. Phase C: the path is restored; a new scheduler process opens the same spool and retries the SAME run of the SAME occurrence.
	writeSDKConfig() // the node's certificate is read again, as a restarted SDK host would
	relay.setDown(false)
	out, exit, stderr = jjSDK(t, python, config, spool, job, scheduled, "resume", first.Run)
	if exit != 0 {
		t.Fatalf("the retry process failed (exit %d)\nstdout: %s\nstderr: %s", exit, out, stderr)
	}
	var retried struct {
		Run           string `json:"run"`
		Occurrence    string `json:"occurrence"`
		FailedAttempt string `json:"failed_attempt"`
		RetryAttempt  string `json:"retry_attempt"`
		Error         string `json:"error"`
		Events        int    `json:"events"`
		Recovered     int    `json:"recovered"`
		Receipts      int    `json:"receipts"`
	}
	if err = json.Unmarshal([]byte(jjLastLine(out)), &retried); err != nil {
		t.Fatalf("resume output %q: %v", out, err)
	}
	if retried.Run != first.Run || retried.Occurrence != key || retried.FailedAttempt != first.FailedAttempt || retried.Error != first.Error || retried.Events != 4 || retried.Recovered != 2 || retried.Receipts == 0 {
		t.Fatalf("the retry must continue the same run and occurrence from the spool, durably: %+v (first %+v)", retried, first)
	}
	if relay.relayed.Load() == 0 {
		t.Fatal("the retry's events did not travel through the restored path")
	}
	retryAttempt, _ := model.ParseID(retried.RetryAttempt)
	if failedAttempt == (model.ID{}) || retryAttempt == (model.ID{}) || errorID == (model.ID{}) || runID == (model.ID{}) {
		t.Fatal("attempt identities missing")
	}

	// 3d. Phase D: the real read route, as the reader, reaches the recovered verdict; the schedule observer attests the data path through the occurrence.
	var view httpapi.JobView
	jjUntil(t, 120*time.Second, "the job reading succeeded and complete", func() (bool, string) {
		code, v, raw := jjView(readerAPI, org, project, job, first.Run)
		view = v
		return code == 200 && v.Health != nil && v.Health.Status == jobs.StatusSucceeded && v.Health.Complete && v.Run != nil && len(v.Run.Attempts) == 2, string(raw)
	})
	jjRecovered(t, "after the retry was delivered", view, key, scheduled, failedAttempt, retryAttempt, errorID)
	jjUntil(t, 90*time.Second, "the observer attesting the data path through the scheduled occurrence", func() (bool, string) {
		_, v, raw := jjView(readerAPI, org, project, job, first.Run)
		view = v
		return v.Observer != nil && v.Observer.Evidence != nil && v.Observer.Evidence.CompleteThrough >= scheduled && v.Observer.State == "fresh", string(raw)
	})
	jjRecovered(t, "with the observer's attestation", view, key, scheduled, failedAttempt, retryAttempt, errorID)
	decided := view.Health.Status

	// 3e. Phase E: a graceful restart of the node on the same data directory reads the same verdict, and no attempt counts twice.
	node.interrupt()
	node.start()
	readerAPI = node.api(node.client())
	jjLogin(t, readerAPI, "reader@example.test", readerPassword)
	jjUntil(t, 120*time.Second, "the same verdict after the second restart", func() (bool, string) {
		code, v, raw := jjView(readerAPI, org, project, job, first.Run)
		view = v
		return code == 200 && v.Health != nil && v.Health.Status == decided && v.Health.Complete && v.Observer != nil && v.Observer.State == "fresh" && v.Run != nil, string(raw)
	})
	jjRecovered(t, "after restart 2", view, key, scheduled, failedAttempt, retryAttempt, errorID)
	// The runner keeps passing over the journal after the restart: the evidence it re-reads must not be counted again.
	time.Sleep(4 * time.Second)
	code, view, raw = jjView(readerAPI, org, project, job, first.Run)
	if code != 200 {
		t.Fatalf("job read %d: %s", code, raw)
	}
	jjRecovered(t, "after restart 2 and further runner passes", view, key, scheduled, failedAttempt, retryAttempt, errorID)
	node.interrupt()
}
