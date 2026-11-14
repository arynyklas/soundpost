// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replays"

	recorderfixtures "github.com/arynyklas/soundpost/fixtures/replays/recorder"
)

// RunEvidence is the 09.06 protected-application-investigation smoke against a REAL
// `soundpost serve` subprocess over HTTPS (real bootstrap, login, scope-first
// routes). It prints one sanitized line per row and exits non-zero unless every
// REQUIRED row is satisfied. It never weakens a row to turn green: rows that the
// served process cannot satisfy today are reported with their exact reason.
//
// Registered as: case "evidence": return RunEvidence(os.Args[2:]).
//
// Flags: --artifact-dir <dir> receives evidence-summary.json (row ids, outcomes and
// reasons only; no identifiers, credentials, content). --fixture-dir (or
// SOUNDPOST_SOURCEMAP_FIXTURE_DIR) is the output of
// `node fixtures/artifacts/generate.mjs <dir>`. --binary is a produced soundpost
// binary; without it the smoke builds ./cmd/soundpost with the repository toolchain.
func RunEvidence(args []string) (result error) {
	stage := "evidence_flags"
	defer func() { result = annotateSmokeFailure("evidence", stage, model.ID{}, result) }()
	f := flag.NewFlagSet("evidence", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	artifactDir := f.String("artifact-dir", "", "sanitized result directory")
	binary := f.String("binary", "", "produced soundpost binary (default: build ./cmd/soundpost)")
	fixtureDir := f.String("fixture-dir", os.Getenv("SOUNDPOST_SOURCEMAP_FIXTURE_DIR"), "output of fixtures/artifacts/generate.mjs")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *artifactDir == "" || *fixtureDir == "" {
		return errors.New("--artifact-dir and --fixture-dir (or SOUNDPOST_SOURCEMAP_FIXTURE_DIR) are required")
	}
	if err := os.MkdirAll(*artifactDir, 0o700); err != nil {
		return err
	}
	stage = "evidence_binary"
	exe := *binary
	if exe == "" {
		tmp, err := os.MkdirTemp("", "soundpost-evidence-bin-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		exe = filepath.Join(tmp, "soundpost")
		build := exec.Command("go", "build", "-trimpath", "-o", exe, "./cmd/soundpost")
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			_ = out
			return &smokeFailure{Stage: "evidence_binary", Code: "build_failed"}
		}
	}
	exe, err := filepath.Abs(exe)
	if err != nil {
		return err
	}
	fixture, err := loadEvidenceFixture(*fixtureDir)
	if err != nil {
		return err
	}
	stage = "evidence_serve"
	j, err := startEvidenceServer(exe)
	if err != nil {
		return err
	}
	defer j.stop()
	stage = "evidence_journey"
	rows := j.journey(fixture)
	stage = "evidence_report"
	unsatisfied := 0
	for _, r := range rows.rows {
		state := "SATISFIED"
		if !r.Satisfied {
			state = "NOT SATISFIED"
			if r.Required {
				unsatisfied++
			}
		}
		kind := "required"
		if !r.Required {
			kind = "optional"
		}
		fmt.Printf("row %-44s %-8s %-13s %s\n", r.ID, kind, state, r.Reason)
	}
	raw, err := json.MarshalIndent(map[string]any{"version": 1, "rows": rows.rows, "required_unsatisfied": unsatisfied}, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(*artifactDir, "evidence-summary.json"), append(raw, '\n'), 0o600); err != nil {
		return err
	}
	if unsatisfied > 0 {
		return &smokeFailure{Stage: "evidence_rows", Code: fmt.Sprintf("%d_required_rows_unsatisfied", unsatisfied)}
	}
	return nil
}

type evidenceRow struct {
	ID        string `json:"id"`
	Required  bool   `json:"required"`
	Satisfied bool   `json:"satisfied"`
	Reason    string `json:"reason"`
}

type evidenceRows struct{ rows []evidenceRow }

func (r *evidenceRows) add(id string, required, ok bool, reason string) {
	r.rows = append(r.rows, evidenceRow{id, required, ok, reason})
}

type evidenceFixture struct {
	generated, mapBytes []byte
	line, column        uint32
}

func loadEvidenceFixture(dir string) (*evidenceFixture, error) {
	fx := &evidenceFixture{}
	var err error
	if fx.generated, err = os.ReadFile(filepath.Join(dir, "simple.mjs")); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, "simple.mjs.map"))
	if err != nil {
		return nil, err
	}
	pos, err := os.ReadFile(filepath.Join(dir, "simple.position.json"))
	if err != nil {
		return nil, err
	}
	var p struct{ GeneratedLine, GeneratedColumn uint32 }
	if err = json.Unmarshal(pos, &p); err != nil || p.GeneratedLine == 0 {
		return nil, errors.New("fixture position unreadable")
	}
	fx.line, fx.column = p.GeneratedLine, p.GeneratedColumn
	var m map[string]any
	if err = json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	m["sourcesContent"] = []any{"// " + evidenceCanaryMap + "\nexport const secret = 1;\n"}
	if fx.mapBytes, err = json.Marshal(m); err != nil {
		return nil, err
	}
	return fx, nil
}

var (
	evidenceCanaryMap     = "EVIDENCE-SMOKE-SOURCESCONTENT-" + model.NewID().String()
	evidenceCanaryReplay  = "EVIDENCE-SMOKE-REPLAY-TEXT-" + model.NewID().String()
	evidenceCanaryMessage = "EVIDENCE-SMOKE-ERROR-MESSAGE-" + model.NewID().String()
	evidenceControl       = "evidence_smoke_control_" + model.NewID().String()
	evidenceRequestID     = regexp.MustCompile(`"request_id":"[0-9a-f]{32}"`)
)

type evidenceServer struct {
	exe, dir, holdDir string
	serveArgs         []string
	cmd               *exec.Cmd
	addr              string
	logs              *syncBuffer
	done              chan error
	stopped, halted   bool
	site              *installSite
	bodies            [][]byte
}

func startEvidenceServer(exe string) (*evidenceServer, error) {
	dir, err := os.MkdirTemp("", "soundpost-evidence-")
	if err != nil {
		return nil, err
	}
	return startEvidenceServerIn(exe, dir)
}

// startEvidenceServerIn serves the installation in dir (a fresh directory, or a restored root).
func startEvidenceServerIn(exe, dir string) (*evidenceServer, error) {
	addr, err := freeAddress()
	if err != nil {
		return nil, err
	}
	s := &evidenceServer{exe: exe, dir: dir, addr: addr, logs: &syncBuffer{}}
	s.serveArgs = []string{"serve", "--mode=single", "--data-dir", dir, "--listen", addr}
	// An operator-selected symbolication backend (private JSON, docs/operations/symbolication.md)
	// is passed through only when the caller sets it; without it the row reports what the
	// served process answers by default on this host.
	if cfg := os.Getenv("SOUNDPOST_SMOKE_SYMBOLICATE_CONFIG"); cfg != "" {
		s.serveArgs = append(s.serveArgs, "--symbolicate-config", cfg)
	}
	if err = s.launch(); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-s.done:
			s.done <- err
			return nil, &smokeFailure{Stage: "evidence_serve", Code: "exited_before_listening"}
		default:
		}
		if raw, err := os.ReadFile(filepath.Join(dir, "server.crt")); err == nil {
			if block, _ := pem.Decode(raw); block != nil {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
						c.Close()
						s.site = newInstallSite("https://"+addr, cert)
						break
					}
				}
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if s.site == nil {
		s.stop()
		return nil, &smokeFailure{Stage: "evidence_serve", Code: "timeout"}
	}
	if err = s.awaitReady(deadline.Add(30 * time.Second)); err != nil {
		s.stop()
		return nil, err
	}
	return s, nil
}

func (s *evidenceServer) launch() error {
	s.done = make(chan error, 1)
	s.cmd = exec.Command(s.exe, s.serveArgs...)
	s.cmd.Stdout, s.cmd.Stderr = s.logs, s.logs
	s.cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	if err := s.cmd.Start(); err != nil {
		return err
	}
	cmd, done := s.cmd, s.done
	go func() { done <- cmd.Wait() }()
	return nil
}

func (s *evidenceServer) awaitReady(deadline time.Time) error {
	for time.Now().Before(deadline) {
		if status, _, err := s.site.get("/readyz"); err == nil && status == 200 {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return &smokeFailure{Stage: "evidence_serve", Code: "not_ready"}
}

// halt stops the process but keeps the data directory (and the pinned site).
func (s *evidenceServer) halt() {
	if s.halted || s.stopped {
		return
	}
	s.halted = true
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.done:
	case <-time.After(20 * time.Second):
		_ = s.cmd.Process.Kill()
		<-s.done
	}
}

// restart serves the same directory on the same address again.
func (s *evidenceServer) restart() error {
	if !s.halted {
		return errors.New("restart of a running server")
	}
	if err := s.launch(); err != nil {
		return err
	}
	s.halted = false
	return s.awaitReady(time.Now().Add(60 * time.Second))
}

func (s *evidenceServer) stop() {
	if s.stopped {
		return
	}
	s.halt()
	s.stopped = true
	os.RemoveAll(s.dir)
}

// ---- tiny HTTP helpers over the pinned-certificate sites ----

type evidenceUser struct {
	site    *installSite
	session auth.Session
	id      model.ID
	email   string
}

func (s *evidenceServer) remember(raw []byte) {
	s.bodies = append(s.bodies, append([]byte(nil), raw...))
}

func (s *evidenceServer) post(u *evidenceUser, path string, body any) (int, []byte) {
	status, raw, err := u.site.post(path, body, u.session.CSRF, "")
	if err != nil {
		return 0, nil
	}
	s.remember(raw)
	return status, raw
}

func (s *evidenceServer) sourcePost(path, credential string, body any) (int, []byte) {
	status, raw, err := s.site.post(path, body, "", credential)
	if err != nil {
		return 0, nil
	}
	s.remember(raw)
	return status, raw
}

func (s *evidenceServer) upload(u *evidenceUser, manifest model.ArtifactManifest, file []byte) (int, []byte) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	raw, _ := json.Marshal(manifest)
	w, _ := mw.CreateFormField("manifest")
	w.Write(raw)
	w, _ = mw.CreateFormFile("file", "simple.mjs.map")
	w.Write(file)
	mw.Close()
	req, err := http.NewRequest("POST", u.site.base+"/api/v1/artifacts", &buf)
	if err != nil {
		return 0, nil
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Origin", u.site.base)
	req.Header.Set("X-CSRF-Token", u.session.CSRF)
	status, out, _, err := u.site.do(req)
	if err != nil {
		return 0, nil
	}
	s.remember(out)
	return status, out
}

// stream reads up to limit bytes of the NDJSON replay stream.
func (s *evidenceServer) stream(u *evidenceUser, org, project, replay model.ID) (int, []httpapi.ReplayLine, []byte) {
	raw, _ := json.Marshal(httpapi.ReplayBody{ScopeFields: httpapi.ScopeFields{Org: org}, Project: project, Replay: replay})
	req, err := http.NewRequest("POST", u.site.base+"/api/v1/replays/stream", bytes.NewReader(raw))
	if err != nil {
		return 0, nil, nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", u.site.base)
	req.Header.Set("X-CSRF-Token", u.session.CSRF)
	resp, err := u.site.client.Do(req)
	if err != nil {
		return 0, nil, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		s.remember(body)
		return resp.StatusCode, nil, body
	}
	var lines []httpapi.ReplayLine
	var all []byte
	br := bufio.NewReaderSize(resp.Body, 64<<10)
	for len(all) < 4<<20 {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			all = append(all, line...)
			var l httpapi.ReplayLine
			if json.Unmarshal(line, &l) == nil {
				lines = append(lines, l)
			}
		}
		if err != nil {
			break
		}
	}
	s.remember(all)
	return 200, lines, all
}

func evidenceNorm(raw []byte, ids ...model.ID) string {
	out := evidenceRequestID.ReplaceAllString(string(raw), `"request_id":"X"`)
	for i, id := range ids {
		out = strings.ReplaceAll(out, id.String(), fmt.Sprintf("<id%d>", i))
	}
	return out
}

func evidenceShape(lines []httpapi.ReplayLine) string {
	var out []string
	for _, l := range lines {
		seq := uint64(0)
		if l.Sequence != nil {
			seq = uint64(*l.Sequence)
		}
		switch l.Type {
		case "checkpoint":
			out = append(out, fmt.Sprintf("C%d", seq))
		case "delta":
			out = append(out, fmt.Sprintf("D%d", seq))
		default:
			out = append(out, l.Type)
		}
	}
	return strings.Join(out, " ")
}

// journey runs the rows; it never returns an error: every failure is a row.
func (s *evidenceServer) journey(fx *evidenceFixture) *evidenceRows {
	rows := &evidenceRows{}
	rows.add("serve_https_ready", true, true, "real `soundpost serve` subprocess, pinned self-signed certificate, GET /readyz 200")
	fail := func(id string, required bool, format string, a ...any) *evidenceRows {
		rows.add(id, required, false, fmt.Sprintf(format, a...))
		return rows
	}

	// Bootstrap and tenants, entirely over HTTPS.
	token, err := os.ReadFile(filepath.Join(s.dir, "bootstrap.token"))
	if err != nil {
		return fail("bootstrap", true, "no bootstrap token file")
	}
	owner := &evidenceUser{site: s.site}
	status, raw, err := owner.site.post("/api/v1/bootstrap", map[string]string{"Token": string(token), "Email": "owner@evidence-smoke.invalid", "Password": "evidence smoke owner password 2026"}, "", "")
	if err != nil || status != 200 || json.Unmarshal(raw, &owner.session) != nil {
		return fail("bootstrap", true, "bootstrap refused: status %d", status)
	}
	orgA, orgB, projA, projB, srcA, srcB := model.NewID(), model.NewID(), model.NewID(), model.NewID(), model.NewID(), model.NewID()
	admin := func(org model.ID, kind string, p auth.AdminPayload) error {
		status, raw, err := owner.site.post("/api/v1/admin/read", struct {
			Kind string `json:"kind"`
		}{"organizations"}, owner.session.CSRF, "")
		if err = requireSmokeResponse("admin_read", status, 200, raw, err); err != nil {
			return err
		}
		var view auth.AdminView
		if err = json.Unmarshal(raw, &view); err != nil {
			return err
		}
		p.Reason = "evidence smoke"
		payload, _ := json.Marshal(p)
		status, raw, err = owner.site.post("/api/v1/admin/commands", auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: view.Revision, OrgID: org, Kind: kind, Payload: payload}, owner.session.CSRF, "")
		return requireSmokeResponse("admin_"+kind, status, 200, raw, err)
	}
	const password = "evidence smoke reader password 2026"
	newUser := func(org model.ID, label string, perms ...auth.Permission) (*evidenceUser, error) {
		u := &evidenceUser{site: newInstallSiteLike(s.site), id: model.NewID()}
		u.email = label + "@evidence-smoke.invalid"
		ps := make([]string, len(perms))
		for i, p := range perms {
			ps[i] = string(p)
		}
		project := projA
		if org == orgB {
			project = projB
		}
		for _, step := range []struct {
			kind string
			p    auth.AdminPayload
		}{
			{"create_user", auth.AdminPayload{ID: u.id, Email: u.email, Password: password}},
			{"membership", auth.AdminPayload{UserID: u.id, Enabled: true}},
			{"grant", auth.AdminPayload{UserID: u.id, ProjectID: project, Enabled: true, Permissions: ps}},
		} {
			if err := admin(org, step.kind, step.p); err != nil {
				return nil, err
			}
		}
		status, raw, err := u.site.post("/api/v1/login", map[string]string{"Email": u.email, "Password": password, "Code": ""}, "", "")
		if err = requireSmokeResponse("login", status, 200, raw, err); err != nil {
			return nil, err
		}
		return u, json.Unmarshal(raw, &u.session)
	}
	for _, o := range []struct{ org, project model.ID }{{orgA, projA}, {orgB, projB}} {
		if err = admin(o.org, "create_org", auth.AdminPayload{Name: "evidence smoke"}); err != nil {
			return fail("tenants", true, "create_org refused")
		}
		if err = admin(o.org, "create_project", auth.AdminPayload{ID: o.project, Name: "web"}); err != nil {
			return fail("tenants", true, "create_project refused")
		}
	}
	all := []auth.Permission{auth.Read, auth.ArtifactRead, auth.ArtifactWrite, httpapi.ReplayRead, httpapi.ProfilesRead}
	analyst, err := newUser(orgA, "analyst", all...)
	if err != nil {
		return fail("tenants", true, "analyst setup refused")
	}
	revoked, err := newUser(orgA, "revoked", auth.ArtifactRead, auth.Read, httpapi.ReplayRead)
	if err != nil {
		return fail("tenants", true, "second reader setup refused")
	}
	outsider, err := newUser(orgB, "outsider", all...)
	if err != nil {
		return fail("tenants", true, "outsider setup refused")
	}
	res := model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "evidence-1", Labels: model.Labels{}}
	kinds := []model.Kind{model.ErrorKind, model.SpanKind, model.Replay, model.Profile, model.CapabilityKind, model.Loss}
	onboard := func(org, project, source model.ID) (string, error) {
		cfg, _ := json.Marshal(auth.SourcePolicyConfig{ProjectID: project, Enabled: true})
		if err := admin(org, "source_policy", auth.AdminPayload{ID: source, Config: cfg}); err != nil {
			return "", err
		}
		pol := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: kinds, Replay: true,
			Resources:  model.ResourceRegistry{Services: []model.ID{res.Service}, Environments: []model.ID{res.Environment}, Builds: []model.ID{res.Build}, Instances: []string{res.Instance}},
			Operations: []string{"operation"}, RetentionDays: map[model.Kind]uint32{}, MaxBytes: 1 << 30, MaxSeries: 100}
		for _, k := range kinds {
			pol.RetentionDays[k] = 14
		}
		status, raw, err := owner.site.post("/api/v1/sources", auth.SourceOnboarding{CommandID: model.NewID(), Org: org, Project: project, Source: source, Expires: model.UnixNano(time.Now().Add(6 * time.Hour).UnixNano()), Policy: pol, Reason: "evidence smoke"}, owner.session.CSRF, "")
		if err = requireSmokeResponse("source_onboard", status, 200, raw, err); err != nil {
			return "", err
		}
		var issued auth.SourceOnboarded
		if err = json.Unmarshal(raw, &issued); err != nil {
			return "", err
		}
		return issued.Credential, nil
	}
	credA, err := onboard(orgA, projA, srcA)
	if err != nil {
		return fail("tenants", true, "source A onboarding refused")
	}
	if _, err = onboard(orgB, projB, srcB); err != nil {
		return fail("tenants", true, "source B onboarding refused")
	}

	// Artifact: real multipart upload, policy-stripped read.
	debugID := "evidence-smoke-debug-" + model.NewID().String()
	manifest := model.ArtifactManifest{Version: 1, Org: orgA, Project: projA, Source: srcA, Build: res.Build, DebugID: debugID, GeneratedSHA256: model.HashCanonical(fx.generated), MapSHA256: model.HashCanonical(fx.mapBytes), Path: "dist/simple.mjs", Size: model.Uint64(len(fx.mapBytes)), RetainUntil: model.UnixNano(time.Now().Add(6 * time.Hour).UnixNano())}
	status2, rawUp := s.upload(analyst, manifest, fx.mapBytes)
	var artifact model.ArtifactReferenceIntent
	if status2 != 200 || json.Unmarshal(rawUp, &artifact) != nil || artifact.ID == (model.ID{}) {
		return fail("artifact_upload_read_policy", true, "multipart upload refused: status %d", status2)
	}
	st, read := s.post(analyst, "/api/v1/artifacts", httpapi.ArtifactReadRequest{Operation: "read", Org: orgA, Project: projA, ID: artifact.ID})
	var stored map[string]any
	if st != 200 || bytes.Contains(read, []byte(evidenceCanaryMap)) || json.Unmarshal(read, &stored) != nil || stored["mappings"] == nil || stored["sourcesContent"] != nil {
		rows.add("artifact_upload_read_policy", true, false, fmt.Sprintf("read back: status %d, sourcesContent present or map unreadable", st))
	} else {
		rows.add("artifact_upload_read_policy", true, true, "real multipart upload; sourcesContent canary stripped by the artifact policy")
	}

	// Error occurrence with the exact build and artifact frame.
	col := fx.column
	frame := model.Frame{Module: "simple.mjs", Function: "throwingFixture_" + evidenceControl, Artifact: artifact.ID.String(), Line: fx.line, Column: &col, InApp: true}
	trace, replayID, profileID := model.NewID(), model.NewID(), model.NewID()
	now := time.Now().UnixNano()
	producer := model.NewID()
	occ := model.ErrorOccurrence{Occurrence: model.NewID(), Class: "TypeError", Mechanism: "manual", Build: res.Build, Fatal: true, Frames: []model.Frame{frame}, Trace: &trace, Replay: &replayID, Profile: &profileID}
	rec := model.Record{ID: model.NewID(), Kind: model.ErrorKind, ObservedAt: model.UnixNano(now - int64(2*time.Second)), Resource: res, Payload: model.Payload{Error: &occ}}
	batch := model.Batch{Version: 1, Project: projA, Source: srcA, Producer: producer, ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{rec}}
	if batch.RouteSlot, err = model.OwnerSlot(orgA, projA, srcA, producer, rec); err != nil {
		return fail("error_occurrence_ingest", true, "owner slot: %v", err)
	}
	if st, rawIngest := s.sourcePost("/ingest/v1/batches", credA, batch); st != 200 {
		rows.add("error_occurrence_ingest", true, false, fmt.Sprintf("ingest refused: status %d %s", st, truncate(rawIngest)))
	} else {
		var generic map[string]any
		wire, _ := json.Marshal(batch)
		_ = json.Unmarshal(wire, &generic)
		if recs, ok := generic["records"].([]any); ok && len(recs) == 1 {
			if rm, ok := recs[0].(map[string]any); ok {
				if pl, ok := rm["payload"].(map[string]any); ok {
					pl["message"] = evidenceCanaryMessage
					generic["id"] = model.NewID().String()
				}
			}
		}
		if st, bad := s.sourcePost("/ingest/v1/batches", credA, generic); st == 200 || bytes.Contains(bad, []byte(evidenceCanaryMessage)) {
			rows.add("error_occurrence_ingest", true, false, "a message-bearing payload was admitted or echoed")
		} else {
			rows.add("error_occurrence_ingest", true, true, "real occurrence with exact build and artifact frame admitted over HTTPS; message-bearing payload refused without echo")
		}
	}

	// Frames: the served process maps only when its startup sandbox probe passed.
	st, rawFrames := s.post(analyst, "/api/v1/evidence/frames", httpapi.FramesBody{Org: orgA, Project: projA, Build: res.Build, Frames: []model.Frame{frame}})
	var fv httpapi.FramesView
	if st != 200 || json.Unmarshal(rawFrames, &fv) != nil || len(fv.Frames) != 1 {
		rows.add("frame_real_mapping", true, false, fmt.Sprintf("frames route answered status %d", st))
	} else if f := fv.Frames[0]; f.Resolved != nil && f.Resolved.Source == "simple.ts" && f.Resolved.Line == 4 && f.Resolved.Column == 8 {
		rows.add("frame_real_mapping", true, true, "real thrown frame resolved to simple.ts:4:8")
	} else {
		startup := "no `symbolicator:` line in the serve log"
		for _, line := range strings.Split(s.logs.String(), "\n") {
			if strings.HasPrefix(line, "symbolicator: ") {
				startup = "serve log: " + strings.TrimSpace(line)
				break
			}
		}
		rows.add("frame_real_mapping", true, false, fmt.Sprintf("served process answered state=%s reason=%s frame_reason=%s; %s (typed answer, original frame kept)", fv.State, fv.Reason, f.Reason, startup))
	}

	// Replay: closed-format chain through the real route.
	svcChunks := evidenceChainSized(replayID, 10, 1)
	admitted := true
	for i, c := range svcChunks {
		if i == 3 {
			continue // lost in transit
		}
		if err = replays.ValidateChunk(c); err != nil {
			return fail("replay_closed_format_ingest", true, "closed-format validation refused a chain chunk: %v", err)
		}
		b := model.Batch{Version: 1, Project: projA, Source: srcA, Producer: producer, ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Replay, ObservedAt: c.Clock.Wall, Resource: res, Payload: model.Payload{Replay: &c}}}}
		b.RouteSlot, _ = model.OwnerSlot(orgA, projA, srcA, producer, b.Records[0])
		if st, _ := s.sourcePost("/ingest/v1/batches", credA, b); st != 200 {
			admitted = false
		}
	}
	tainted := evidenceChainSized(model.NewID(), 1, 1)[0]
	tainted.Nodes = []model.MaskedNode{{ID: 1, Tag: "div", Text: evidenceCanaryReplay}}
	tb := model.Batch{Version: 1, Project: projA, Source: srcA, Producer: producer, ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Replay, ObservedAt: tainted.Clock.Wall, Resource: res, Payload: model.Payload{Replay: &tainted}}}}
	tb.RouteSlot, _ = model.OwnerSlot(orgA, projA, srcA, producer, tb.Records[0])
	rawStored := false
	if st, body := s.sourcePost("/ingest/v1/batches", credA, tb); st == 200 || bytes.Contains(body, []byte(evidenceCanaryReplay)) {
		rawStored = true
	}
	switch {
	case !admitted:
		rows.add("replay_closed_format_ingest", true, false, "the real route refused a closed-format chunk")
	case rawStored:
		rows.add("replay_closed_format_ingest", true, false, "the real route admitted or echoed raw replay text")
	default:
		rows.add("replay_closed_format_ingest", true, true, "closed-format chunks admitted over the real route; raw text refused without echo")
	}
	stRep, lines, _ := s.stream(analyst, orgA, projA, replayID)
	if stRep == 200 && evidenceShape(lines) == "open C1 D2 D3 gap C6 D7 D8 D9 D10 end" {
		rows.add("replay_stream_readable_with_gap", true, true, "stream shows the explicit gap")
	} else {
		rows.add("replay_stream_readable_with_gap", true, false, fmt.Sprintf("the replay admitted over the real route is not readable through /api/v1/replays/stream: status %d lines %q", stRep, evidenceShape(lines)))
	}
	realOK, realDetail := s.realRecorderChain(analyst, orgA, projA, srcA, producer, credA, res)
	rows.add("replay_real_recorder_chunks", true, realOK, realDetail)
	// Does the route enforce the closed-format chain? A first chunk naming a previous
	// hash is rejected by replays.ValidateChunk.
	chainBad := evidenceChainSized(model.NewID(), 1, 1)[0]
	chainBad.Previous = model.HashCanonical([]byte("not the chain"))
	if replays.ValidateChunk(chainBad) == nil {
		rows.add("replay_admission_enforces_closed_format", true, false, "harness: the validator accepted the chain-invalid probe")
	} else {
		cb := model.Batch{Version: 1, Project: projA, Source: srcA, Producer: producer, ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Replay, ObservedAt: chainBad.Clock.Wall, Resource: res, Payload: model.Payload{Replay: &chainBad}}}}
		cb.RouteSlot, _ = model.OwnerSlot(orgA, projA, srcA, producer, cb.Records[0])
		if st, _ := s.sourcePost("/ingest/v1/batches", credA, cb); st == 200 {
			rows.add("replay_admission_enforces_closed_format", true, false, "the real ingest route admitted a first chunk that names a previous hash, which replays.ValidateChunk rejects: the replay gate (ingest.SetReplayGate) is missing or does not enforce the closed format, so chain, checkpoint and recorder-version rules are not enforced at intake")
		} else {
			rows.add("replay_admission_enforces_closed_format", true, true, fmt.Sprintf("the real route refused a chain-invalid chunk (status %d)", st))
		}
	}

	// Profile: a real chunk and its capability record go through the real ingest route
	// (the source policy onboarded above lists Profile and Capability), then are read
	// back through /api/v1/profiles/view. The row is satisfied only by what that view shows.
	capID := model.NewID()
	pclock := model.TraceClock{Wall: model.UnixNano(now - int64(time.Second)), Mono: 1000, Domain: model.ClockDomain{Host: model.NewID(), Boot: model.NewID(), Runtime: model.NewID()}}
	chunk := model.ProfileChunk{Profile: profileID, Process: model.NewID(), Capability: capID, Method: "runtime_cpu", Units: "samples", Start: model.UnixNano(now - int64(2*time.Second)), End: model.UnixNano(now - int64(time.Second)), Clock: pclock,
		Frames:  []model.ProfileFrame{{Module: "simple.mjs", Function: "throwingFixture", Artifact: artifact.ID.String(), Offset: model.Uint64(fx.line)}},
		Stacks:  []model.ProfileStack{{Frames: []uint32{0}}},
		Samples: []model.ProfileSample{{At: 1001, Stack: 0, Count: 1, Thread: 1}, {At: 1002, Stack: 0, Count: 2, Thread: 1}, {At: 1003, Stack: 0, Count: 3, Thread: 1}}}
	capability := model.Capability{Runtime: "web", Version: "1", Build: "evidence", OS: "linux", Arch: "amd64", Signal: model.Profile, Method: "runtime_cpu", Status: "supported", Reason: "probed", Coverage: model.Coverage{Frames: "partial", Threads: "none", Workers: "none", Tasks: "none"}, Clock: pclock.Domain, Expires: model.UnixNano(now + int64(time.Hour))}
	profileSent := true
	for _, r := range []model.Record{
		{ID: capID, Kind: model.CapabilityKind, ObservedAt: model.UnixNano(now - int64(2*time.Second)), Resource: res, Payload: model.Payload{Capability: &capability}},
		{ID: model.NewID(), Kind: model.Profile, ObservedAt: model.UnixNano(now - int64(time.Second)), Resource: res, Payload: model.Payload{Profile: &chunk}},
	} {
		pb := model.Batch{Version: 1, Project: projA, Source: srcA, Producer: producer, ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{r}}
		pb.RouteSlot, _ = model.OwnerSlot(orgA, projA, srcA, producer, r)
		if st, body := s.sourcePost("/ingest/v1/batches", credA, pb); st != 200 {
			profileSent = false
			rows.add("profile_real_view", true, false, fmt.Sprintf("the real ingest route refused a %s record: status %d %s", r.Kind, st, truncate(body)))
			break
		}
	}
	profileWindow := map[string]any{"start": model.UnixNano(now - int64(time.Hour)), "end": model.UnixNano(now + int64(time.Hour))}
	if profileSent {
		stProf, rawProf := s.post(analyst, "/api/v1/profiles/view", map[string]any{"org": orgA, "project": projA, "profile": profileID, "window": profileWindow})
		var pr httpapi.ProfileResponse
		linked := false
		if json.Unmarshal(rawProf, &pr) == nil && pr.View != nil {
			for _, l := range pr.View.Links {
				if l.Available && l.Reference != nil && l.Reference.Kind == "artifact" && l.Reference.ID == artifact.ID && l.Reference.Build == res.Build {
					linked = true
				}
			}
		}
		switch {
		case stProf != 200 || pr.View == nil:
			rows.add("profile_real_view", true, false, fmt.Sprintf("the profile delivered through real ingest was not readable: status %d %s", stProf, truncate(rawProf)))
		case pr.State != httpapi.StateReady || pr.View.Completeness != "complete":
			rows.add("profile_real_view", true, false, fmt.Sprintf("view state %s completeness %s reasons %v", pr.State, pr.View.Completeness, pr.View.Reasons))
		case pr.View.Profile != profileID || len(pr.View.Samples) != 3 || len(pr.View.Capabilities) != 1 || pr.View.Capabilities[0].ID != capID || pr.View.Capabilities[0].Value.Signal != model.Profile || pr.View.Capabilities[0].Value.Clock != chunk.Clock.Domain || pr.View.Capabilities[0].Value.Status != "supported":
			rows.add("profile_real_view", true, false, fmt.Sprintf("view shape wrong: %d samples, %d capabilities", len(pr.View.Samples), len(pr.View.Capabilities)))
		case len(pr.View.Frames) != 1 || pr.View.Frames[0].Artifact != artifact.ID.String() || !linked:
			rows.add("profile_real_view", true, false, "the profile frame does not link to the uploaded artifact through an available explicit reference")
		default:
			rows.add("profile_real_view", true, true, "profile and capability record delivered over the real ingest route; /api/v1/profiles/view returned 3 samples, the linked capability record (profile signal, same clock domain, supported) and the frame's artifact link resolved as available")
		}
	}

	// Isolation: the other organization cannot tell A's identities from missing ones.
	type pair struct {
		name          string
		real, control func() (int, []byte)
		a, c          []model.ID
	}
	ghost := model.NewID()
	prof := func(org, project, profile model.ID) func() (int, []byte) {
		return func() (int, []byte) {
			return s.post(outsider, "/api/v1/profiles/view", map[string]any{"org": org, "project": project, "profile": profile, "window": map[string]any{"start": model.UnixNano(now - int64(time.Hour)), "end": model.UnixNano(now + int64(time.Hour))}})
		}
	}
	readOf := func(org, project, id model.ID) func() (int, []byte) {
		return func() (int, []byte) {
			return s.post(outsider, "/api/v1/artifacts", httpapi.ArtifactReadRequest{Operation: "read", Org: org, Project: project, ID: id})
		}
	}
	framesOf := func(org, project, art model.ID) func() (int, []byte) {
		return func() (int, []byte) {
			f := frame
			f.Artifact = art.String()
			return s.post(outsider, "/api/v1/evidence/frames", httpapi.FramesBody{Org: org, Project: project, Build: res.Build, Frames: []model.Frame{f}})
		}
	}
	streamOf := func(org, project, replay model.ID) func() (int, []byte) {
		return func() (int, []byte) {
			st, _, body := s.stream(outsider, org, project, replay)
			return st, body
		}
	}
	pairs := []pair{
		{"artifact naming A", readOf(orgA, projA, artifact.ID), readOf(model.NewID(), model.NewID(), ghost), nil, nil},
		{"artifact own scope, A's id", readOf(orgB, projB, artifact.ID), readOf(orgB, projB, ghost), []model.ID{artifact.ID}, []model.ID{ghost}},
		{"frames own scope, A's artifact", framesOf(orgB, projB, artifact.ID), framesOf(orgB, projB, ghost), []model.ID{artifact.ID}, []model.ID{ghost}},
		{"replay naming A", streamOf(orgA, projA, replayID), streamOf(model.NewID(), model.NewID(), model.NewID()), nil, nil},
		{"replay own scope, A's id", streamOf(orgB, projB, replayID), streamOf(orgB, projB, ghost), []model.ID{replayID}, []model.ID{ghost}},
		{"profile naming A", prof(orgA, projA, profileID), prof(model.NewID(), model.NewID(), ghost), nil, nil},
		{"profile own scope, A's id", prof(orgB, projB, profileID), prof(orgB, projB, ghost), []model.ID{profileID}, []model.ID{ghost}},
	}
	isolated := true
	why := ""
	for _, p := range pairs {
		a, b := p.real, p.control
		sa, ra := a()
		sb, rb := b()
		if sa != sb || evidenceNorm(ra, p.a...) != evidenceNorm(rb, p.c...) || bytes.Contains(ra, []byte("simple.ts")) {
			isolated, why = false, p.name
			break
		}
	}
	if isolated {
		rows.add("isolation_same_ids_other_org", true, true, fmt.Sprintf("%d route variants answer the other organization byte-identically to random identities", len(pairs)))
	} else {
		rows.add("isolation_same_ids_other_org", true, false, "distinguishable: "+why)
	}

	// Mid-stream revoke: a large replay is read through a client with a tiny receive
	// buffer, so the server is genuinely mid-response when the grant is revoked.
	bigReplay := model.NewID()
	bigOK := true
	for _, c := range evidenceChainSized(bigReplay, 100, 1300) {
		b := model.Batch{Version: 1, Project: projA, Source: srcA, Producer: producer, ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Replay, ObservedAt: c.Clock.Wall, Resource: res, Payload: model.Payload{Replay: &c}}}}
		b.RouteSlot, _ = model.OwnerSlot(orgA, projA, srcA, producer, b.Records[0])
		if st, _ := s.sourcePost("/ingest/v1/batches", credA, b); st != 200 {
			bigOK = false
			break
		}
	}
	revoke := func() error {
		return admin(orgA, "grant", auth.AdminPayload{UserID: revoked.id, ProjectID: projA, Enabled: false})
	}
	if !bigOK {
		rows.add("lifecycle_midstream_halt_typed_revoke", true, false, "the large replay was not admitted by the real route")
		if err = revoke(); err != nil {
			rows.add("lifecycle_grant_revoke_denies_reads", true, false, "revocation command refused")
			return rows
		}
	} else if delivered, last, why := s.midstreamHalt(revoked, orgA, projA, bigReplay, revoke, replays.ReasonAuthorityRevoked); why != "" {
		rows.add("lifecycle_midstream_halt_typed_revoke", true, false, why)
	} else {
		rows.add("lifecycle_midstream_halt_typed_revoke", true, true, fmt.Sprintf("grant revoked mid-stream over HTTPS: %d of 100 chunks delivered, then one typed %s, nothing after", delivered, last))
	}
	{
		sa, _ := s.post(revoked, "/api/v1/artifacts", httpapi.ArtifactReadRequest{Operation: "read", Org: orgA, Project: projA, ID: artifact.ID})
		sb, _ := s.post(revoked, "/api/v1/evidence/frames", httpapi.FramesBody{Org: orgA, Project: projA, Build: res.Build, Frames: []model.Frame{frame}})
		sc, _, _ := s.stream(revoked, orgA, projA, replayID)
		if sa == 200 || sb == 200 || sc == 200 {
			rows.add("lifecycle_grant_revoke_denies_reads", true, false, fmt.Sprintf("after the grant was revoked: artifact %d frames %d replay %d", sa, sb, sc))
		} else {
			rows.add("lifecycle_grant_revoke_denies_reads", true, true, fmt.Sprintf("after revocation artifact/frames/replay answered %d/%d/%d", sa, sb, sc))
		}
	}
	// Single-node backup around the served process, taken BEFORE the deletion: the server
	// is stopped (backup create opens the installation exclusively), the backup and the
	// restore authority are made with the real CLI (docs/operations/backup-restore.md),
	// and the same installation is served again on the same address.
	bk := s.takeBackup("owner@evidence-smoke.invalid", "evidence smoke owner password 2026")
	if err = s.restartAfterBackup(bk); err != nil {
		return fail("restore_keeps_current_deletion_authority", true, "the served process did not come back after the backup: %v", err)
	}
	var beginStatus int
	var deletionOp model.ID
	// Deletion saga: a granted reader has the large replay open mid-response when an
	// org admin begins retire_project over HTTPS (POST /api/v1/admin/deletions,
	// retention.Service.Delete behind RegisterDeletionRoutes). The row is satisfied
	// only by what is observed: 202 fencing, then exactly one typed revoke on the open
	// stream and nothing after it, a denied re-read, and a lifecycle poll that shows
	// the operation. A process that registers no such route answers 404/405 and the
	// row stays unsatisfied with that status.
	if !bigOK {
		rows.add("lifecycle_deletion_saga_halts_stream", true, false, "the large replay was not admitted by the real route")
	} else {
		begin := func() error {
			status, raw, err := owner.site.post("/api/v1/admin/read", struct {
				Kind string `json:"kind"`
			}{"organizations"}, owner.session.CSRF, "")
			if err = requireSmokeResponse("admin_read", status, 200, raw, err); err != nil {
				return err
			}
			var view auth.AdminView
			if err = json.Unmarshal(raw, &view); err != nil {
				return err
			}
			status, raw, err = owner.site.post("/api/v1/admin/deletions", httpapi.DeletionRequest{CommandID: model.NewID(), ExpectedRevision: model.Uint64(view.Revision), Mode: model.DeleteRetireProject,
				OrgID: orgA, ProjectIDs: []model.ID{projA}, Reason: "evidence smoke deletion saga"}, owner.session.CSRF, "")
			beginStatus = status
			if err != nil {
				return err
			}
			s.remember(raw)
			var receipt httpapi.DeletionReceipt
			if status != http.StatusAccepted || json.Unmarshal(raw, &receipt) != nil || receipt.Phase != model.DeletePhaseFencing {
				return errors.New("the deletion was not accepted as a fencing receipt")
			}
			deletionOp = receipt.OperationID
			return nil
		}
		delivered, last, why := s.midstreamHalt(analyst, orgA, projA, bigReplay, begin, replays.ReasonAuthorityRevoked, replays.ReasonDeleted)
		switch {
		case beginStatus != http.StatusAccepted:
			rows.add("lifecycle_deletion_saga_halts_stream", true, false, fmt.Sprintf("the served process did not begin the deletion: POST /api/v1/admin/deletions answered status %d (RegisterDeletionRoutes must be registered next to RegisterActionRoutes in appcore)", beginStatus))
		case why != "":
			rows.add("lifecycle_deletion_saga_halts_stream", true, false, why)
		default:
			reread, _, _ := s.stream(analyst, orgA, projA, bigReplay)
			pollStatus, pollRaw, pollErr := owner.site.get("/api/v1/lifecycle/operations/" + deletionOp.String() + "?org=" + orgA.String())
			var polled httpapi.LifecycleOperation
			switch {
			case reread == 200:
				rows.add("lifecycle_deletion_saga_halts_stream", true, false, "the stream halted but the deleted project's replay is still readable afterwards")
			case pollErr != nil || pollStatus != 200 || json.Unmarshal(pollRaw, &polled) != nil || polled.State != httpapi.StateReady || polled.ID != deletionOp || (polled.Phase != model.DeletePhaseFencing && polled.Phase != model.DeletePhaseComplete):
				rows.add("lifecycle_deletion_saga_halts_stream", true, false, fmt.Sprintf("the stream halted but the lifecycle poll does not show the operation: status %d", pollStatus))
			default:
				rows.add("lifecycle_deletion_saga_halts_stream", true, true, fmt.Sprintf("retire_project begun over HTTPS (202 fencing): %d of 100 chunks delivered to the open reader, then one typed %s, nothing after; re-read answered %d; lifecycle poll phase %s", delivered, last, reread, polled.Phase))
			}
		}
	}
	if bk.err != "" {
		rows.add("restore_keeps_current_deletion_authority", true, false, "the pre-deletion backup could not be taken around the served process: "+bk.err)
	} else if deletionOp == (model.ID{}) {
		rows.add("restore_keeps_current_deletion_authority", true, false, "no deletion was begun over HTTPS, so there is no deletion authority to compare against the backup")
	} else {
		ok, why := s.restoreAfterDeletion(bk, owner, orgA, projA, deletionOp)
		rows.add("restore_keeps_current_deletion_authority", true, ok, why)
	}

	// Canaries: responses, process log and the whole data directory.
	s.stop()
	leaked := ""
	check := func(where string, raw []byte) {
		for name, c := range map[string]string{"source_content": evidenceCanaryMap, "replay_text": evidenceCanaryReplay, "error_message": evidenceCanaryMessage} {
			if bytes.Contains(raw, []byte(c)) && leaked == "" {
				leaked = name + " in " + where
			}
		}
	}
	for _, b := range s.bodies {
		check("a response", b)
	}
	check("the process log", []byte(s.logs.String()))
	if leaked != "" {
		rows.add("canary_responses_logs", true, false, leaked)
	} else {
		rows.add("canary_responses_logs", true, true, fmt.Sprintf("%d responses and the process log carry no canary", len(s.bodies)))
	}
	return rows
}

func truncate(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	return s
}

// evidenceChainSized builds n hash-chained closed-format chunks (checkpoints at 1 and
// 6), each carrying `events` masked pointer events.
func evidenceChainSized(replay model.ID, n, events int) []model.ReplayChunk {
	session := model.NewID()
	domain := model.ClockDomain{Host: model.NewID(), Boot: model.NewID(), Runtime: model.NewID()}
	var prev, cpHash model.Hash
	var cpSeq uint64
	out := make([]model.ReplayChunk, 0, n)
	for i := 1; i <= n; i++ {
		wall := model.UnixNano(time.Now().UnixNano())
		masked := make([]model.MaskedEvent, events)
		for k := range masked {
			masked[k] = model.MaskedEvent{At: model.MonoNano(wall) + model.MonoNano(k), Kind: "pointer", Node: 1, X: int32(i), Y: int32(k % 1000)}
		}
		c := model.ReplayChunk{Replay: replay, Session: session, Recorder: "1", Sequence: model.Uint64(i), Previous: prev, Clock: model.TraceClock{Wall: wall, Mono: model.MonoNano(i) * 1000, Domain: domain}, PolicyRevision: 1, Events: masked}
		checkpoint := i == 1 || i == 6
		if checkpoint {
			c.CheckpointSequence, c.Checkpoint = model.Uint64(i), prev
			c.Nodes = []model.MaskedNode{{ID: 1, Tag: "div", Class: "masked", Text: "[masked]"}, {ID: 2, Parent: 1, Tag: "button", Text: "[masked]"}}
		} else {
			c.CheckpointSequence, c.Checkpoint = model.Uint64(cpSeq), cpHash
		}
		h, _ := replays.ChunkHash(c)
		prev = h
		if checkpoint {
			cpSeq, cpHash = uint64(i), h
		}
		out = append(out, c)
	}
	return out
}

// realRecorderChain sends the chunks the real browser recorder emitted (fixtures/replays/recorder, generated by
// packages/browser/test/replay-wire.test.ts) through the real ingest route, one batch each and in order, then reads the
// replay back through the stream. Every chunk must be admitted by the closed Go validator without any conversion, and the
// stored chain must come back continuous with exactly the hashes the recorder computed in the browser.
func (s *evidenceServer) realRecorderChain(analyst *evidenceUser, org, project, source, producer model.ID, credential string, res model.Resource) (bool, string) {
	scenario, err := recorderfixtures.Load("session")
	if err != nil {
		return false, "recorder fixtures unreadable: " + err.Error()
	}
	chunks, err := scenario.Chunks()
	if err != nil {
		return false, "the closed Go schema refused the recorder's own chunks: " + err.Error()
	}
	hashes := make([]model.Hash, len(chunks))
	for i := range chunks {
		if hashes[i], err = replays.ChunkHash(chunks[i]); err != nil {
			return false, fmt.Sprintf("recorder chunk %d has no canonical hash", i+1)
		}
		rec := model.Record{ID: model.NewID(), Kind: model.Replay, ObservedAt: chunks[i].Clock.Wall, Resource: res, Payload: model.Payload{Replay: &chunks[i]}}
		b := model.Batch{Version: 1, Project: project, Source: source, Producer: producer, ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{rec}}
		if b.RouteSlot, err = model.OwnerSlot(org, project, source, producer, rec); err != nil {
			return false, fmt.Sprintf("recorder chunk %d has no owner slot", i+1)
		}
		if st, _ := s.sourcePost("/ingest/v1/batches", credential, b); st != 200 {
			return false, fmt.Sprintf("the real ingest route refused recorder chunk %d: status %d", i+1, st)
		}
	}
	status, lines, _ := s.stream(analyst, org, project, chunks[0].Replay)
	const want = "open C1 D2 D3 D4 C5 D6 end"
	if got := evidenceShape(lines); status != 200 || got != want {
		return false, fmt.Sprintf("the stored recorder replay did not read back as one continuous chain: status %d, stream %q, want %q", status, got, want)
	}
	for _, l := range lines {
		if (l.Type == "checkpoint" || l.Type == "delta") && (l.Sequence == nil || l.Hash == nil || *l.Sequence < 1 || int(*l.Sequence) > len(hashes) || *l.Hash != hashes[*l.Sequence-1]) {
			return false, "a stored recorder chunk came back with a hash other than the one the recorder computed"
		}
	}
	return true, fmt.Sprintf("%d chunks emitted by the real recorder admitted unconverted over the real route and read back as %q with the recorder's own chain hashes", len(chunks), want)
}

// midstreamHalt opens the replay with a tiny-receive-buffer client, reads three
// lines, runs the revocation, drains the rest and checks the halt: the stream must
// end with exactly one typed revoke whose reason is one of reasons, and nothing
// after it. why is empty on success.
func (s *evidenceServer) midstreamHalt(u *evidenceUser, org, project, replay model.ID, revoke func() error, reasons ...string) (delivered int, last string, why string) {
	base, ok := u.site.client.Transport.(*http.Transport)
	if !ok {
		return 0, "", "unexpected client transport"
	}
	tr := base.Clone()
	dialer := &net.Dialer{}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dialer.DialContext(ctx, network, addr)
		if err == nil {
			if tcp, ok := c.(*net.TCPConn); ok {
				_ = tcp.SetReadBuffer(4096)
			}
		}
		return c, err
	}
	client := &http.Client{Transport: tr, Jar: u.site.client.Jar}
	raw, _ := json.Marshal(httpapi.ReplayBody{ScopeFields: httpapi.ScopeFields{Org: org}, Project: project, Replay: replay})
	req, err := http.NewRequest("POST", u.site.base+"/api/v1/replays/stream", bytes.NewReader(raw))
	if err != nil {
		return 0, "", "request"
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", u.site.base)
	req.Header.Set("X-CSRF-Token", u.session.CSRF)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return 0, "", "the large replay was not readable before the revocation"
	}
	defer resp.Body.Close()
	br := bufio.NewReaderSize(resp.Body, 4096)
	var lines []httpapi.ReplayLine
	read := func() (httpapi.ReplayLine, []byte, bool) {
		raw, err := br.ReadBytes('\n')
		if len(raw) == 0 && err != nil {
			return httpapi.ReplayLine{}, nil, false
		}
		var l httpapi.ReplayLine
		if json.Unmarshal(raw, &l) != nil {
			return httpapi.ReplayLine{Type: "undecodable"}, raw, true
		}
		return l, raw, true
	}
	for range 3 {
		l, _, ok := read()
		if !ok {
			return 0, "", "the stream ended before the revocation"
		}
		lines = append(lines, l)
	}
	if lines[0].Type != "open" || lines[1].Type != "checkpoint" || lines[2].Type != "delta" {
		return 0, "", "unexpected first lines " + evidenceShape(lines)
	}
	if err = revoke(); err != nil {
		return 0, "", "the revocation command was refused"
	}
	for {
		l, raw, ok := read()
		if !ok {
			break
		}
		if bytes.Contains(raw, []byte(evidenceCanaryReplay)) {
			return 0, "", "a replay canary crossed the stream"
		}
		lines = append(lines, l)
	}
	end := lines[len(lines)-1]
	if end.Type != "revoke" || !slices.Contains(reasons, end.Reason) {
		return 0, "", fmt.Sprintf("the stream did not end with the typed revoke: last line %q (%s)", end.Type, end.Reason)
	}
	for i, l := range lines {
		switch l.Type {
		case "revoke":
			if i != len(lines)-1 {
				return 0, "", "lines after the typed revoke"
			}
		case "checkpoint", "delta":
			delivered++
		}
	}
	if delivered >= 100 {
		return 0, "", "the whole replay was delivered: nothing was halted"
	}
	return delivered, end.Type + " (" + end.Reason + ")", ""
}

func newInstallSiteLike(s *installSite) *installSite {
	cp := *s
	jar, _ := cookiejar.New(nil)
	cp.client = &http.Client{Transport: s.client.Transport, Jar: jar, Timeout: s.client.Timeout, CheckRedirect: s.client.CheckRedirect}
	return &cp
}

// evidenceBackup is the single-node backup made around the served process: key
// material lives in a 0700 temporary directory and never in a log or artifact.
type evidenceBackup struct {
	tmp, keyDir, authKeys, authDir, destDir, id string
	authFiles                                   int
	err                                         string
}

// cli runs the produced binary's subcommand and returns its stdout. The CLI's own
// failure lines carry a closed code and no key or input value.
func (s *evidenceServer) cli(env []string, args ...string) ([]byte, error) {
	cmd := exec.Command(s.exe, args...)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %s", args[0], args[1], strings.TrimSpace(truncate(stderr.Bytes())))
	}
	return out, nil
}

// takeBackup stops the served process (backup create opens the installation
// exclusively) and runs keygen, authority-keygen, authority-init and create.
func (s *evidenceServer) takeBackup(email, password string) *evidenceBackup {
	bk := &evidenceBackup{}
	s.halt()
	tmp, err := os.MkdirTemp("", "soundpost-evidence-backup-")
	if err != nil {
		bk.err = err.Error()
		return bk
	}
	bk.tmp = tmp
	bk.keyDir, bk.authKeys, bk.authDir, bk.destDir = filepath.Join(tmp, "keys"), filepath.Join(tmp, "authority.keys"), filepath.Join(tmp, "authority"), filepath.Join(tmp, "dest")
	if err = os.MkdirAll(bk.keyDir, 0o700); err != nil {
		bk.err = err.Error()
		return bk
	}
	steps := [][]string{
		{"backup", "keygen", "--key-dir", bk.keyDir, "--id", "evidence-data-kek"},
		{"backup", "keygen", "--key-dir", bk.keyDir, "--id", "evidence-secret-kek"},
		{"backup", "authority-keygen", "--out", bk.authKeys, "--id", "evidence-authority"},
		{"backup", "authority-init", "--data-dir", s.dir, "--authority-keys", bk.authKeys, "--authority-dir", bk.authDir},
	}
	for _, step := range steps {
		if _, err = s.cli(nil, step...); err != nil {
			bk.err = err.Error()
			return bk
		}
	}
	out, err := s.cli([]string{"SOUNDPOST_ADMIN_PASSWORD=" + password}, "backup", "create", "--data-dir", s.dir, "--admin-email", email, "--key-dir", bk.keyDir,
		"--data-kek", "evidence-data-kek", "--secret-kek", "evidence-secret-kek", "--authority-keys", bk.authKeys, "--authority-dir", bk.authDir, "--dest-dir", bk.destDir)
	if err != nil {
		bk.err = err.Error()
		return bk
	}
	var report struct {
		BackupID string `json:"backup_id"`
	}
	if json.Unmarshal(out, &report) != nil || report.BackupID == "" {
		bk.err = "backup create printed no backup id"
		return bk
	}
	bk.id = report.BackupID
	bk.authFiles = evidenceCountFiles(bk.authDir)
	return bk
}

// restartAfterBackup serves the same installation again. When the backup was made, the
// full authority keys and the authority journal the backup bound are given to serve, so
// the deletions it runs checkpoint to the same authority a restore reads.
func (s *evidenceServer) restartAfterBackup(bk *evidenceBackup) error {
	if bk.err == "" {
		s.serveArgs = append(s.serveArgs, "--authority-keys", bk.authKeys, "--authority-dir", bk.authDir)
	}
	return s.restart()
}

// evidenceOrgView reads the organizations view as the (instance owner) caller.
func (s *evidenceServer) evidenceOrgView(u *evidenceUser, org, project model.ID) (orgPresent, projectPresent bool, orgs int, err error) {
	status, raw, err := u.site.post("/api/v1/admin/read", struct {
		Kind string `json:"kind"`
	}{"organizations"}, u.session.CSRF, "")
	if err != nil || status != 200 {
		return false, false, 0, fmt.Errorf("admin read answered status %d", status)
	}
	var view auth.AdminView
	if err = json.Unmarshal(raw, &view); err != nil {
		return false, false, 0, err
	}
	for _, o := range view.Organizations {
		if o.ID == org {
			orgPresent = true
			_, projectPresent = o.Projects[project.String()]
		}
	}
	return orgPresent, projectPresent, len(view.Organizations), nil
}

func evidencePollOperation(u *evidenceUser, org, op model.ID) (httpapi.LifecycleOperation, int) {
	var polled httpapi.LifecycleOperation
	status, raw, err := u.site.get("/api/v1/lifecycle/operations/" + op.String() + "?org=" + org.String())
	if err != nil || json.Unmarshal(raw, &polled) != nil {
		return httpapi.LifecycleOperation{}, status
	}
	return polled, status
}

// restoreAfterDeletion waits for the deletion to complete on the live installation,
// stops it, restores the PRE-deletion backup into a fresh root, activates it, serves
// it and reports what the restored installation shows for the deleted project. It
// returns satisfied only when the project stays gone and the operation is visible.
func (s *evidenceServer) restoreAfterDeletion(bk *evidenceBackup, owner *evidenceUser, org, project, op model.ID) (bool, string) {
	var live httpapi.LifecycleOperation
	for deadline := time.Now().Add(90 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		live, _ = evidencePollOperation(owner, org, op)
		if live.Phase == model.DeletePhaseComplete {
			break
		}
	}
	if live.Phase != model.DeletePhaseComplete {
		return false, fmt.Sprintf("the deletion did not reach complete on the served process within 90s (phase %q)", live.Phase)
	}
	liveOrg, liveProject, liveOrgs, err := s.evidenceOrgView(owner, org, project)
	if err != nil {
		return false, "live organizations view after the deletion: " + err.Error()
	}
	s.halt()
	root := filepath.Join(bk.tmp, "restored")
	common := []string{"--authority-keys", bk.authKeys, "--authority-dir", bk.authDir}
	restoreOut, err := s.cli(nil, append([]string{"backup", "restore", "--backup-id", bk.id, "--root", root, "--key-dir", bk.keyDir, "--dest-dir", bk.destDir}, common...)...)
	if err != nil {
		return false, "restore of the pre-deletion backup failed: " + err.Error()
	}
	var restoreReport struct {
		Tombstones int `json:"tombstones"`
	}
	_ = json.Unmarshal(restoreOut, &restoreReport)
	restoredTombstones := restoreReport.Tombstones
	if _, err = s.cli(nil, append([]string{"backup", "activate", "--root", root}, common...)...); err != nil {
		return false, "activation of the restored root failed: " + err.Error()
	}
	restored, err := startEvidenceServerIn(s.exe, root)
	if err != nil {
		return false, "the restored root did not serve: " + err.Error()
	}
	defer restored.stop()
	token, err := os.ReadFile(filepath.Join(root, "bootstrap.token"))
	if err != nil {
		return false, "the restored root has no recovery bootstrap token"
	}
	recovered := &evidenceUser{site: restored.site}
	status, raw, err := recovered.site.post("/api/v1/bootstrap", map[string]string{"Token": string(token), "Email": "recovery@evidence-smoke.invalid", "Password": "evidence smoke recovery password 2026"}, "", "")
	if err != nil || status != 200 || json.Unmarshal(raw, &recovered.session) != nil {
		return false, fmt.Sprintf("recovery bootstrap on the restored root refused: status %d", status)
	}
	rOrg, rProject, rOrgs, err := restored.evidenceOrgView(recovered, org, project)
	if err != nil {
		return false, "restored organizations view: " + err.Error()
	}
	polled, pollStatus := evidencePollOperation(recovered, org, op)
	visible := pollStatus == 200 && polled.ID == op && polled.State == httpapi.StateReady
	facts := fmt.Sprintf("live after the deletion: org present=%v project present=%v (%d organizations listed), operation phase %s; authority journal files %d at the backup, %d after the deletion; restore of the pre-deletion backup reported %d tombstones and activated; restored recovery view: org present=%v project present=%v, %d organizations listed, operation lookup status %d visible=%v", liveOrg, liveProject, liveOrgs, live.Phase, bk.authFiles, evidenceCountFiles(bk.authDir), restoredTombstones, rOrg, rProject, rOrgs, pollStatus, visible)
	if rOrgs == 0 && liveOrgs > 0 {
		facts += " (the recovery admin sees none of the " + fmt.Sprint(liveOrgs) + " organizations, including the one that was never deleted: restore quarantine hides every organization until reconciled, so the view says nothing about the deleted project; the deletion is observed through the authority journal and the restore's tombstone count, and the readable-rows check is the in-process restore test)"
	}
	switch {
	case evidenceCountFiles(bk.authDir) <= bk.authFiles:
		return false, "PRODUCT DEFECT: the served process never checkpointed the completed deletion to the restore authority, so the authority the restore reads cannot hold it; " + facts
	case restoredTombstones < 1:
		return false, "PRODUCT DEFECT: the authority journal grew but the restore of the older backup applied no tombstone; " + facts
	case rProject:
		return false, "PRODUCT DEFECT: the restored installation holds the project whose deletion had completed (the older backup won over the current deletion authority); " + facts
	}
	return true, "the served deletion checkpointed to the restore authority (journal grew) and restoring the PRE-deletion backup applied that tombstone and activated; the deleted project is absent from the restored installation; " + facts
}

// evidenceCountFiles counts the regular files below dir (the authority journal's records).
func evidenceCountFiles(dir string) int {
	n := 0
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	return n
}
