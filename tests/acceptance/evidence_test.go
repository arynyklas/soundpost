// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package acceptance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/backup"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
	"github.com/arynyklas/soundpost/internal/policy"
	"github.com/arynyklas/soundpost/internal/profiles"
	"github.com/arynyklas/soundpost/internal/replays"
	"github.com/arynyklas/soundpost/internal/retention"
	"github.com/arynyklas/soundpost/internal/symbolicate"
)

// TestEvidenceRealFrameReplayAndScopeLifecycle is the 09.06 acceptance over a REAL
// in-process node: appcore.Open (real control Raft group, auth, C03 admission, C05
// storage, artifact service, retention saga) served over real HTTPS by
// httpapi.NewServer(..., app.Register). Every read and write below goes through the
// committed scope-first HTTP routes with a real session cookie and CSRF binding.
//
// What is real: the multipart artifact upload, the Vite-generated map and its
// thrown position (fixtures/artifacts), the OCI symbolication sandbox (when the
// local qualification image is usable), replay chunks through the closed format
// the Go validator accepts and the real ingest route, the nativeperf assembler and
// exporter, the retention deletion saga, the backup/restore/authority drill.
//
// What is NOT real, and each is recorded as an unsatisfied row (never as success):
//   - the browser recorder's own chunks (the closed format refuses them: a known
//     cross-language gap), so the replay here is hand-chained through the closed format;
//   - an SDK profile (no SDK profile reaches the backend); the profile is the real
//     assembler/exporter fed constructed sanitized events, not perf-captured samples;
//   - an issue grouped from the ingested occurrence (nothing turns an admitted
//     occurrence into a GroupingIssue);
//   - replay and profile investigation links (investigate answers grant_not_built).
//
// The fixture directory comes from SOUNDPOST_SOURCEMAP_FIXTURE_DIR (the output of
// `node fixtures/artifacts/generate.mjs <dir>`): a missing fixture is a failure,
// never a skip.
func TestEvidenceRealFrameReplayAndScopeLifecycle(t *testing.T) {
	var logs syncLog
	prevOut := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prevOut)

	n := newEvNode(t)
	r := &evReport{}
	defer func() { r.log(t) }()

	n.artifactRows(r)
	n.errorRows(r)
	n.frameRows(r)
	n.releaseIssueRows(r)
	n.traceInvestigateRows(r)
	n.replayRows(r)
	n.profileRows(r)
	n.isolationRows(r)
	n.backupRow(r)
	n.revokeStreamRow(r)
	n.deleteStreamRow(r)
	n.restoreRows(r)
	n.restoreProbeRow(r)
	n.canaryRows(r, &logs)
}

// ---------------------------------------------------------------------------
// report

type evRow struct {
	ID        string
	Required  bool
	Satisfied bool
	Reason    string
}
type evReport struct {
	mu   sync.Mutex
	rows []evRow
}

func (r *evReport) add(id string, required, ok bool, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows = append(r.rows, evRow{id, required, ok, reason})
}
func (r *evReport) log(t *testing.T) {
	t.Helper()
	for _, row := range r.rows {
		state := "SATISFIED"
		if !row.Satisfied {
			state = "NOT SATISFIED"
		}
		kind := "required"
		if !row.Required {
			kind = "optional"
		}
		t.Logf("row %-40s %-8s %-13s %s", row.ID, kind, state, row.Reason)
	}
}

type syncLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncLog) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncLog) bytes() []byte { s.mu.Lock(); defer s.mu.Unlock(); return slices.Clone(s.b.Bytes()) }

// ---------------------------------------------------------------------------
// node

type evPerson struct {
	id      model.ID
	email   string
	session auth.Session
	cred    auth.Credential
}

type evNode struct {
	t   *testing.T
	ctx context.Context
	dir string
	app *appcore.App
	srv *httptest.Server

	authority *backup.Authority
	authKeys  backup.AuthorityKeys
	keyDir    string
	offhost   string
	authDir   string
	backups   *backup.Service
	manifest  backup.BackupManifest

	owner                    evPerson
	orgA, orgB, projA, projB model.ID
	srcA, srcB               model.ID
	credA, credB             string
	srcCredA                 auth.SourceCredential
	analyst, plain, adminA   evPerson
	outsider                 evPerson
	revoker, deleter         evPerson
	res                      model.Resource

	sandbox       symbolicate.Config
	sandboxWhy    string
	fixtureDir    string
	mapBytes      []byte // what was uploaded (sourcesContent canary included)
	generated     []byte
	position      struct{ GeneratedLine, GeneratedColumn uint32 }
	debugID       string
	artifact      model.ArtifactReferenceIntent
	artifactB     model.ArtifactReferenceIntent
	errorBatch    model.Batch
	errorReceipt  model.Receipt
	errorTrace    model.ID
	frame         model.Frame
	smallReplay   model.ID
	bigReplay     model.ID
	bigChunks     int
	profileRoot   model.ID
	profileWall   model.UnixNano
	replayBatches []model.Batch
	releaseID     model.ID

	canaryMap, canaryReplay, canaryMessage, canaryControl string

	mu        sync.Mutex
	responses [][]byte
}

func evHex(prefix string) string { return prefix + model.NewID().String() }

func faultIs(err error, code model.Code) bool {
	var f *model.Fault
	return errors.As(err, &f) && f.Code == code
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

func newEvNode(t *testing.T) *evNode {
	t.Helper()
	n := &evNode{t: t, ctx: context.Background(), dir: t.TempDir(), orgA: model.NewID(), orgB: model.NewID(), projA: model.NewID(), projB: model.NewID(), srcA: model.NewID(), srcB: model.NewID(),
		canaryMap: evHex("EVIDENCE-SOURCESCONTENT-CANARY-"), canaryReplay: evHex("EVIDENCE-REPLAY-TEXT-CANARY-"), canaryMessage: evHex("EVIDENCE-ERROR-MESSAGE-CANARY-"), canaryControl: evHex("evidence_control_")}
	n.fixtureDir = os.Getenv("SOUNDPOST_SOURCEMAP_FIXTURE_DIR")
	if n.fixtureDir == "" {
		t.Fatal("SOUNDPOST_SOURCEMAP_FIXTURE_DIR is required: run `node fixtures/artifacts/generate.mjs <dir>` and point the variable at <dir> (a missing real fixture is a failure, not a skip)")
	}
	var err error
	if n.generated, err = os.ReadFile(filepath.Join(n.fixtureDir, "simple.mjs")); err != nil {
		t.Fatal(err)
	}
	rawMap, err := os.ReadFile(filepath.Join(n.fixtureDir, "simple.mjs.map"))
	if err != nil {
		t.Fatal(err)
	}
	rawPos, err := os.ReadFile(filepath.Join(n.fixtureDir, "simple.position.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(rawPos, &n.position); err != nil || n.position.GeneratedLine == 0 {
		t.Fatalf("fixture position unreadable: %v", err)
	}
	// The real generated map carries no source content. Add the canary the policy
	// must strip: the manifest says no private sources.
	var m map[string]any
	if err = json.Unmarshal(rawMap, &m); err != nil {
		t.Fatal(err)
	}
	sources, _ := m["sources"].([]any)
	content := make([]any, len(sources))
	for i := range content {
		content[i] = "// " + n.canaryMap + "\nexport const secret" + fmt.Sprint(i) + " = 1;\n"
	}
	m["sourcesContent"] = content
	if n.mapBytes, err = json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	n.debugID = evHex("evidence-debug-")

	n.sandbox, n.sandboxWhy = evSandboxConfig()
	n.app, err = appcore.Open(filepath.Join(n.dir, "live"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if n.app != nil {
			n.app.Close()
		}
	})
	sym, err := n.app.NewSymbolicator(n.sandbox)
	if err != nil {
		t.Fatal(err)
	}
	// The wiring the parent must add to appcore.Open: see docs/acceptance/evidence.md.
	n.app.Evidence = httpapi.NewEvidence(sym, n.app.Releases, n.app.Releases)
	n.serve(n.app)
	n.setupAuthority()
	n.setupTenants()
	return n
}

func (n *evNode) serve(app *appcore.App) {
	n.t.Helper()
	if n.srv != nil {
		n.srv.Close()
	}
	n.srv = httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, app.Register).Handler)
	n.t.Cleanup(n.srv.Close)
}

// evSandboxConfig derives the operator sandbox configuration from the documented
// OCI qualification image. It returns the empty configuration (no mode selected:
// the service answers a typed sandbox_unavailable per frame) and the exact reason
// when the runtime or image cannot be used.
func evSandboxConfig() (symbolicate.Config, string) {
	docker, err := exec.LookPath("docker")
	if err != nil {
		return symbolicate.Config{}, "no docker runtime on PATH"
	}
	tag := os.Getenv("SOUNDPOST_SYMBOLICATE_IMAGE")
	if tag == "" {
		tag = "soundpost-symbolicate:qualification"
	}
	out, err := exec.Command(docker, "image", "inspect", "--format", `{{.Id}} {{index .Config.Labels "org.soundpost.worker.sha256"}}`, tag).Output()
	if err != nil {
		return symbolicate.Config{}, "local image " + tag + " is not present"
	}
	fields := strings.Fields(string(out))
	if len(fields) != 2 || !strings.HasPrefix(fields[0], "sha256:") {
		return symbolicate.Config{}, "image " + tag + " has no worker provenance label"
	}
	var h model.Hash
	if err = json.Unmarshal([]byte(`"`+fields[1]+`"`), &h); err != nil {
		return symbolicate.Config{}, "image worker label is not a hash"
	}
	return symbolicate.Config{Mode: "oci", OCIRuntime: docker, OCIImage: fields[0], WorkerSHA256: h}, ""
}

// ---------------------------------------------------------------------------
// admin / people

func (n *evNode) cmd(org model.ID, kind string, p auth.AdminPayload) {
	n.t.Helper()
	var revision model.Revision
	if err := n.app.Control.View(n.ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
		n.t.Fatal(err)
	}
	p.Reason = "evidence acceptance"
	raw, _ := json.Marshal(p)
	if _, err := n.app.Auth.AdminCommand(n.ctx, n.owner.cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); err != nil {
		n.t.Fatalf("admin %s: %v", kind, err)
	}
}

const evPassword = "evidence acceptance reader 2026"

func (n *evNode) user(org model.ID, label string) evPerson {
	n.t.Helper()
	id := model.NewID()
	email := label + "-" + id.String()[:8] + "@example.test"
	n.cmd(org, "create_user", auth.AdminPayload{ID: id, Email: email, Password: evPassword})
	n.cmd(org, "membership", auth.AdminPayload{UserID: id, Enabled: true})
	return n.login(evPerson{id: id, email: email})
}

func (n *evNode) login(p evPerson) evPerson {
	n.t.Helper()
	s, err := n.app.Auth.Login(n.ctx, p.email, evPassword, "")
	if err != nil {
		n.t.Fatal(err)
	}
	c, err := n.app.Auth.Authenticate(n.ctx, s.Token)
	if err != nil {
		n.t.Fatal(err)
	}
	p.session, p.cred = s, c
	return p
}

func (n *evNode) grant(org model.ID, p evPerson, project model.ID, enabled bool, perms ...auth.Permission) {
	n.t.Helper()
	ps := make([]string, len(perms))
	for i, v := range perms {
		ps[i] = string(v)
	}
	n.cmd(org, "grant", auth.AdminPayload{UserID: p.id, ProjectID: project, Enabled: enabled, Permissions: ps})
}

func (n *evNode) setupAuthority() {
	n.t.Helper()
	n.keyDir, n.offhost, n.authDir = filepath.Join(n.dir, "keys"), filepath.Join(n.dir, "offhost"), filepath.Join(n.dir, "authority")
	for _, id := range []string{"evidence-data-kek", "evidence-secret-kek"} {
		k, err := backup.GenerateKey(id)
		if err != nil {
			n.t.Fatal(err)
		}
		if err = backup.WriteKeyFile(n.keyDir, k); err != nil {
			n.t.Fatal(err)
		}
	}
	var err error
	if n.authKeys, err = backup.GenerateAuthorityKeys("evidence-authority"); err != nil {
		n.t.Fatal(err)
	}
	dest, err := backup.NewLocalDestination(n.authDir)
	if err != nil {
		n.t.Fatal(err)
	}
	if n.authority, err = backup.NewAuthority(dest, n.authKeys, time.Now); err != nil {
		n.t.Fatal(err)
	}
	var installation model.ID
	if err = n.app.Control.View(n.ctx, func(st control.State) error { installation = st.Installation; return nil }); err != nil {
		n.t.Fatal(err)
	}
	if _, err = n.authority.Initialize(n.ctx, installation); err != nil {
		n.t.Fatal(err)
	}
	if err = n.app.Retention.UseAuthority(n.authority); err != nil {
		n.t.Fatal(err)
	}
	plane := backup.EngineDataPlane(n.app.Storage)
	if n.backups, err = backup.New(backup.Config{Control: n.app.Control, Data: plane, Processed: backup.AppliedProcessed(plane), Authority: n.authority, Authorizer: n.app.Auth, Keys: backup.KeyDir(n.keyDir), DataKEK: "evidence-data-kek", SecretKEK: "evidence-secret-kek", Attempts: backup.DirAttempts(filepath.Join(n.dir, "live", "backup-attempts")), Clock: time.Now}); err != nil {
		n.t.Fatal(err)
	}
}

var evKinds = []model.Kind{model.ErrorKind, model.SpanKind, model.Replay, model.Profile, model.CapabilityKind, model.Loss, model.Metric}

func (n *evNode) setupTenants() {
	n.t.Helper()
	boot, err := n.app.Control.BootstrapToken()
	if err != nil {
		n.t.Fatal(err)
	}
	s, err := n.app.Auth.Bootstrap(n.ctx, boot, "evidence-owner@example.test", "evidence owner password 2026")
	if err != nil {
		n.t.Fatal(err)
	}
	c, err := n.app.Auth.Authenticate(n.ctx, s.Token)
	if err != nil {
		n.t.Fatal(err)
	}
	n.owner = evPerson{id: s.User, session: s, cred: c}
	for _, o := range []struct{ org, project model.ID }{{n.orgA, n.projA}, {n.orgB, n.projB}} {
		n.cmd(o.org, "create_org", auth.AdminPayload{Name: "evidence"})
		n.cmd(o.org, "create_project", auth.AdminPayload{ID: o.project, Name: "web"})
	}
	all := []auth.Permission{auth.Read, auth.ArtifactRead, auth.ArtifactWrite, httpapi.ReplayRead, httpapi.ProfilesRead}
	n.analyst = n.user(n.orgA, "analyst")
	n.grant(n.orgA, n.analyst, n.projA, true, all...)
	n.revoker = n.user(n.orgA, "revoker")
	n.grant(n.orgA, n.revoker, n.projA, true, auth.Read, httpapi.ReplayRead)
	n.deleter = n.user(n.orgA, "deleter")
	n.grant(n.orgA, n.deleter, n.projA, true, auth.Read, httpapi.ReplayRead)
	n.plain = n.user(n.orgA, "plain")
	n.grant(n.orgA, n.plain, n.projA, true, auth.Read)
	n.adminA = n.user(n.orgA, "admin")
	n.cmd(n.orgA, "org_admin", auth.AdminPayload{UserID: n.adminA.id, Enabled: true})
	n.outsider = n.user(n.orgB, "outsider")
	n.grant(n.orgB, n.outsider, n.projB, true, all...)

	// The SAME service/environment/build identities in both organizations: only the
	// organization scope separates them.
	n.res = model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "evidence-1", Labels: model.Labels{}}
	onboard := func(org, project, source model.ID) string {
		cfg, _ := json.Marshal(auth.SourcePolicyConfig{ProjectID: project, Enabled: true})
		n.cmd(org, "source_policy", auth.AdminPayload{ID: source, Config: cfg})
		pol := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: evKinds, Replay: true,
			Resources:  model.ResourceRegistry{Services: []model.ID{n.res.Service}, Environments: []model.ID{n.res.Environment}, Builds: []model.ID{n.res.Build}, Instances: []string{n.res.Instance}},
			Operations: []string{"operation"}, RetentionDays: map[model.Kind]uint32{}, MaxBytes: 1 << 30, MaxSeries: 100}
		for _, k := range evKinds {
			pol.RetentionDays[k] = 14
		}
		issued, err := n.app.Auth.OnboardSource(n.ctx, n.owner.cred, auth.SourceOnboarding{CommandID: model.NewID(), Org: org, Project: project, Source: source, Expires: model.UnixNano(time.Now().Add(6 * time.Hour).UnixNano()), Policy: pol, Reason: "evidence acceptance"})
		if err != nil {
			n.t.Fatal(err)
		}
		return issued.Credential
	}
	n.credA = onboard(n.orgA, n.projA, n.srcA)
	n.credB = onboard(n.orgB, n.projB, n.srcB)
	if n.srcCredA, err = n.app.Auth.AuthenticateSource(n.ctx, n.credA, "", false); err != nil {
		n.t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// HTTP

var evRequestID = regexp.MustCompile(`"request_id":"[0-9a-f]{32}"`)

type evResp struct {
	status int
	body   []byte
}

func (n *evNode) remember(raw []byte) {
	n.mu.Lock()
	n.responses = append(n.responses, slices.Clone(raw))
	n.mu.Unlock()
}

func (n *evNode) request(who evPerson, method, path, contentType string, body []byte) evResp {
	n.t.Helper()
	req, err := http.NewRequest(method, n.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		n.t.Fatal(err)
	}
	if who.session.Token != "" {
		req.Header.Set("Cookie", "__Host-soundpost="+who.session.Token)
		req.Header.Set("X-CSRF-Token", who.session.CSRF)
	}
	req.Header.Set("Origin", n.srv.URL)
	req.Header.Set("Content-Type", contentType)
	resp, err := n.srv.Client().Do(req)
	if err != nil {
		n.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		n.t.Fatal(err)
	}
	n.remember(raw)
	return evResp{resp.StatusCode, raw}
}

func (n *evNode) post(who evPerson, path string, v any) evResp {
	n.t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		n.t.Fatal(err)
	}
	return n.request(who, "POST", path, "application/json", raw)
}

// sourcePost sends a JSON body to an ingest route with a source credential.
func (n *evNode) sourcePost(path, credential string, raw []byte) evResp {
	n.t.Helper()
	req, _ := http.NewRequest("POST", n.srv.URL+path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.srv.Client().Do(req)
	if err != nil {
		n.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	n.remember(out)
	return evResp{resp.StatusCode, out}
}

func (n *evNode) ingest(credential string, raw []byte) evResp {
	return n.sourcePost("/ingest/v1/batches", credential, raw)
}

func (n *evNode) receiptLookup(credential string, q model.ReceiptRequest) evResp {
	raw, _ := json.Marshal(q)
	return n.sourcePost("/ingest/v1/receipts", credential, raw)
}

func (n *evNode) batchFor(project, source, org, producer model.ID, rec model.Record) model.Batch {
	n.t.Helper()
	b := model.Batch{Version: 1, Project: project, Source: source, Producer: producer, ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{rec}}
	var err error
	if b.RouteSlot, err = model.OwnerSlot(org, project, source, producer, rec); err != nil {
		n.t.Fatal(err)
	}
	return b
}

// evNorm erases the per-request correlation ID and the named identities, so two
// answers can be compared byte for byte.
func evNorm(raw []byte, ids ...model.ID) string {
	s := evRequestID.ReplaceAllString(string(raw), `"request_id":"X"`)
	for i, id := range ids {
		s = strings.ReplaceAll(s, id.String(), fmt.Sprintf("<id%d>", i))
	}
	return s
}

// ---------------------------------------------------------------------------
// rows: artifact

func (n *evNode) manifest0(org, project, source model.ID) model.ArtifactManifest {
	return model.ArtifactManifest{Version: 1, Org: org, Project: project, Source: source, Build: n.res.Build, DebugID: n.debugID,
		GeneratedSHA256: model.HashCanonical(n.generated), MapSHA256: model.HashCanonical(n.mapBytes), Path: "dist/simple.mjs", SourceContent: false,
		Size: model.Uint64(len(n.mapBytes)), RetainUntil: model.UnixNano(time.Now().Add(6 * time.Hour).UnixNano())}
}

func (n *evNode) upload(who evPerson, m model.ArtifactManifest, file []byte) evResp {
	n.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	raw, _ := json.Marshal(m)
	w, _ := mw.CreateFormField("manifest")
	w.Write(raw)
	w, _ = mw.CreateFormFile("file", "simple.mjs.map")
	w.Write(file)
	mw.Close()
	return n.request(who, "POST", "/api/v1/artifacts", mw.FormDataContentType(), buf.Bytes())
}

func (n *evNode) readArtifact(who evPerson, org, project, id model.ID, op string) evResp {
	return n.post(who, "/api/v1/artifacts", httpapi.ArtifactReadRequest{Operation: op, Org: org, Project: project, ID: id})
}

func (n *evNode) artifactRows(r *evReport) {
	t := n.t
	t.Helper()
	m := n.manifest0(n.orgA, n.projA, n.srcA)
	up := n.upload(n.analyst, m, n.mapBytes)
	if up.status != 200 {
		t.Fatalf("artifact upload over the real multipart route: %d %s", up.status, up.body)
	}
	if err := json.Unmarshal(up.body, &n.artifact); err != nil || n.artifact.ID == (model.ID{}) || n.artifact.Manifest.Build != n.res.Build || n.artifact.Manifest.DebugID != n.debugID {
		t.Fatalf("upload receipt is not the exact scoped manifest: %v %s", err, up.body)
	}
	n.frame = model.Frame{Module: "simple.mjs", Function: "throwingFixture_" + n.canaryControl, Artifact: n.artifact.ID.String(), Line: n.position.GeneratedLine, Column: &n.position.GeneratedColumn, InApp: true}
	read := n.readArtifact(n.analyst, n.orgA, n.projA, n.artifact.ID, "read")
	if read.status != 200 {
		t.Fatalf("authorized map read: %d %s", read.status, read.body)
	}
	if bytes.Contains(read.body, []byte(n.canaryMap)) || bytes.Contains(up.body, []byte(n.canaryMap)) {
		t.Fatal("source content crossed the artifact policy: the stored/returned map carries sourcesContent")
	}
	var stored map[string]any
	if err := json.Unmarshal(read.body, &stored); err != nil || stored["mappings"] == nil || stored["sourcesContent"] != nil {
		t.Fatalf("stored map is not the stripped real map: %v", err)
	}
	if src := n.readArtifact(n.analyst, n.orgA, n.projA, n.artifact.ID, "sources"); src.status != 404 || bytes.Contains(src.body, []byte(n.canaryMap)) {
		t.Fatalf("private-source read of an artifact without private sources: %d %s", src.status, src.body)
	}
	if plain := n.readArtifact(n.plain, n.orgA, n.projA, n.artifact.ID, "read"); plain.status == 200 {
		t.Fatalf("a telemetry-only user read the map: %d", plain.status)
	}
	r.add("artifact_upload_read_policy", true, true, "real multipart upload of the Vite map; sourcesContent stripped; sources read refused; telemetry-only reader refused")
}

// ---------------------------------------------------------------------------
// rows: error occurrence

func (n *evNode) errorRows(r *evReport) {
	t := n.t
	t.Helper()
	n.errorTrace = model.NewID()
	var span model.SpanID
	span[0] = 7
	now := time.Now().UnixNano()
	clock := model.TraceClock{Wall: model.UnixNano(now - int64(3*time.Second)), Mono: 1, Domain: model.ClockDomain{Host: model.NewID(), Boot: model.NewID(), Runtime: model.NewID()}}
	end := clock
	end.Wall += model.UnixNano(100 * time.Millisecond)
	end.Mono += model.MonoNano(100 * time.Millisecond)
	n.smallReplay, n.bigReplay, n.profileRoot = model.NewID(), model.NewID(), model.NewID()
	occ := model.ErrorOccurrence{Occurrence: model.NewID(), Class: "TypeError", Mechanism: "manual", Build: n.res.Build, Handled: false, Fatal: true,
		Frames: []model.Frame{n.frame}, Trace: &n.errorTrace, Span: &span, Replay: &n.smallReplay, Profile: &n.profileRoot}
	producer := model.NewID()
	rec := model.Record{ID: model.NewID(), Kind: model.ErrorKind, ObservedAt: model.UnixNano(now - int64(2*time.Second)), Resource: n.res, Payload: model.Payload{Error: &occ}}
	n.errorBatch = n.batchFor(n.projA, n.srcA, n.orgA, producer, rec)
	raw, _ := json.Marshal(n.errorBatch)
	got := n.ingest(n.credA, raw)
	if got.status != 200 {
		t.Fatalf("real error occurrence refused by the ingest route: %d %s", got.status, got.body)
	}
	if err := json.Unmarshal(got.body, &n.errorReceipt); err != nil || n.errorReceipt.Cursor.Index == 0 {
		t.Fatalf("error receipt: %v", err)
	}
	// The matching span of the same trace.
	spanRec := model.Record{ID: model.NewID(), Kind: model.SpanKind, ObservedAt: model.UnixNano(now - int64(3*time.Second)), Resource: n.res, Payload: model.Payload{Span: &model.Span{Trace: n.errorTrace, ID: span, Kind: "internal", Operation: "operation", Start: clock, End: &end, Status: "error", SampleProbability: model.FloatBits(0x3ff0000000000000), SampleDecision: "keep"}}}
	sb := n.batchFor(n.projA, n.srcA, n.orgA, producer, spanRec)
	raw, _ = json.Marshal(sb)
	if got = n.ingest(n.credA, raw); got.status != 200 {
		t.Fatalf("span of the error's trace refused: %d %s", got.status, got.body)
	}
	// One metric series: a restore of a project with admitted batches but no metric
	// series is refused (see restoreProbeRow); the journey needs a restorable project.
	value := model.FloatBits(math.Float64bits(42.5))
	metricRec := model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(now - int64(5*time.Second)), Resource: n.res, Payload: model.Payload{Metric: &model.MetricPoint{Name: "evidence_requests", Labels: model.Labels{}, SampleKind: "float", Value: &value, Unit: "1", Type: "gauge"}}}
	mb := n.batchFor(n.projA, n.srcA, n.orgA, producer, metricRec)
	raw, _ = json.Marshal(mb)
	if got = n.ingest(n.credA, raw); got.status != 200 {
		t.Fatalf("metric refused: %d %s", got.status, got.body)
	}
	// An error message is not a representable field: a message-bearing payload must
	// be refused, and the canary must not be echoed.
	bad := model.Batch{Version: 1, Project: n.projA, Source: n.srcA, Producer: producer, ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.ErrorKind, ObservedAt: rec.ObservedAt, Resource: n.res, Payload: model.Payload{Error: &model.ErrorOccurrence{Occurrence: model.NewID(), Class: "TypeError", Mechanism: "manual", Build: n.res.Build, Frames: []model.Frame{}}}}}}
	raw, _ = json.Marshal(bad)
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	injected := 0
	if records, ok := generic["records"].([]any); ok {
		for _, rr := range records {
			if rm, ok := rr.(map[string]any); ok {
				if pl, ok := rm["payload"].(map[string]any); ok {
					pl["message"] = n.canaryMessage
					injected++
				}
			}
		}
	}
	if injected != 1 {
		t.Fatalf("could not place the message canary in the wire payload (%d)", injected)
	}
	raw, _ = json.Marshal(generic)
	if refused := n.ingest(n.credA, raw); refused.status == 200 || bytes.Contains(refused.body, []byte(n.canaryMessage)) {
		t.Fatalf("an error message field was admitted or echoed: %d %s", refused.status, refused.body)
	}
	r.add("error_occurrence_ingest", true, true, "real occurrence with exact build + artifact frame ingested over HTTPS; matching span ingested; message-bearing payload refused without echo")
}

// ---------------------------------------------------------------------------
// rows: frames (sandbox)

func (n *evNode) frames(who evPerson, org, project, build model.ID, includeSources bool, frames ...model.Frame) (evResp, httpapi.FramesView) {
	n.t.Helper()
	got := n.post(who, "/api/v1/evidence/frames", httpapi.FramesBody{Org: org, Project: project, Build: build, Frames: frames, IncludeSources: includeSources})
	var v httpapi.FramesView
	if got.status == 200 {
		if err := json.Unmarshal(got.body, &v); err != nil {
			n.t.Fatalf("not a frames view: %v %s", err, got.body)
		}
	}
	return got, v
}

// framesRetryDeadline resolves one frame, retrying only while the answer is the
// typed `deadline`.
func (n *evNode) framesRetryDeadline(who evPerson, org, project, build model.ID, f model.Frame) (evResp, httpapi.FramesView, int) {
	n.t.Helper()
	for attempt := 1; ; attempt++ {
		got, v := n.frames(who, org, project, build, false, f)
		if bytes.Contains(got.body, []byte(n.canaryMap)) {
			n.t.Fatal("a frames answer leaked the source canary")
		}
		if got.status != 200 || len(v.Frames) != 1 || v.Frames[0].Reason != string(symbolicate.Deadline) || attempt == 8 {
			return got, v, attempt
		}
		time.Sleep(time.Second)
	}
}

func (n *evNode) frameRows(r *evReport) {
	t := n.t
	t.Helper()
	// A cold container start, or a loaded host, can exceed the sandbox's own 100 ms
	// frame / 5 s call bound: the service then answers the typed `deadline` and keeps
	// the original frame. The bounds are never widened; a bounded number of fresh
	// requests is allowed to land inside them, and every attempt is checked for leaks.
	got, v, attempts := n.framesRetryDeadline(n.analyst, n.orgA, n.projA, n.res.Build, n.frame)
	if got.status != 200 || len(v.Frames) != 1 {
		t.Fatalf("frames route: %d %s", got.status, got.body)
	}
	f := v.Frames[0]
	if bytes.Contains(got.body, []byte(n.canaryMap)) || f.Source.Context != nil {
		t.Fatal("source text left the server without include_sources")
	}
	if f.Original.Function != n.frame.Function || f.Original.Line != n.frame.Line {
		t.Fatal("the original sanitized frame was not retained")
	}
	if n.sandboxWhy == "" {
		if f.Reason != string(symbolicate.Resolved) || f.Resolved == nil || f.Resolved.Source != "simple.ts" || f.Resolved.Line != 4 || f.Resolved.Column != 8 {
			t.Fatalf("OCI sandbox is configured but the real thrown frame did not resolve to simple.ts:4:8: reason=%q resolved=%+v", f.Reason, f.Resolved)
		}
		r.add("frame_real_mapping", true, true, fmt.Sprintf("real Vite-thrown generated position resolved to the known original simple.ts:4:8 by the OCI-sandboxed worker (image %s..., %d attempt(s) to land inside the sandbox deadline)", n.sandbox.OCIImage[:19], attempts))
	} else {
		if f.Reason != string(symbolicate.SandboxUnavailable) || f.Resolved != nil {
			t.Fatalf("no sandbox (%s): want the typed sandbox_unavailable and no mapping, got reason=%q resolved=%+v", n.sandboxWhy, f.Reason, f.Resolved)
		}
		r.add("frame_real_mapping", true, false, "sandbox unavailable ("+n.sandboxWhy+"): typed sandbox_unavailable, original frame kept")
	}
	// With include_sources and no private-source artifact nothing is released.
	_, withSources := n.frames(n.analyst, n.orgA, n.projA, n.res.Build, true, n.frame)
	if len(withSources.Frames) == 1 && withSources.Frames[0].Source.Context != nil {
		t.Fatal("source context released for an artifact that holds no private sources")
	}
	// A telemetry-only reader sees the original frame, never a mapped position.
	got, v = n.frames(n.plain, n.orgA, n.projA, n.res.Build, false, n.frame)
	if got.status != 200 || len(v.Frames) != 1 || v.Frames[0].Resolved != nil || v.Frames[0].Reason != httpapi.ReasonArtifactGrantAbsent {
		t.Fatalf("telemetry-only reader frames: %d %s", got.status, got.body)
	}
	// An exact immutable build: another build never selects this map.
	other, ov := n.frames(n.analyst, n.orgA, n.projA, model.NewID(), false, n.frame)
	if other.status != 200 || len(ov.Frames) != 1 || ov.Frames[0].Resolved != nil || ov.Frames[0].Reason == string(symbolicate.Resolved) {
		t.Fatalf("a different build resolved the map: %d %s", other.status, other.body)
	}
	r.add("frame_scope_and_build_exactness", true, true, "telemetry-only reader: original frame + artifact_read_not_granted; wrong build: unresolved")
}

// ---------------------------------------------------------------------------
// rows: release and issue

func (n *evNode) releaseIssueRows(r *evReport) {
	t := n.t
	t.Helper()
	scope, err := n.app.Auth.Authorize(n.ctx, n.adminA.cred, n.orgA, []model.ID{n.projA}, auth.OrgAdmin)
	if err != nil {
		t.Fatalf("org admin scope: %v", err)
	}
	var revision model.Revision
	if err = n.app.Control.View(n.ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	n.releaseID = model.NewID()
	_, err = n.app.Releases.Register(n.ctx, scope, model.Release{ID: n.releaseID, Org: n.orgA, Project: n.projA, BuildID: n.res.Build, Parents: []model.ID{}, BuildTime: model.UnixNano(time.Now().UnixNano()),
		DebugArtifacts: []model.ReleaseDebugArtifact{{ArtifactID: n.artifact.ID, DebugID: n.debugID, SHA256: n.artifact.Manifest.GeneratedSHA256}}, DisplayLabel: "evidence 1.0.0"}, revision, model.NewID())
	if err != nil {
		t.Fatalf("release registration: %v", err)
	}
	got := n.post(n.adminA, "/api/v1/evidence/release", httpapi.ReleaseBody{Org: n.orgA, Project: n.projA, Release: n.releaseID})
	var rv httpapi.ReleaseView
	if got.status != 200 || json.Unmarshal(got.body, &rv) != nil || rv.State != httpapi.StateReady || rv.Release == nil || rv.Release.BuildID != n.res.Build || len(rv.Release.DebugArtifacts) != 1 || rv.Release.DebugArtifacts[0].ArtifactID != n.artifact.ID {
		t.Fatalf("release view of the registered build: %d %s", got.status, got.body)
	}
	got = n.post(n.analyst, "/api/v1/evidence/release", httpapi.ReleaseBody{Org: n.orgA, Project: n.projA, Release: n.releaseID})
	rv = httpapi.ReleaseView{}
	if got.status != 200 || json.Unmarshal(got.body, &rv) != nil || rv.State != httpapi.StateNotAvailable || rv.Reason != httpapi.ReasonReleaseNeedsAdmin || rv.Release != nil {
		t.Fatalf("a project reader got release records: %d %s", got.status, got.body)
	}
	r.add("release_registry_view", true, true, "admin reads the release bound to the exact build and artifact; project reader gets the typed release_records_need_org_admin")

	// The issue route needs a grouped issue. Nothing in the tree turns an admitted
	// occurrence into a GroupingIssue, so the only observable behaviour is the typed
	// not-found of an unknown issue.
	got = n.post(n.adminA, "/api/v1/evidence/issue", httpapi.IssueBody{Org: n.orgA, Project: n.projA, Issue: model.NewID()})
	if got.status != 404 {
		t.Fatalf("an unknown issue is not a typed not-found: %d %s", got.status, got.body)
	}
	r.add("issue_evidence_of_ingested_error", true, false, "no component groups an admitted occurrence into a GroupingIssue (internal/releases only migrates, internal/control stores): the occurrence cannot be read back through /api/v1/evidence/issue; an unknown issue is the typed 404")
}

// ---------------------------------------------------------------------------
// rows: trace + investigate

func (n *evNode) traceInvestigateRows(r *evReport) {
	t := n.t
	t.Helper()
	window := map[string]any{"start": model.UnixNano(time.Now().Add(-time.Hour).UnixNano()), "end": model.UnixNano(time.Now().Add(time.Hour).UnixNano())}
	got := n.post(n.analyst, "/api/v1/traces/view", map[string]any{"org": n.orgA, "project": n.projA, "trace": n.errorTrace, "window": window})
	var tv httpapi.TraceView
	if got.status != 200 || json.Unmarshal(got.body, &tv) != nil || tv.Trace != n.errorTrace || tv.Path == nil {
		t.Fatalf("trace view of the error's own trace: %d %s", got.status, got.body)
	}
	inv := map[string]any{"org": n.orgA, "kind": "trace", "projects": []model.ID{n.projA}, "target": n.errorTrace, "window": window, "limit": 10}
	got = n.post(n.analyst, "/api/v1/investigate", inv)
	var iv httpapi.InvestigationView
	if got.status != 200 || json.Unmarshal(got.body, &iv) != nil || iv.Link == nil || !iv.Link.Available || iv.Link.ID != n.errorTrace {
		t.Fatalf("authorized trace link from the error: %d %s", got.status, got.body)
	}
	r.add("trace_view_and_link", true, true, "the error's trace opens through /traces/view and /investigate (link available)")
	for _, kind := range []string{"replay", "profile"} {
		inv["kind"], inv["target"] = kind, n.smallReplay
		got = n.post(n.analyst, "/api/v1/investigate", inv)
		iv = httpapi.InvestigationView{}
		if got.status != 200 || json.Unmarshal(got.body, &iv) != nil || iv.State != httpapi.StateNotAvailable || iv.Reason != httpapi.ReasonGrantNotBuilt || iv.Link != nil {
			t.Fatalf("investigate %s must be the typed not_available: %d %s", kind, got.status, got.body)
		}
	}
	r.add("investigate_replay_profile_links", true, false, "/api/v1/investigate answers grant_not_built for replay and profile targets: an error cannot navigate to its replay/profile through the investigation route (direct /replays/stream and /profiles/view reads are exercised separately)")
}

// ---------------------------------------------------------------------------
// replay

type evRecorder struct {
	replay, session model.ID
	domain          model.ClockDomain
	seq, cpSeq      uint64
	prev, cpHash    model.Hash
	events          int
}

func newEvRecorder(replay model.ID, events int) *evRecorder {
	return &evRecorder{replay: replay, session: model.NewID(), events: events, domain: model.ClockDomain{Host: model.NewID(), Boot: model.NewID(), Runtime: model.NewID()}}
}

func (r *evRecorder) next(t *testing.T, checkpoint bool) model.ReplayChunk {
	t.Helper()
	r.seq++
	wall := model.UnixNano(time.Now().UnixNano())
	events := make([]model.MaskedEvent, r.events)
	for i := range events {
		events[i] = model.MaskedEvent{At: model.MonoNano(wall) + model.MonoNano(i), Kind: "pointer", Node: 1, X: int32(r.seq), Y: int32(i % 1000)}
	}
	c := model.ReplayChunk{Replay: r.replay, Session: r.session, Recorder: "1", Sequence: model.Uint64(r.seq), Previous: r.prev, Clock: model.TraceClock{Wall: wall, Mono: model.MonoNano(r.seq) * 1000, Domain: r.domain}, PolicyRevision: 1, Events: events}
	if checkpoint {
		c.CheckpointSequence, c.Checkpoint = model.Uint64(r.seq), r.prev
		c.Nodes = []model.MaskedNode{{ID: 1, Tag: "div", Class: "masked", Text: "[masked]"}, {ID: 2, Parent: 1, Tag: "button", Text: "[masked]"}}
	} else {
		c.CheckpointSequence, c.Checkpoint = model.Uint64(r.cpSeq), r.cpHash
	}
	h, err := replays.ChunkHash(c)
	if err != nil {
		t.Fatal(err)
	}
	r.prev = h
	if checkpoint {
		r.cpSeq, r.cpHash = r.seq, h
	}
	return c
}

// sendChunk admits one chunk the way production should: closed-format validation,
// the real HTTPS ingest route, then the index step (the ingest route does not run
// Validate/Record itself: that is the application wiring gap recorded in the report).
func (n *evNode) sendChunk(svc *replays.Service, fresh func() policy.SourceGrant, producer model.ID, c model.ReplayChunk) int {
	n.t.Helper()
	raw, _ := json.Marshal(c)
	if _, err := svc.ValidateJSON(fresh(), raw); err != nil {
		n.t.Fatalf("closed-format validation refused a chain chunk: %v", err)
	}
	b := n.batchFor(n.projA, n.srcA, n.orgA, producer, model.Record{ID: model.NewID(), Kind: model.Replay, ObservedAt: c.Clock.Wall, Resource: n.res, Payload: model.Payload{Replay: &c}})
	wire, _ := json.Marshal(b)
	got := n.ingest(n.credA, wire)
	if got.status != 200 {
		return got.status
	}
	n.replayBatches = append(n.replayBatches, b)
	var receipt model.Receipt
	if err := json.Unmarshal(got.body, &receipt); err != nil {
		n.t.Fatal(err)
	}
	for _, d := range receipt.SignalDeadlines {
		if d.Kind == model.Replay {
			// Record is idempotent; the control CAS is Stale when admission commits
			// raced it, and a fresh attempt reads the new revision.
			var err error
			for range 20 {
				if err = svc.Record(n.ctx, fresh(), n.projA, c, d.RetainUntil); !faultIs(err, model.Stale) {
					break
				}
			}
			if err != nil {
				n.t.Fatalf("replay index: %v", err)
			}
			return 200
		}
	}
	n.t.Fatal("receipt has no replay deadline")
	return 0
}

type evStream struct {
	resp *http.Response
	br   *bufio.Reader
}

func (n *evNode) streamRequest(client *http.Client, who evPerson, org, project, replay model.ID, probe bool) (*http.Response, error) {
	raw, _ := json.Marshal(httpapi.ReplayBody{ScopeFields: httpapi.ScopeFields{Org: org}, Project: project, Replay: replay, Probe: probe})
	req, _ := http.NewRequest("POST", n.srv.URL+"/api/v1/replays/stream", bytes.NewReader(raw))
	req.Header.Set("Cookie", "__Host-soundpost="+who.session.Token)
	req.Header.Set("X-CSRF-Token", who.session.CSRF)
	req.Header.Set("Origin", n.srv.URL)
	req.Header.Set("Content-Type", "application/json")
	return client.Do(req)
}

// openStream returns the stream on 200 and otherwise the status and body.
func (n *evNode) openStream(who evPerson, org, project, replay model.ID, probe bool) (*evStream, int, []byte) {
	n.t.Helper()
	resp, err := n.streamRequest(n.srv.Client(), who, org, project, replay, probe)
	if err != nil {
		n.t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		n.remember(body)
		return nil, resp.StatusCode, body
	}
	return &evStream{resp: resp, br: bufio.NewReaderSize(resp.Body, 64<<10)}, 200, nil
}

// next reads one NDJSON line; ok is false at the end of the body.
func (s *evStream) next() (httpapi.ReplayLine, []byte, bool) {
	raw, err := s.br.ReadBytes('\n')
	if len(raw) == 0 && err != nil {
		return httpapi.ReplayLine{}, nil, false
	}
	var l httpapi.ReplayLine
	if jerr := json.Unmarshal(raw, &l); jerr != nil {
		return httpapi.ReplayLine{Type: "undecodable"}, raw, true
	}
	return l, raw, true
}
func (s *evStream) close() { s.resp.Body.Close() }

func (n *evNode) drain(s *evStream, canaries ...string) []httpapi.ReplayLine {
	var out []httpapi.ReplayLine
	for {
		l, raw, ok := s.next()
		if !ok {
			return out
		}
		for _, c := range canaries {
			if bytes.Contains(raw, []byte(c)) {
				n.t.Fatalf("a canary crossed the replay stream in a %s line", l.Type)
			}
		}
		out = append(out, l)
	}
}

func evRender(lines []httpapi.ReplayLine) string {
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
		case "gap":
			through := uint64(0)
			if l.Through != nil {
				through = uint64(*l.Through)
			}
			out = append(out, fmt.Sprintf("G%d-%d(%s)", seq, through, l.Reason))
		default:
			out = append(out, l.Type)
		}
	}
	return strings.Join(out, " ")
}

const evSmallReplayShape = "open C1 D2 D3 G4-5(missing_chunk) C6 D7 D8 D9 D10 end"

// replaySvc returns the replay service and a resolver of a FRESH source grant (the
// closed-format check requires a grant resolved after the latest policy/control
// change).
func (n *evNode) replaySvc() (*replays.Service, func() policy.SourceGrant) {
	n.t.Helper()
	svc, err := replays.New(n.app.Storage, n.app.Auth, n.app.Control)
	if err != nil {
		n.t.Fatal(err)
	}
	pol, err := policy.New(n.app.Auth, nil)
	if err != nil {
		n.t.Fatal(err)
	}
	return svc, func() policy.SourceGrant {
		g, err := pol.ResolveSource(n.ctx, n.srcCredA, n.projA, n.srcA, 1)
		if err != nil {
			n.t.Fatal(err)
		}
		return g
	}
}

func (n *evNode) replayRows(r *evReport) {
	t := n.t
	t.Helper()
	svc, fresh := n.replaySvc()
	g := fresh()
	producer := model.NewID()
	// Unmasked page text is refused by the closed-format gate and by the real route.
	rec := newEvRecorder(model.NewID(), 1)
	tainted := rec.next(t, true)
	tainted.Nodes = []model.MaskedNode{{ID: 1, Tag: "div", Text: n.canaryReplay}}
	raw, _ := json.Marshal(tainted)
	if _, err := svc.ValidateJSON(g, raw); err == nil {
		t.Fatal("the closed-format gate accepted raw node text")
	} else if strings.Contains(err.Error(), n.canaryReplay) {
		t.Fatal("a validation error echoed page content")
	}
	tb := n.batchFor(n.projA, n.srcA, n.orgA, producer, model.Record{ID: model.NewID(), Kind: model.Replay, ObservedAt: tainted.Clock.Wall, Resource: n.res, Payload: model.Payload{Replay: &tainted}})
	wire, _ := json.Marshal(tb)
	if refused := n.ingest(n.credA, wire); refused.status == 200 || bytes.Contains(refused.body, []byte(n.canaryReplay)) {
		t.Fatalf("the real ingest route stored or echoed raw replay text: %d", refused.status)
	}

	// The small replay: 10 chunks, the 4th lost in transit.
	small := newEvRecorder(n.smallReplay, 3)
	for i := 1; i <= 10; i++ {
		c := small.next(t, i == 1 || i == 6)
		if i == 4 {
			continue
		}
		if status := n.sendChunk(svc, fresh, producer, c); status != 200 {
			t.Fatalf("chunk %d refused by the real route: %d", i, status)
		}
	}
	s, status, body := n.openStream(n.analyst, n.orgA, n.projA, n.smallReplay, false)
	if status != 200 {
		t.Fatalf("authorized replay stream: %d %s", status, body)
	}
	lines := n.drain(s, n.canaryReplay)
	s.close()
	if evRender(lines) != evSmallReplayShape {
		t.Fatalf("replay stream %q, want %q", evRender(lines), evSmallReplayShape)
	}
	for _, l := range lines {
		if l.Chunk != nil {
			for _, node := range l.Chunk.Nodes {
				if node.Text != "" && node.Text != "[masked]" {
					t.Fatal("unmasked text released by the stream")
				}
			}
		}
	}
	// A reader without replay.read gets no stream, and nothing of the replay.
	if _, st, body := n.openStream(n.plain, n.orgA, n.projA, n.smallReplay, false); st == 200 || bytes.Contains(body, []byte("chunk")) {
		t.Fatalf("a telemetry-only reader opened the replay stream: %d", st)
	}
	r.add("replay_closed_format_stream_and_gap", true, true, "hand-chained closed-format chunks through the real route; real stream shows an explicit missing_chunk gap and masked text only; raw text refused without echo")
	r.add("replay_real_recorder_chunks", true, false, "the browser recorder's own chunks are refused by the Go validator (known cross-language gap): no recorder chunk was admitted, only closed-format chunks built here")
	// Does the route enforce the closed-format chain? A first chunk that names a
	// previous hash is rejected by replays.ValidateChunk (Invalid).
	chainBad := newEvRecorder(model.NewID(), 1).next(t, true)
	chainBad.Previous = model.HashCanonical([]byte("not the chain"))
	if _, err := svc.ValidateJSON(fresh(), mustJSON(chainBad)); err == nil {
		t.Fatal("the closed-format validator accepted a first chunk with a previous hash")
	}
	cb := n.batchFor(n.projA, n.srcA, n.orgA, producer, model.Record{ID: model.NewID(), Kind: model.Replay, ObservedAt: chainBad.Clock.Wall, Resource: n.res, Payload: model.Payload{Replay: &chainBad}})
	if got := n.ingest(n.credA, mustJSON(cb)); got.status == 200 {
		r.add("replay_admission_enforces_closed_format", true, false, "the real ingest route admitted a first chunk that names a previous hash, which replays.ValidateChunk rejects: the replay gate (ingest.SetReplayGate) is missing or does not enforce the closed format, so chain, checkpoint and recorder-version rules are not enforced at intake")
	} else {
		r.add("replay_admission_enforces_closed_format", true, true, fmt.Sprintf("the real route refused a chain-invalid chunk (status %d)", got.status))
	}

	// The large replay used by the revoke and deletion rows.
	n.bigChunks = 100
	big := newEvRecorder(n.bigReplay, 1300)
	for i := 1; i <= n.bigChunks; i++ {
		if status := n.sendChunk(svc, fresh, producer, big.next(t, i == 1 || i == 50)); status != 200 {
			t.Fatalf("large replay chunk %d refused: %d", i, status)
		}
	}
}

// ---------------------------------------------------------------------------
// profile

type evLease struct{}

func (evLease) Bytes() uint64 { return 2 << 20 }
func (evLease) Close() error  { return nil }

type evAdmitter struct{ n *evNode }

func (a evAdmitter) Admit(_ context.Context, _ policy.SourceGrant, b model.Batch) (model.Receipt, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return model.Receipt{}, err
	}
	got := a.n.ingest(a.n.credA, raw)
	if got.status != 200 {
		return model.Receipt{}, fmt.Errorf("batch route refused the batch: %d", got.status)
	}
	var receipt model.Receipt
	return receipt, model.StrictJSON(got.body, &receipt)
}

type evLookup struct{ n *evNode }

func (l evLookup) LookupReceipt(_ context.Context, q model.ReceiptRequest) (model.Receipt, error) {
	got := l.n.receiptLookup(l.n.credA, q)
	if got.status != 200 {
		return model.Receipt{}, model.Fail(model.NotFound)
	}
	var receipt model.Receipt
	return receipt, model.StrictJSON(got.body, &receipt)
}

func evCapabilities() nativeperf.Capabilities {
	return nativeperf.Capabilities{CPU: nativeperf.Supported, OffCPU: nativeperf.Supported, RunqueueSplit: nativeperf.Supported, Permissions: nativeperf.Permissions{CPUEventOpen: nativeperf.Supported, SchedulerEventOpen: nativeperf.Supported}, FrameCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}, ThreadCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}}
}

func (n *evNode) profileBody(org, project, profile model.ID) map[string]any {
	return map[string]any{"org": org, "project": project, "profile": profile, "window": map[string]any{"start": n.profileWall, "end": n.profileWall + 2_000_000_000}}
}

func (n *evNode) profileRows(r *evReport) {
	t := n.t
	t.Helper()
	domain := nativeperf.ClockDomain{HostID: "evidence-host", BootID: "evidence-boot"}
	task := func(tid uint32) nativeperf.TaskKey {
		return nativeperf.TaskKey{BootID: "evidence-boot", PIDNamespace: 1, TGID: 70, TID: tid, ProcessStart: 1, Generation: 1}
	}
	const period = 10_101_010
	var events []nativeperf.SanitizedEvent
	for i := range 12 {
		tk := task(71)
		if i%2 == 1 {
			tk = task(72)
		}
		chain := []nativeperf.CallchainEntry{{IP: model.Uint64(0x401100 + i*8)}, {IP: 0x401180}, {IP: 0x4011f0}, {IP: 0x401260}}
		events = append(events, nativeperf.SanitizedEvent{Kind: nativeperf.EventCPU, Time: model.MonoNano(1_000_000 * (i + 1)), Sequence: model.Uint64(i + 1), Domain: domain, Task: tk, CPUEvent: &nativeperf.CPUSample{IP: chain[0].IP, Callchain: chain, Method: nativeperf.MethodSoftwareCPUClock, Unit: nativeperf.UnitCPUClockNanoseconds, RequestedHz: 99, Period: period}})
	}
	events = append(events, nativeperf.SanitizedEvent{Kind: nativeperf.EventLoss, Time: model.MonoNano(13_000_000), Sequence: 13, Domain: domain, Loss: &nativeperf.LossEvent{Reason: nativeperf.ReasonSampleLost, Count: 3}})
	intervals := evSchedulerIntervals(t, domain, task(71))
	n.profileWall = model.UnixNano(time.Now().UnixNano())
	limits := nativeperf.ProfileLimits{Profile: n.profileRoot, Process: model.NewID(), Capability: model.NewID(), Domain: domain, PolicyRevision: 1, Sequence: 1, Start: n.profileWall, End: n.profileWall + 2_000_000_000,
		Clock: model.TraceClock{Wall: n.profileWall, Domain: model.ClockDomain{Host: model.NewID(), Boot: model.NewID(), Runtime: model.NewID()}}, Complete: true, MaxBytes: 8 << 20, MaxSamples: 8192, MaxIntervals: 8192, MaxFrames: 4096, MaxStacks: 4096}
	producer := model.NewID()
	exporter, err := nativeperf.NewExporter(evAdmitter{n}, evLookup{n}, nativeperf.ExportConfig{Project: n.projA, Source: n.srcA, Producer: producer, Resource: n.res, Limits: limits, Capabilities: evCapabilities()}, evLease{})
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Close()
	pol, err := policy.New(n.app.Auth, nil)
	if err != nil {
		t.Fatal(err)
	}
	g, err := pol.ResolveSource(n.ctx, n.srcCredA, n.projA, n.srcA, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = exporter.Send(n.ctx, g, nativeperf.ProfileChunk{ProfileID: n.profileRoot, PolicyRevision: 1, Domain: domain, Events: events, Intervals: intervals}); err != nil || !exporter.Stats().Admitted {
		t.Fatalf("the real exporter did not get the assembled profile admitted over HTTPS: %v", err)
	}
	got := n.post(n.analyst, "/api/v1/profiles/view", n.profileBody(n.orgA, n.projA, n.profileRoot))
	var pv httpapi.ProfileResponse
	if got.status != 200 || json.Unmarshal(got.body, &pv) != nil || pv.View == nil || pv.Profile != n.profileRoot || pv.State != httpapi.StateReady && pv.State != httpapi.StateIncomplete {
		t.Fatalf("profile view of the assembled profile: %d %s", got.status, got.body)
	}
	var view profiles.ProfileView = *pv.View
	if view.Project != n.projA || view.Profile != n.profileRoot {
		t.Fatal("profile view bound to another identity")
	}
	if status := n.post(n.plain, "/api/v1/profiles/view", n.profileBody(n.orgA, n.projA, n.profileRoot)).status; status == 200 {
		t.Fatalf("a reader without profiles.read opened the profile: %d", status)
	}
	r.add("profile_assembler_export_view", true, true, "real nativeperf assembler + exporter, admitted over the real HTTPS route, read through /profiles/view; reader without profiles.read refused")
	r.add("profile_real_capture_or_sdk", true, false, "the events are constructed sanitized events fed to the real assembler: no perf-captured sample (native acquisition is a separate qualification) and no SDK profile reaches the backend (03.09 finding)")
}

func evSchedulerIntervals(t *testing.T, d nativeperf.ClockDomain, k nativeperf.TaskKey) []nativeperf.Interval {
	t.Helper()
	const blocked, runnable = 40_000_000, 15_000_000
	base := uint64(100_000_000)
	out := nativeperf.SanitizedEvent{Kind: nativeperf.EventSwitch, Time: model.MonoNano(base), Sequence: model.Uint64(1000 + base/1_000_000), Domain: d, Switch: &nativeperf.SchedulerSwitch{Previous: &k, PreviousState: 1, MissingCallchain: nativeperf.ReasonMissingSwitchCallchain}}
	wake := nativeperf.SanitizedEvent{Kind: nativeperf.EventWakeup, Time: model.MonoNano(base + blocked), Sequence: model.Uint64(1000 + (base+blocked)/1_000_000), Domain: d, Task: k, Wakeup: &nativeperf.SchedulerWakeup{Target: k}}
	in := nativeperf.SanitizedEvent{Kind: nativeperf.EventSwitch, Time: model.MonoNano(base + blocked + runnable), Sequence: model.Uint64(1000 + (base+blocked+runnable)/1_000_000), Domain: d, Switch: &nativeperf.SchedulerSwitch{Next: &k}}
	c := nativeperf.NewCorrelator(nativeperf.DefaultConfig(1))
	if e := c.Configure(d, []uint32{0}, 4<<20); e != nil {
		t.Fatal(e)
	}
	var intervals []nativeperf.Interval
	for _, event := range []nativeperf.SanitizedEvent{out, wake, in} {
		got, e := c.Consume(event)
		if e != nil {
			t.Fatal(e)
		}
		intervals = append(intervals, got...)
	}
	if e := c.ReportProgress(0, model.MonoNano(base+blocked+runnable+100_000_000)); e != nil {
		t.Fatal(e)
	}
	got, e := c.Advance(model.MonoNano(base + blocked + runnable))
	if e != nil {
		t.Fatal(e)
	}
	return append(intervals, got...)
}

// ---------------------------------------------------------------------------
// isolation

type evPair struct {
	name          string
	real, control func() evResp
	realIDs, ctl  []model.ID
}

func (n *evNode) isolationRows(r *evReport) {
	t := n.t
	t.Helper()
	// Organization B uploads the identical bytes under its own scope: same generated
	// hash, same map hash, same build and debug identities, a different artifact.
	mb := n.manifest0(n.orgB, n.projB, n.srcB)
	up := n.upload(n.outsider, mb, n.mapBytes)
	if up.status != 200 || json.Unmarshal(up.body, &n.artifactB) != nil || n.artifactB.ID == n.artifact.ID {
		t.Fatalf("second organization upload of identical bytes: %d %s", up.status, up.body)
	}
	if n.artifactB.Manifest.GeneratedSHA256 != n.artifact.Manifest.GeneratedSHA256 || n.artifactB.Manifest.MapSHA256 != n.artifact.Manifest.MapSHA256 {
		t.Fatal("the two organizations do not hold the same hashes")
	}
	// The warm cache of A's map must not serve B's frame for A's artifact, but B's
	// own artifact (same hashes) resolves under B's own scope.
	frameFor := func(a model.ID) model.Frame {
		return model.Frame{Module: "simple.mjs", Function: "throwingFixture", Artifact: a.String(), Line: n.position.GeneratedLine, Column: &n.position.GeneratedColumn}
	}
	own, ov, _ := n.framesRetryDeadline(n.outsider, n.orgB, n.projB, n.res.Build, frameFor(n.artifactB.ID))
	if own.status != 200 || len(ov.Frames) != 1 {
		t.Fatalf("B frames: %d %s", own.status, own.body)
	}
	if n.sandboxWhy == "" && (ov.Frames[0].Resolved == nil || ov.Frames[0].Resolved.Line != 4) {
		t.Fatalf("B's own artifact with identical hashes did not resolve under B's scope: %s", own.body)
	}

	rnd := model.NewID
	ghost := rnd()
	ow := n.outsider
	window := map[string]any{"start": model.UnixNano(time.Now().Add(-time.Hour).UnixNano()), "end": model.UnixNano(time.Now().Add(time.Hour).UnixNano())}
	frames := func(org, project, build, artifact model.ID) func() evResp {
		return func() evResp {
			g, _ := n.frames(ow, org, project, build, false, frameFor(artifact))
			return g
		}
	}
	post := func(path string, body func() any) func() evResp {
		return func() evResp { return n.post(ow, path, body()) }
	}
	inv := func(org, project, target model.ID) func() evResp {
		return post("/api/v1/investigate", func() any {
			return map[string]any{"org": org, "kind": "trace", "projects": []model.ID{project}, "target": target, "window": window, "limit": 10}
		})
	}
	pairs := []evPair{
		{"artifact read, A's identities", func() evResp { return n.readArtifact(ow, n.orgA, n.projA, n.artifact.ID, "read") }, func() evResp { return n.readArtifact(ow, rnd(), rnd(), ghost, "read") }, nil, nil},
		{"artifact read, own scope, A's ID", func() evResp { return n.readArtifact(ow, n.orgB, n.projB, n.artifact.ID, "read") }, func() evResp { return n.readArtifact(ow, n.orgB, n.projB, ghost, "read") }, []model.ID{n.artifact.ID}, []model.ID{ghost}},
		{"artifact sources, own scope, A's ID", func() evResp { return n.readArtifact(ow, n.orgB, n.projB, n.artifact.ID, "sources") }, func() evResp { return n.readArtifact(ow, n.orgB, n.projB, ghost, "sources") }, []model.ID{n.artifact.ID}, []model.ID{ghost}},
		{"frames naming A", frames(n.orgA, n.projA, n.res.Build, n.artifact.ID), frames(rnd(), rnd(), rnd(), ghost), nil, nil},
		{"frames own scope, A's artifact", frames(n.orgB, n.projB, n.res.Build, n.artifact.ID), frames(n.orgB, n.projB, n.res.Build, ghost), []model.ID{n.artifact.ID}, []model.ID{ghost}},
		{"release naming A", post("/api/v1/evidence/release", func() any {
			return httpapi.ReleaseBody{Org: n.orgA, Project: n.projA, Release: n.releaseID}
		}), post("/api/v1/evidence/release", func() any { return httpapi.ReleaseBody{Org: rnd(), Project: rnd(), Release: rnd()} }), nil, nil},
		{"release own scope, A's ID", post("/api/v1/evidence/release", func() any {
			return httpapi.ReleaseBody{Org: n.orgB, Project: n.projB, Release: n.releaseID}
		}), post("/api/v1/evidence/release", func() any { return httpapi.ReleaseBody{Org: n.orgB, Project: n.projB, Release: ghost} }), []model.ID{n.releaseID}, []model.ID{ghost}},
		{"issue naming A", post("/api/v1/evidence/issue", func() any { return httpapi.IssueBody{Org: n.orgA, Project: n.projA, Issue: ghost} }),
			post("/api/v1/evidence/issue", func() any { return httpapi.IssueBody{Org: rnd(), Project: rnd(), Issue: ghost} }), nil, nil},
		{"replay naming A", func() evResp { return n.streamStatus(ow, n.orgA, n.projA, n.smallReplay) }, func() evResp { return n.streamStatus(ow, rnd(), rnd(), rnd()) }, nil, nil},
		{"replay own scope, A's ID", func() evResp { return n.streamStatus(ow, n.orgB, n.projB, n.smallReplay) }, func() evResp { return n.streamStatus(ow, n.orgB, n.projB, ghost) }, []model.ID{n.smallReplay}, []model.ID{ghost}},
		{"profile naming A", post("/api/v1/profiles/view", func() any { return n.profileBody(n.orgA, n.projA, n.profileRoot) }), post("/api/v1/profiles/view", func() any { return n.profileBody(rnd(), rnd(), ghost) }), nil, nil},
		{"profile own scope, A's ID", post("/api/v1/profiles/view", func() any { return n.profileBody(n.orgB, n.projB, n.profileRoot) }), post("/api/v1/profiles/view", func() any { return n.profileBody(n.orgB, n.projB, ghost) }), []model.ID{n.profileRoot}, []model.ID{ghost}},
		{"trace own scope, A's ID", post("/api/v1/traces/view", func() any {
			return map[string]any{"org": n.orgB, "project": n.projB, "trace": n.errorTrace, "window": window}
		}), post("/api/v1/traces/view", func() any {
			return map[string]any{"org": n.orgB, "project": n.projB, "trace": ghost, "window": window}
		}), []model.ID{n.errorTrace}, []model.ID{ghost}},
		{"investigate naming A", inv(n.orgA, n.projA, n.errorTrace), inv(rnd(), rnd(), ghost), nil, nil},
		{"investigate own scope, A's trace", inv(n.orgB, n.projB, n.errorTrace), inv(n.orgB, n.projB, ghost), []model.ID{n.errorTrace}, []model.ID{ghost}},
	}
	for _, p := range pairs {
		a, b := p.real(), p.control()
		if a.status != b.status || evNorm(a.body, p.realIDs...) != evNorm(b.body, p.ctl...) {
			t.Fatalf("isolation %q: the other organization can tell A's identity from a missing one:\n real:    %d %s\n control: %d %s", p.name, a.status, a.body, b.status, b.body)
		}
		if bytes.Contains(a.body, []byte(n.frame.Function)) || bytes.Contains(a.body, []byte("simple.ts")) {
			t.Fatalf("isolation %q: organization A content in a foreign answer", p.name)
		}
	}
	r.add("isolation_same_ids_other_org", true, true, fmt.Sprintf("%d route variants: the other organization's answers for A's IDs/hashes are byte-identical (request id and echoed IDs normalized) to those for random IDs; B's own identical-hash artifact resolves only under B's scope", len(pairs)))
}

// streamStatus opens a replay stream and returns the status and the whole body
// (bounded), for answers that must be indistinguishable.
func (n *evNode) streamStatus(who evPerson, org, project, replay model.ID) evResp {
	n.t.Helper()
	s, status, body := n.openStream(who, org, project, replay, false)
	if s == nil {
		return evResp{status, body}
	}
	defer s.close()
	var all []byte
	for {
		_, raw, ok := s.next()
		if !ok {
			break
		}
		all = append(all, raw...)
		if len(all) > 1<<20 {
			break
		}
	}
	return evResp{status, all}
}

// ---------------------------------------------------------------------------
// backup (taken BEFORE the deletion: the "older" backup of the restore row)

func (n *evNode) backupRow(r *evReport) {
	t := n.t
	t.Helper()
	scope, err := n.app.Auth.InstanceScope(n.ctx, n.owner.cred, "evidence acceptance backup")
	if err != nil {
		t.Fatalf("instance scope: %v", err)
	}
	dest, err := backup.NewLocalDestination(n.offhost)
	if err != nil {
		t.Fatal(err)
	}
	if n.manifest, err = n.backups.Run(n.ctx, scope, dest); err != nil {
		t.Fatalf("backup: %v", err)
	}
	r.add("backup_before_deletion", true, true, fmt.Sprintf("encrypted backup of the live node taken before the deletion (authority sequence %d)", n.manifest.Deletion.Sequence))
}

// ---------------------------------------------------------------------------
// lifecycle: grant revoke / deletion while a stream is open

// slowClient returns an HTTP client whose connections keep a tiny receive buffer,
// so an unread response stalls the server's writes instead of being absorbed by
// kernel buffers: the server is then genuinely mid-stream when authority changes.
func (n *evNode) slowClient() *http.Client {
	base := n.srv.Client().Transport.(*http.Transport).Clone()
	dialer := &net.Dialer{}
	base.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dialer.DialContext(ctx, network, addr)
		if err == nil {
			if tcp, ok := c.(*net.TCPConn); ok {
				_ = tcp.SetReadBuffer(4096)
			}
		}
		return c, err
	}
	return &http.Client{Transport: base}
}

// haltedStream reads three lines, runs the authority change, then drains and requires
// a single terminal typed revoke with no chunk after it and fewer chunks than exist.
func (n *evNode) haltedStream(who evPerson, change func(), label, wantReason string) (delivered int) {
	t := n.t
	t.Helper()
	resp, err := n.streamRequest(n.slowClient(), who, n.orgA, n.projA, n.bigReplay, false)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%s: slow stream open: %v", label, err)
	}
	s := &evStream{resp: resp, br: bufio.NewReaderSize(resp.Body, 4096)}
	defer s.close()
	var lines []httpapi.ReplayLine
	for range 3 {
		l, raw, ok := s.next()
		if !ok || bytes.Contains(raw, []byte(n.canaryReplay)) {
			t.Fatalf("%s: stream ended or leaked before the change", label)
		}
		lines = append(lines, l)
	}
	if lines[0].Type != "open" || lines[1].Type != "checkpoint" || lines[2].Type != "delta" {
		t.Fatalf("%s: unexpected first lines %q", label, evRender(lines))
	}
	change()
	lines = append(lines, n.drain(s, n.canaryReplay)...)
	last := lines[len(lines)-1]
	if last.Type != "revoke" || last.Reason != wantReason {
		t.Fatalf("%s: the stream did not end with the typed revoke (%s): last line %q (%s)", label, wantReason, last.Type, last.Reason)
	}
	for i, l := range lines {
		switch l.Type {
		case "revoke":
			if i != len(lines)-1 {
				t.Fatalf("%s: lines after the typed revoke", label)
			}
		case "checkpoint", "delta":
			delivered++
		}
	}
	if delivered >= n.bigChunks {
		t.Fatalf("%s: the whole replay was delivered (%d chunks): nothing was halted", label, delivered)
	}
	return delivered
}

func (n *evNode) revokeStreamRow(r *evReport) {
	t := n.t
	t.Helper()
	delivered := n.haltedStream(n.revoker, func() { n.grant(n.orgA, n.revoker, n.projA, false) }, "grant revoke", replays.ReasonAuthorityRevoked)
	if s, status, _ := n.openStream(n.revoker, n.orgA, n.projA, n.bigReplay, false); s != nil || status == 200 {
		t.Fatal("a revoked reader opened a new stream")
	}
	if s, status, _ := n.openStream(n.revoker, n.orgA, n.projA, n.bigReplay, true); s != nil || status == 200 {
		t.Fatal("a revoked reader's probe was answered")
	}
	r.add("lifecycle_grant_revoke_halts_stream", true, true, fmt.Sprintf("grant revoked mid-stream: %d of %d chunks delivered, then one typed revoke (authority_revoked), nothing after; new stream and probe refused", delivered, n.bigChunks))
}

func (n *evNode) deleteEntities(entities ...model.ID) retention.DeleteReceipt {
	n.t.Helper()
	var last error
	for range 50 {
		scope, err := n.app.Auth.Authorize(n.ctx, n.owner.cred, n.orgA, nil, auth.OrgAdmin)
		if err != nil {
			n.t.Fatal(err)
		}
		var revision model.Revision
		if err = n.app.Control.View(n.ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
			n.t.Fatal(err)
		}
		receipt, err := n.app.Retention.Delete(n.ctx, scope, retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: revision, Mode: model.DeleteEntity, OrgID: n.orgA, ProjectIDs: []model.ID{n.projA}, EntityIDs: entities, Reason: "evidence acceptance deletion"})
		if err == nil {
			return receipt
		}
		var fault *model.Fault
		if !errors.As(err, &fault) || fault.Code != model.Conflict {
			n.t.Fatalf("deletion: %v", err)
		}
		last = err
	}
	n.t.Fatalf("deletion kept conflicting: %v", last)
	return retention.DeleteReceipt{}
}

func (n *evNode) deleteStreamRow(r *evReport) {
	t := n.t
	t.Helper()
	var receipt retention.DeleteReceipt
	delivered := n.haltedStream(n.deleter, func() {
		receipt = n.deleteEntities(n.bigReplay, n.artifact.Map.Manifest.Root)
	}, "deletion", replays.ReasonDeleted)
	scope, err := n.app.Auth.Authorize(n.ctx, n.owner.cred, n.orgA, nil, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	for range 100 {
		if err = n.app.Retention.RunOnce(n.ctx); err != nil {
			t.Fatalf("retention worker: %v", err)
		}
		if receipt, err = n.app.Retention.PollDelete(n.ctx, scope, receipt.OperationID); err != nil {
			t.Fatal(err)
		}
		if receipt.Phase == model.DeletePhaseComplete && receipt.Physical == retention.PhysicalDone {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if receipt.Phase != model.DeletePhaseComplete || receipt.Physical != retention.PhysicalDone {
		t.Fatalf("deletion saga did not complete: phase=%s physical=%s", receipt.Phase, receipt.Physical)
	}
	// Everything the deletion covers is gone, indistinguishably from not-found, while
	// the replay outside the deletion is still served.
	ghost := model.NewID()
	a := n.readArtifact(n.analyst, n.orgA, n.projA, n.artifact.ID, "read")
	b := n.readArtifact(n.analyst, n.orgA, n.projA, ghost, "read")
	if a.status != 404 || evNorm(a.body, n.artifact.ID) != evNorm(b.body, ghost) {
		t.Fatalf("deleted artifact is still distinguishable: %d %s", a.status, a.body)
	}
	got, v := n.frames(n.analyst, n.orgA, n.projA, n.res.Build, false, n.frame)
	if got.status != 200 || len(v.Frames) != 1 || v.Frames[0].Resolved != nil || v.Frames[0].Reason == string(symbolicate.Resolved) {
		t.Fatalf("a deleted map still resolved a frame (warm cache?): %d %s", got.status, got.body)
	}
	x := n.streamStatus(n.analyst, n.orgA, n.projA, n.bigReplay)
	y := n.streamStatus(n.analyst, n.orgA, n.projA, ghost)
	if x.status != 404 || evNorm(x.body, n.bigReplay) != evNorm(y.body, ghost) {
		t.Fatalf("deleted replay is still distinguishable: %d %s", x.status, x.body)
	}
	s, status, body := n.openStream(n.analyst, n.orgA, n.projA, n.smallReplay, false)
	if s == nil {
		t.Fatalf("the replay outside the deletion became unreadable: %d %s", status, body)
	}
	if evRender(n.drain(s)) != evSmallReplayShape {
		t.Fatal("the replay outside the deletion changed")
	}
	s.close()
	r.add("lifecycle_deletion_halts_stream", true, true, fmt.Sprintf("C12 entity deletion (replay + artifact root) mid-stream: %d of %d chunks delivered then one typed revoke; saga complete; artifact, replay and warm-cache frame answer as not-found/unresolved; unrelated replay still served", delivered, n.bigChunks))
}

// ---------------------------------------------------------------------------
// restore from the OLDER backup

func (n *evNode) restoreRows(r *evReport) {
	t := n.t
	t.Helper()
	oldAnalyst, oldOutsider, oldCredA := n.analyst, n.outsider, n.credA
	cur, err := n.authority.Current(n.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if uint64(cur.Head.Sequence) <= uint64(n.manifest.Deletion.Sequence) {
		t.Fatalf("the deletion did not advance the independent authority past the backup (%d <= %d)", cur.Head.Sequence, n.manifest.Deletion.Sequence)
	}
	// Disaster: the live node is gone.
	n.srv.Close()
	if err = n.app.Close(); err != nil {
		t.Fatal(err)
	}
	n.app = nil
	keys := backup.KeyDir(n.keyDir)
	source, err := backup.NewLocalDestination(n.offhost)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := backup.LoadManifest(n.ctx, source, n.manifest.ID, keys)
	if err != nil {
		t.Fatal(err)
	}
	authDest, err := backup.NewLocalDestination(n.authDir)
	if err != nil {
		t.Fatal(err)
	}
	restoreAuthority, err := backup.NewAuthority(authDest, n.authKeys.Restricted(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	restorer, err := backup.NewRestorer(backup.RestoreConfig{Keys: keys, Source: source, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(n.dir, "restored")
	if _, err = restorer.Restore(n.ctx, manifest, backup.DestinationRoot(restored), restoreAuthority); err != nil {
		t.Fatalf("restore: %v", err)
	}
	app2, err := appcore.OpenForActivation(restored)
	if err != nil {
		t.Fatal(err)
	}
	n.app = app2
	t.Cleanup(func() { app2.Close() })
	authority2, err := backup.NewAuthority(authDest, n.authKeys, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err = app2.Retention.UseAuthority(authority2); err != nil {
		t.Fatal(err)
	}
	sym2, err := app2.NewSymbolicator(n.sandbox)
	if err != nil {
		t.Fatal(err)
	}
	app2.Evidence = httpapi.NewEvidence(sym2, app2.Releases, app2.Releases)
	n.serve(app2)

	// Before activation nothing is served.
	if got := n.readArtifact(oldAnalyst, n.orgA, n.projA, n.artifact.ID, "read"); got.status == 200 {
		t.Fatalf("restored node served an artifact before activation: %d", got.status)
	}
	wire, _ := json.Marshal(n.errorBatch)
	if got := n.ingest(oldCredA, wire); got.status == 200 {
		t.Fatal("the old source credential was honored before activation")
	}
	report, err := backup.Activate(n.ctx, backup.DestinationRoot(restored), app2, authority2, time.Now)
	if err != nil {
		t.Fatalf("activation: %v", err)
	}
	if report.Tombstones < 1 || report.AuthorityGeneration == 0 || app2.Storage.RestoreReady() != nil {
		t.Fatalf("activation did not apply the CURRENT deletion authority: %+v", report)
	}
	r.add("restore_keeps_current_deletion_authority", true, true, fmt.Sprintf("restored from the pre-deletion backup (sequence %d); activation applied the authority's current head (sequence %d, %d tombstone(s))", n.manifest.Deletion.Sequence, cur.Head.Sequence, report.Tombstones))

	// Old users, sessions and tokens stay inactive in the new auth generation.
	if _, err = app2.Auth.Authenticate(n.ctx, oldAnalyst.session.Token); err == nil {
		t.Fatal("an old session authenticated in the restored generation")
	}
	if got := n.readArtifact(oldAnalyst, n.orgA, n.projA, n.artifact.ID, "read"); got.status == 200 {
		t.Fatalf("an old session read through the restored node: %d", got.status)
	}
	if got := n.ingest(oldCredA, wire); got.status == 200 {
		t.Fatal("the old source credential was honored after activation")
	}
	for _, p := range []evPerson{oldAnalyst, oldOutsider} {
		if _, err = app2.Auth.Login(n.ctx, p.email, evPassword, ""); err == nil {
			t.Fatal("an old account logged in before reconciliation")
		}
	}
	r.add("restore_old_credentials_inactive", true, true, "old session cookie, old source credential and old accounts (both organizations) refused after activation")

	// Fresh recovery bootstrap and reconciliation of ONE user and the source.
	boot, err := app2.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	rs, err := app2.Auth.Bootstrap(n.ctx, boot, "evidence-recovery@example.test", "evidence recovery password 2026")
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := app2.Auth.Authenticate(n.ctx, rs.Token)
	if err != nil {
		t.Fatal(err)
	}
	reason := "evidence acceptance: verified against the original administrator ticket"
	for _, item := range []auth.Reconciliation{{Kind: auth.ReconcileAccount, User: oldAnalyst.id}, {Kind: auth.ReconcileMembership, Org: n.orgA, User: oldAnalyst.id}, {Kind: auth.ReconcileGrant, Org: n.orgA, User: oldAnalyst.id, Project: n.projA}} {
		item.Reason = reason
		if _, err = app2.Auth.Reconcile(n.ctx, recovery, item); err != nil {
			t.Fatalf("reconcile %s: %v", item.Kind, err)
		}
	}
	issued, err := app2.Auth.Reconcile(n.ctx, recovery, auth.Reconciliation{Kind: auth.ReconcileSource, Source: n.srcA, Reason: reason})
	if err != nil || issued.Credential == "" || issued.Credential == oldCredA {
		t.Fatalf("source reconcile: %v", err)
	}
	if _, err = app2.Auth.Login(n.ctx, oldOutsider.email, evPassword, ""); err == nil {
		t.Fatal("a user nobody reconciled became active")
	}
	analyst := n.login(oldAnalyst)
	if analyst.session.Token == oldAnalyst.session.Token {
		t.Fatal("the new session reuses the old token")
	}
	if _, err = app2.Auth.Authenticate(n.ctx, oldAnalyst.session.Token); err == nil {
		t.Fatal("the old session came back after reconciliation")
	}

	// The data came back (the unrelated replay is served) but the deletion is the
	// authority: the deleted replay and artifact are not revived.
	s, status, body := n.openStream(analyst, n.orgA, n.projA, n.smallReplay, false)
	if s == nil {
		t.Fatalf("the restored data plane lost the unrelated replay: %d %s", status, body)
	}
	if evRender(n.drain(s, n.canaryReplay)) != evSmallReplayShape {
		t.Fatal("restored replay differs")
	}
	s.close()
	ghost := model.NewID()
	x, y := n.streamStatus(analyst, n.orgA, n.projA, n.bigReplay), n.streamStatus(analyst, n.orgA, n.projA, ghost)
	if x.status != 404 || evNorm(x.body, n.bigReplay) != evNorm(y.body, ghost) {
		t.Fatalf("the deleted replay was revived by the restore: %d %s", x.status, x.body)
	}
	a, b := n.readArtifact(analyst, n.orgA, n.projA, n.artifact.ID, "read"), n.readArtifact(analyst, n.orgA, n.projA, ghost, "read")
	if a.status != 404 || evNorm(a.body, n.artifact.ID) != evNorm(b.body, ghost) {
		t.Fatalf("the deleted artifact was revived by the restore: %d %s", a.status, a.body)
	}
	got, v := n.frames(analyst, n.orgA, n.projA, n.res.Build, false, n.frame)
	if got.status != 200 || len(v.Frames) != 1 || v.Frames[0].Resolved != nil {
		t.Fatalf("a frame resolved through a restored deleted map: %d %s", got.status, got.body)
	}
	// A receipt lookup returns receipt facts only, and neither a retried chunk nor a
	// re-upload revives anything.
	rec := n.receiptLookup(issued.Credential, model.ReceiptRequest{Source: n.errorBatch.Source, Producer: n.errorBatch.Producer, RouteSlot: n.errorBatch.RouteSlot, BatchID: n.errorBatch.ID, OriginalHash: n.errorReceipt.Hash})
	for _, leak := range []string{n.frame.Function, "simple.mjs", n.canaryMap} {
		if strings.Contains(string(rec.body), leak) {
			t.Fatalf("a receipt lookup carried raw content (%d)", rec.status)
		}
	}
	var resent bool
	for _, b := range n.replayBatches {
		if len(b.Records) != 1 || b.Records[0].Payload.Replay == nil || b.Records[0].Payload.Replay.Replay != n.bigReplay {
			continue
		}
		raw, _ := json.Marshal(b)
		_ = n.ingest(issued.Credential, raw)
		q := n.receiptLookup(issued.Credential, model.ReceiptRequest{Source: b.Source, Producer: b.Producer, RouteSlot: b.RouteSlot, BatchID: b.ID, OriginalHash: model.Hash{}})
		if bytes.Contains(q.body, []byte(`"events"`)) || bytes.Contains(q.body, []byte(`"nodes"`)) {
			t.Fatal("a receipt lookup returned deleted replay content")
		}
		resent = true
		break
	}
	if !resent {
		t.Fatal("no admitted chunk of the deleted replay to retry")
	}
	if again := n.streamStatus(analyst, n.orgA, n.projA, n.bigReplay); again.status != 404 {
		t.Fatalf("a retried chunk revived the deleted replay: %d", again.status)
	}
	if re := n.upload(analyst, n.manifest0(n.orgA, n.projA, n.srcA), n.mapBytes); re.status == 200 {
		var fresh model.ArtifactReferenceIntent
		if json.Unmarshal(re.body, &fresh) == nil && fresh.ID == n.artifact.ID {
			t.Fatal("re-upload revived the deleted artifact identity")
		}
	}
	if a = n.readArtifact(analyst, n.orgA, n.projA, n.artifact.ID, "read"); a.status != 404 {
		t.Fatalf("the deleted artifact identity answers after a re-upload: %d", a.status)
	}
	r.add("restore_deleted_not_revived", true, true, "after reconciling one user: the unrelated replay is served again (data restored) while the deleted replay and artifact answer as not-found; frames unresolved; receipt lookup carries no content; a retried chunk and a re-upload do not revive the old identities")
}

// ---------------------------------------------------------------------------
// canaries

func (n *evNode) canaryRows(r *evReport, logs *syncLog) {
	t := n.t
	t.Helper()
	canaries := []string{n.canaryMap, n.canaryReplay, n.canaryMessage}
	n.mu.Lock()
	for i, body := range n.responses {
		for _, c := range canaries {
			if bytes.Contains(body, []byte(c)) {
				n.mu.Unlock()
				t.Fatalf("a canary appeared in response #%d", i)
			}
		}
	}
	count := len(n.responses)
	n.mu.Unlock()
	for _, c := range canaries {
		if bytes.Contains(logs.bytes(), []byte(c)) {
			t.Fatal("a canary appeared in the process log")
		}
	}
	r.add("canary_responses_logs", true, true, fmt.Sprintf("%d HTTP responses and the process log carry no source-content, replay-text or error-message canary", count))
	// Storage: every file of both roots. A positive control (a legitimately stored
	// value) is required, or the scan proves nothing about this storage format.
	control, leaked := 0, 0
	for _, root := range []string{filepath.Join(n.dir, "live"), filepath.Join(n.dir, "restored")} {
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			if bytes.Contains(raw, []byte(n.canaryControl)) {
				control++
			}
			for _, c := range canaries {
				if bytes.Contains(raw, []byte(c)) {
					leaked++
				}
			}
			return nil
		})
	}
	if leaked != 0 {
		t.Fatalf("a canary is present in %d storage file(s)", leaked)
	}
	if control == 0 {
		r.add("canary_storage_scan", true, false, "inconclusive: the positive control (a stored frame identity) is not readable in plaintext on disk, so absence of the canaries proves nothing about this storage format")
		return
	}
	r.add("canary_storage_scan", true, true, fmt.Sprintf("no canary in any storage file of the live and restored roots; positive control found in %d file(s)", control))
}

// ---------------------------------------------------------------------------
// restore of a project without metric series

// evMiniRestore backs up a tiny node whose one project holds one admitted error
// batch (and one metric series when withMetric), restores it into a clean root and
// returns the error of the activation (nil: restored and open).
func evMiniRestore(t *testing.T, withMetric bool) error {
	t.Helper()
	n := &evNode{t: t, ctx: context.Background(), dir: t.TempDir(), orgA: model.NewID(), orgB: model.NewID(), projA: model.NewID(), projB: model.NewID(), srcA: model.NewID(), srcB: model.NewID()}
	var err error
	if n.app, err = appcore.Open(filepath.Join(n.dir, "live")); err != nil {
		t.Fatal(err)
	}
	liveClosed := false
	defer func() {
		if !liveClosed {
			n.app.Close()
		}
	}()
	n.setupAuthority()
	n.setupTenants()
	pol, err := policy.New(n.app.Auth, nil)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := pol.ResolveSource(n.ctx, n.srcCredA, n.projA, n.srcA, 1)
	if err != nil {
		t.Fatal(err)
	}
	producer := model.NewID()
	admit := func(rec model.Record) {
		b := n.batchFor(n.projA, n.srcA, n.orgA, producer, rec)
		if _, err := n.app.Ingest.Admit(n.ctx, grant, b); err != nil {
			t.Fatalf("admission: %v", err)
		}
	}
	now := time.Now().UnixNano()
	admit(model.Record{ID: model.NewID(), Kind: model.ErrorKind, ObservedAt: model.UnixNano(now - int64(time.Second)), Resource: n.res, Payload: model.Payload{Error: &model.ErrorOccurrence{Occurrence: model.NewID(), Class: "TypeError", Mechanism: "manual", Build: n.res.Build, Frames: []model.Frame{}}}})
	if withMetric {
		value := model.FloatBits(math.Float64bits(1))
		admit(model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(now - int64(2*time.Second)), Resource: n.res, Payload: model.Payload{Metric: &model.MetricPoint{Name: "evidence_probe", Labels: model.Labels{}, SampleKind: "float", Value: &value, Unit: "1", Type: "gauge"}}})
	}
	scope, err := n.app.Auth.InstanceScope(n.ctx, n.owner.cred, "evidence restore probe")
	if err != nil {
		t.Fatal(err)
	}
	dest, err := backup.NewLocalDestination(n.offhost)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := n.backups.Run(n.ctx, scope, dest)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	if err = n.app.Close(); err != nil {
		t.Fatal(err)
	}
	liveClosed = true
	keys := backup.KeyDir(n.keyDir)
	source, err := backup.NewLocalDestination(n.offhost)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := backup.LoadManifest(n.ctx, source, manifest.ID, keys)
	if err != nil {
		t.Fatal(err)
	}
	authDest, err := backup.NewLocalDestination(n.authDir)
	if err != nil {
		t.Fatal(err)
	}
	restoreAuthority, err := backup.NewAuthority(authDest, n.authKeys.Restricted(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	restorer, err := backup.NewRestorer(backup.RestoreConfig{Keys: keys, Source: source, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(n.dir, "restored")
	if _, err = restorer.Restore(n.ctx, loaded, backup.DestinationRoot(restored), restoreAuthority); err != nil {
		t.Fatalf("restore: %v", err)
	}
	app2, err := appcore.OpenForActivation(restored)
	if err != nil {
		t.Fatal(err)
	}
	defer app2.Close()
	authority2, err := backup.NewAuthority(authDest, n.authKeys, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err = app2.Retention.UseAuthority(authority2); err != nil {
		t.Fatal(err)
	}
	_, err = backup.Activate(n.ctx, backup.DestinationRoot(restored), app2, authority2, time.Now)
	return err
}

func (n *evNode) restoreProbeRow(r *evReport) {
	t := n.t
	t.Helper()
	if err := evMiniRestore(t, true); err != nil {
		t.Fatalf("control: a project with a metric series did not restore: %v", err)
	}
	err := evMiniRestore(t, false)
	if err == nil {
		r.add("restore_project_without_metric_series", true, true, "a project with admitted batches and no metric series restores and activates")
		return
	}
	r.add("restore_project_without_metric_series", true, false, fmt.Sprintf("activation of a restore whose project holds admitted batches but no metric series fails with %q while the same restore with one metric series succeeds: CommitQuotaReconciliation (internal/storage/snapshot.go) compares the certificate's per-project series digests, which exist for every project with consumed batches even when the series set is empty (line ~739), against a recompute that only creates an entry for projects holding metric records (line ~971): the restore of such a node cannot activate", err))
}
