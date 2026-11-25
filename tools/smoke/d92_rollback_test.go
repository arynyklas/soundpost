// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/gitlab/gitlabtest"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
)

// The D92 records (an error issue's owner and external link, an incident's title, notes and external link)
// are members of control-state records the previous release cannot read. Decision D93 makes them writable only
// on a contracted installation, because writing one is the one-way point of a rollback. These two cases run the
// PRODUCED binaries (release directories of the previous and the candidate build, the env variables of
// TestUpgradeRollbackOfProducedBinaries) over HTTP, as an organization administrator, against a local TLS stub
// GitLab:
//
//   - TestD92RollbackBornContracted: a fresh data directory started by the NEW binary (born contracted) takes
//     every D92 write; the previous release is then started on that very directory and what it does is
//     recorded and asserted exactly; the new binary starts again and must read every record byte for byte.
//   - TestD92RollbackNotContracted: a directory made and bootstrapped by the PREVIOUS release, upgraded by the
//     new binary without contraction: every D92 write is refused 501 needs_contracted_installation, nothing is
//     written, and the previous release then reads everything as before.

const d92Reason = "d92 rollback smoke"

// d92Answer is one HTTP answer.
type d92Answer struct {
	Status int
	Body   []byte
}

func (a d92Answer) typed() (code, detail string) {
	var e struct{ Code, Detail string }
	_ = json.Unmarshal(a.Body, &e)
	return e.Code, e.Detail
}

// uncontracted is the typed refusal of a D92 write on an installation that is not contracted.
func (a d92Answer) uncontracted() bool {
	code, detail := a.typed()
	return a.Status == 501 && code == "unsupported" && detail == "needs_contracted_installation"
}

func (a d92Answer) String() string { return fmt.Sprintf("%d %s", a.Status, trunc(string(a.Body), 240)) }

// Full is the answer with its whole body.
func (a d92Answer) Full() string { return fmt.Sprintf("%d %s", a.Status, a.Body) }

type d92Named struct {
	name string
	ans  d92Answer
}

// d92Install is one installation under test: the previous release's and the candidate's binary on one data
// directory, the organization administrator, the issue and the incident the issue producer made.
type d92Install struct {
	t                *testing.T
	oldHost, newHost *binaryHost
	site             *installSite
	fx               *installFixture
	owner, admin     *expandUser
	issue, incident  model.ID
	window           string
	stub             *gitlabtest.Server
}

func d92Releases(t *testing.T) (oldRel, newRel string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes and signals")
	}
	oldRel, newRel = os.Getenv("SOUNDPOST_UPGRADE_OLD_RELEASE"), os.Getenv("SOUNDPOST_UPGRADE_NEW_RELEASE")
	if oldRel == "" || newRel == "" {
		t.Skip("set SOUNDPOST_UPGRADE_OLD_RELEASE and SOUNDPOST_UPGRADE_NEW_RELEASE to release directories")
	}
	return oldRel, newRel
}

// d92StubCA writes the stub GitLab's own certificate (it is its own trust root and names its address) as the
// PEM file of --notify-ca-file; the certificate is read from a handshake verified against the stub's pool.
func d92StubCA(t *testing.T, stub *gitlabtest.Server) string {
	t.Helper()
	u, err := url.Parse(stub.URL)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", u.Host, &tls.Config{RootCAs: stub.Pool, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	path := filepath.Join(t.TempDir(), "stub-ca.pem")
	if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: conn.ConnectionState().PeerCertificates[0].Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// newD92Install makes the two hosts of one data directory; both get the egress allowance and the trust root of
// the stub GitLab (the previous release has the same flags).
func newD92Install(t *testing.T, stub *gitlabtest.Server) *d92Install {
	t.Helper()
	oldRel, newRel := d92Releases(t)
	args := []string{"--notify-egress-allow", stub.Allow.String(), "--notify-ca-file", d92StubCA(t, stub)}
	rep := map[string]any{}
	mk := func(rel string) *binaryHost {
		h, err := newBinaryHost(filepath.Join(rel, "linux-amd64", "soundpost"), rel, rep)
		if err != nil {
			t.Fatal(err)
		}
		return h.(*binaryHost)
	}
	oldHost, newHost := mk(oldRel), mk(newRel)
	newHost.cleanup() // only its binary is used: it runs on the old host's directory
	newHost.dir, newHost.holdDir = oldHost.dir, oldHost.holdDir
	oldHost.args, newHost.args = args, args
	t.Cleanup(oldHost.cleanup)
	if sum := func(h *binaryHost) string { s, _ := fileSHA256(h.path); return s }; sum(oldHost) == sum(newHost) {
		t.Fatal("the previous release and the candidate are the same binary")
	}
	return &d92Install{t: t, oldHost: oldHost, newHost: newHost, stub: stub, window: strconv.FormatInt(time.Now().Add(time.Hour).UnixNano(), 10)}
}

// start starts host's binary and waits until it is ready; the administrator logs in again (a restart, or another
// binary, needs a new session) once the installation is provisioned.
func (d *d92Install) start(h *binaryHost) installRun {
	d.t.Helper()
	r, err := h.start()
	if err != nil {
		d.t.Fatal(err)
	}
	cert, err := r.waitCertificate()
	if err != nil {
		r.kill()
		d.t.Fatalf("%s: %v\n%s", filepath.Base(filepath.Dir(h.path)), err, lastLines(h.logs.String(), 8))
	}
	if d.site == nil {
		d.site = newInstallSite(r.url(), cert)
	}
	d.site.base = r.url()
	if err = r.release(); err != nil {
		r.kill()
		d.t.Fatal(err)
	}
	if err = r.waitReady(90 * time.Second); err != nil {
		tail := lastLines(h.logs.String(), 8)
		r.kill()
		d.t.Fatalf("not ready: %v\n%s", err, tail)
	}
	d.t.Cleanup(func() { r.kill() })
	if d.admin != nil {
		if err = d.admin.login(d.site); err != nil {
			d.t.Fatal(err)
		}
	}
	return r
}

func (d *d92Install) post(path string, body any) d92Answer {
	d.t.Helper()
	var stale int
	status, raw, err := postRetryStale(d.admin.on(d.site), path, body, d.admin.session.CSRF, "", &stale)
	if err != nil {
		d.t.Fatalf("%s: %v", path, err)
	}
	return d92Answer{status, raw}
}

// provision bootstraps the running installation, makes an organization administrator and lets the served
// issue producer make an issue and an incident from one ingested error.
func (d *d92Install) provision(r installRun) {
	d.t.Helper()
	token, err := r.bootstrapToken()
	if err != nil {
		d.t.Fatal(err)
	}
	if d.fx, err = bootstrapInstallation(d.site, token); err != nil {
		d.t.Fatal(err)
	}
	d.owner = newExpandUser(d.site, "owner@install-smoke.invalid", d.fx.password)
	if err = d.owner.login(d.site); err != nil {
		d.t.Fatal(err)
	}
	d.admin = newExpandUser(d.site, "admin@d92-rollback.invalid", "d92 rollback organization administrator password 2026")
	d.admin.id = model.NewID()
	for _, step := range []struct {
		kind string
		p    auth.AdminPayload
	}{
		{"create_user", auth.AdminPayload{ID: d.admin.id, Email: d.admin.email, Password: d.admin.password}},
		{"membership", auth.AdminPayload{UserID: d.admin.id, Enabled: true}},
		{"org_admin", auth.AdminPayload{UserID: d.admin.id, Enabled: true}},
	} {
		if err = expandAdmin(d.owner, d.site, d.fx.org, step.kind, step.p); err != nil {
			d.t.Fatal(err)
		}
	}
	if err = d.admin.login(d.site); err != nil {
		d.t.Fatal(err)
	}

	resource := model.Resource{Service: d.fx.service, Environment: d.fx.environment, Build: d.fx.build, Instance: "instance", Labels: model.Labels{}}
	occ := model.ErrorOccurrence{Occurrence: model.NewID(), Class: "D92Error", Mechanism: "manual", Build: d.fx.build, Handled: true, Frames: []model.Frame{}}
	rec := model.Record{ID: model.NewID(), Kind: model.ErrorKind, ObservedAt: model.UnixNano(time.Now().Add(-time.Second).UnixNano()), Resource: resource, Payload: model.Payload{Error: &occ}}
	if err = ingestRecord(d.site, d.fx, rec, "d92_error"); err != nil {
		d.t.Fatal(err)
	}
	fp, err := issues.Fingerprint(1, d.fx.org, d.fx.project, occ)
	if err != nil {
		d.t.Fatal(err)
	}
	h := sha256.New()
	h.Write([]byte("soundpost.issue.v1"))
	h.Write(d.fx.org[:])
	h.Write(d.fx.project[:])
	h.Write([]byte{0, 1})
	h.Write(fp[:])
	copy(d.issue[:], h.Sum(nil))
	deadline := time.Now().Add(90 * time.Second)
	for ; time.Now().Before(deadline); time.Sleep(300 * time.Millisecond) {
		ans := d.issueEvidence()
		var v httpapi.IssueView
		if ans.Status == 200 && json.Unmarshal(ans.Body, &v) == nil && v.Grouping != nil {
			break
		}
	}
	for ; time.Now().Before(deadline); time.Sleep(300 * time.Millisecond) {
		var q httpapi.QueueView
		if ans := d.queue(); ans.Status == 200 && json.Unmarshal(ans.Body, &q) == nil && len(q.Entries) > 0 {
			if len(q.Entries) != 1 {
				d.t.Fatalf("the producer made %d incidents from one error", len(q.Entries))
			}
			d.incident = q.Entries[0].ID
			return
		}
	}
	d.t.Fatal("the served producers made no issue and incident from the ingested error within 90 s")
}

// ---- reads ----

func (d *d92Install) incidentGet() d92Answer {
	return d.post("/api/v1/incidents/get", httpapi.IncidentGetBody{Org: d.fx.org, ProjectID: d.fx.project, TargetID: d.incident})
}

func (d *d92Install) queue() d92Answer {
	return d.post("/api/v1/queue", httpapi.QueueBody{Org: d.fx.org, QueueRequest: httpapi.QueueRequest{Projects: []model.ID{d.fx.project}, Limit: 50}})
}

func (d *d92Install) issueEvidence() d92Answer {
	return d.post("/api/v1/evidence/issue", httpapi.IssueBody{Org: d.fx.org, Project: d.fx.project, Issue: d.issue})
}

func (d *d92Install) investigateIssue() d92Answer {
	return d.post("/api/v1/investigate", map[string]any{"org": d.fx.org.String(), "kind": "issue", "projects": []string{d.fx.project.String()}, "target": d.issue.String(),
		"window": map[string]string{"start": "0", "end": d.window}, "limit": 50})
}

func (d *d92Install) markdown(path string, id model.ID) d92Answer {
	return d.post(path, httpapi.MarkdownBody{Org: d.fx.org, ProjectID: d.fx.project, ID: id, Format: "timeline"})
}

func (d *d92Install) gitlabPreview(kind string, id model.ID) d92Answer {
	return d.post("/api/v1/gitlab/issues", map[string]any{"op": httpapi.GitLabOpPreview, "org": d.fx.org, "project_id": d.fx.project, "entity": map[string]any{"kind": kind, "id": id}})
}

// settingsRead is the organization's GitLab settings as the caller sees them.
func (d *d92Install) settingsRead() d92Answer {
	return d.post("/api/v1/gitlab/settings", map[string]any{"op": httpapi.GitLabOpRead, "org": d.fx.org})
}

// previousReads are the reads the previous release serves.
func (d *d92Install) previousReads() []d92Named {
	return []d92Named{{"incident_get", d.incidentGet()}, {"queue", d.queue()}, {"issue_evidence", d.issueEvidence()}, {"investigate_issue", d.investigateIssue()}}
}

// candidateReads are every read of the D92 records the candidate serves.
func (d *d92Install) candidateReads() []d92Named {
	return append(d.previousReads(),
		d92Named{"incident_timeline_markdown", d.markdown("/api/v1/incidents/markdown", d.incident)},
		d92Named{"gitlab_preview_incident", d.gitlabPreview("incident", d.incident)},
		d92Named{"gitlab_preview_issue", d.gitlabPreview("issue", d.issue)},
		d92Named{"gitlab_settings", d.settingsRead()})
}

func (d *d92Install) issueRevision() model.Uint64 {
	var v httpapi.IssueView
	if ans := d.issueEvidence(); ans.Status != 200 || json.Unmarshal(ans.Body, &v) != nil || v.Grouping == nil {
		d.t.Fatalf("issue evidence: %s", ans)
	}
	return v.Grouping.Revision
}

func (d *d92Install) incidentVersion() model.Uint64 {
	var v httpapi.IncidentView
	if ans := d.incidentGet(); ans.Status != 200 || json.Unmarshal(ans.Body, &v) != nil {
		d.t.Fatalf("incident get: %s", ans)
	}
	return v.Version
}

// ---- the D92 writes ----

func (d *d92Install) assignIssue() d92Answer {
	return d.post("/api/v1/actions", httpapi.ActionBody{Org: d.fx.org, ActionRequest: httpapi.ActionRequest{CommandID: model.NewID(), ExpectedVersion: d.issueRevision(), ProjectID: d.fx.project, TargetID: d.issue,
		EntityKind: httpapi.EntityIssue, Kind: httpapi.ActionAssign, Payload: httpapi.ActionPayload{Owner: &d.admin.id}}})
}

func (d *d92Install) incidentAction(kind httpapi.ActionKind, p httpapi.ActionPayload) d92Answer {
	return d.post("/api/v1/actions", httpapi.ActionBody{Org: d.fx.org, ActionRequest: httpapi.ActionRequest{CommandID: model.NewID(), ExpectedVersion: d.incidentVersion(), ProjectID: d.fx.project, TargetID: d.incident,
		EntityKind: httpapi.EntityIncident, Kind: kind, Payload: p}})
}

func (d *d92Install) titleIncident() d92Answer {
	return d.incidentAction(httpapi.ActionTitle, httpapi.ActionPayload{Title: "Checkout fails after deploy"})
}

func (d *d92Install) noteIncident() d92Answer {
	return d.incidentAction(httpapi.ActionNote, httpapi.ActionPayload{Note: "Rolled the deploy back; watching the error rate."})
}

// connectGitLab saves the organization's connection to the stub (an organization setting the previous release
// ignores): base URL, token, and one mapping for the project.
func (d *d92Install) connectGitLab() d92Answer {
	var cur httpapi.GitLabSettingsView
	if ans := d.settingsRead(); ans.Status != 200 || json.Unmarshal(ans.Body, &cur) != nil {
		d.t.Fatalf("gitlab settings read: %s", ans)
	}
	return d.post("/api/v1/gitlab/settings", map[string]any{"op": httpapi.GitLabOpSave, "org": d.fx.org, "command_id": model.NewID(), "expected_epoch": cur.Epoch, "reason": d92Reason,
		"connection": httpapi.GitLabConnectionBody{BaseURL: d.stub.URL, Token: "glpat-d92-rollback-token", Mappings: []auth.GitLabMapping{{ProjectID: d.fx.project, GitLabProject: "shop/web", CreateFrom: []string{"incident", "issue"}, Labels: []string{}}}}})
}

func (d *d92Install) createGitLab(kind string, id model.ID) d92Answer {
	return d.post("/api/v1/gitlab/issues", map[string]any{"op": httpapi.GitLabOpCreate, "org": d.fx.org, "project_id": d.fx.project, "entity": map[string]any{"kind": kind, "id": id}, "command_id": model.NewID()})
}

// ---- the stored control state ----

// storedKeys is the stored control state of the (stopped) installation by top-level member.
func (d *d92Install) storedKeys(dir string) map[string]string {
	d.t.Helper()
	state, _, err := readControlState(dir)
	if err != nil {
		d.t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err = json.Unmarshal(state, &m); err != nil {
		d.t.Fatal(err)
	}
	out := map[string]string{}
	for k, v := range m {
		out[k] = string(v)
	}
	return out
}

// contracted is whether the organization carries the contraction mark and whether the installation is marked
// born contracted, from the stored control state.
func (d *d92Install) contracted() (orgMark, born bool) {
	d.t.Helper()
	settings, err := readOrgSettings(d.oldHost.dir, d.fx.org)
	if err != nil {
		d.t.Fatal(err)
	}
	_, orgMark = settings[model.IndexesContractedKey]
	state, _, err := readControlState(d.oldHost.dir)
	if err != nil {
		d.t.Fatal(err)
	}
	var st struct{ OIDC map[string]json.RawMessage }
	if err = json.Unmarshal(state, &st); err != nil {
		d.t.Fatal(err)
	}
	_, born = st.OIDC[model.IndexesContractedKey]
	return orgMark, born
}

// perRun are the only values that differ between two answers of one unchanged state: the request ID an error body
// carries (per request) and the node's own origin (https://127.0.0.1:<port>), which is a per-start value (the port is
// chosen at every start) that the console links in the timeline export and in the GitLab description are built from.
var perRun = regexp.MustCompile(`"request_id":"[0-9a-f]+"|https://127\.0\.0\.1:[0-9]+`)

func normalized(b []byte) []byte { return perRun.ReplaceAll(b, []byte("<per-run>")) }

// requireSameReads requires every read to be the same answer, byte for byte, but for the per-request and per-start values.
func requireSameReads(t *testing.T, what string, before, after []d92Named) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("%s: %d reads against %d", what, len(before), len(after))
	}
	for i := range before {
		if before[i].name != after[i].name || before[i].ans.Status != after[i].ans.Status || !bytes.Equal(normalized(before[i].ans.Body), normalized(after[i].ans.Body)) {
			t.Errorf("%s: %s differs:\n  before %s\n  after  %s", what, before[i].name, before[i].ans, after[i].ans)
		}
	}
}

func mustJSON[T any](t *testing.T, what string, ans d92Answer) T {
	t.Helper()
	var v T
	if ans.Status != 200 || json.Unmarshal(ans.Body, &v) != nil {
		t.Fatalf("%s: %s", what, ans)
	}
	return v
}

// ---- what the previous release does on a directory the candidate wrote ----

type d92Observed struct {
	Exited  bool   `json:"exited"`
	Exit    string `json:"exit,omitempty"`
	Ready   bool   `json:"ready"`
	Reason  string `json:"reason,omitempty"`
	LogTail string `json:"-"`
}

// observe starts host's binary on its directory and records whether it listens, exits, is ready or says why
// it is not. The running process (if any) is returned.
func (d *d92Install) observe(h *binaryHost) (installRun, d92Observed) {
	d.t.Helper()
	logStart := len(h.logs.String())
	r, err := h.start()
	if err != nil {
		d.t.Fatal(err)
	}
	var obs d92Observed
	exitText := func() {
		br := r.(*binaryRun)
		select {
		case e := <-br.done:
			br.done <- e
			obs.Exited, obs.Exit = true, fmt.Sprint(e)
		default:
		}
	}
	if _, err = r.waitCertificate(); err != nil {
		exitText()
		obs.LogTail = h.logs.String()[logStart:]
		if !obs.Exited {
			r.kill()
		}
		return nil, obs
	}
	d.site.base = r.url()
	_ = r.release()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if st, e := r.readyOnce(); e == nil {
			obs.Ready, obs.Reason = st.Ready, st.Reason
			if st.Ready || (st.Reason != "" && st.Reason != "starting" && st.Reason != "startup_hold") {
				break
			}
		}
		exitText()
		if obs.Exited {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	obs.LogTail = h.logs.String()[logStart:]
	return r, obs
}

func (d *d92Install) report(name string, v any) {
	raw, _ := json.MarshalIndent(v, "", "  ")
	d.t.Logf("D92 %s: %s", name, raw)
	if out := os.Getenv("SOUNDPOST_D92_REPORT"); out != "" {
		f, err := os.OpenFile(out, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			fmt.Fprintf(f, "%s %s: %s\n", d.t.Name(), name, strings.ReplaceAll(string(raw), "\n", " "))
			f.Close()
		}
	}
}
