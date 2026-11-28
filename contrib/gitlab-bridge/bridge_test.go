// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testSecret   = "bridge-secret-0123456789"
	testPrevious = "bridge-previous-9876543210"
	testToken    = "bridge-gitlab-token-abcdef"
	orgID        = "a1000000000000000000000000000000"
	projectID    = "b2000000000000000000000000000000"
	otherProject = "b3000000000000000000000000000000"
	issueID      = "c3000000000000000000000000000000"
	incidentID   = "d4000000000000000000000000000000"
)

// ---------------------------------------------------------------- stub GitLab

type stubIssue struct {
	IID         int
	Description string
	Title       string
	Labels      string
	Notes       []string
}

// stubGitLab is a local GitLab. NO real GitLab instance is involved.
type stubGitLab struct {
	mu     sync.Mutex
	issues []*stubIssue
	posts  int
	notes  int
	tokens []string
	fail   int // answer this status to every request while non-zero
}

func (s *stubGitLab) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = append(s.tokens, r.Header.Get("PRIVATE-TOKEN"))
	if s.fail != 0 {
		w.WriteHeader(s.fail)
		return
	}
	path := r.URL.EscapedPath()
	const prefix = "/api/v4/projects/shop%2Fweb/issues"
	switch {
	case r.Method == "GET" && path == prefix:
		var out []map[string]any
		for _, it := range s.issues {
			if strings.Contains(it.Description, r.URL.Query().Get("search")) {
				out = append(out, map[string]any{"iid": it.IID, "web_url": fmt.Sprintf("https://gitlab.example.test/shop/web/-/issues/%d", it.IID), "description": it.Description})
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	case r.Method == "POST" && path == prefix:
		s.posts++
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		it := &stubIssue{IID: len(s.issues) + 1, Description: in["description"], Title: in["title"], Labels: in["labels"]}
		s.issues = append(s.issues, it)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"iid": it.IID, "web_url": fmt.Sprintf("https://gitlab.example.test/shop/web/-/issues/%d", it.IID), "description": it.Description})
	case strings.HasPrefix(path, prefix+"/") && strings.HasSuffix(path, "/notes"):
		iid, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(path, prefix+"/"), "/notes"))
		if iid < 1 || iid > len(s.issues) {
			http.NotFound(w, r)
			return
		}
		it := s.issues[iid-1]
		if r.Method == "POST" {
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			it.Notes = append(it.Notes, in["body"])
			s.notes++
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":1}`))
			return
		}
		var out []map[string]string
		for _, n := range it.Notes {
			out = append(out, map[string]string{"body": n})
		}
		_ = json.NewEncoder(w).Encode(out)
	default:
		http.NotFound(w, r)
	}
}

func (s *stubGitLab) counts() (issues, posts, notes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.issues), s.posts, s.notes
}

func (s *stubGitLab) set(f func(*stubGitLab)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

// ---------------------------------------------------------------- rig

type rig struct {
	t      *testing.T
	stub   *stubGitLab
	srv    *httptest.Server
	state  string
	now    time.Time
	b      *bridge
	logs   *bytes.Buffer
	logsMu sync.Mutex
}

func (r *rig) clock() time.Time { return r.now }

func testConfig(base, state string) Config {
	return Config{GitLabBaseURL: base, StateFile: state, Secret: testSecret, GitLabToken: testToken,
		Projects: map[string]ProjectMapping{projectID: {GitLabProject: "shop/web", Labels: []string{"soundpost", "triage"}}}}
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, stub: &stubGitLab{}, now: time.Unix(1_800_000_000, 0), logs: &bytes.Buffer{}}
	r.srv = httptest.NewTLSServer(r.stub)
	t.Cleanup(r.srv.Close)
	r.state = filepath.Join(t.TempDir(), "state", "deliveries.log")
	r.boot()
	return r
}

// boot (re)starts the bridge over the same state file, like a process restart.
func (r *rig) boot() {
	r.t.Helper()
	if r.b != nil {
		r.b.seen.close()
	}
	seen, err := openDedup(r.state, dedupTTL, dedupMax, r.clock)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(seen.close)
	gl := newGitLabClient(r.srv.URL, testToken, nil)
	gl.http = r.srv.Client()
	gl.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	r.b = newBridge(testConfig(r.srv.URL, r.state), gl, seen, r.clock)
	r.b.logf = func(format string, args ...any) {
		r.logsMu.Lock()
		defer r.logsMu.Unlock()
		fmt.Fprintf(r.logs, format+"\n", args...)
	}
}

type delivery struct {
	id, event string
	body      map[string]any
	secret    string
	ts        time.Time
}

func (r *rig) newDelivery(event, id string, extra map[string]any) delivery {
	body := map[string]any{"version": 1, "delivery_id": id, "event": event, "occurred_at": "1800000000000000000", "org": orgID, "project": projectID, "url": "https://console.example.test/#view=issues&org=" + orgID}
	for k, v := range extra {
		body[k] = v
	}
	return delivery{id: id, event: event, body: body, secret: testSecret, ts: r.now}
}

func (r *rig) send(d delivery, mutate func(*http.Request)) (int, map[string]string) {
	r.t.Helper()
	raw, _ := json.Marshal(d.body)
	ts := strconv.FormatInt(d.ts.Unix(), 10)
	req := httptest.NewRequest("POST", "/soundpost", bytes.NewReader(raw))
	req.Header.Set("Soundpost-Event", d.event)
	req.Header.Set("Soundpost-Delivery-ID", d.id)
	req.Header.Set("Soundpost-Timestamp", ts)
	req.Header.Set("Soundpost-Signature", sign([]byte(d.secret), ts, d.id, raw))
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	r.b.routes().ServeHTTP(rec, req)
	var out map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (r *rig) issueNew(id string) delivery {
	return r.newDelivery("issue.new", id, map[string]any{"issue": issueID, "release_id": "e5000000000000000000000000000000"})
}

// ---------------------------------------------------------------- tests

func TestIssueNewCreatesOneGitLabIssue(t *testing.T) {
	r := newRig(t)
	status, out := r.send(r.issueNew("deliv1"), nil)
	if status != 200 || out["status"] != "created" {
		t.Fatalf("%d %v", status, out)
	}
	issues, posts, _ := r.stub.counts()
	if issues != 1 || posts != 1 {
		t.Fatalf("issues %d posts %d", issues, posts)
	}
	it := r.stub.issues[0]
	marker := markerOf(orgID, "issue", issueID)
	if it.Title != "Soundpost issue c3000000" || it.Labels != "soundpost,triage" || !strings.Contains(it.Description, marker) {
		t.Fatalf("issue %+v", it)
	}
	for _, want := range []string{issueID, projectID, orgID, "[Open in Soundpost](https://console.example.test/#view=issues"} {
		if !strings.Contains(it.Description, want) {
			t.Errorf("description lacks %q:\n%s", want, it.Description)
		}
	}
	for _, seen := range r.stub.tokens {
		if seen != testToken {
			t.Fatalf("PRIVATE-TOKEN %q", seen)
		}
	}
}

func TestIncidentOpenedTitleCarriesSeverity(t *testing.T) {
	r := newRig(t)
	d := r.newDelivery("incident.opened", "deliv-inc", map[string]any{"incident": incidentID, "severity": "critical"})
	status, out := r.send(d, nil)
	if status != 200 || out["status"] != "created" {
		t.Fatalf("%d %v", status, out)
	}
	it := r.stub.issues[0]
	if it.Title != "Soundpost incident d4000000 (critical)" || !strings.Contains(it.Description, "- Severity: `critical`") || !strings.Contains(it.Description, markerOf(orgID, "incident", incidentID)) {
		t.Fatalf("issue %+v", it)
	}
	// The same incident and the same issue ID never share a marker.
	if markerOf(orgID, "incident", incidentID) == markerOf(orgID, "issue", incidentID) || markerOf(orgID, "issue", issueID) == markerOf("a2000000000000000000000000000000", "issue", issueID) {
		t.Fatal("markers collide")
	}
}

func TestBadSignatureIsRefusedAndNothingIsSent(t *testing.T) {
	r := newRig(t)
	d := r.issueNew("deliv-bad")
	d.secret = "some-other-secret-0123456789"
	if status, out := r.send(d, nil); status != 401 || out["code"] != "signature_invalid" {
		t.Fatalf("wrong secret: %d %v", status, out)
	}
	if status, _ := r.send(r.issueNew("deliv-tamper"), func(req *http.Request) {
		req.Body = http.NoBody
		raw := []byte(`{"version":1,"delivery_id":"deliv-tamper","event":"issue.new","org":"` + orgID + `","project":"` + projectID + `","issue":"` + issueID + `","note":"x"}`)
		req.Body = nopCloser{bytes.NewReader(raw)}
	}); status != 401 {
		t.Fatalf("tampered body: %d", status)
	}
	for name, mutate := range map[string]func(*http.Request){
		"no signature":      func(req *http.Request) { req.Header.Del("Soundpost-Signature") },
		"no delivery id":    func(req *http.Request) { req.Header.Del("Soundpost-Delivery-ID") },
		"no timestamp":      func(req *http.Request) { req.Header.Del("Soundpost-Timestamp") },
		"garbage signature": func(req *http.Request) { req.Header.Set("Soundpost-Signature", "v1=zz,v2=abcd") },
		"short signature":   func(req *http.Request) { req.Header.Set("Soundpost-Signature", "v1=abcd") },
		"other delivery id": func(req *http.Request) { req.Header.Set("Soundpost-Delivery-ID", "deliv-other") },
		"other timestamp":   func(req *http.Request) { req.Header.Set("Soundpost-Timestamp", strconv.FormatInt(r.now.Unix()+1, 10)) },
	} {
		if status, _ := r.send(r.issueNew("deliv-x"), mutate); status != 401 {
			t.Errorf("%s: %d", name, status)
		}
	}
	if issues, posts, _ := r.stub.counts(); issues != 0 || posts != 0 || len(r.stub.tokens) != 0 {
		t.Fatalf("GitLab reached by an unsigned request")
	}
}

type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }

func TestStaleTimestampIsRefused(t *testing.T) {
	r := newRig(t)
	for name, ts := range map[string]time.Time{"six minutes old": r.now.Add(-6 * time.Minute), "six minutes ahead": r.now.Add(6 * time.Minute), "a day old": r.now.Add(-24 * time.Hour)} {
		d := r.issueNew("deliv-stale")
		d.ts = ts
		if status, out := r.send(d, nil); status != 401 || out["code"] != "timestamp_stale" {
			t.Errorf("%s: %d %v", name, status, out)
		}
	}
	// Inside the window is fine, at either edge.
	for _, ts := range []time.Time{r.now.Add(-4 * time.Minute), r.now.Add(4 * time.Minute)} {
		d := r.issueNew("deliv-edge-" + strconv.FormatInt(ts.Unix(), 10))
		d.ts = ts
		if status, out := r.send(d, nil); status != 200 {
			t.Errorf("inside the window: %d %v", status, out)
		}
	}
	if issues, _, _ := r.stub.counts(); issues != 1 {
		t.Fatalf("issues %d", issues)
	}
}

func TestSecretRotationAcceptsAnyOfTheValues(t *testing.T) {
	r := newRig(t)
	r.b.cfg.PreviousSecret = testPrevious
	r.b.secrets = [][]byte{[]byte(testSecret), []byte(testPrevious)}
	// Signed with the previous secret only.
	d := r.issueNew("deliv-prev")
	d.secret = testPrevious
	if status, out := r.send(d, nil); status != 200 {
		t.Fatalf("previous secret: %d %v", status, out)
	}
	// Soundpost sends two v1 values during a rotation; the second is the one that matches.
	d = r.newDelivery("incident.opened", "deliv-two", map[string]any{"incident": incidentID, "severity": "major"})
	raw, _ := json.Marshal(d.body)
	ts := strconv.FormatInt(d.ts.Unix(), 10)
	two := sign([]byte("a-secret-this-bridge-lacks-1"), ts, d.id, raw) + "," + sign([]byte(testSecret), ts, d.id, raw)
	if status, out := r.send(d, func(req *http.Request) { req.Header.Set("Soundpost-Signature", two) }); status != 200 {
		t.Fatalf("two values: %d %v", status, out)
	}
	// A secret the bridge does not know is still refused.
	d = r.issueNew("deliv-unknown")
	d.secret = "a-secret-this-bridge-lacks-1"
	if status, _ := r.send(d, nil); status != 401 {
		t.Fatalf("unknown secret: %d", status)
	}
}

func TestReplayOfADeliveryIsADuplicate(t *testing.T) {
	r := newRig(t)
	d := r.issueNew("deliv-replay")
	if status, out := r.send(d, nil); status != 200 || out["status"] != "created" {
		t.Fatalf("%d %v", status, out)
	}
	for range 3 {
		if status, out := r.send(d, nil); status != 200 || out["status"] != "duplicate" {
			t.Fatalf("replay: %d %v", status, out)
		}
	}
	if issues, posts, _ := r.stub.counts(); issues != 1 || posts != 1 {
		t.Fatalf("issues %d posts %d", issues, posts)
	}
}

func TestDeduplicationSurvivesARestart(t *testing.T) {
	r := newRig(t)
	d := r.issueNew("deliv-restart")
	if status, _ := r.send(d, nil); status != 200 {
		t.Fatal(status)
	}
	r.boot()
	r.stub.set(func(s *stubGitLab) { s.tokens = nil })
	if status, out := r.send(d, nil); status != 200 || out["status"] != "duplicate" {
		t.Fatalf("after a restart: %d %v", status, out)
	}
	if len(r.stub.tokens) != 0 {
		t.Fatal("GitLab was asked about a delivery the state file already held")
	}
}

func TestCrashBeforeTheDeliveryWasRecordedNeverDuplicates(t *testing.T) {
	// The issue was created but the process died before the delivery ID was written:
	// the retry (a restart with an empty state) finds the issue by its marker.
	r := newRig(t)
	d := r.issueNew("deliv-crash")
	if status, _ := r.send(d, nil); status != 200 {
		t.Fatal(status)
	}
	if err := os.Remove(r.state); err != nil {
		t.Fatal(err)
	}
	r.boot()
	if status, out := r.send(d, nil); status != 200 || out["status"] != "exists" {
		t.Fatalf("retry: %d %v", status, out)
	}
	// A different delivery about the same entity finds the same issue too.
	if status, out := r.send(r.issueNew("deliv-crash-2"), nil); status != 200 || out["status"] != "exists" {
		t.Fatalf("second delivery: %d %v", status, out)
	}
	if issues, posts, _ := r.stub.counts(); issues != 1 || posts != 1 {
		t.Fatalf("issues %d posts %d: lookup must come before create", issues, posts)
	}
}

func TestSearchAloneIsNotTrusted(t *testing.T) {
	r := newRig(t)
	// An issue that mentions another marker must not be taken for ours.
	r.stub.issues = []*stubIssue{{IID: 1, Description: "see " + markerOf(orgID, "issue", incidentID)}}
	if status, out := r.send(r.issueNew("deliv-other"), nil); status != 200 || out["status"] != "created" {
		t.Fatalf("%d %v", status, out)
	}
	if issues, _, _ := r.stub.counts(); issues != 2 {
		t.Fatalf("issues %d", issues)
	}
}

func TestGitLabFailureIs5xxAndTheDeliveryIsNotRecorded(t *testing.T) {
	r := newRig(t)
	d := r.issueNew("deliv-500")
	r.stub.set(func(s *stubGitLab) { s.fail = 500 })
	if status, out := r.send(d, nil); status != 502 || out["code"] != "gitlab_unavailable" {
		t.Fatalf("GitLab 500: %d %v", status, out)
	}
	r.stub.set(func(s *stubGitLab) { s.fail = 401 })
	if status, _ := r.send(d, nil); status != 502 {
		t.Fatalf("GitLab 401 must be retried too: %d", status)
	}
	if r.b.seen.has("deliv-500") {
		t.Fatal("a failed delivery was recorded as done")
	}
	r.stub.set(func(s *stubGitLab) { s.fail = 0 })
	if status, out := r.send(d, nil); status != 200 || out["status"] != "created" {
		t.Fatalf("retry: %d %v", status, out)
	}
	if issues, posts, _ := r.stub.counts(); issues != 1 || posts != 1 {
		t.Fatalf("issues %d posts %d", issues, posts)
	}
}

func TestRegressedAddsOneNoteAndCreatesTheIssueWhenAbsent(t *testing.T) {
	r := newRig(t)
	reg := r.newDelivery("issue.regressed", "deliv-reg", map[string]any{"issue": issueID, "revision": "7", "release_id": "e5000000000000000000000000000000"})
	// No issue yet: it is created first, then the note is added.
	if status, out := r.send(reg, nil); status != 200 || out["status"] != "noted" {
		t.Fatalf("%d %v", status, out)
	}
	issues, posts, notes := r.stub.counts()
	if issues != 1 || posts != 1 || notes != 1 {
		t.Fatalf("issues %d posts %d notes %d", issues, posts, notes)
	}
	if n := r.stub.issues[0].Notes[0]; !strings.Contains(n, "revision 7") || !strings.Contains(n, "Soundpost delivery: deliv-reg") {
		t.Fatalf("note %q", n)
	}
	// The issue exists now: a second regression adds a note, never an issue.
	if status, out := r.send(r.newDelivery("issue.regressed", "deliv-reg-2", map[string]any{"issue": issueID, "revision": "9"}), nil); status != 200 || out["status"] != "noted" {
		t.Fatalf("%d %v", status, out)
	}
	if issues, posts, notes = r.stub.counts(); issues != 1 || posts != 1 || notes != 2 {
		t.Fatalf("issues %d posts %d notes %d", issues, posts, notes)
	}
	// A crash after the note and before the record: the retry adds no second note.
	if err := os.Remove(r.state); err != nil {
		t.Fatal(err)
	}
	r.boot()
	if status, out := r.send(reg, nil); status != 200 || out["status"] != "noted" {
		t.Fatalf("retry: %d %v", status, out)
	}
	if issues, posts, notes = r.stub.counts(); issues != 1 || posts != 1 || notes != 2 {
		t.Fatalf("a retry duplicated work: issues %d posts %d notes %d", issues, posts, notes)
	}
}

func TestOtherEventsAndUnmappedProjectsAreAcknowledgedAndIgnored(t *testing.T) {
	r := newRig(t)
	for _, ev := range []string{"issue.resolved", "incident.acknowledged", "incident.resolved", "release.registered", "something.else"} {
		d := r.newDelivery(ev, "deliv-"+strings.ReplaceAll(ev, ".", "-"), map[string]any{"issue": issueID})
		if status, out := r.send(d, nil); status != 200 || out["status"] != "ignored" {
			t.Errorf("%s: %d %v", ev, status, out)
		}
	}
	if status, out := r.send(r.newDelivery("test.ping", "deliv-ping", nil), nil); status != 200 || out["status"] != "pong" {
		t.Errorf("ping: %d %v", status, out)
	}
	d := r.newDelivery("issue.new", "deliv-unmapped", map[string]any{"issue": issueID, "project": otherProject})
	if status, out := r.send(d, nil); status != 200 || out["status"] != "ignored" {
		t.Errorf("unmapped project: %d %v", status, out)
	}
	if len(r.stub.tokens) != 0 {
		t.Fatal("GitLab was called for an event that is not mirrored")
	}
}

func TestMalformedPayloadsAreRefusedAfterTheSignature(t *testing.T) {
	r := newRig(t)
	for name, mutate := range map[string]func(map[string]any){
		"version":          func(b map[string]any) { b["version"] = 2 },
		"delivery id":      func(b map[string]any) { b["delivery_id"] = "other" },
		"entity id":        func(b map[string]any) { b["issue"] = "not-hex" },
		"severity":         func(b map[string]any) { b["severity"] = "catastrophic" },
		"revision":         func(b map[string]any) { b["revision"] = "7; drop" },
		"url scheme":       func(b map[string]any) { b["url"] = "javascript:alert(1)" },
		"url credentials":  func(b map[string]any) { b["url"] = "https://u:p@console.example.test/" },
		"url mention":      func(b map[string]any) { b["url"] = "https://console.example.test/#@all" },
		"service markup":   func(b map[string]any) { b["service"] = "@all~label#1" },
		"release markup":   func(b map[string]any) { b["release_id"] = "/close @all" },
		"url markup":       func(b map[string]any) { b["url"] = "https://console.example.test/\"><script>" },
		"project":          func(b map[string]any) { b["project"] = "x" },
		"incident for new": func(b map[string]any) { delete(b, "issue"); b["incident"] = incidentID },
	} {
		d := r.issueNew("deliv-bad-" + strings.ReplaceAll(name, " ", "-"))
		mutate(d.body)
		if status, out := r.send(d, nil); status != 400 {
			t.Errorf("%s: %d %v", name, status, out)
		}
	}
	if len(r.stub.tokens) != 0 {
		t.Fatal("GitLab reached")
	}
	// Method and size.
	rec := httptest.NewRecorder()
	r.b.routes().ServeHTTP(rec, httptest.NewRequest("GET", "/soundpost", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", rec.Code)
	}
	big := httptest.NewRecorder()
	r.b.routes().ServeHTTP(big, httptest.NewRequest("POST", "/soundpost", bytes.NewReader(make([]byte, maxBody+1))))
	if big.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("large body: %d", big.Code)
	}
}

func TestLogsCarryNoSecretToken(t *testing.T) {
	r := newRig(t)
	r.stub.set(func(s *stubGitLab) { s.fail = 500 })
	_, _ = r.send(r.issueNew("deliv-log"), nil)
	bad := r.issueNew("deliv-log-2")
	bad.secret = "wrong-secret-0123456789"
	_, _ = r.send(bad, nil)
	r.stub.set(func(s *stubGitLab) { s.fail = 0 })
	_, _ = r.send(r.issueNew("deliv-log-3"), nil)
	r.logsMu.Lock()
	defer r.logsMu.Unlock()
	for _, secret := range []string{testSecret, testToken, "wrong-secret", "Soundpost-Signature", "v1="} {
		if strings.Contains(r.logs.String(), secret) {
			t.Fatalf("log carries %q:\n%s", secret, r.logs.String())
		}
	}
	if r.logs.Len() == 0 {
		t.Fatal("nothing was logged")
	}
}

func TestDedupIsBoundedAndExpiresAfterTwentyFiveHours(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "d.log")
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	// A file with an old entry, a live one, a torn line and a foreign line.
	old := strconv.FormatInt(now.Add(-26*time.Hour).Unix(), 10)
	live := strconv.FormatInt(now.Add(-24*time.Hour).Unix(), 10)
	if err := os.WriteFile(path, []byte(old+" gone\n"+live+" kept\ngarbage\n"+live+" bad id\n12"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := openDedup(path, dedupTTL, 3, clock)
	if err != nil {
		t.Fatal(err)
	}
	if d.has("gone") || !d.has("kept") {
		t.Fatalf("ttl: gone=%v kept=%v", d.has("gone"), d.has("kept"))
	}
	// Memory is bounded: the oldest entry makes room.
	for i, id := range []string{"a1", "a2", "a3", "a4"} {
		now = now.Add(time.Second * time.Duration(i+1))
		if err = d.add(id); err != nil {
			t.Fatal(err)
		}
	}
	if len(d.entries) > 3 || d.has("kept") || !d.has("a4") {
		t.Fatalf("entries %v", d.entries)
	}
	// An entry crosses the 25 hour line while the process runs.
	now = now.Add(26 * time.Hour)
	if d.has("a4") {
		t.Fatal("an entry older than 25 hours still counts")
	}
	d.close()
	reopened, err := openDedup(path, dedupTTL, 3, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	if len(reopened.entries) != 0 {
		t.Fatalf("expired entries survived a restart: %v", reopened.entries)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("state file mode %v %v", info, err)
	}
}

func TestLoadConfigRefusesUnsafeConfigurations(t *testing.T) {
	dir := t.TempDir()
	write := func(c map[string]any) string {
		raw, _ := json.Marshal(c)
		p := filepath.Join(dir, "c.json")
		_ = os.WriteFile(p, raw, 0o600)
		return p
	}
	base := func() map[string]any {
		return map[string]any{"gitlab_base_url": "https://gitlab.example.test", "state_file": filepath.Join(dir, "s"), "projects": map[string]any{projectID: map[string]any{"gitlab_project": "shop/web"}}}
	}
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	good := map[string]string{"SOUNDPOST_WEBHOOK_SECRET": testSecret, "GITLAB_TOKEN": testToken}
	cfg, err := loadConfig(write(base()), env(good))
	if err != nil || cfg.Secret != testSecret || cfg.GitLabToken != testToken || cfg.Listen == "" {
		t.Fatalf("good config: %+v %v", cfg, err)
	}
	for name, c := range map[string]struct {
		mutate func(map[string]any)
		env    map[string]string
	}{
		"http gitlab":    {func(m map[string]any) { m["gitlab_base_url"] = "http://gitlab.example.test" }, good},
		"credentials":    {func(m map[string]any) { m["gitlab_base_url"] = "https://u:p@gitlab.example.test" }, good},
		"no state file":  {func(m map[string]any) { delete(m, "state_file") }, good},
		"no projects":    {func(m map[string]any) { m["projects"] = map[string]any{} }, good},
		"bad project id": {func(m map[string]any) { m["projects"] = map[string]any{"x": map[string]any{"gitlab_project": "a/b"}} }, good},
		"bad path": {func(m map[string]any) {
			m["projects"] = map[string]any{projectID: map[string]any{"gitlab_project": "a b"}}
		}, good},
		"unknown field":  {func(m map[string]any) { m["secrets"] = "x" }, good},
		"no secret":      {func(m map[string]any) {}, map[string]string{"GITLAB_TOKEN": testToken}},
		"short secret":   {func(m map[string]any) {}, map[string]string{"SOUNDPOST_WEBHOOK_SECRET": "short", "GITLAB_TOKEN": testToken}},
		"no token":       {func(m map[string]any) {}, map[string]string{"SOUNDPOST_WEBHOOK_SECRET": testSecret}},
		"short previous": {func(m map[string]any) {}, map[string]string{"SOUNDPOST_WEBHOOK_SECRET": testSecret, "SOUNDPOST_WEBHOOK_SECRET_PREVIOUS": "p", "GITLAB_TOKEN": testToken}},
		"comma in a label": {func(m map[string]any) {
			m["projects"] = map[string]any{projectID: map[string]any{"gitlab_project": "a/b", "labels": []string{"a,b"}}}
		}, good},
	} {
		m := base()
		c.mutate(m)
		if _, err := loadConfig(write(m), env(c.env)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
