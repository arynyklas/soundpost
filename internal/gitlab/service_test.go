// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package gitlab

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

const testToken = "tok-0123456789abcdef-test"

// ---------------------------------------------------------------- GitLab stub

type stubIssue struct {
	IID         uint64
	Description string
	Title       string
	Labels      string
}

// stub is a local GitLab. NO real GitLab instance is involved.
type stub struct {
	srv *httptest.Server
	mu  sync.Mutex

	issues []stubIssue
	posts  int
	gets   int
	// tokens are the PRIVATE-TOKEN header values seen.
	tokens []string
	paths  []string

	// post behaviour
	postStatus     int           // when set, answer it without creating
	createThenFail int           // create the issue, then answer this status
	createThenDrop bool          // create the issue, then drop the connection
	postDelay      time.Duration // wait before answering a POST
	postBody       string        // answer this body (200) instead of an issue
	sloppySearch   bool          // list answers every issue, whatever the search
	getStatus      int
	redirectTo     string
	selfToken      string
}

func newStub(t *testing.T) *stub {
	t.Helper()
	s := &stub{}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stub) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(s.srv.Certificate())
	return p
}

func (s *stub) count() (posts, gets int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.posts, s.gets
}

func (s *stub) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.tokens = append(s.tokens, r.Header.Get("PRIVATE-TOKEN"))
	s.paths = append(s.paths, r.URL.EscapedPath())
	if s.redirectTo != "" {
		to := s.redirectTo
		s.mu.Unlock()
		http.Redirect(w, r, to, http.StatusFound)
		return
	}
	s.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.EscapedPath() == "/api/v4/personal_access_tokens/self":
		w.Header().Set("Content-Type", "application/json")
		body := s.selfToken
		if body == "" {
			body = `{"id":1,"name":"soundpost","active":true,"revoked":false,"scopes":["api","read_api","Bad Scope!"],"expires_at":"2027-01-31"}`
		}
		_, _ = w.Write([]byte(body))
	case r.Method == http.MethodGet && r.URL.EscapedPath() == "/api/v4/projects/shop%2Fweb/issues":
		s.mu.Lock()
		s.gets++
		status := s.getStatus
		var out []map[string]any
		for _, it := range s.issues {
			if s.sloppySearch || strings.Contains(it.Description, r.URL.Query().Get("search")) {
				out = append(out, issueJSON(it))
			}
		}
		s.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	case r.Method == http.MethodPost && r.URL.EscapedPath() == "/api/v4/projects/shop%2Fweb/issues":
		s.mu.Lock()
		s.posts++
		delay, status, then, drop, body := s.postDelay, s.postStatus, s.createThenFail, s.createThenDrop, s.postBody
		s.mu.Unlock()
		if delay > 0 {
			time.Sleep(delay)
		}
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		s.mu.Lock()
		it := stubIssue{IID: uint64(len(s.issues) + 1), Description: in["description"], Title: in["title"], Labels: in["labels"]}
		s.issues = append(s.issues, it)
		s.mu.Unlock()
		switch {
		case drop:
			c, _, _ := w.(http.Hijacker).Hijack()
			_ = c.Close()
		case then != 0:
			w.WriteHeader(then)
		case body != "":
			_, _ = w.Write([]byte(body))
		default:
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(issueJSON(it))
		}
	default:
		http.NotFound(w, r)
	}
}

func issueJSON(it stubIssue) map[string]any {
	return map[string]any{"iid": it.IID, "web_url": fmt.Sprintf("https://gitlab.example.test/shop/web/-/issues/%d", it.IID), "description": it.Description, "title": it.Title}
}

// ---------------------------------------------------------------- fakes

type fakeSettings struct {
	conn  Connection
	found bool
}

func (f *fakeSettings) Connection(context.Context, model.ID) (Connection, bool, error) {
	return f.conn, f.found, nil
}

type fakeEntity struct {
	facts    Facts
	version  uint64
	external []model.ExternalLink
}

// fakeEntities applies the real model state machine under a version CAS, like the
// incident reducer and the issue lifecycle do.
type fakeEntities struct {
	mu       sync.Mutex
	clock    func() model.UnixNano
	byKey    map[Target]*fakeEntity
	applied  []model.ExternalOp
	failEnds bool   // every external_end is refused (a crash before it is recorded)
	bump     func() // runs once before the next begin is applied: another action moves the entity
	deny     map[Target]bool
}

func (f *fakeEntities) key(kind string, project, id model.ID) Target {
	return Target{Org: testOrg, Project: project, Kind: kind, ID: id}
}

func (f *fakeEntities) Read(_ context.Context, _ auth.Scope, kind string, project, id model.ID) (Entity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.byKey[f.key(kind, project, id)]
	if !ok || f.deny[f.key(kind, project, id)] {
		return Entity{}, model.Fail(model.NotFound)
	}
	return Entity{Facts: e.facts, Version: e.version, External: append([]model.ExternalLink(nil), e.external...)}, nil
}

func (f *fakeEntities) Apply(_ context.Context, _ auth.Scope, kind string, project, id model.ID, expected uint64, op model.ExternalOp) (Entity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.byKey[f.key(kind, project, id)]
	if !ok {
		return Entity{}, model.Fail(model.NotFound)
	}
	if f.bump != nil && op.Kind == model.ExternalBegin {
		bump := f.bump
		f.bump = nil
		e.version++
		bump()
	}
	if expected != e.version {
		return Entity{}, ErrVersionConflict
	}
	if f.failEnds && op.Kind == model.ExternalEnd {
		return Entity{}, model.Fail(model.Unavailable)
	}
	next, err := model.ApplyExternal(e.external, op, testActor, f.clock())
	if err != nil {
		return Entity{}, err
	}
	e.external, e.version = next, e.version+1
	f.applied = append(f.applied, op)
	return Entity{Facts: e.facts, Version: e.version, External: append([]model.ExternalLink(nil), next...)}, nil
}

func (f *fakeEntities) links(kind string, project, id model.ID) []model.ExternalLink {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]model.ExternalLink(nil), f.byKey[f.key(kind, project, id)].external...)
}

var (
	testOrg     = mustID("a1")
	testProject = mustID("b2")
	testIncA    = mustID("c3")
	testIncB    = mustID("c4")
	testIssue   = mustID("d5")
	testActor   = mustID("e6")
)

func mustID(prefix string) model.ID {
	id, err := model.ParseID(prefix + strings.Repeat("0", 32-len(prefix)))
	if err != nil {
		panic(err)
	}
	return id
}

type rig struct {
	t        *testing.T
	stub     *stub
	svc      *Service
	ents     *fakeEntities
	settings *fakeSettings
	now      time.Time
	mu       sync.Mutex
}

func (r *rig) clock() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.now
}

func (r *rig) advance(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, stub: newStub(t), now: time.Unix(1_800_000_000, 0)}
	r.settings = &fakeSettings{found: true, conn: Connection{BaseURL: r.stub.srv.URL, Token: testToken,
		Mappings: []Mapping{{Project: testProject, GitLabProject: "shop/web", CreateFrom: []string{KindIncident, KindIssue}, Labels: []string{"soundpost", "triage"}}}}}
	r.ents = &fakeEntities{clock: func() model.UnixNano { return model.UnixNano(r.clock().UnixNano()) }, deny: map[Target]bool{}, byKey: map[Target]*fakeEntity{
		{Org: testOrg, Project: testProject, Kind: KindIncident, ID: testIncA}: {version: 3, facts: Facts{Kind: KindIncident, ID: testIncA, Project: testProject, Severity: "major", Status: "open", Related: []Ref{{Kind: KindIssue, ID: testIssue}}}},
		{Org: testOrg, Project: testProject, Kind: KindIncident, ID: testIncB}: {version: 1, facts: Facts{Kind: KindIncident, ID: testIncB, Project: testProject, Severity: "minor", Status: "open"}},
		{Org: testOrg, Project: testProject, Kind: KindIssue, ID: testIssue}:   {version: 7, facts: Facts{Kind: KindIssue, ID: testIssue, Project: testProject, Status: "open"}},
	}}
	eg := Egress{loopbackOK: true}
	svc, err := New(Options{Settings: r.settings, Entities: r.ents, Origin: "https://console.example.test", Egress: eg, RootCAs: r.stub.pool(), Timeout: 3 * time.Second, Now: r.clock})
	if err != nil {
		t.Fatal(err)
	}
	r.svc = svc
	return r
}

func (r *rig) target(kind string, id model.ID) Target {
	return Target{Org: testOrg, Project: testProject, Kind: kind, ID: id}
}

func (r *rig) create(kind string, id model.ID) (Result, error) {
	return r.svc.Create(context.Background(), auth.Scope{}, CreateRequest{Target: r.target(kind, id), CommandID: model.NewID()})
}

func wantState(t *testing.T, res Result, err error, state string) {
	t.Helper()
	if err != nil || res.State != state {
		t.Fatalf("result %+v err %v, want state %s", res, err, state)
	}
}

// ---------------------------------------------------------------- tests

func TestCreateHappyPath(t *testing.T) {
	r := newRig(t)
	res, err := r.create(KindIncident, testIncA)
	wantState(t, res, err, StateLinked)
	if !res.Created || res.IID != 1 || res.GitLabProject != "shop/web" || !strings.HasPrefix(res.URL, "https://") {
		t.Fatalf("result %+v", res)
	}
	posts, gets := r.stub.count()
	if posts != 1 || gets != 1 {
		t.Fatalf("posts %d gets %d: lookup first, then exactly one create", posts, gets)
	}
	it := r.stub.issues[0]
	marker := model.ExternalMarker(testOrg, KindIncident, testIncA)
	if !strings.Contains(it.Description, marker) || it.Title != "Soundpost incident "+testIncA.String()[:8] || it.Labels != "soundpost,triage" {
		t.Fatalf("issue %+v", it)
	}
	for _, want := range []string{testIncA.String(), "major", "open", testIssue.String(), "https://console.example.test/#view=incidents&org=" + testOrg.String() + "&projects=" + testProject.String() + "&incident=" + testProject.String() + ":" + testIncA.String()} {
		if !strings.Contains(it.Description, want) {
			t.Errorf("description lacks %q:\n%s", want, it.Description)
		}
	}
	links := r.ents.links(KindIncident, testProject, testIncA)
	if len(links) != 1 || links[0].State != model.ExternalLinked || links[0].IID != 1 {
		t.Fatalf("links %+v", links)
	}
	// One GitLab issue per entity, ever: a second create returns the stored link.
	res, err = r.create(KindIncident, testIncA)
	wantState(t, res, err, StateLinked)
	if res.Created {
		t.Fatalf("second create reported created: %+v", res)
	}
	if posts, _ := r.stub.count(); posts != 1 {
		t.Fatalf("posts %d after second create", posts)
	}
}

func TestCreateIssueEntityAndCallerText(t *testing.T) {
	r := newRig(t)
	res, err := r.svc.Create(context.Background(), auth.Scope{}, CreateRequest{Target: r.target(KindIssue, testIssue), CommandID: model.NewID(), Title: "Checkout fails", Description: "Owner call", Labels: []string{"p1"}})
	wantState(t, res, err, StateLinked)
	it := r.stub.issues[0]
	if it.Title != "Checkout fails" || it.Labels != "p1" || !strings.HasPrefix(it.Description, "Owner call") || !strings.Contains(it.Description, model.ExternalMarker(testOrg, KindIssue, testIssue)) {
		t.Fatalf("issue %+v", it)
	}
	for _, bad := range []CreateRequest{
		{Title: "bad\x00title"}, {Title: strings.Repeat("x", 256)}, {Description: "steal soundpost-ref-0123456789abcdef0123456789abcdef"}, {Labels: []string{"a,b"}},
	} {
		bad.Target, bad.CommandID = r.target(KindIncident, testIncB), model.NewID()
		if _, err := r.svc.Create(context.Background(), auth.Scope{}, bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if posts, _ := r.stub.count(); posts != 1 {
		t.Fatalf("posts %d", posts)
	}
}

func TestMarkerLookupFindsIssueOfPreviousUnknownAttempt(t *testing.T) {
	r := newRig(t)
	r.stub.createThenFail = http.StatusInternalServerError
	res, err := r.create(KindIncident, testIncA)
	wantState(t, res, err, StateUnknown)
	if res.Code != CodeServerError {
		t.Fatalf("code %q", res.Code)
	}
	if l := r.ents.links(KindIncident, testProject, testIncA); len(l) != 1 || l[0].State != model.ExternalUnknown || l[0].Code != CodeServerError {
		t.Fatalf("links %+v", l)
	}
	r.stub.mu.Lock()
	r.stub.createThenFail = 0
	r.stub.mu.Unlock()
	// The next create looks the issue up by its marker BEFORE creating: no second POST.
	res, err = r.create(KindIncident, testIncA)
	wantState(t, res, err, StateLinked)
	if res.Created || res.IID != 1 {
		t.Fatalf("result %+v", res)
	}
	if posts, _ := r.stub.count(); posts != 1 {
		t.Fatalf("stub saw %d POSTs, want exactly one", posts)
	}
}

func TestSearchAloneIsNeverTrusted(t *testing.T) {
	r := newRig(t)
	r.stub.issues = []stubIssue{{IID: 9, Description: "unrelated " + model.ExternalMarker(testOrg, KindIncident, testIncB)}, {IID: 10, Description: "no marker at all"}}
	r.stub.sloppySearch = true
	res, err := r.create(KindIncident, testIncA)
	wantState(t, res, err, StateLinked)
	if !res.Created || res.IID != 3 {
		t.Fatalf("a sloppy search result was trusted: %+v", res)
	}
}

func TestTwoConcurrentCreatesMakeOnePost(t *testing.T) {
	r := newRig(t)
	r.stub.postDelay = 300 * time.Millisecond
	var wg sync.WaitGroup
	results := make([]Result, 2)
	errs := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = r.create(KindIncident, testIncA)
		}()
	}
	wg.Wait()
	linked, busy := 0, 0
	for i := range 2 {
		switch {
		case errs[i] == nil && results[i].State == StateLinked:
			linked++
		case detail(errs[i]) == "in_progress":
			busy++
		default:
			t.Fatalf("result %d: %+v %v", i, results[i], errs[i])
		}
	}
	if linked != 1 || busy != 1 {
		t.Fatalf("linked %d busy %d", linked, busy)
	}
	if posts, _ := r.stub.count(); posts != 1 {
		t.Fatalf("stub saw %d POSTs", posts)
	}
}

func TestCrashBetweenCreateAndEndThenRetryFindsByMarker(t *testing.T) {
	r := newRig(t)
	r.ents.failEnds = true
	res, err := r.create(KindIncident, testIncA)
	wantState(t, res, err, StateUnknown)
	if res.Code != CodeNotRecorded {
		t.Fatalf("code %q", res.Code)
	}
	if l := r.ents.links(KindIncident, testProject, testIncA); len(l) != 1 || l[0].State != model.ExternalCreating {
		t.Fatalf("links %+v: the lease must still stand", l)
	}
	r.ents.failEnds = false
	// While the lease stands nobody else creates.
	if _, err = r.create(KindIncident, testIncA); detail(err) != "in_progress" {
		t.Fatalf("err %v", err)
	}
	r.advance(3 * time.Minute)
	res, err = r.create(KindIncident, testIncA)
	wantState(t, res, err, StateLinked)
	if res.Created || res.IID != 1 {
		t.Fatalf("result %+v", res)
	}
	if posts, _ := r.stub.count(); posts != 1 {
		t.Fatalf("stub saw %d POSTs, want one", posts)
	}
}

func TestConnectionDropAfterWriteIsUnknownThenRecheckLinks(t *testing.T) {
	r := newRig(t)
	r.stub.createThenDrop = true
	res, err := r.create(KindIncident, testIncA)
	wantState(t, res, err, StateUnknown)
	r.stub.mu.Lock()
	r.stub.createThenDrop = false
	r.stub.mu.Unlock()
	res, err = r.svc.Recheck(context.Background(), auth.Scope{}, r.target(KindIncident, testIncA))
	wantState(t, res, err, StateLinked)
	if res.Created || res.IID != 1 {
		t.Fatalf("result %+v", res)
	}
	if posts, _ := r.stub.count(); posts != 1 {
		t.Fatalf("recheck created: %d POSTs", posts)
	}
	if l := r.ents.links(KindIncident, testProject, testIncA); l[0].State != model.ExternalLinked {
		t.Fatalf("links %+v", l)
	}
}

func TestRecheckNeverCreates(t *testing.T) {
	r := newRig(t)
	res, err := r.svc.Recheck(context.Background(), auth.Scope{}, r.target(KindIncident, testIncA))
	wantState(t, res, err, StateNotLinked)
	if res.Code != CodeNoMatch {
		t.Fatalf("code %q", res.Code)
	}
	r.stub.createThenFail = http.StatusBadGateway
	_, _ = r.create(KindIncident, testIncB)
	r.stub.mu.Lock()
	r.stub.issues = nil // the issue did not survive
	r.stub.createThenFail = 0
	r.stub.mu.Unlock()
	res, err = r.svc.Recheck(context.Background(), auth.Scope{}, r.target(KindIncident, testIncB))
	wantState(t, res, err, StateUnknown)
	if posts, _ := r.stub.count(); posts != 1 {
		t.Fatalf("posts %d", posts)
	}
}

func TestRecheckWhileLeaseHeldIsInProgress(t *testing.T) {
	r := newRig(t)
	r.ents.failEnds = true
	_, _ = r.create(KindIncident, testIncA)
	if _, err := r.svc.Recheck(context.Background(), auth.Scope{}, r.target(KindIncident, testIncA)); detail(err) != "in_progress" {
		t.Fatalf("err %v", err)
	}
}

func TestDefiniteClientErrorsAreRefusedWithClosedCodes(t *testing.T) {
	for status, code := range map[int]string{401: CodeUnauthorized, 403: CodeForbidden, 404: CodeNotFound, 400: CodeInvalid, 422: CodeUnprocessable} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			r := newRig(t)
			r.stub.postStatus = status
			res, err := r.create(KindIncident, testIncA)
			wantState(t, res, err, StateRefused)
			if res.Code != code {
				t.Fatalf("code %q want %q", res.Code, code)
			}
			if l := r.ents.links(KindIncident, testProject, testIncA); len(l) != 1 || l[0].State != model.ExternalRefused || l[0].Code != code {
				t.Fatalf("links %+v", l)
			}
			// A refusal is not terminal: after the cause is fixed the create goes through.
			r.stub.mu.Lock()
			r.stub.postStatus = 0
			r.stub.mu.Unlock()
			res, err = r.create(KindIncident, testIncA)
			wantState(t, res, err, StateLinked)
			if posts, _ := r.stub.count(); posts != 2 {
				t.Fatalf("posts %d", posts)
			}
		})
	}
}

func TestUncertainOutcomesAreUnknown(t *testing.T) {
	t.Run("5xx", func(t *testing.T) {
		r := newRig(t)
		r.stub.postStatus = 503
		res, err := r.create(KindIncident, testIncA)
		wantState(t, res, err, StateUnknown)
	})
	t.Run("lookup 5xx", func(t *testing.T) {
		r := newRig(t)
		r.stub.getStatus = 500
		res, err := r.create(KindIncident, testIncA)
		wantState(t, res, err, StateUnknown)
		if posts, _ := r.stub.count(); posts != 0 {
			t.Fatalf("created after a failed lookup: %d", posts)
		}
	})
	t.Run("unparsable 2xx", func(t *testing.T) {
		r := newRig(t)
		r.stub.postBody = "<html>not json</html>"
		res, err := r.create(KindIncident, testIncA)
		wantState(t, res, err, StateUnknown)
		if res.Code != CodeBadResponse {
			t.Fatalf("code %q", res.Code)
		}
		// The issue exists on the stub: the next create links it, no second POST.
		r.stub.mu.Lock()
		r.stub.postBody = ""
		r.stub.mu.Unlock()
		res, err = r.create(KindIncident, testIncA)
		wantState(t, res, err, StateLinked)
		if posts, _ := r.stub.count(); posts != 1 {
			t.Fatalf("posts %d", posts)
		}
	})
	t.Run("timeout after the request was written", func(t *testing.T) {
		r := newRig(t)
		r.stub.postDelay = 700 * time.Millisecond
		r.svc.o.Timeout = 150 * time.Millisecond
		res, err := r.create(KindIncident, testIncA)
		wantState(t, res, err, StateUnknown)
		if res.Code != CodeTimeout {
			t.Fatalf("code %q", res.Code)
		}
	})
}

func TestConnectionRefusedBeforeAnyByteIsRefusedNotUnknown(t *testing.T) {
	r := newRig(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	r.settings.conn.BaseURL = "https://" + addr
	res, err := r.create(KindIncident, testIncA)
	wantState(t, res, err, StateRefused)
	if res.Code != CodeUnreachable {
		t.Fatalf("code %q", res.Code)
	}
}

func TestEgressRules(t *testing.T) {
	t.Run("loopback base url without the test seam", func(t *testing.T) {
		r := newRig(t)
		r.svc.o.Egress = Egress{}
		res, err := r.create(KindIncident, testIncA)
		wantState(t, res, err, StateRefused)
		if res.Code != CodeEgress {
			t.Fatalf("code %q", res.Code)
		}
		if posts, gets := r.stub.count(); posts+gets != 0 {
			t.Fatalf("stub reached: %d/%d", posts, gets)
		}
		if l := r.ents.links(KindIncident, testProject, testIncA); len(l) != 0 {
			t.Fatalf("a refused egress must leave no link: %+v", l)
		}
	})
	t.Run("private and metadata literals", func(t *testing.T) {
		for _, base := range []string{"https://10.1.2.3", "https://192.168.0.9:8443", "https://169.254.169.254", "https://[::1]", "https://[fd00::1]"} {
			if _, _, err := ValidBaseURL(base, Egress{}); !IsEgressBlocked(err) {
				t.Errorf("%s: err %v", base, err)
			}
		}
		// An administrator may allow a private prefix, never loopback or metadata.
		allow := Egress{AllowPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
		if _, _, err := ValidBaseURL("https://10.1.2.3", allow); err != nil {
			t.Errorf("allowed prefix refused: %v", err)
		}
		if _, _, err := ValidBaseURL("https://169.254.169.254", allow); err == nil {
			t.Error("metadata allowed")
		}
		if err := (Egress{AllowPrefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}).Validate(); err == nil {
			t.Error("loopback allow list accepted")
		}
	})
	t.Run("name resolving to a blocked address", func(t *testing.T) {
		r := newRig(t)
		r.svc.o.Egress = Egress{Resolver: staticResolver{"gitlab.internal.test": {netip.MustParseAddr("127.0.0.1")}}}
		r.settings.conn.BaseURL = "https://gitlab.internal.test:" + portOf(r.stub.srv.URL)
		res, err := r.create(KindIncident, testIncA)
		wantState(t, res, err, StateRefused)
		if res.Code != CodeEgress {
			t.Fatalf("code %q", res.Code)
		}
		if posts, gets := r.stub.count(); posts+gets != 0 {
			t.Fatalf("stub reached: %d/%d", posts, gets)
		}
	})
	t.Run("base url shape", func(t *testing.T) {
		for _, base := range []string{"http://gitlab.example.test", "https://user:pw@gitlab.example.test", "https://gitlab.example.test/?x=1", "https://gitlab.example.test/#f", "https://gitlab.example.test/a/../b", "", "gitlab.example.test"} {
			if _, _, err := ValidBaseURL(base, Egress{}); err == nil {
				t.Errorf("%q accepted", base)
			}
		}
		if b, h, err := ValidBaseURL("https://gitlab.example.test/gitlab/", Egress{}); err != nil || b != "https://gitlab.example.test/gitlab" || h != "gitlab.example.test" {
			t.Errorf("%q %q %v", b, h, err)
		}
	})
}

type staticResolver map[string][]netip.Addr

func (s staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return s[host], nil
}

func portOf(raw string) string { return raw[strings.LastIndex(raw, ":")+1:] }

func TestRedirectIsNeverFollowed(t *testing.T) {
	r := newRig(t)
	target := newStub(t)
	r.stub.redirectTo = target.srv.URL + "/api/v4/projects/shop%2Fweb/issues"
	res, err := r.create(KindIncident, testIncA)
	wantState(t, res, err, StateRefused)
	if res.Code != CodeRedirect {
		t.Fatalf("code %q", res.Code)
	}
	if posts, gets := target.count(); posts+gets != 0 {
		t.Fatalf("redirect target reached: %d/%d", posts, gets)
	}
}

func TestTokenIsOnlyEverTheHeaderNeverInAnyAnswerOrRecord(t *testing.T) {
	r := newRig(t)
	r.stub.createThenFail = 500
	res1, err1 := r.create(KindIncident, testIncA)
	r.stub.mu.Lock()
	r.stub.createThenFail, r.stub.postStatus = 0, 401
	r.stub.mu.Unlock()
	res2, err2 := r.create(KindIncident, testIncB)
	r.settings.conn.BaseURL = "https://127.0.0.1:1"
	res3, err3 := r.create(KindIssue, testIssue)
	tok, terr := r.svc.CheckToken(context.Background(), testOrg)
	raw, _ := json.Marshal([]any{res1, err1, res2, err2, res3, err3, tok, terr, r.ents.applied})
	dump := string(raw) + fmt.Sprintf("%+v %+v %+v %v", res1, res2, res3, terr)
	for _, id := range []model.ID{testIncA, testIncB} {
		dump += fmt.Sprintf("%+v", r.ents.links(KindIncident, testProject, id))
	}
	if strings.Contains(dump, testToken) || strings.Contains(dump, "tok-0123") {
		t.Fatalf("token leaked: %s", dump)
	}
	for _, seen := range r.stub.tokens {
		if seen != testToken {
			t.Fatalf("PRIVATE-TOKEN header %q", seen)
		}
	}
	if len(r.stub.tokens) == 0 {
		t.Fatal("no request carried the token")
	}
	for _, p := range r.stub.paths {
		if strings.Contains(p, "tok-0123") {
			t.Fatalf("token in URL path %q", p)
		}
	}
}

func TestPreconditionsAreTypedRefusalsWithoutAnyGitLabCall(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*rig)
		code   string
	}{
		"not connected":   {func(r *rig) { r.settings.found = false }, CodeNotConnected},
		"mapping missing": {func(r *rig) { r.settings.conn.Mappings = nil }, CodeMappingMissing},
		"other project":   {func(r *rig) { r.settings.conn.Mappings[0].Project = mustID("ff") }, CodeMappingMissing},
		"kind not mapped": {func(r *rig) { r.settings.conn.Mappings[0].CreateFrom = []string{KindIssue} }, CodeMappingKind},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			tc.mutate(r)
			res, err := r.create(KindIncident, testIncA)
			wantState(t, res, err, StateRefused)
			if res.Code != tc.code {
				t.Fatalf("code %q", res.Code)
			}
			if posts, gets := r.stub.count(); posts+gets != 0 {
				t.Fatalf("GitLab reached")
			}
			if l := r.ents.links(KindIncident, testProject, testIncA); len(l) != 0 {
				t.Fatalf("links %+v", l)
			}
		})
	}
}

func TestScopeDenialIsTheEntityNotFound(t *testing.T) {
	r := newRig(t)
	r.ents.deny[r.target(KindIncident, testIncA)] = true
	_, err := r.create(KindIncident, testIncA)
	if !faultCode(err, model.NotFound) {
		t.Fatalf("err %v", err)
	}
	if _, err = r.svc.Preview(context.Background(), auth.Scope{}, r.target(KindIncident, testIncA)); !faultCode(err, model.NotFound) {
		t.Fatalf("preview err %v", err)
	}
	if _, err = r.svc.Recheck(context.Background(), auth.Scope{}, r.target(KindIncident, testIncA)); !faultCode(err, model.NotFound) {
		t.Fatalf("recheck err %v", err)
	}
	if posts, gets := r.stub.count(); posts+gets != 0 {
		t.Fatal("GitLab reached for an entity the caller cannot see")
	}
}

func faultCode(err error, code model.Code) bool {
	f, ok := err.(*model.Fault)
	return ok && f.Code == code
}

func TestCreateRetriesAfterAVersionConflict(t *testing.T) {
	r := newRig(t)
	r.ents.bump = func() {} // another action moves the incident between the read and the begin
	res, err := r.create(KindIncident, testIncA)
	wantState(t, res, err, StateLinked)
	if posts, _ := r.stub.count(); posts != 1 {
		t.Fatalf("posts %d", posts)
	}
}

func TestCommandIDReplayReturnsTheFirstResult(t *testing.T) {
	r := newRig(t)
	req := CreateRequest{Target: r.target(KindIncident, testIncA), CommandID: model.NewID()}
	first, err := r.svc.Create(context.Background(), auth.Scope{}, req)
	wantState(t, first, err, StateLinked)
	again, err := r.svc.Create(context.Background(), auth.Scope{}, req)
	if err != nil || again != first || !again.Created {
		t.Fatalf("replay %+v (%v), first %+v", again, err, first)
	}
	if posts, _ := r.stub.count(); posts != 1 {
		t.Fatalf("posts %d", posts)
	}
}

func TestLinkFromAdoptsTheLinkOfAnotherEntity(t *testing.T) {
	r := newRig(t)
	if res, err := r.svc.LinkFrom(context.Background(), auth.Scope{}, auth.Scope{}, r.target(KindIncident, testIncB), r.target(KindIssue, testIssue)); err != nil || res.State != StateRefused || res.Code != CodeSourceNotLinked {
		t.Fatalf("unlinked source: %+v %v", res, err)
	}
	res, err := r.create(KindIssue, testIssue)
	wantState(t, res, err, StateLinked)
	got, err := r.svc.LinkFrom(context.Background(), auth.Scope{}, auth.Scope{}, r.target(KindIncident, testIncB), r.target(KindIssue, testIssue))
	wantState(t, got, err, StateLinked)
	if got.URL != res.URL || got.IID != res.IID || got.Created {
		t.Fatalf("got %+v want %+v", got, res)
	}
	if l := r.ents.links(KindIncident, testProject, testIncB); len(l) != 1 || l[0].URL != res.URL || l[0].Marker != model.ExternalMarker(testOrg, KindIncident, testIncB) {
		t.Fatalf("links %+v", l)
	}
	if posts, _ := r.stub.count(); posts != 1 {
		t.Fatalf("posts %d", posts)
	}
	other := r.target(KindIssue, testIssue)
	other.Org = mustID("99")
	if _, err = r.svc.LinkFrom(context.Background(), auth.Scope{}, auth.Scope{}, r.target(KindIncident, testIncA), other); !faultCode(err, model.Invalid) {
		t.Fatalf("cross-org link_from: %v", err)
	}
	if _, err = r.svc.LinkFrom(context.Background(), auth.Scope{}, auth.Scope{}, r.target(KindIncident, testIncA), r.target(KindIncident, testIncA)); !faultCode(err, model.Invalid) {
		t.Fatalf("self link_from: %v", err)
	}
}

func TestPreviewStatesDefaultsAndExisting(t *testing.T) {
	r := newRig(t)
	p, err := r.svc.Preview(context.Background(), auth.Scope{}, r.target(KindIncident, testIncA))
	if err != nil || !p.Available || p.GitLabProject != "shop/web" || p.Title != "Soundpost incident "+testIncA.String()[:8] || p.Existing != nil || len(p.Labels) != 2 {
		t.Fatalf("preview %+v %v", p, err)
	}
	if strings.Contains(p.Description, "soundpost-ref-") || !strings.Contains(p.Description, testIssue.String()) {
		t.Fatalf("description %q", p.Description)
	}
	res, err := r.create(KindIssue, testIssue)
	wantState(t, res, err, StateLinked)
	p, err = r.svc.Preview(context.Background(), auth.Scope{}, r.target(KindIncident, testIncA))
	if err != nil || p.Existing == nil || p.Existing.URL != res.URL || p.Existing.From == nil || p.Existing.From.ID != testIssue {
		t.Fatalf("existing from the linked issue: %+v %v", p, err)
	}
	r.settings.found = false
	p, err = r.svc.Preview(context.Background(), auth.Scope{}, r.target(KindIncident, testIncB))
	if err != nil || p.Available || p.Reason != CodeNotConnected {
		t.Fatalf("preview %+v %v", p, err)
	}
}

func TestCheckToken(t *testing.T) {
	r := newRig(t)
	res, err := r.svc.CheckToken(context.Background(), testOrg)
	if err != nil || !res.OK || res.ExpiresAt != "2027-01-31" || len(res.Scopes) != 2 || res.Scopes[0] != "api" {
		t.Fatalf("%+v %v", res, err)
	}
	r.stub.selfToken = `{"active":false,"revoked":true,"scopes":["api"],"expires_at":null}`
	res, _ = r.svc.CheckToken(context.Background(), testOrg)
	if res.OK || res.Code != CodeTokenInactive || res.ExpiresAt != "" {
		t.Fatalf("%+v", res)
	}
	r.stub.selfToken = `garbage`
	res, _ = r.svc.CheckToken(context.Background(), testOrg)
	if res.OK || res.Code != CodeBadResponse {
		t.Fatalf("%+v", res)
	}
	r.settings.found = false
	res, _ = r.svc.CheckToken(context.Background(), testOrg)
	if res.OK || res.Code != CodeNotConnected {
		t.Fatalf("%+v", res)
	}
}
