// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
	"soundpost/internal/query"
	"soundpost/internal/query/profile"
	"soundpost/internal/storage"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countingFeed is the real C05 committed feed with a subscription counter.
type countingFeed struct {
	inner      query.ChangeSubscriber
	subscribes atomic.Int64
}

func (c *countingFeed) Subscribe(ctx context.Context, scope auth.Scope, req storage.SubscribeRequest) (storage.ChangeIterator, error) {
	c.subscribes.Add(1)
	return c.inner.Subscribe(ctx, scope, req)
}

// liveEnv is the real stack behind the live routes: real control store and
// auth, real C03 ingestion over HTTPS, the real C05 storage commit feed, the
// owned live service and the owned routes.
type liveEnv struct {
	*isoEnv
	svc      *query.LiveService
	feed     *countingFeed
	server   *httptest.Server
	client   *http.Client
	registry profile.Registry
	logSet   string
}

func newLiveEnv(t *testing.T, mutate func(*query.LiveLimits)) *liveEnv {
	t.Helper()
	e := &liveEnv{isoEnv: newIsoEnv(t)}
	var err error
	if e.registry, err = profile.Load(os.DirFS("../../profiles/query")); err != nil {
		t.Fatal(err)
	}
	e.logSet = featureSetOf(t, queryLogql)
	cfg := query.DefaultLiveLimits()
	cfg.Heartbeat = time.Hour
	if mutate != nil {
		mutate(&cfg)
	}
	limits := query.DefaultLimits()
	limits.RevalidateInterval = 25 * time.Millisecond
	e.feed = &countingFeed{inner: e.app.Storage}
	if e.svc, err = query.NewLiveService(e.feed, e.app.Auth, e.registry, limits, query.WithLiveDeleteGenerations(e.deletes), query.WithLiveLimits(cfg)); err != nil {
		t.Fatal(err)
	}
	e.server = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterLiveRoutes(mux, e.app.Auth, e.svc)
	}).Handler)
	t.Cleanup(func() {
		e.server.CloseClientConnections()
		e.server.Close()
		_ = e.svc.Close()
	})
	e.client = e.server.Client()
	return e
}

// logSource onboards a structured log source and admits lines through the real
// ingestion route.
func (e *liveEnv) logSource(org, project model.ID) sourceFixture {
	e.t.Helper()
	var values []model.Scalar
	for _, name := range []string{"alice", "bob", "carol", "dave", "erin", "frank", "grace"} {
		var v model.Scalar
		_ = json.Unmarshal([]byte(`"`+name+`"`), &v)
		values = append(values, v)
	}
	tpl := model.LogTemplate{ID: "signin", Revision: 1, Line: "user {name} signed in", Severity: "info", Fields: []model.TemplateField{{Name: "name", Type: "string", MaxBytes: 16, Sensitivity: "metadata", Values: values}}}
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Log}, Templates: []model.LogTemplate{tpl}, RetentionDays: map[model.Kind]uint32{model.Log: 7}, MaxBytes: 1 << 20, MaxSeries: 100, Labels: map[string][]string{"app": {"web"}}}
	return e.onboard(org, project, model.NewID(), sharedIDs{model.NewID(), model.NewID(), model.NewID()}, policy, auth.SourcePolicyConfig{ProjectID: project, Enabled: true})
}

func (e *liveEnv) admit(s sourceFixture, name string) {
	e.t.Helper()
	var v model.Scalar
	_ = json.Unmarshal([]byte(`"`+name+`"`), &v)
	ts := model.UnixNano(e.tick.Add(1))
	e.ingest(s, model.Record{ID: model.NewID(), Kind: model.Log, ObservedAt: ts, Resource: e.resource(s), Payload: model.Payload{Log: &model.LogRecord{Timestamp: &ts, TemplateID: "signin", TemplateRevision: 1, Fields: map[string]model.Scalar{"name": v}, StreamLabels: model.Labels{{Name: "app", Value: "web"}}, Metadata: map[string]model.Scalar{}}}})
}

func (e *liveEnv) request(who person, method, path string, body any, headers map[string]string) *http.Request {
	e.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			e.t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, e.server.URL+path, reader)
	if err != nil {
		e.t.Fatal(err)
	}
	if who.Session.Token != "" {
		req.Header.Set("Cookie", "__Host-soundpost="+who.Session.Token)
		req.Header.Set("X-CSRF-Token", who.Session.CSRF)
	}
	req.Header.Set("Origin", e.server.URL)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func (e *liveEnv) body(org model.ID, project model.ID, expr string) map[string]any {
	return map[string]any{"org": org.String(), "profile": queryLogql, "feature_set": e.logSet, "expression": expr, "projects": []string{project.String()}}
}

func (e *liveEnv) ticket(who person, body map[string]any) (int, string, []byte) {
	e.t.Helper()
	resp, err := e.client.Do(e.request(who, "POST", "/api/v1/live-tickets", body, nil))
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out struct {
		Ticket string `json:"ticket"`
	}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out.Ticket, raw
}

func (e *liveEnv) mustTicket(who person, body map[string]any) string {
	e.t.Helper()
	status, id, raw := e.ticket(who, body)
	if status != 200 || id == "" {
		e.t.Fatalf("ticket: %d %s", status, raw)
	}
	return id
}

type sseEvent struct {
	ID, Type string
	Data     query.LiveEvent
	Comment  bool
}

// sseConn is one open GET /api/v1/live stream.
type sseConn struct {
	t      *testing.T
	resp   *http.Response
	events chan sseEvent
	cancel context.CancelFunc
	done   chan struct{}
}

func (e *liveEnv) connect(who person, ticket, lastEventID string) (*sseConn, int, []byte) {
	e.t.Helper()
	headers := map[string]string{}
	if lastEventID != "" {
		headers["Last-Event-ID"] = lastEventID
	}
	req := e.request(who, "GET", "/api/v1/live?ticket="+ticket, nil, headers)
	ctx, cancel := context.WithCancel(context.Background())
	resp, err := e.client.Do(req.WithContext(ctx))
	if err != nil {
		cancel()
		e.t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()
		return nil, resp.StatusCode, raw
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" || resp.Header.Get("Cache-Control") != "no-store" {
		e.t.Fatalf("not an uncached event stream: %q %q", ct, resp.Header.Get("Cache-Control"))
	}
	c := &sseConn{t: e.t, resp: resp, events: make(chan sseEvent, 1024), cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(c.done)
		defer close(c.events)
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 1<<16), 1<<20)
		var cur sseEvent
		var data []string
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if cur.Type != "" {
					_ = json.Unmarshal([]byte(strings.Join(data, "\n")), &cur.Data)
					c.events <- cur
				}
				cur, data = sseEvent{}, nil
			case strings.HasPrefix(line, ":"):
			case strings.HasPrefix(line, "id: "):
				cur.ID = strings.TrimPrefix(line, "id: ")
			case strings.HasPrefix(line, "event: "):
				cur.Type = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				data = append(data, strings.TrimPrefix(line, "data: "))
			}
		}
	}()
	return c, 200, nil
}

func (c *sseConn) next(timeout time.Duration) (sseEvent, bool) {
	c.t.Helper()
	select {
	case ev, ok := <-c.events:
		return ev, ok
	case <-time.After(timeout):
		c.t.Fatal("no event within the deadline")
	}
	return sseEvent{}, false
}

func (c *sseConn) expect(typ string) sseEvent {
	c.t.Helper()
	ev, ok := c.next(5 * time.Second)
	if !ok || ev.Type != typ {
		c.t.Fatalf("want %s event, got %+v (open %v)", typ, ev, ok)
	}
	return ev
}

func (c *sseConn) silent(d time.Duration) {
	c.t.Helper()
	select {
	case ev, ok := <-c.events:
		if ok {
			c.t.Fatalf("unexpected event %+v", ev)
		}
	case <-time.After(d):
	}
}

func (c *sseConn) ended() {
	c.t.Helper()
	select {
	case _, ok := <-c.events:
		if ok {
			c.t.Fatal("event after the stream should have ended")
		}
	case <-time.After(5 * time.Second):
		c.t.Fatal("stream did not end")
	}
}

func (c *sseConn) close() {
	c.cancel()
	c.resp.Body.Close()
	<-c.done
}

func (e *liveEnv) idle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var u query.LiveUsage
	for time.Now().Before(deadline) {
		u = e.svc.Usage()
		if u.Streams == 0 && u.OpenIterators == 0 && u.MemoryUsed == 0 && u.Goroutines == 0 && u.Attached == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("live service did not return to idle: %+v", u)
}

func safeLine(name string) string { return "user " + name + " signed in" }

// TestLiveOverHTTPRealStorage streams real committed records over the owned
// SSE route: ordered event IDs, one subscription, nothing polled.
func TestLiveOverHTTPRealStorage(t *testing.T) {
	e := newLiveEnv(t, nil)
	p := model.NewID()
	org := e.org("live org", p)
	alice := e.user(org, "alice@example.test")
	e.grant(org, alice, p, true, auth.Read)
	src := e.logSource(org, p)

	conn, status, raw := e.connect(alice, e.mustTicket(alice, e.body(org, p, `{app="web"}`)), "")
	if conn == nil {
		t.Fatalf("connect: %d %s", status, raw)
	}
	defer conn.close()
	open := conn.expect("open")
	if open.Data.StreamID == (model.ID{}) || open.ID != "" {
		t.Fatalf("open event: %+v", open)
	}
	conn.silent(300 * time.Millisecond)
	for _, name := range []string{"alice", "bob", "carol"} {
		e.admit(src, name)
	}
	for i, name := range []string{"alice", "bob", "carol"} {
		ev := conn.expect("record")
		if ev.ID != string(rune('1'+i)) || ev.Data.Sequence != model.Uint64(i+1) {
			t.Fatalf("event IDs must be the ordered stream sequence: %+v", ev)
		}
		if ev.Data.Entry == nil || ev.Data.Entry.Line != safeLine(name) || ev.Data.Project == nil || *ev.Data.Project != p {
			t.Fatalf("record %d: %+v", i, ev.Data)
		}
		if len(ev.Data.Cursors) == 0 {
			t.Fatalf("a record must carry its committed cursor: %+v", ev.Data)
		}
	}
	if got := e.feed.subscribes.Load(); got != 1 {
		t.Fatalf("one subscription must serve the whole stream, saw %d", got)
	}
}

func TestLivePipelineAppliesOverHTTP(t *testing.T) {
	e := newLiveEnv(t, nil)
	p := model.NewID()
	org := e.org("live org", p)
	alice := e.user(org, "alice@example.test")
	e.grant(org, alice, p, true, auth.Read)
	src := e.logSource(org, p)
	conn, _, _ := e.connect(alice, e.mustTicket(alice, e.body(org, p, `{app="web"} |= "bob"`)), "")
	defer conn.close()
	conn.expect("open")
	e.admit(src, "alice")
	e.admit(src, "bob")
	ev := conn.expect("record")
	if ev.Data.Entry.Line != safeLine("bob") || ev.ID != "1" {
		t.Fatalf("the line filter must apply to the stream and not consume sequences: %+v", ev)
	}
}

// TestLiveReconnectReplayOverHTTP reconnects with Last-Event-ID, receives the
// subsequent events once, and then an explicit gap with exact bounds after the
// bounded replay buffer evicted events.
func TestLiveReconnectReplayOverHTTP(t *testing.T) {
	e := newLiveEnv(t, nil)
	p := model.NewID()
	org := e.org("live org", p)
	alice := e.user(org, "alice@example.test")
	e.grant(org, alice, p, true, auth.Read)
	src := e.logSource(org, p)
	body := e.body(org, p, `{app="web"}`)
	body["budget"] = map[string]any{"timeout_ns": "0", "memory_bytes": "0", "max_returned": "2"}
	conn, _, _ := e.connect(alice, e.mustTicket(alice, body), "")
	open := conn.expect("open")
	e.admit(src, "alice")
	first := conn.expect("record")
	conn.close()

	// Committed while disconnected: sequence 2..6, only the last two retained.
	for _, name := range []string{"bob", "carol", "dave", "erin", "frank"} {
		e.admit(src, name)
	}
	deadline := time.Now().Add(5 * time.Second)
	for e.svc.Usage().MemoryUsed == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // the detached stream consumes the feed

	resume := e.body(org, p, `{app="web"}`)
	resume["budget"] = body["budget"]
	resume["resume_stream_id"] = open.Data.StreamID.String()
	conn2, status, raw := e.connect(alice, e.mustTicket(alice, resume), first.ID)
	if conn2 == nil {
		t.Fatalf("reconnect: %d %s", status, raw)
	}
	defer conn2.close()
	reopen := conn2.expect("open")
	if reopen.Data.StreamID != open.Data.StreamID {
		t.Fatal("reconnect inside the window must attach to the retained stream")
	}
	gap := conn2.expect("gap")
	if gap.Data.Gap == nil || gap.Data.Gap.Reason != query.GapReplayEvicted || gap.Data.Gap.FromSequence != 2 || gap.Data.Gap.ToSequence != 4 || gap.ID != "4" {
		t.Fatalf("evicted replay must be an explicit gap with exact bounds: %+v", gap)
	}
	for i, name := range []string{"erin", "frank"} {
		ev := conn2.expect("record")
		if ev.Data.Entry.Line != safeLine(name) || ev.ID != string(rune('5'+i)) {
			t.Fatalf("replay after the gap: %+v", ev)
		}
	}
	conn2.silent(200 * time.Millisecond)
	if got := e.feed.subscribes.Load(); got != 1 {
		t.Fatalf("replay must not resubscribe: %d subscriptions", got)
	}
}

func TestLiveReplayInsideWindowDeliversOnceOverHTTP(t *testing.T) {
	e := newLiveEnv(t, nil)
	p := model.NewID()
	org := e.org("live org", p)
	alice := e.user(org, "alice@example.test")
	e.grant(org, alice, p, true, auth.Read)
	src := e.logSource(org, p)
	conn, _, _ := e.connect(alice, e.mustTicket(alice, e.body(org, p, `{app="web"}`)), "")
	open := conn.expect("open")
	e.admit(src, "alice")
	e.admit(src, "bob")
	conn.expect("record")
	last := conn.expect("record")
	conn.close()
	e.admit(src, "carol")
	time.Sleep(300 * time.Millisecond)
	resume := e.body(org, p, `{app="web"}`)
	resume["resume_stream_id"] = open.Data.StreamID.String()
	conn2, _, _ := e.connect(alice, e.mustTicket(alice, resume), last.ID)
	defer conn2.close()
	conn2.expect("open")
	ev := conn2.expect("record")
	if ev.Data.Entry.Line != safeLine("carol") || ev.ID != "3" {
		t.Fatalf("only the subsequent event may arrive: %+v", ev)
	}
	conn2.silent(300 * time.Millisecond)
}

// TestLiveRevokeAndDeleteMidStreamOverHTTP changes authority while the stream is
// established and requires the typed terminal event, an ended body, and no
// record committed afterwards.
func TestLiveRevokeAndDeleteMidStreamOverHTTP(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		change       func(e *liveEnv, org, p model.ID, alice person)
	}{
		{"revocation", "scope_revoked", func(e *liveEnv, org, p model.ID, alice person) { e.grant(org, alice, p, false, auth.Read) }},
		{"deletion", "deleted", func(e *liveEnv, org, p model.ID, alice person) { e.deletes.bump.Add(1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newLiveEnv(t, nil)
			p := model.NewID()
			org := e.org("live org", p)
			alice := e.user(org, "alice@example.test")
			e.grant(org, alice, p, true, auth.Read)
			src := e.logSource(org, p)
			conn, _, _ := e.connect(alice, e.mustTicket(alice, e.body(org, p, `{app="web"}`)), "")
			defer conn.close()
			conn.expect("open")
			e.admit(src, "alice")
			if ev := conn.expect("record"); ev.Data.Entry.Line != safeLine("alice") {
				t.Fatalf("%+v", ev)
			}
			tc.change(e, org, p, alice)
			e.admit(src, "bob")
			secret := false
			for {
				ev, ok := conn.next(5 * time.Second)
				if !ok {
					t.Fatal("body ended without a terminal event")
				}
				if ev.Type == "record" {
					secret = true
				}
				if ev.Type == "revoke" {
					if ev.Data.Reason != tc.reason || ev.Data.Failure == nil || ev.Data.Entry != nil {
						t.Fatalf("terminal event: %+v", ev)
					}
					break
				}
				if ev.Type == "heartbeat" || ev.Type == "gap" {
					continue
				}
				t.Fatalf("unexpected %+v", ev)
			}
			if secret {
				t.Fatal("a record committed after the change reached the consumer")
			}
			conn.ended()
			e.admit(src, "carol")
			e.idle(t)
		})
	}
}

// TestLiveAuthorizationMatrixOverHTTP: every wrong principal, org, project,
// session or ticket gets the same indistinguishable NotFound before any feed
// access, and nothing about the stream leaks.
func TestLiveAuthorizationMatrixOverHTTP(t *testing.T) {
	e := newLiveEnv(t, func(l *query.LiveLimits) { l.ReplayWindow = 300 * time.Millisecond })
	p1, p2 := model.NewID(), model.NewID()
	orgA := e.org("org A", p1, p2)
	orgB := e.org("org B", model.NewID())
	alice := e.user(orgA, "alice@example.test")
	bob := e.user(orgA, "bob@example.test")
	carol := e.user(orgB, "carol@example.test")
	e.grant(orgA, alice, p1, true, auth.Read)
	e.grant(orgA, bob, p2, true, auth.Read)
	src := e.logSource(orgA, p1)
	secret := e.logSource(orgA, p2)
	e.admit(secret, "frank")

	denied := map[string]string{}
	check := func(name string, status int, raw []byte) {
		t.Helper()
		if status != 404 {
			t.Fatalf("%s: want 404, got %d %s", name, status, raw)
		}
		denied[name] = denial(t, status, raw)
	}
	status, _, raw := e.ticket(alice, e.body(orgA, p2, `{app="web"}`))
	check("sibling project", status, raw)
	status, _, raw = e.ticket(carol, e.body(orgA, p1, `{app="web"}`))
	check("another org", status, raw)
	status, _, raw = e.ticket(alice, e.body(orgA, model.NewID(), `{app="web"}`))
	check("guessed project", status, raw)
	status, _, raw = e.ticket(alice, e.body(orgB, p1, `{app="web"}`))
	check("wrong org", status, raw)
	var reference string
	for name, d := range denied {
		if reference == "" {
			reference = d
		} else if d != reference {
			t.Fatalf("%s: denial distinguishable (%q vs %q)", name, d, reference)
		}
	}
	if e.feed.subscribes.Load() != 0 {
		t.Fatal("a denied request reached the feed")
	}

	// A ticket copied to another session (even of the same org) is refused, and
	// the refused presenter does not burn it.
	ticket := e.mustTicket(alice, e.body(orgA, p1, `{app="web"}`))
	// A wrong-session presenter and an unknown ticket get the same denial body
	// (the per-request ID is the only field that may differ).
	cu, unknownStatus, unknownRaw := e.connect(alice, model.NewID().String(), "")
	if cu != nil || unknownStatus != 404 {
		t.Fatalf("an unknown ticket: %d %s", unknownStatus, unknownRaw)
	}
	unknown := denial(t, unknownStatus, unknownRaw)
	for name, who := range map[string]person{"another principal": bob, "another org": carol} {
		c, status, raw := e.connect(who, ticket, "")
		if c != nil || status != 404 {
			t.Fatalf("%s used the ticket: %d %s", name, status, raw)
		}
		if got := denial(t, status, raw); got != unknown {
			t.Fatalf("%s: a wrong-session ticket is distinguishable from an unknown one (%q vs %q)", name, got, unknown)
		}
	}
	c, status, raw := e.connect(alice, ticket, "")
	if c == nil {
		t.Fatalf("the owner's ticket was burned by a refused presenter: %d %s", status, raw)
	}
	c.expect("open")
	e.admit(src, "alice")
	if ev := c.expect("record"); ev.Data.Entry.Line != safeLine("alice") {
		t.Fatalf("%+v", ev)
	}
	c.close()
	if _, status, _ := e.connect(alice, ticket, ""); status != 404 {
		t.Fatalf("a ticket is single use: %d", status)
	}
	// A request cannot smuggle authority or selectors through the URL.
	for name, path := range map[string]string{
		"no ticket":    "/api/v1/live",
		"extra param":  "/api/v1/live?ticket=" + ticket + "&expression=x",
		"bad ticket":   "/api/v1/live?ticket=zz",
		"zero ticket":  "/api/v1/live?ticket=00000000000000000000000000000000",
		"query secret": "/api/v1/live?ticket=" + ticket + "&token=x",
	} {
		resp, err := e.client.Do(e.request(alice, "GET", path, nil, nil))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 && resp.StatusCode != 404 {
			t.Fatalf("%s: %d", name, resp.StatusCode)
		}
	}
	resp, err := e.client.Do(e.request(alice, "GET", "/api/v1/live?ticket="+e.mustTicket(alice, e.body(orgA, p1, `{app="web"}`)), nil, map[string]string{"Last-Event-ID": "abc"}))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("malformed Last-Event-ID: %d", resp.StatusCode)
	}
	// Unauthenticated callers and elevation requests are refused.
	resp, err = e.client.Do(e.request(person{}, "GET", "/api/v1/live?ticket="+ticket, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 && resp.StatusCode != 403 {
		t.Fatalf("anonymous stream: %d", resp.StatusCode)
	}
	body := e.body(orgA, p1, `{app="web"}`)
	body["elevation"] = model.NewID().String()
	if status, _, raw := e.ticket(alice, body); status != 403 {
		t.Fatalf("elevated live streams must be refused: %d %s", status, raw)
	}
	// Telemetry from p2 never reached alice's streams.
	e.idle(t)
}

// TestLiveRestrictedSourceOverHTTP: the named-reader entitlement bounds a raw
// stream to its one source for its whole life.
func TestLiveRestrictedSourceOverHTTP(t *testing.T) {
	e := newLiveEnv(t, nil)
	ids := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	p := model.NewID()
	org := e.org("raw org", p)
	a := e.user(org, "a@example.test")
	b := e.user(org, "b@example.test")
	for _, who := range []person{a, b} {
		e.grant(org, who, p, true, auth.Read, auth.RawRead)
	}
	mk := func(reader person, app string) sourceFixture {
		source := model.NewID()
		cfg := auth.SourcePolicyConfig{ProjectID: p, Restricted: true, Readers: []model.ID{reader.ID}, Enabled: true}
		policy := e.rawPolicy(e.actor.ID)
		policy.Labels = map[string][]string{"app": {app}}
		return e.onboard(org, p, source, ids, policy, cfg)
	}
	x, y := mk(a, "x"), mk(b, "y")
	raw := func(s sourceFixture, app, text string) {
		var msg model.Scalar
		_ = json.Unmarshal([]byte(`"`+text+`"`), &msg)
		ts := model.UnixNano(e.tick.Add(1))
		e.ingest(s, model.Record{ID: model.NewID(), Kind: model.Log, ObservedAt: ts, Resource: e.resource(s), Payload: model.Payload{Log: &model.LogRecord{Timestamp: &ts, Severity: "error", TemplateID: "raw", TemplateRevision: 1, Fields: map[string]model.Scalar{"msg": msg}, Line: text, StreamLabels: model.Labels{{Name: "app", Value: app}}, Metadata: map[string]model.Scalar{}, SourceClass: "restricted_raw"}}})
	}
	body := func(src model.ID, app string) map[string]any {
		m := e.body(org, p, `{app="`+app+`"}`)
		m["permission"] = "raw.read"
		m["source"] = src.String()
		return m
	}
	for name, c := range map[string]struct {
		who person
		src model.ID
	}{"B reading X": {b, x.ID}, "A reading Y": {a, y.ID}, "A reading a guessed source": {a, model.NewID()}} {
		if status, _, rawBody := e.ticket(c.who, body(c.src, "x")); status != 404 {
			t.Fatalf("%s: %d %s", name, status, rawBody)
		}
	}
	if e.feed.subscribes.Load() != 0 {
		t.Fatal("a refused raw stream reached the feed")
	}
	conn, status, rb := e.connect(a, e.mustTicket(a, body(x.ID, "x")), "")
	if conn == nil {
		t.Fatalf("A streams X: %d %s", status, rb)
	}
	defer conn.close()
	conn.expect("open")
	raw(y, "y", "secret-y")
	raw(x, "x", "secret-x")
	ev := conn.expect("record")
	if ev.Data.Entry.Line != "secret-x" || ev.Data.Entry.Source == nil || *ev.Data.Entry.Source != x.ID {
		t.Fatalf("A's X stream: %+v", ev.Data)
	}
	conn.silent(300 * time.Millisecond)
	// The reader's raw.read grant withdrawn mid-stream ends it before any further byte.
	e.grant(org, a, p, false, auth.RawRead)
	raw(x, "x", "secret-after-removal")
	for {
		ev, ok := conn.next(5 * time.Second)
		if !ok {
			t.Fatal("stream ended without a terminal event")
		}
		if ev.Type == "record" {
			t.Fatalf("a record was released after the reader entitlement was removed: %+v", ev.Data)
		}
		if ev.Type == "revoke" {
			break
		}
	}
	conn.ended()
}

// TestLiveCapsAndTeardownOverHTTP: per-principal connection caps answer 429 and
// every connection ending path releases the subscription, account and
// goroutines.
func TestLiveCapsAndTeardownOverHTTP(t *testing.T) {

	e := newLiveEnv(t, func(l *query.LiveLimits) {
		l.MaxStreams, l.MaxStreamsPerOrg, l.MaxStreamsPerPrincipal = 4, 3, 1
		l.ReplayWindow = 400 * time.Millisecond
	})
	p := model.NewID()
	org := e.org("live org", p)
	alice := e.user(org, "alice@example.test")
	bob := e.user(org, "bob@example.test")
	e.grant(org, alice, p, true, auth.Read)
	e.grant(org, bob, p, true, auth.Read)
	src := e.logSource(org, p)
	before := runtime.NumGoroutine()
	first, _, _ := e.connect(alice, e.mustTicket(alice, e.body(org, p, `{app="web"}`)), "")
	first.expect("open")
	second := e.mustTicket(alice, e.body(org, p, `{app="web"}`))
	if c, status, raw := e.connect(alice, second, ""); c != nil || status != 429 {
		t.Fatalf("per-principal connection cap: %d %s", status, raw)
	}
	other, _, _ := e.connect(bob, e.mustTicket(bob, e.body(org, p, `{app="web"}`)), "")
	other.expect("open")
	e.admit(src, "alice")
	first.expect("record")
	other.expect("record")
	// A dropped client leaves a detached stream that lapses with its window.
	first.close()
	other.close()
	e.idle(t)
	e.admit(src, "bob")
	// Capacity returned.
	again, status, raw := e.connect(alice, e.mustTicket(alice, e.body(org, p, `{app="web"}`)), "")
	if again == nil {
		t.Fatalf("capacity must return: %d %s", status, raw)
	}
	again.expect("open")
	again.close()
	e.idle(t)
	e.client.CloseIdleConnections()
	e.server.CloseClientConnections()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before+10 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > before+10 {
		buf := make([]byte, 1<<16)
		n := runtime.Stack(buf, true)
		t.Fatalf("goroutines leaked: %d before, %d after\n%s", before, got, buf[:n])
	}
}

func TestLiveHeartbeatOverHTTP(t *testing.T) {
	e := newLiveEnv(t, func(l *query.LiveLimits) { l.Heartbeat = 50 * time.Millisecond })
	p := model.NewID()
	org := e.org("live org", p)
	alice := e.user(org, "alice@example.test")
	e.grant(org, alice, p, true, auth.Read)
	conn, _, _ := e.connect(alice, e.mustTicket(alice, e.body(org, p, `{app="web"}`)), "")
	defer conn.close()
	conn.expect("open")
	hb := conn.expect("heartbeat")
	if hb.ID != "" || len(hb.Data.Watermarks) == 0 {
		t.Fatalf("a heartbeat has no sequence and carries the feed watermarks: %+v", hb)
	}
}

func TestLiveTicketValidationOverHTTP(t *testing.T) {
	e := newLiveEnv(t, nil)
	p := model.NewID()
	org := e.org("live org", p)
	alice := e.user(org, "alice@example.test")
	e.grant(org, alice, p, true, auth.Read)
	for name, expr := range map[string]string{"metric expression": `rate({app="web"}[1m])`, "syntax error": `{app="web"`, "empty": ""} {
		status, _, raw := e.ticket(alice, e.body(org, p, expr))
		if status != 400 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		if bytes.Contains(raw, []byte(`app="web"`)) {
			t.Fatalf("%s: the error echoes the expression: %s", name, raw)
		}
	}
	body := e.body(org, p, `{app="web"}`)
	body["unknown_field"] = 1
	if status, _, _ := e.ticket(alice, body); status != 400 {
		t.Fatalf("unknown fields are refused: %d", status)
	}
	if e.feed.subscribes.Load() != 0 {
		t.Fatal("an invalid request reached the feed")
	}
}

// TestLiveStreamOriginAndCSRFOverHTTP pins the cookie-session guarantees of the
// live GET at the route: the browser's same-origin shape (no Origin, Sec-Fetch-Site:
// same-origin) opens the stream, but only together with the CSRF token, and every
// other shape is refused before the ticket is read. A refused request must not
// consume the ticket, and HEAD must never reach the ticket ledger.
func TestLiveStreamOriginAndCSRFOverHTTP(t *testing.T) {
	e := newLiveEnv(t, func(l *query.LiveLimits) { l.ReplayWindow = 100 * time.Millisecond })
	p := model.NewID()
	org := e.org("live org", p)
	alice := e.user(org, "alice@example.test")
	e.grant(org, alice, p, true, auth.Read)
	stream := func(ticket string, shape func(*http.Request)) (int, string) {
		t.Helper()
		req := e.request(alice, "GET", "/api/v1/live?ticket="+ticket, nil, nil)
		shape(req)
		ctx, cancel := context.WithCancel(context.Background())
		resp, err := e.client.Do(req.WithContext(ctx))
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		status, contentType := resp.StatusCode, resp.Header.Get("Content-Type")
		if status != 200 {
			_, _ = io.Copy(io.Discard, resp.Body)
		}
		cancel()
		resp.Body.Close()
		// An opened stream counts against the per-principal cap until the server
		// notices the disconnect: wait for that so the rows cannot interfere.
		e.idle(t)
		return status, contentType
	}
	sameOriginFetch := func(r *http.Request) {
		r.Header.Del("Origin")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	for _, c := range []struct {
		name  string
		shape func(*http.Request)
		want  int
	}{
		{"no origin, no fetch metadata", func(r *http.Request) { r.Header.Del("Origin") }, 403},
		{"no origin, cross-site", func(r *http.Request) { r.Header.Del("Origin"); r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
		{"no origin, same-site", func(r *http.Request) { r.Header.Del("Origin"); r.Header.Set("Sec-Fetch-Site", "same-site") }, 403},
		{"no origin, same-origin, no CSRF token", func(r *http.Request) { sameOriginFetch(r); r.Header.Del("X-CSRF-Token") }, 403},
		{"no origin, same-origin, wrong CSRF token", func(r *http.Request) { sameOriginFetch(r); r.Header.Set("X-CSRF-Token", "not-the-token") }, 403},
		{"matching origin, no CSRF token", func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, 403},
		{"foreign origin with same-origin metadata", func(r *http.Request) {
			r.Header.Set("Origin", "https://evil.example.test")
			r.Header.Set("Sec-Fetch-Site", "same-origin")
		}, 403},
	} {
		ticket := e.mustTicket(alice, e.body(org, p, `{app="web"}`))
		if status, _ := stream(ticket, c.shape); status != c.want {
			t.Errorf("%s: status %d, want %d", c.name, status, c.want)
		}
		// The refusal happened before the ticket was read: it is still usable.
		if status, _ := stream(ticket, sameOriginFetch); status != 200 {
			t.Errorf("%s: the refused request consumed the ticket (retry %d)", c.name, status)
		}
	}
	// The accepted browser shape opens a real event stream.
	if status, ct := stream(e.mustTicket(alice, e.body(org, p, `{app="web"}`)), sameOriginFetch); status != 200 || ct != "text/event-stream" {
		t.Errorf("same-origin fetch: %d %q", status, ct)
	}
	// HEAD is a safe probe: it must not burn the single-use ticket.
	ticket := e.mustTicket(alice, e.body(org, p, `{app="web"}`))
	if status, _ := stream(ticket, func(r *http.Request) { sameOriginFetch(r); r.Method = http.MethodHead }); status != 405 {
		t.Errorf("HEAD on the stream: %d, want 405", status)
	}
	if status, _ := stream(ticket, sameOriginFetch); status != 200 {
		t.Errorf("HEAD consumed the live ticket (GET %d)", status)
	}
}
