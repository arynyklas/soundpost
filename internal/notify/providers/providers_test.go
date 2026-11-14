// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package providers

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// ---------------------------------------------------------------- fixtures

const (
	canarySecret = "CANARY-SECRET-7f3a91c2d4e85b60"
	canaryToken  = "123456:CANARY-BOT-TOKEN-aa11bb22cc33"
	canaryPath   = "CANARY-HOOK-PATH-90ab"
)

type org struct {
	id    model.ID
	scope auth.Scope
}

// newOrg is a real control store and auth service with one organization and an
// organization-admin scope.
func newOrg(t *testing.T) org {
	t.Helper()
	ctx := context.Background()
	store, err := control.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	wall := time.Unix(1_800_000_000, 0)
	svc, err := auth.NewService(auth.AuthDependencies{Control: store, Now: func() time.Time { return wall }})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.EnableSingle(ctx, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	boot, err := store.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := svc.Bootstrap(ctx, boot, "owner@example.test", "a long test password 2026")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := svc.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	id := model.NewID()
	var rev model.Revision
	if err = store.View(ctx, func(st control.State) error { rev = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(auth.AdminPayload{Name: "notify", Reason: "fixture"})
	if _, err = svc.AdminCommand(ctx, cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: id, Kind: "create_org", Payload: raw}); err != nil {
		t.Fatal(err)
	}
	scope, err := svc.Authorize(ctx, cred, id, nil, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	return org{id: id, scope: scope}
}

// registry is a fake DestinationSource and SecretReader.
type registry struct {
	mu      sync.Mutex
	recs    map[[2]model.ID]notify.DestinationRecord
	secrets map[[2]model.ID]string
	reads   int
}

func newRegistry() *registry {
	return &registry{recs: map[[2]model.ID]notify.DestinationRecord{}, secrets: map[[2]model.ID]string{}}
}

func (r *registry) put(o, id model.ID, rec notify.DestinationRecord, secret string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec.HasSecret = secret != ""
	r.recs[[2]model.ID{o, id}] = rec
	if secret != "" {
		r.secrets[[2]model.ID{o, id}] = secret
	}
}

func (r *registry) Destination(_ context.Context, _ auth.Scope, o, id model.ID) (notify.DestinationRecord, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.recs[[2]model.ID{o, id}]
	return rec, ok, nil
}

func (r *registry) Read(_ context.Context, _ auth.Scope, ref notify.SecretRef) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reads++
	s, ok := r.secrets[[2]model.ID{ref.Org, ref.ID}]
	if !ok {
		return nil, errors.New("sealed secret missing " + canarySecret)
	}
	return []byte(s), nil
}

type stamper struct {
	mu   sync.Mutex
	now  time.Time
	seen map[[2]uint64]time.Time
	err  error
}

func (s *stamper) AttemptTime(_ context.Context, _ auth.Scope, id model.ID, attempt uint32) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return time.Time{}, s.err
	}
	k := [2]uint64{uint64(id[0])<<8 | uint64(id[1]), uint64(attempt)}
	if t, ok := s.seen[k]; ok {
		return t, nil
	}
	if s.seen == nil {
		s.seen = map[[2]uint64]time.Time{}
	}
	s.seen[k] = s.now
	return s.now, nil
}

func (s *stamper) advance(d time.Duration) {
	s.mu.Lock()
	s.now = s.now.Add(d)
	s.mu.Unlock()
}

var (
	recipient = model.ID{0xd1, 0x01}
	delivery1 = model.ID{0xde, 0xad, 0x01}
	entity    = notify.Entity{Kind: notify.EntityIncident, ID: model.ID{0x53}}
)

func mkDelivery(o model.ID, attempt uint32) notify.Delivery {
	r := recipient
	return notify.Delivery{
		ID:      delivery1,
		Key:     notify.IntentKey{Org: o, Policy: model.ID{0xf1}, Entity: entity, ImpactRevision: 3, Kind: notify.KindOpen, Recipient: &r},
		Route:   notify.RouteImmediate,
		Attempt: attempt,
		Template: notify.Template{
			Entity: entity, Tier: notify.Tier("urgent"), Severity: 2, Source: notify.SourceState("firing"), Freshness: notify.Freshness("fresh"), Human: notify.HumanStatus("open"),
			Explanation: notify.Explanation{Failures: 7, Operations: 100, Rate: notify.RateKnown, RateBasisPoints: 700},
		},
	}
}

const origin = "https://soundpost.example.test"

func testCommon(reg *registry) Common {
	dests, err := notify.NewDestinations(reg, reg)
	if err != nil {
		panic(err)
	}
	return Common{Destinations: dests, PublicOrigin: origin, Egress: EgressPolicy{loopbackOK: true}, Timeout: 2 * time.Second}
}

// tlsServer is a real HTTPS server whose listener counts accepted connections.
type tlsServer struct {
	*httptest.Server
	accepts atomic.Int64
	pool    *x509.CertPool
}

type countingListener struct {
	net.Listener
	n *atomic.Int64
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.n.Add(1)
	}
	return c, err
}

func newTLSServer(t *testing.T, h http.Handler) *tlsServer {
	t.Helper()
	s := &tlsServer{}
	s.Server = httptest.NewUnstartedServer(h)
	s.Server.Listener = countingListener{Listener: s.Server.Listener, n: &s.accepts}
	s.Server.StartTLS()
	t.Cleanup(s.Server.Close)
	s.pool = x509.NewCertPool()
	s.pool.AddCert(s.Server.Certificate())
	return s
}

func (s *tlsServer) client() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: s.pool}}}
}

type captured struct {
	mu   sync.Mutex
	reqs []capturedReq
}

type capturedReq struct {
	path   string
	header http.Header
	body   []byte
}

func (c *captured) add(r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	c.reqs = append(c.reqs, capturedReq{path: r.URL.Path, header: r.Header.Clone(), body: b})
	c.mu.Unlock()
}

func (c *captured) all() []capturedReq {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]capturedReq(nil), c.reqs...)
}

// ---------------------------------------------------------------- webhook

func webhookFixture(t *testing.T, h http.Handler) (notify.Sender, *tlsServer, org, *stamper, *registry) {
	t.Helper()
	o := newOrg(t)
	srv := newTLSServer(t, h)
	reg := newRegistry()
	reg.put(o.id, recipient, notify.DestinationRecord{Type: "webhook", Endpoint: srv.URL + "/hook/" + canaryPath, Enabled: true}, canarySecret)
	st := &stamper{now: time.Unix(1_800_000_000, 0)}
	s, err := NewWebhook(WebhookConfig{Common: testCommon(reg), Stamper: st}, reg, srv.client())
	if err != nil {
		t.Fatal(err)
	}
	return s, srv, o, st, reg
}

func TestProvidersWireAndUncertainty(t *testing.T) {
	t.Run("webhook retry keeps id and exact body, gets fresh timestamp and signature", func(t *testing.T) {
		var cap captured
		var calls atomic.Int64
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cap.add(r)
			if calls.Add(1) == 1 {
				w.Header().Set("Retry-After", "7")
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.Header().Set(HeaderReceiptID, "rcpt-42")
			w.WriteHeader(http.StatusAccepted)
		})
		s, _, o, st, _ := webhookFixture(t, h)
		out, err := s.Send(context.Background(), o.scope, mkDelivery(o.id, 1))
		if err != nil {
			t.Fatal(err)
		}
		if out.Kind != notify.OutcomeRetry || out.Code != "rate_limited" || out.RetryAfter != model.UnixNano(7*time.Second) {
			t.Fatalf("first attempt: %+v", out)
		}
		st.advance(90 * time.Second)
		out, err = s.Send(context.Background(), o.scope, mkDelivery(o.id, 2))
		if err != nil {
			t.Fatal(err)
		}
		if out.Kind != notify.OutcomeAccepted || out.ProviderID != "rcpt-42" {
			t.Fatalf("second attempt: %+v", out)
		}
		reqs := cap.all()
		if len(reqs) != 2 {
			t.Fatalf("requests: %d", len(reqs))
		}
		a, b := reqs[0], reqs[1]
		if string(a.body) != string(b.body) {
			t.Fatalf("body bytes changed between attempts:\n%s\n%s", a.body, b.body)
		}
		if a.header.Get(HeaderDeliveryID) != delivery1.String() || b.header.Get(HeaderDeliveryID) != delivery1.String() {
			t.Fatal("delivery id not stable")
		}
		if a.header.Get(HeaderTimestamp) == b.header.Get(HeaderTimestamp) || a.header.Get(HeaderSignature) == b.header.Get(HeaderSignature) {
			t.Fatal("retry must get a fresh timestamp and signature")
		}
		// the body fields
		var body map[string]any
		if err = json.Unmarshal(a.body, &body); err != nil {
			t.Fatal(err)
		}
		if body["version"] != float64(1) || body["delivery_id"] != delivery1.String() || body["event_kind"] != "open" || body["impact_revision"] != float64(3) {
			t.Fatalf("body: %s", a.body)
		}
		if body["link"] != origin+"/incidents/"+entity.ID.String() {
			t.Fatalf("link %v", body["link"])
		}
		if strings.Contains(string(a.body), canarySecret) {
			t.Fatal("secret in body")
		}
		// signature input is exactly "<unix>.<delivery id>.<body>"
		for _, r := range reqs {
			ts := r.header.Get(HeaderTimestamp)
			unix, _ := parseUnix(ts)
			ref := hmac.New(sha256.New, []byte(canarySecret))
			ref.Write([]byte(ts + "." + delivery1.String() + "."))
			ref.Write(r.body)
			want := "v1=" + hex.EncodeToString(ref.Sum(nil))
			if Sign([]byte(canarySecret), unix, delivery1.String(), r.body) != want {
				t.Fatal("Sign does not follow the documented input")
			}
			if r.header.Get(HeaderSignature) != want || !strings.HasPrefix(want, "v1=") || len(want) != 3+64 {
				t.Fatalf("signature %q want %q", r.header.Get(HeaderSignature), want)
			}
		}
		// the receiver verifies both, within the window, and dedups by delivery ID
		now := time.Unix(1_800_000_000, 0)
		rc := NewReceiver([]byte(canarySecret), func() time.Time { return now }, 0)
		first, err := rc.Receive(a.header, a.body)
		if err != nil || first.Duplicate || first.DeliveryID != delivery1.String() {
			t.Fatalf("first receive: %+v %v", first, err)
		}
		now = now.Add(90 * time.Second)
		second, err := rc.Receive(b.header, b.body)
		if err != nil || !second.Duplicate {
			t.Fatalf("retry must verify and dedup: %+v %v", second, err)
		}
		// replay window: the first request replayed 6 minutes later is refused
		now = now.Add(6 * time.Minute)
		if _, err = rc.Receive(a.header, a.body); !errors.Is(err, ErrReplayWindow) {
			t.Fatalf("replay: %v", err)
		}
		// a tampered body or wrong secret is refused
		bad := append([]byte(nil), b.body...)
		bad[len(bad)-3] ^= 1
		now = time.Unix(1_800_000_090, 0)
		if _, err = rc.Receive(b.header, bad); !errors.Is(err, ErrSignature) {
			t.Fatalf("tamper: %v", err)
		}
		other := NewReceiver([]byte("another-secret-0123456789"), func() time.Time { return now }, 0)
		if _, err = other.Receive(b.header, b.body); !errors.Is(err, ErrSignature) {
			t.Fatalf("wrong secret: %v", err)
		}
	})

	t.Run("webhook classification", func(t *testing.T) {
		cases := []struct {
			name    string
			handler http.HandlerFunc
			kind    notify.OutcomeKind
			code    string
			after   time.Duration
			id      string
		}{
			{"429 retry-after", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "30")
				w.WriteHeader(429)
			}, notify.OutcomeRetry, "rate_limited", 30 * time.Second, ""},
			{"500", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }, notify.OutcomeRetry, "http_500", 0, ""},
			{"400 definite terminal", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(400) }, notify.OutcomeTerminal, "http_400", 0, ""},
			{"2xx without receipt id", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }, notify.OutcomeAccepted, "", 0, "webhook-200:" + delivery1.String()},
			{"huge response is bounded", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				_, _ = w.Write([]byte(strings.Repeat("x", 4<<20)))
			}, notify.OutcomeAccepted, "", 0, "webhook-200:" + delivery1.String()},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				s, _, o, _, _ := webhookFixture(t, c.handler)
				out, err := s.Send(context.Background(), o.scope, mkDelivery(o.id, 1))
				if err != nil || out.Kind != c.kind || out.Code != c.code || out.RetryAfter != model.UnixNano(c.after) || out.ProviderID != c.id {
					t.Fatalf("%+v %v", out, err)
				}
			})
		}
	})

	t.Run("webhook timeout after the request was written is unknown", func(t *testing.T) {
		release := make(chan struct{})
		var got atomic.Int64
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got.Add(1)
			<-release
		})
		o := newOrg(t)
		srv := newTLSServer(t, h)
		defer close(release)
		reg := newRegistry()
		reg.put(o.id, recipient, notify.DestinationRecord{Type: "webhook", Endpoint: srv.URL, Enabled: true}, canarySecret)
		c := testCommon(reg)
		c.Timeout = 300 * time.Millisecond
		s, err := NewWebhook(WebhookConfig{Common: c, Stamper: &stamper{now: time.Unix(1_800_000_000, 0)}}, reg, srv.client())
		if err != nil {
			t.Fatal(err)
		}
		out, err := s.Send(context.Background(), o.scope, mkDelivery(o.id, 1))
		if err != nil || out.Kind != notify.OutcomeUnknown || out.Code != "timeout" {
			t.Fatalf("%+v %v", out, err)
		}
		if got.Load() != 1 {
			t.Fatal("request never reached the receiver")
		}
	})

	t.Run("webhook connection refused before any byte is a definite retry", func(t *testing.T) {
		s, srv, o, _, _ := webhookFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("must not be called") }))
		srv.Server.Close() // port now refuses
		out, err := s.Send(context.Background(), o.scope, mkDelivery(o.id, 1))
		if err != nil || out.Kind != notify.OutcomeRetry || out.Code != "connect_failed" {
			t.Fatalf("%+v %v", out, err)
		}
	})

	t.Run("webhook without an attempt timestamp sends nothing", func(t *testing.T) {
		var calls atomic.Int64
		s, _, o, st, _ := webhookFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
		st.err = errors.New("store down")
		out, _ := s.Send(context.Background(), o.scope, mkDelivery(o.id, 1))
		if out.Kind != notify.OutcomeRetry || out.Code != "timestamp_unavailable" || calls.Load() != 0 {
			t.Fatalf("%+v calls=%d", out, calls.Load())
		}
	})

	t.Run("telegram", func(t *testing.T) {
		run := func(t *testing.T, status int, body string, hdr map[string]string) (notify.Outcome, capturedReq, string) {
			var cap captured
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				cap.add(r)
				for k, v := range hdr {
					w.Header().Set(k, v)
				}
				w.WriteHeader(status)
				_, _ = w.Write([]byte(body))
			})
			o := newOrg(t)
			srv := newTLSServer(t, h)
			reg := newRegistry()
			reg.put(o.id, recipient, notify.DestinationRecord{Type: "telegram", Address: "-1001234567890", Enabled: true}, canaryToken)
			s, err := NewTelegram(TelegramConfig{Common: testCommon(reg), APIBase: srv.URL}, reg, srv.client())
			if err != nil {
				t.Fatal(err)
			}
			out, err := s.Send(context.Background(), o.scope, mkDelivery(o.id, 1))
			if err != nil {
				t.Fatal(err)
			}
			r := cap.all()
			if len(r) != 1 {
				t.Fatalf("requests %d", len(r))
			}
			return out, r[0], srv.URL
		}
		out, req, _ := run(t, 200, `{"ok":true,"result":{"message_id":4242,"chat":{"id":-1001234567890}}}`, nil)
		if out.Kind != notify.OutcomeAccepted || out.ProviderID != "4242" {
			t.Fatalf("%+v", out)
		}
		if req.path != "/bot"+canaryToken+"/sendMessage" {
			t.Fatalf("path %q", req.path)
		}
		var sent map[string]any
		_ = json.Unmarshal(req.body, &sent)
		text, _ := sent["text"].(string)
		if sent["chat_id"] != "-1001234567890" || !strings.Contains(text, origin+"/incidents/"+entity.ID.String()) || !strings.Contains(text, delivery1.String()) || !strings.Contains(text, "Failures: 7") || !strings.Contains(text, "7.00%") {
			t.Fatalf("message: %v", sent)
		}
		if _, hasMode := sent["parse_mode"]; hasMode {
			t.Fatal("no markup mode may be used")
		}
		for _, c := range []struct {
			name   string
			status int
			body   string
			hdr    map[string]string
			kind   notify.OutcomeKind
			code   string
			after  time.Duration
		}{
			{"rate limit", 429, `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 31","parameters":{"retry_after":31}}`, nil, notify.OutcomeRetry, "rate_limited", 31 * time.Second},
			{"rate limit header only", 429, `{}`, map[string]string{"Retry-After": "12"}, notify.OutcomeRetry, "rate_limited", 12 * time.Second},
			{"bad request", 400, `{"ok":false,"error_code":400,"description":"chat not found"}`, nil, notify.OutcomeTerminal, "http_400", 0},
			{"unauthorized", 401, `{"ok":false,"error_code":401}`, nil, notify.OutcomeTerminal, "http_401", 0},
			{"server error", 502, ``, nil, notify.OutcomeRetry, "http_502", 0},
			{"2xx that is not an acceptance", 200, `<html>proxy</html>`, nil, notify.OutcomeUnknown, "bad_response", 0},
			{"ok false in 200", 200, `{"ok":false}`, nil, notify.OutcomeUnknown, "bad_response", 0},
			{"ok false even with a message id", 200, `{"ok":false,"result":{"message_id":5}}`, nil, notify.OutcomeUnknown, "bad_response", 0},
		} {
			o, _, _ := run(t, c.status, c.body, c.hdr)
			if o.Kind != c.kind || o.Code != c.code || o.RetryAfter != model.UnixNano(c.after) {
				t.Fatalf("%s: %+v", c.name, o)
			}
			if strings.Contains(o.Code+o.ProviderID, canaryToken) {
				t.Fatalf("%s leaks token", c.name)
			}
		}
	})
}

func parseUnix(s string) (int64, error) {
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("bad")
		}
		n = n*10 + int64(c-'0')
	}
	return n, nil
}

// ---------------------------------------------------------------- SMTP

type smtpServer struct {
	addr      string
	mode      string // "starttls" or "implicit" or "plain"
	cert      tls.Certificate
	pool      *x509.CertPool
	finalCode string // reply to the end of data
	hangData  bool
	dropData  bool
	rcptCode  string
	authCode  string

	mu       sync.Mutex
	cmds     []string
	plainCmd []string // commands seen before TLS
	data     string
	authUser string
	authPass string
	accepts  atomic.Int64
}

func newSMTPServer(t *testing.T, mode string) *smtpServer {
	t.Helper()
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(ts.Close)
	s := &smtpServer{mode: mode, cert: ts.TLS.Certificates[0], pool: x509.NewCertPool(), finalCode: "250 2.0.0 Ok: queued as 4F2A91B", rcptCode: "250 2.1.5 Ok", authCode: "235 2.7.0 Authentication successful"}
	s.pool.AddCert(ts.Certificate())
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if mode == "implicit" {
		l = tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{s.cert}})
	}
	s.addr = l.Addr().String()
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			s.accepts.Add(1)
			go s.serve(c)
		}
	}()
	return s
}

func (s *smtpServer) record(c string, encrypted bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cmds = append(s.cmds, c)
	if !encrypted {
		s.plainCmd = append(s.plainCmd, c)
	}
}

func (s *smtpServer) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	encrypted := s.mode == "implicit"
	r := bufio.NewReader(c)
	say := func(l string) { _, _ = c.Write([]byte(l + "\r\n")) }
	say("220 relay.example.test ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		if verb == "AUTH" {
			s.record("AUTH", encrypted)
		} else {
			s.record(line, encrypted)
		}
		switch verb {
		case "EHLO":
			say("250-relay.example.test")
			if s.mode == "starttls" && !encrypted {
				say("250-STARTTLS")
			}
			say("250 AUTH PLAIN LOGIN")
		case "STARTTLS":
			say("220 ready")
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{s.cert}})
			if err = tc.Handshake(); err != nil {
				return
			}
			c = tc
			r = bufio.NewReader(tc)
			say = func(l string) { _, _ = tc.Write([]byte(l + "\r\n")) }
			encrypted = true
		case "AUTH":
			parts := strings.Fields(line)
			if len(parts) == 3 {
				raw, _ := base64.StdEncoding.DecodeString(parts[2])
				f := strings.Split(string(raw), "\x00")
				if len(f) == 3 {
					s.mu.Lock()
					s.authUser, s.authPass = f[1], f[2]
					s.mu.Unlock()
				}
			}
			say(s.authCode)
		case "MAIL":
			say("250 2.1.0 Ok")
		case "RCPT":
			say(s.rcptCode)
		case "DATA":
			say("354 End data with <CR><LF>.<CR><LF>")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			s.mu.Lock()
			s.data = b.String()
			s.mu.Unlock()
			if s.dropData {
				return
			}
			if s.hangData {
				time.Sleep(5 * time.Second)
				return
			}
			say(s.finalCode)
		case "QUIT":
			say("221 bye")
			return
		default:
			say("502 unknown")
		}
	}
}

func smtpFixture(t *testing.T, s *smtpServer, tlsMode SMTPTLS, secret string, rec notify.DestinationRecord) (notify.Sender, org, *registry) {
	t.Helper()
	o := newOrg(t)
	host, port, _ := net.SplitHostPort(s.addr)
	reg := newRegistry()
	rec.Type, rec.Enabled = "smtp", true
	if rec.Address == "" {
		rec.Address = "oncall@example.test"
	}
	reg.put(o.id, recipient, rec, secret)
	p, _ := parsePort(port)
	c := testCommon(reg)
	c.Timeout = 2 * time.Second
	sender, err := NewSMTP(SMTPConfig{Common: c, Host: host, Port: p, TLS: tlsMode, Username: "relay-user", RequireAuth: true, From: "soundpost@example.test", RootCAs: s.pool}, reg)
	if err != nil {
		t.Fatal(err)
	}
	return sender, o, reg
}

func parsePort(s string) (int, error) {
	n, err := parseUnix(s)
	return int(n), err
}

func TestProvidersSMTPWire(t *testing.T) {
	for _, mode := range []struct {
		srv string
		tls SMTPTLS
	}{{"starttls", SMTPStartTLS}, {"implicit", SMTPImplicitTLS}} {
		t.Run("accepted "+mode.srv, func(t *testing.T) {
			s := newSMTPServer(t, mode.srv)
			sender, o, _ := smtpFixture(t, s, mode.tls, canarySecret, notify.DestinationRecord{})
			out, err := sender.Send(context.Background(), o.scope, mkDelivery(o.id, 1))
			if err != nil || out.Kind != notify.OutcomeAccepted || out.ProviderID != "4F2A91B" {
				t.Fatalf("%+v %v", out, err)
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.authUser != "relay-user" || s.authPass != canarySecret {
				t.Fatalf("auth: %q", s.authUser)
			}
			joined := strings.Join(s.cmds, "|")
			if !strings.Contains(joined, "MAIL FROM:<soundpost@example.test>") || !strings.Contains(joined, "RCPT TO:<oncall@example.test>") {
				t.Fatalf("envelope: %s", joined)
			}
			for _, want := range []string{"To: oncall@example.test", "Subject: [Soundpost] incident opened (severity 2)", "Message-ID: <" + delivery1.String() + "@soundpost.invalid>", "Link: " + origin + "/incidents/" + entity.ID.String(), "Failures: 7", "Delivery: " + delivery1.String()} {
				if !strings.Contains(s.data, want) {
					t.Fatalf("message lacks %q:\n%s", want, s.data)
				}
			}
			if strings.Contains(s.data, canarySecret) {
				t.Fatal("secret in message")
			}
			if mode.srv == "starttls" {
				// nothing but the greeting EHLO and STARTTLS may precede encryption
				if got := strings.Join(s.plainCmd, "|"); !strings.HasPrefix(got, "EHLO ") || strings.Contains(got, "AUTH") || strings.Contains(got, "MAIL") || strings.Contains(got, "RCPT") {
					t.Fatalf("plaintext phase: %s", got)
				}
			}
		})
	}

	t.Run("no STARTTLS means nothing is sent and no credential leaves", func(t *testing.T) {
		s := newSMTPServer(t, "plain")
		sender, o, _ := smtpFixture(t, s, SMTPStartTLS, canarySecret, notify.DestinationRecord{})
		out, err := sender.Send(context.Background(), o.scope, mkDelivery(o.id, 1))
		if err != nil || out.Kind != notify.OutcomeRetry || out.Code != "starttls_unavailable" {
			t.Fatalf("%+v %v", out, err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, c := range s.cmds {
			if strings.HasPrefix(c, "AUTH") || strings.HasPrefix(c, "MAIL") || strings.HasPrefix(c, "RCPT") || strings.HasPrefix(c, "DATA") {
				t.Fatalf("sent %q in the clear", c)
			}
		}
		if strings.Contains(strings.Join(s.cmds, ""), canarySecret) || strings.Contains(strings.Join(s.cmds, ""), base64.StdEncoding.EncodeToString([]byte(canarySecret))) {
			t.Fatal("credential in the clear")
		}
	})

	t.Run("untrusted relay certificate is refused before anything is sent", func(t *testing.T) {
		s := newSMTPServer(t, "starttls")
		s.pool = x509.NewCertPool() // client trusts nothing
		sender, o, _ := smtpFixture(t, s, SMTPStartTLS, canarySecret, notify.DestinationRecord{})
		out, _ := sender.Send(context.Background(), o.scope, mkDelivery(o.id, 1))
		if out.Kind != notify.OutcomeRetry || out.Code != "tls_failed" {
			t.Fatalf("%+v", out)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, c := range s.cmds {
			if strings.HasPrefix(c, "AUTH") || strings.HasPrefix(c, "MAIL") {
				t.Fatalf("sent %q", c)
			}
		}
	})

	classification := []struct {
		name  string
		setup func(*smtpServer)
		kind  notify.OutcomeKind
		code  string
	}{
		{"451 after data is a definite retry", func(s *smtpServer) { s.finalCode = "451 4.3.0 try later" }, notify.OutcomeRetry, "smtp_451"},
		{"554 after data is terminal", func(s *smtpServer) { s.finalCode = "554 5.7.1 rejected" }, notify.OutcomeTerminal, "smtp_554"},
		{"550 recipient is terminal", func(s *smtpServer) { s.rcptCode = "550 5.1.1 no such user" }, notify.OutcomeTerminal, "smtp_550"},
		{"450 recipient is retry", func(s *smtpServer) { s.rcptCode = "450 4.2.0 greylisted" }, notify.OutcomeRetry, "smtp_450"},
		{"535 is terminal auth failure", func(s *smtpServer) { s.authCode = "535 5.7.8 bad credentials" }, notify.OutcomeTerminal, "auth_failed"},
		{"250 without queue id is still accepted with evidence", func(s *smtpServer) { s.finalCode = "250 OK" }, notify.OutcomeAccepted, ""},
		{"silence after the end of data is possible acceptance", func(s *smtpServer) { s.hangData = true }, notify.OutcomeUnknown, "timeout"},
		{"connection drop after the end of data is possible acceptance", func(s *smtpServer) { s.dropData = true }, notify.OutcomeUnknown, "transport_error"},
	}
	for _, c := range classification {
		t.Run(c.name, func(t *testing.T) {
			s := newSMTPServer(t, "starttls")
			c.setup(s)
			sender, o, _ := smtpFixture(t, s, SMTPStartTLS, canarySecret, notify.DestinationRecord{})
			start := time.Now()
			out, err := sender.Send(context.Background(), o.scope, mkDelivery(o.id, 1))
			if err != nil || out.Kind != c.kind || out.Code != c.code {
				t.Fatalf("%+v %v (%s)", out, err, time.Since(start))
			}
			if c.kind == notify.OutcomeAccepted && out.ProviderID != "smtp-250:"+delivery1.String() {
				t.Fatalf("provider id %q", out.ProviderID)
			}
		})
	}

	t.Run("recipient header injection is impossible", func(t *testing.T) {
		s := newSMTPServer(t, "starttls")
		o := newOrg(t)
		reg := newRegistry()
		reg.put(o.id, recipient, notify.DestinationRecord{Type: "smtp", Address: "a@example.test\r\nBcc: x@example.test", Enabled: true}, canarySecret)
		host, port, _ := net.SplitHostPort(s.addr)
		p, _ := parsePort(port)
		sender, err := NewSMTP(SMTPConfig{Common: testCommon(reg), Host: host, Port: p, TLS: SMTPStartTLS, Username: "u", RequireAuth: true, From: "soundpost@example.test", RootCAs: s.pool}, reg)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := sender.Send(context.Background(), o.scope, mkDelivery(o.id, 1))
		if out.Kind != notify.OutcomeTerminal || out.Code != "destination_invalid" || s.accepts.Load() != 0 {
			t.Fatalf("%+v accepts=%d", out, s.accepts.Load())
		}
	})
}

// ---------------------------------------------------------------- destinations

func TestProvidersNoArbitraryDestinationSelection(t *testing.T) {
	var calls atomic.Int64
	s, srv, o, _, reg := webhookFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	// a recipient that is not a configured destination sends nothing
	d := mkDelivery(o.id, 1)
	other := model.ID{0xaa, 0xbb}
	d.Key.Recipient = &other
	out, _ := s.Send(context.Background(), o.scope, d)
	if out.Kind != notify.OutcomeTerminal || out.Code != "no_destination" {
		t.Fatalf("%+v", out)
	}
	// the shared queue entry has no recipient and so no external destination
	d.Key.Recipient = nil
	if out, _ = s.Send(context.Background(), o.scope, d); out.Code != "no_destination" {
		t.Fatalf("%+v", out)
	}
	// a delivery of another organization under this scope is a scope mismatch
	d = mkDelivery(model.ID{9}, 1)
	if out, _ = s.Send(context.Background(), o.scope, d); out.Code != "scope_mismatch" {
		t.Fatalf("%+v", out)
	}
	// the same recipient ID configured only in a different organization is not reachable
	o2 := newOrg(t)
	reg.put(o2.id, recipient, notify.DestinationRecord{Type: "webhook", Endpoint: srv.URL, Enabled: true}, canarySecret)
	if out, _ = s.Send(context.Background(), o2.scope, mkDelivery(o2.id, 1)); out.Kind != notify.OutcomeAccepted {
		t.Fatalf("own org destination: %+v", out)
	}
	calls.Store(0)
	reg.mu.Lock()
	delete(reg.recs, [2]model.ID{o.id, recipient})
	reg.mu.Unlock()
	if out, _ = s.Send(context.Background(), o.scope, mkDelivery(o.id, 1)); out.Code != "no_destination" || calls.Load() != 0 {
		t.Fatalf("removed destination: %+v calls=%d", out, calls.Load())
	}
}

func TestProvidersSecretAndErrorRedaction(t *testing.T) {
	// the secret reader fails with an error that quotes the secret
	o := newOrg(t)
	srv := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	reg := newRegistry()
	reg.put(o.id, recipient, notify.DestinationRecord{Type: "webhook", Endpoint: srv.URL + "/" + canaryPath, Enabled: true}, "")
	reg.recs[[2]model.ID{o.id, recipient}] = notify.DestinationRecord{Type: "webhook", Endpoint: srv.URL + "/" + canaryPath, Enabled: true, HasSecret: true}
	s, err := NewWebhook(WebhookConfig{Common: testCommon(reg), Stamper: &stamper{now: time.Now()}}, reg, srv.client())
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Send(context.Background(), o.scope, mkDelivery(o.id, 1))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), canarySecret) || strings.Contains(string(b), canaryPath) || out.Code != "secret_forbidden" && out.Code != "secret_unavailable" {
		t.Fatalf("%s", b)
	}
	if srv.accepts.Load() != 0 {
		t.Fatal("sent without a secret")
	}
	// a short signing secret is refused
	reg.put(o.id, recipient, notify.DestinationRecord{Type: "webhook", Endpoint: srv.URL, Enabled: true}, "short")
	if out, _ = s.Send(context.Background(), o.scope, mkDelivery(o.id, 1)); out.Code != "secret_missing" || srv.accepts.Load() != 0 {
		t.Fatalf("%+v", out)
	}
}

// ---------------------------------------------------------------- egress

func TestEgressForbiddenAddresses(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.1.2.3", "::1", "0.0.0.0", "::", "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		"169.254.169.254", "169.254.1.1", "fe80::1", "fc00::1", "fd00:ec2::254", "fd12:3456::1", "100.64.0.1", "100.127.255.255",
		"100.100.100.200", "168.63.129.16", "224.0.0.1", "239.255.255.250", "ff02::1", "ff05::2", "255.255.255.255", "240.0.0.1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::ffff:192.168.0.1", "::ffff:100.64.0.1",
		"64:ff9b::7f00:1", "64:ff9b::a00:1", "2002:7f00:1::1", "2002:a00:1::1", "::127.0.0.1", "198.18.0.1", "192.0.2.1", "2001:db8::1", "2001::1",
	}
	p := EgressPolicy{}
	for _, s := range blocked {
		if err := p.check(netip.MustParseAddr(s)); !errors.Is(err, errEgressBlocked) {
			t.Errorf("%s must be blocked: %v", s, err)
		}
	}
	for _, s := range []string{"93.184.216.34", "8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8", "100.63.255.255", "100.128.0.1", "172.15.255.255", "172.32.0.1"} {
		if err := p.check(netip.MustParseAddr(s)); err != nil {
			t.Errorf("%s must be allowed: %v", s, err)
		}
	}
	if err := p.check(netip.MustParseAddr("fe80::1%eth0")); err == nil {
		t.Error("zoned address must be blocked")
	}
	// the test seam is off by default and only ever lifts loopback
	if err := (EgressPolicy{}).check(netip.MustParseAddr("127.0.0.1")); err == nil {
		t.Fatal("loopback allowed by default")
	}
	if err := (EgressPolicy{loopbackOK: true}).check(netip.MustParseAddr("10.0.0.1")); err == nil {
		t.Fatal("seam lifted more than loopback")
	}
	if err := (EgressPolicy{loopbackOK: true}).check(netip.MustParseAddr("169.254.169.254")); err == nil {
		t.Fatal("seam lifted metadata")
	}
}

func TestEgressOperatorAllowList(t *testing.T) {
	p := EgressPolicy{AllowPrefixes: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16"), netip.MustParsePrefix("fd00:1234::/32")}}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"10.1.2.3", "::ffff:10.1.2.3", "fd00:1234::5"} {
		if err := p.check(netip.MustParseAddr(s)); err != nil {
			t.Errorf("%s must be allowed by the operator entry: %v", s, err)
		}
	}
	for _, s := range []string{"10.2.0.1", "10.0.0.1", "fd00:9999::1", "192.168.0.1"} {
		if err := p.check(netip.MustParseAddr(s)); err == nil {
			t.Errorf("%s must stay blocked", s)
		}
	}
	for _, bad := range []string{"127.0.0.0/8", "0.0.0.0/0", "169.254.169.254/32", "169.254.0.0/16", "::1/128", "::/0", "fe80::/10", "224.0.0.0/4", "::ffff:127.0.0.0/104", "100.100.100.200/32", "fd00:ec2::254/128"} {
		if err := (EgressPolicy{AllowPrefixes: []netip.Prefix{netip.MustParsePrefix(bad)}}).validate(); err == nil {
			t.Errorf("allow prefix %s must be refused", bad)
		}
	}
}

func listener(t *testing.T) (net.Listener, *atomic.Int64) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int64
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { l.Close() })
	return l, &n
}

func TestEgressDialerControlChecksTheActualAddress(t *testing.T) {
	l, n := listener(t)
	p := EgressPolicy{}
	// The Control hook alone, with an IP literal that bypasses name resolution.
	d := &net.Dialer{Control: p.control, Timeout: time.Second}
	_, err := d.DialContext(context.Background(), "tcp", l.Addr().String())
	if !errors.Is(err, errEgressBlocked) {
		t.Fatalf("control must block the dialed address: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if n.Load() != 0 {
		t.Fatal("blocked address was connected to")
	}
	if err := p.control("udp4", "93.184.216.34:53", nil); err == nil {
		t.Fatal("non-tcp must be refused")
	}
	if err := p.control("tcp4", "not-an-address", nil); err == nil {
		t.Fatal("unparseable address must be refused")
	}
	allowed := EgressPolicy{loopbackOK: true}
	d = &net.Dialer{Control: allowed.control, Timeout: time.Second}
	c, err := d.DialContext(context.Background(), "tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

type fakeResolver struct {
	answers []netip.Addr
	lookups atomic.Int64
}

func (r *fakeResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.lookups.Add(1)
	return r.answers, nil
}

func TestEgressDNSRebindingMakesZeroConnections(t *testing.T) {
	l, n := listener(t)
	_, port, _ := net.SplitHostPort(l.Addr().String())
	for _, tc := range []struct {
		name    string
		answers []string
	}{
		{"name resolves to loopback", []string{"127.0.0.1"}},
		{"name resolves to mapped loopback", []string{"::ffff:127.0.0.1"}},
		{"public answer first, private second", []string{"93.184.216.34", "10.0.0.5"}},
		{"private first", []string{"192.168.1.10", "93.184.216.34"}},
		{"metadata", []string{"169.254.169.254"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var addrs []netip.Addr
			for _, a := range tc.answers {
				addrs = append(addrs, netip.MustParseAddr(a))
			}
			res := &fakeResolver{answers: addrs}
			dial := (EgressPolicy{Resolver: res}).dialContext(time.Second)
			_, err := dial(context.Background(), "tcp", net.JoinHostPort("rebind.example.test", port))
			if !errors.Is(err, errEgressBlocked) {
				t.Fatalf("err=%v", err)
			}
			time.Sleep(30 * time.Millisecond)
			if n.Load() != 0 {
				t.Fatal("a blocked answer was connected to")
			}
			if res.lookups.Load() != 1 {
				t.Fatalf("lookups %d: the checked answer must be the dialed one", res.lookups.Load())
			}
		})
	}
}

func TestEgressWebhookToLoopbackIsRefusedWithZeroConnections(t *testing.T) {
	// Production configuration: the test seam is NOT set.
	o := newOrg(t)
	srv := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("receiver was contacted") }))
	reg := newRegistry()
	reg.put(o.id, recipient, notify.DestinationRecord{Type: "webhook", Endpoint: srv.URL, Enabled: true}, canarySecret)
	dests, _ := notify.NewDestinations(reg, reg)
	c := Common{Destinations: dests, PublicOrigin: origin, Timeout: time.Second}
	s, err := NewWebhook(WebhookConfig{Common: c, Stamper: &stamper{now: time.Now()}}, reg, srv.client())
	if err != nil {
		t.Fatal(err)
	}
	out, _ := s.Send(context.Background(), o.scope, mkDelivery(o.id, 1))
	if out.Kind != notify.OutcomeTerminal || out.Code != "egress_blocked" {
		t.Fatalf("%+v", out)
	}
	if srv.accepts.Load() != 0 {
		t.Fatal("loopback receiver saw a connection")
	}
	// also through a name that resolves to loopback
	reg.put(o.id, recipient, notify.DestinationRecord{Type: "webhook", Endpoint: "https://hooks.example.test:" + portOf(srv.URL) + "/", Enabled: true}, canarySecret)
	c.Egress.Resolver = &fakeResolver{answers: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	s, _ = NewWebhook(WebhookConfig{Common: c, Stamper: &stamper{now: time.Now()}}, reg, srv.client())
	if out, _ = s.Send(context.Background(), o.scope, mkDelivery(o.id, 1)); out.Code != "egress_blocked" || srv.accepts.Load() != 0 {
		t.Fatalf("%+v accepts=%d", out, srv.accepts.Load())
	}
}

func portOf(raw string) string {
	u, _ := url.Parse(raw)
	return u.Port()
}

func TestEgressProductionConstructorsRefuseLoopback(t *testing.T) {
	reg := newRegistry()
	dests, _ := notify.NewDestinations(reg, reg)
	c := Common{Destinations: dests, PublicOrigin: origin}
	if _, err := NewTelegram(TelegramConfig{Common: c, APIBase: "https://127.0.0.1:8443"}, reg, nil); err == nil {
		t.Fatal("telegram accepted a loopback API base")
	}
	if _, err := NewTelegram(TelegramConfig{Common: c, APIBase: "https://[::1]:8443"}, reg, nil); err == nil {
		t.Fatal("telegram accepted a loopback API base")
	}
	if _, err := NewTelegram(TelegramConfig{Common: c, APIBase: "http://api.telegram.org"}, reg, nil); err == nil {
		t.Fatal("telegram accepted plain http")
	}
	if _, err := NewSMTP(SMTPConfig{Common: c, Host: "127.0.0.1", Port: 587, TLS: SMTPStartTLS, From: "a@example.test"}, reg); err == nil {
		t.Fatal("smtp accepted a loopback host")
	}
	if _, err := NewSMTP(SMTPConfig{Common: c, Host: "169.254.169.254", Port: 587, TLS: SMTPStartTLS, From: "a@example.test"}, reg); err == nil {
		t.Fatal("smtp accepted a metadata host")
	}
	if _, err := NewSMTP(SMTPConfig{Common: c, Host: "relay.example.test", Port: 25, TLS: "", From: "a@example.test"}, reg); err == nil {
		t.Fatal("smtp accepted no transport security")
	}
	if _, err := NewSMTP(SMTPConfig{Common: c, Host: "relay.example.test", Port: 25, TLS: "plain", From: "a@example.test"}, reg); err == nil {
		t.Fatal("smtp accepted plaintext")
	}
	bad := Common{Destinations: dests, PublicOrigin: "http://soundpost.example.test"}
	if _, err := NewWebhook(WebhookConfig{Common: bad, Stamper: &stamper{}}, reg, nil); err == nil {
		t.Fatal("http public origin accepted")
	}
	if _, err := NewWebhook(WebhookConfig{Common: c, Stamper: &stamper{}}, reg, &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}); err == nil {
		t.Fatal("disabled certificate verification accepted")
	}
	loop := c
	loop.Egress.AllowPrefixes = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	if _, err := NewWebhook(WebhookConfig{Common: loop, Stamper: &stamper{}}, reg, nil); err == nil {
		t.Fatal("loopback allow-list accepted")
	}
}

func TestEgressSuppliedClientCannotBypassTheDialer(t *testing.T) {
	t.Run("supplied dialer is replaced", func(t *testing.T) {
		var dialed atomic.Int64
		o := newOrg(t)
		srv := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("receiver was contacted") }))
		reg := newRegistry()
		// a host name that resolves (through the policy's resolver) to loopback
		reg.put(o.id, recipient, notify.DestinationRecord{Type: "webhook", Endpoint: "https://hooks.example.test:" + portOf(srv.URL) + "/", Enabled: true}, canarySecret)
		dests, _ := notify.NewDestinations(reg, reg)
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: srv.pool},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialed.Add(1)
				return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
			},
		}
		c := Common{Destinations: dests, PublicOrigin: origin, Timeout: time.Second, Egress: EgressPolicy{Resolver: &fakeResolver{answers: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}}
		s, err := NewWebhook(WebhookConfig{Common: c, Stamper: &stamper{now: time.Now()}}, reg, &http.Client{Transport: tr})
		if err != nil {
			t.Fatal(err)
		}
		out, _ := s.Send(context.Background(), o.scope, mkDelivery(o.id, 1))
		if out.Code != "egress_blocked" || dialed.Load() != 0 || srv.accepts.Load() != 0 {
			t.Fatalf("%+v dialed=%d accepts=%d", out, dialed.Load(), srv.accepts.Load())
		}
	})
	t.Run("supplied proxy is ignored", func(t *testing.T) {
		proxy, proxied := listener(t)
		o := newOrg(t)
		srv := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
		reg := newRegistry()
		reg.put(o.id, recipient, notify.DestinationRecord{Type: "webhook", Endpoint: srv.URL, Enabled: true}, canarySecret)
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: srv.pool},
			Proxy:           func(*http.Request) (*url.URL, error) { return url.Parse("http://" + proxy.Addr().String()) },
		}
		s, err := NewWebhook(WebhookConfig{Common: testCommon(reg), Stamper: &stamper{now: time.Now()}}, reg, &http.Client{Transport: tr})
		if err != nil {
			t.Fatal(err)
		}
		out, _ := s.Send(context.Background(), o.scope, mkDelivery(o.id, 1))
		if out.Kind != notify.OutcomeAccepted || proxied.Load() != 0 || srv.accepts.Load() != 1 {
			t.Fatalf("%+v proxied=%d accepts=%d", out, proxied.Load(), srv.accepts.Load())
		}
	})
}

// buggyResolver hands out a destination whose secret reference points at another
// organization; the senders must not trust the resolver for that.
type buggyResolver struct{ other model.ID }

func (b buggyResolver) Resolve(_ context.Context, scope auth.Scope, d notify.Delivery, ch notify.Channel) (notify.Destination, error) {
	return notify.Destination{ID: *d.Key.Recipient, Org: scope.OrgID(), Channel: ch, Target: "https://hooks.example.test/x", Secret: &notify.SecretRef{Org: b.other, ID: *d.Key.Recipient}}, nil
}

func TestProvidersNeverReadAForeignSecretRef(t *testing.T) {
	o := newOrg(t)
	reg := newRegistry()
	reg.put(model.ID{0x99}, recipient, notify.DestinationRecord{Type: "webhook", Enabled: true}, canarySecret)
	c := Common{Destinations: buggyResolver{other: model.ID{0x99}}, PublicOrigin: origin, Egress: EgressPolicy{loopbackOK: true}, Timeout: time.Second}
	s, err := NewWebhook(WebhookConfig{Common: c, Stamper: &stamper{now: time.Now()}}, reg, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := s.Send(context.Background(), o.scope, mkDelivery(o.id, 1))
	if out.Kind != notify.OutcomeTerminal || out.Code != "secret_forbidden" || reg.reads != 0 {
		t.Fatalf("%+v reads=%d", out, reg.reads)
	}
}

func TestEgressRedirectIsRefusedWithZeroConnectionToTarget(t *testing.T) {
	target := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("redirect target contacted") }))
	for _, code := range []int{301, 302, 303, 307, 308} {
		first := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/steal", code)
		})
		s, srv, o, _, _ := webhookFixture(t, first)
		out, err := s.Send(context.Background(), o.scope, mkDelivery(o.id, 1))
		if err != nil || out.Kind != notify.OutcomeTerminal || out.Code != "redirect_refused" {
			t.Fatalf("%d: %+v %v", code, out, err)
		}
		if srv.accepts.Load() != 1 || target.accepts.Load() != 0 {
			t.Fatalf("%d: first=%d target=%d", code, srv.accepts.Load(), target.accepts.Load())
		}
	}
}

func TestEgressPerOrganizationHostAllowList(t *testing.T) {
	var calls atomic.Int64
	s, srv, o, _, reg := webhookFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	_ = s
	dests, _ := notify.NewDestinations(reg, reg)
	c := Common{Destinations: dests, PublicOrigin: origin, Timeout: time.Second, Egress: EgressPolicy{loopbackOK: true, OrgHosts: map[model.ID][]string{o.id: {"hooks.allowed.example.test"}}}}
	s2, err := NewWebhook(WebhookConfig{Common: c, Stamper: &stamper{now: time.Now()}}, reg, srv.client())
	if err != nil {
		t.Fatal(err)
	}
	out, _ := s2.Send(context.Background(), o.scope, mkDelivery(o.id, 1))
	if out.Kind != notify.OutcomeTerminal || out.Code != "host_not_allowed" || calls.Load() != 0 || srv.accepts.Load() != 0 {
		t.Fatalf("%+v", out)
	}
}

func TestEgressHTTPSRequiredForWebhook(t *testing.T) {
	o := newOrg(t)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("plain http contacted") }))
	defer plain.Close()
	reg := newRegistry()
	reg.put(o.id, recipient, notify.DestinationRecord{Type: "webhook", Endpoint: plain.URL, Enabled: true}, canarySecret)
	s, err := NewWebhook(WebhookConfig{Common: testCommon(reg), Stamper: &stamper{now: time.Now()}}, reg, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := s.Send(context.Background(), o.scope, mkDelivery(o.id, 1))
	if out.Kind != notify.OutcomeTerminal || out.Code != "destination_invalid" {
		t.Fatalf("%+v", out)
	}
}

func TestProvidersSenderErrorsNeverCarryText(t *testing.T) {
	// The Sender interface returns a nil error for every classified outcome, so no
	// transport text can travel with it.
	o := newOrg(t)
	reg := newRegistry()
	reg.put(o.id, recipient, notify.DestinationRecord{Type: "telegram", Address: "-100123", Enabled: true}, canaryToken)
	dests, _ := notify.NewDestinations(reg, reg)
	s, err := NewTelegram(TelegramConfig{Common: Common{Destinations: dests, PublicOrigin: origin, Egress: EgressPolicy{loopbackOK: true}, Timeout: time.Second}, APIBase: "https://127.0.0.1:1"}, reg, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Send(context.Background(), o.scope, mkDelivery(o.id, 1))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), canaryToken) || out.Kind != notify.OutcomeRetry {
		t.Fatalf("%s", b)
	}
}
