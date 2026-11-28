// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package providers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// ---------------------------------------------------------------- fixtures

const (
	previousSecret = "PREVIOUS-SECRET-0123456789abcdef"
	currentSecret  = canarySecret // the endpoint's current secret
)

// eventReg is the fake registry with a previous-secret slot per endpoint.
type eventReg struct {
	*registry
	prev    map[[2]model.ID]string
	prevErr error
}

func (r *eventReg) Read(ctx context.Context, scope auth.Scope, ref notify.SecretRef) ([]byte, error) {
	if !ref.Previous {
		return r.registry.Read(ctx, scope, ref)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reads++
	if r.prevErr != nil {
		return nil, r.prevErr
	}
	s, ok := r.prev[[2]model.ID{ref.Org, ref.ID}]
	if !ok {
		return nil, model.Fail(model.Forbidden)
	}
	return []byte(s), nil
}

type eventRig struct {
	t      *testing.T
	sender *eventSender
	srv    *tlsServer
	org    org
	st     *stamper
	reg    *eventReg
	cap    *captured
}

var (
	evIncident = notify.Entity{Kind: notify.EntityIncident, ID: model.ID{0x53}}
	evService  = model.ID{0x5e}
	evRelease  = model.ID{0x7e}
)

func eventCommon(reg *eventReg) Common {
	dests, err := notify.NewDestinations(reg, reg)
	if err != nil {
		panic(err)
	}
	return Common{Destinations: dests, PublicOrigin: origin, Egress: EgressPolicy{loopbackOK: true}, Timeout: 2 * time.Second}
}

// newEventRig is a real HTTPS receiver and an event_webhook destination with the
// current secret; edit changes the destination record (rotation state, events).
func newEventRig(t *testing.T, h http.Handler, edit func(*notify.DestinationRecord, *eventReg, model.ID)) *eventRig {
	t.Helper()
	o := newOrg(t)
	r := &eventRig{t: t, org: o, cap: &captured{}, st: &stamper{now: time.Unix(1_800_000_000, 0)}}
	r.srv = newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.cap.add(req)
		h.ServeHTTP(w, req)
	}))
	r.reg = &eventReg{registry: newRegistry(), prev: map[[2]model.ID]string{}}
	rec := notify.DestinationRecord{Type: "event_webhook", Endpoint: r.srv.URL + "/hook/" + canaryPath, Enabled: true, Events: []string{"incident.opened"}}
	if edit != nil {
		edit(&rec, r.reg, o.id)
	}
	r.reg.put(o.id, recipient, rec, currentSecret)
	s, err := newEventSender(EventWebhookConfig{Common: eventCommon(r.reg), Stamper: r.st}, r.reg, r.srv.client())
	if err != nil {
		t.Fatal(err)
	}
	r.sender = s
	return r
}

func accept(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }

func mkEventDelivery(o model.ID, name notify.EventName, entity notify.Entity, attempt uint32) notify.Delivery {
	r := recipient
	rel := evRelease
	return notify.Delivery{
		ID:      delivery1,
		Key:     notify.IntentKey{Org: o, Policy: model.ID{0xf1}, Entity: entity, ImpactRevision: 3, Kind: notify.KindEvent, Recipient: &r, Ordinal: 1},
		Route:   notify.RouteImmediate,
		Attempt: attempt,
		Template: notify.Template{Entity: entity, Project: project1, Severity: notify.SeverityCritical, Service: &notify.ServiceRef{ID: evService},
			Event: &notify.EventFact{Event: name, OccurredAt: 1_800_000_000_123_456_789, Revision: 3, Release: &rel}},
	}
}

func (r *eventRig) send(attempt uint32) notify.Outcome {
	r.t.Helper()
	out, err := r.sender.Send(context.Background(), r.org.scope, mkEventDelivery(r.org.id, notify.EventIncidentOpened, evIncident, attempt))
	if err != nil {
		r.t.Fatal(err)
	}
	return out
}

func (r *eventRig) receiver(secret string) *Receiver {
	return NewReceiver([]byte(secret), func() time.Time { return r.st.now }, 0)
}

func (r *eventRig) only() capturedReq {
	r.t.Helper()
	reqs := r.cap.all()
	if len(reqs) != 1 {
		r.t.Fatalf("requests: %d", len(reqs))
	}
	return reqs[0]
}

// ---------------------------------------------------------------- body

var (
	hexID   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	decimal = regexp.MustCompile(`^[0-9]{1,20}$`)
)

// The body is a pure function of the delivery (identical bytes every time), carries the
// entity under the member of its kind, and nothing in it is text: every value is an ID,
// an enum, a decimal or the console link.
func TestEventBodyIsDeterministicAndIdentifiersOnly(t *testing.T) {
	o := model.ID{0x0a, 0x0b}
	cases := []struct {
		event  notify.EventName
		entity notify.Entity
		member string
		view   string
	}{
		{notify.EventIncidentOpened, evIncident, "incident", "incidents"},
		{notify.EventIncidentAcknowledged, evIncident, "incident", "incidents"},
		{notify.EventIncidentResolved, evIncident, "incident", "incidents"},
		{notify.EventIssueNew, notify.Entity{Kind: notify.EntityIssue, ID: model.ID{0x54}}, "issue", "issues"},
		{notify.EventIssueRegressed, notify.Entity{Kind: notify.EntityIssue, ID: model.ID{0x54}}, "issue", "issues"},
		{notify.EventIssueResolved, notify.Entity{Kind: notify.EntityIssue, ID: model.ID{0x54}}, "issue", "issues"},
		{notify.EventReleaseRegistered, notify.Entity{Kind: notify.EntityRelease, ID: model.ID{0x55}}, "release", "releases"},
		{notify.EventTestPing, notify.Entity{Kind: notify.EntityEndpoint, ID: model.ID{0x56}}, "endpoint", "queue"},
	}
	allowed := map[string]bool{"version": true, "delivery_id": true, "event": true, "occurred_at": true, "org": true, "project": true, "incident": true, "issue": true, "release": true,
		"endpoint": true, "severity": true, "release_id": true, "service": true, "revision": true, "url": true}
	for _, c := range cases {
		d := mkEventDelivery(o, c.event, c.entity, 1)
		a, err := EventBody(d, origin)
		if err != nil {
			t.Fatalf("%s: %v", c.event, err)
		}
		d.Attempt, d.NextAttempt = 9, 12345 // the attempt never reaches the body
		b, _ := EventBody(d, origin)
		if string(a) != string(b) {
			t.Fatalf("%s: the body changed between attempts:\n%s\n%s", c.event, a, b)
		}
		var m map[string]any
		if err = json.Unmarshal(a, &m); err != nil {
			t.Fatal(err)
		}
		for k, v := range m {
			if !allowed[k] {
				t.Fatalf("%s: unexpected member %q", c.event, k)
			}
			s, isString := v.(string)
			switch {
			case k == "version":
				if v != float64(1) {
					t.Fatalf("version %v", v)
				}
			case !isString:
				t.Fatalf("%s: member %q is not a string: %v", c.event, k, v)
			case k == "event", k == "severity":
				// closed enums, checked below
			case k == "occurred_at", k == "revision":
				if !decimal.MatchString(s) {
					t.Fatalf("%s: %q = %q is not a decimal", c.event, k, s)
				}
			case k == "url":
				if !strings.HasPrefix(s, origin+"/") || strings.ContainsAny(s, " <>\"") {
					t.Fatalf("%s: url %q", c.event, s)
				}
			default:
				if !hexID.MatchString(s) {
					t.Fatalf("%s: member %q = %q is not an identifier", c.event, k, s)
				}
			}
		}
		if m["event"] != string(c.event) || m["delivery_id"] != d.ID.String() || m["org"] != o.String() || m["project"] != project1.String() || m["occurred_at"] != "1800000000123456789" || m["severity"] != "critical" {
			t.Fatalf("%s: %s", c.event, a)
		}
		if m[c.member] != c.entity.ID.String() {
			t.Fatalf("%s: entity member %q: %s", c.event, c.member, a)
		}
		for _, other := range []string{"incident", "issue", "release", "endpoint"} {
			if _, has := m[other]; has != (other == c.member) {
				t.Fatalf("%s: member %q presence is %v: %s", c.event, other, has, a)
			}
		}
		if !strings.Contains(m["url"].(string), "#view="+c.view+"&org="+o.String()+"&projects="+project1.String()) {
			t.Fatalf("%s: url %v", c.event, m["url"])
		}
		if c.member == "release" || c.member == "endpoint" {
			continue
		}
		if m["service"] != evService.String() || m["release_id"] != evRelease.String() || m["revision"] != "3" {
			t.Fatalf("%s: %s", c.event, a)
		}
	}
	// Golden: the exact bytes of one event (field order is part of the contract).
	d := mkEventDelivery(o, notify.EventIssueRegressed, notify.Entity{Kind: notify.EntityIssue, ID: model.ID{0x54}}, 1)
	got, _ := EventBody(d, origin)
	want := `{"version":1,"delivery_id":"` + d.ID.String() + `","event":"issue.regressed","occurred_at":"1800000000123456789","org":"` + o.String() + `","project":"` + project1.String() +
		`","issue":"` + model.ID{0x54}.String() + `","severity":"critical","release_id":"` + evRelease.String() + `","service":"` + evService.String() + `","revision":"3","url":"` +
		origin + `/#view=issues&org=` + o.String() + `&projects=` + project1.String() + `&target=` + project1.String() + `:` + model.ID{0x54}.String() + `"}`
	if string(got) != want {
		t.Fatalf("golden body:\n got %s\nwant %s", got, want)
	}
	// What is not an event, or names the wrong entity, has no body.
	bad := mkEventDelivery(o, notify.EventIssueNew, evIncident, 1) // an issue event about an incident
	if _, err := EventBody(bad, origin); err == nil {
		t.Fatal("a body for a mismatched entity")
	}
	bad = mkEventDelivery(o, "incident.exploded", evIncident, 1)
	if _, err := EventBody(bad, origin); err == nil {
		t.Fatal("a body for an unknown event")
	}
	bad = mkEventDelivery(o, notify.EventIncidentOpened, evIncident, 1)
	bad.Key.Kind = notify.KindOpen
	if _, err := EventBody(bad, origin); err == nil {
		t.Fatal("a body for a notification")
	}
	bad = mkEventDelivery(o, notify.EventIncidentOpened, evIncident, 1)
	bad.Template.Severity = 9
	if _, err := EventBody(bad, origin); err == nil {
		t.Fatal("a body with an unknown severity")
	}
}

// ---------------------------------------------------------------- signature

// goldenSignature is HMAC-SHA256("0123456789abcdef", "1800000000.dead01.{\"a\":1}"), computed
// independently of Sign (and confirmed with `openssl dgst -sha256 -hmac`).
const goldenSignature = "v1=2a970c2eaf66d8b8f14f29ae50e11022c79b1ac9589d7f7ff7884d10d5f436a2"

func TestEventSignatureGoldenVector(t *testing.T) {
	secret, id, body := []byte("0123456789abcdef"), "dead01", []byte(`{"a":1}`)
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("1800000000.dead01."))
	m.Write(body)
	independent := "v1=" + hex.EncodeToString(m.Sum(nil))
	got := Sign(secret, 1_800_000_000, id, body)
	if got != independent {
		t.Fatalf("Sign %s, independent %s", got, independent)
	}
	if got != goldenSignature {
		t.Fatalf("golden vector: got %s", got)
	}
	// The header of a rotation carries both, current first.
	h := eventSignatureHeader(secret, []byte("fedcba9876543210"), 1_800_000_000, id, body)
	parts := strings.Split(h, ",")
	if len(parts) != 2 || parts[0] != got || parts[1] != Sign([]byte("fedcba9876543210"), 1_800_000_000, id, body) {
		t.Fatalf("rotation header: %s", h)
	}
	if h = eventSignatureHeader(secret, nil, 1_800_000_000, id, body); h != got {
		t.Fatalf("single header: %s", h)
	}
}

// ---------------------------------------------------------------- wire

// A retry keeps the delivery ID and the exact body, gets a fresh timestamp and signature,
// carries the event name, verifies with the reference Receiver, and the Receiver reports
// the second arrival as a duplicate of the first (dedup by delivery ID).
func TestEventWireRetryKeepsIdentityAndReceiverDeduplicates(t *testing.T) {
	var calls int
	rig := newEventRig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set(HeaderReceiptID, "rcpt-42")
		w.WriteHeader(http.StatusAccepted)
	}), nil)
	out := rig.send(1)
	if out.Kind != notify.OutcomeRetry || out.Code != "rate_limited" || out.RetryAfter != model.UnixNano(7*time.Second) {
		t.Fatalf("first attempt: %+v", out)
	}
	rig.st.advance(90 * time.Second)
	out = rig.send(2)
	if out.Kind != notify.OutcomeAccepted || out.ProviderID != "rcpt-42" {
		t.Fatalf("second attempt: %+v", out)
	}
	reqs := rig.cap.all()
	if len(reqs) != 2 {
		t.Fatalf("requests: %d", len(reqs))
	}
	a, b := reqs[0], reqs[1]
	if string(a.body) != string(b.body) || a.header.Get(HeaderDeliveryID) != delivery1.String() || b.header.Get(HeaderDeliveryID) != delivery1.String() {
		t.Fatal("body or delivery id changed between attempts")
	}
	if a.header.Get(HeaderTimestamp) == b.header.Get(HeaderTimestamp) || a.header.Get(HeaderSignature) == b.header.Get(HeaderSignature) {
		t.Fatal("a retry must get a fresh timestamp and signature")
	}
	for _, r := range reqs {
		if r.header.Get(HeaderEvent) != "incident.opened" || r.header.Get("Content-Type") != "application/json" || !strings.HasPrefix(r.header.Get(HeaderSignature), "v1=") ||
			strings.Contains(r.header.Get(HeaderSignature), ",") || r.path != "/hook/"+canaryPath {
			t.Fatalf("request: %+v", r)
		}
	}
	// Receiver: first arrival verifies; the retry (a fresh valid signature) is the duplicate.
	recv := NewReceiver([]byte(currentSecret), func() time.Time { return rig.st.now }, 0)
	rig.st.now = time.Unix(1_800_000_000, 0)
	first, err := recv.Receive(a.header, a.body)
	if err != nil || first.Duplicate || first.DeliveryID != delivery1.String() {
		t.Fatalf("first receipt: %+v %v", first, err)
	}
	rig.st.now = time.Unix(1_800_000_090, 0)
	second, err := recv.Receive(b.header, b.body)
	if err != nil || !second.Duplicate {
		t.Fatalf("the retry must be a duplicate: %+v %v", second, err)
	}
	// A different delivery is not a duplicate of it.
	other := mkEventDelivery(rig.org.id, notify.EventIncidentOpened, evIncident, 1)
	other.ID = model.ID{0xde, 0xad, 0x02}
	body, _ := EventBody(other, origin)
	h := http.Header{}
	h.Set(HeaderDeliveryID, other.ID.String())
	h.Set(HeaderTimestamp, strconv.FormatInt(rig.st.now.Unix(), 10))
	h.Set(HeaderSignature, Sign([]byte(currentSecret), rig.st.now.Unix(), other.ID.String(), body))
	if r, err := recv.Receive(h, body); err != nil || r.Duplicate {
		t.Fatalf("another delivery: %+v %v", r, err)
	}
	// Nothing secret leaked into the outcome or the request.
	for _, r := range reqs {
		if strings.Contains(string(r.body), currentSecret) || strings.Contains(r.header.Get(HeaderSignature), currentSecret) {
			t.Fatal("the secret is on the wire")
		}
	}
}

// During a rotation the request carries two v1 signatures and either secret verifies it
// at the Receiver; once the window has passed (judged at the attempt's own time) only the
// current secret signs and the previous secret is not even read; a previous secret that
// is gone does not stop the delivery, an unreadable one retries.
func TestEventRotationSignsWithBothThenOnlyTheCurrentSecret(t *testing.T) {
	until := time.Unix(1_800_000_000, 0).Add(time.Hour)
	rotating := func(rec *notify.DestinationRecord, reg *eventReg, org model.ID) {
		rec.HasPrevious, rec.PreviousUntil = true, model.UnixNano(until.UnixNano())
		reg.prev[[2]model.ID{org, recipient}] = previousSecret
	}
	t.Run("both signatures while the window is open", func(t *testing.T) {
		rig := newEventRig(t, http.HandlerFunc(accept), rotating)
		if out := rig.send(1); out.Kind != notify.OutcomeAccepted {
			t.Fatalf("%+v", out)
		}
		req := rig.only()
		header := req.header.Get(HeaderSignature)
		sigs := strings.Split(header, ",")
		if len(sigs) != 2 || sigs[0] != Sign([]byte(currentSecret), 1_800_000_000, delivery1.String(), req.body) || sigs[1] != Sign([]byte(previousSecret), 1_800_000_000, delivery1.String(), req.body) {
			t.Fatalf("signatures: %s", header)
		}
		for name, secret := range map[string]string{"current": currentSecret, "previous": previousSecret} {
			if _, err := rig.receiver(secret).Receive(req.header, req.body); err != nil {
				t.Fatalf("a receiver with the %s secret refused it: %v", name, err)
			}
		}
		if _, err := rig.receiver("an-unrelated-secret-0123456789").Receive(req.header, req.body); !errors.Is(err, ErrSignature) {
			t.Fatalf("a wrong secret: %v", err)
		}
		if strings.Contains(header, previousSecret) || strings.Contains(string(req.body), previousSecret) {
			t.Fatal("the previous secret is on the wire")
		}
	})
	t.Run("only the current signature once the window has passed", func(t *testing.T) {
		rig := newEventRig(t, http.HandlerFunc(accept), rotating)
		rig.st.now = until.Add(time.Second)
		reads := rig.reg.reads
		if out := rig.send(1); out.Kind != notify.OutcomeAccepted {
			t.Fatalf("%+v", out)
		}
		req := rig.only()
		if strings.Contains(req.header.Get(HeaderSignature), ",") {
			t.Fatalf("an expired previous secret still signs: %s", req.header.Get(HeaderSignature))
		}
		if _, err := rig.receiver(currentSecret).Receive(req.header, req.body); err != nil {
			t.Fatalf("current: %v", err)
		}
		if _, err := rig.receiver(previousSecret).Receive(req.header, req.body); !errors.Is(err, ErrSignature) {
			t.Fatalf("the dropped previous secret verified: %v", err)
		}
		if rig.reg.reads-reads != 1 {
			t.Fatalf("secret reads: %d (only the current secret is read once the window passed)", rig.reg.reads-reads)
		}
	})
	t.Run("the window ends exactly at its instant", func(t *testing.T) {
		rig := newEventRig(t, http.HandlerFunc(accept), rotating)
		rig.st.now = until // PreviousUntil is exclusive
		rig.send(1)
		if strings.Contains(rig.only().header.Get(HeaderSignature), ",") {
			t.Fatal("the previous secret signed at its expiry instant")
		}
	})
	t.Run("a gone previous secret does not stop the delivery", func(t *testing.T) {
		rig := newEventRig(t, http.HandlerFunc(accept), func(rec *notify.DestinationRecord, reg *eventReg, org model.ID) {
			rec.HasPrevious, rec.PreviousUntil = true, model.UnixNano(until.UnixNano())
		})
		if out := rig.send(1); out.Kind != notify.OutcomeAccepted {
			t.Fatalf("%+v", out)
		}
		if strings.Contains(rig.only().header.Get(HeaderSignature), ",") {
			t.Fatal("signed with a previous secret that does not exist")
		}
	})
	t.Run("an unreadable previous secret is a retry that sends nothing", func(t *testing.T) {
		rig := newEventRig(t, http.HandlerFunc(accept), rotating)
		rig.reg.prevErr = errors.New("sealed store down " + previousSecret)
		out := rig.send(1)
		if out.Kind != notify.OutcomeRetry || out.Code != "secret_unavailable" || len(rig.cap.all()) != 0 {
			t.Fatalf("%+v requests %d", out, len(rig.cap.all()))
		}
		if strings.Contains(out.Code+out.ProviderID, previousSecret) {
			t.Fatal("a secret reached the outcome")
		}
	})
}

// ---------------------------------------------------------------- egress and outcomes

// The same egress rules as every webhook: loopback, private, link-local and metadata
// literals, names that resolve to them, plain http and an organization host allow-list
// all refuse with ZERO connections; a redirect is never followed.
func TestEventEgressRefusesWithZeroConnections(t *testing.T) {
	t.Run("loopback under the production policy", func(t *testing.T) {
		o := newOrg(t)
		srv := newTLSServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("receiver was contacted") }))
		reg := &eventReg{registry: newRegistry(), prev: map[[2]model.ID]string{}}
		reg.put(o.id, recipient, notify.DestinationRecord{Type: "event_webhook", Endpoint: srv.URL, Enabled: true}, currentSecret)
		dests, _ := notify.NewDestinations(reg, reg)
		c := Common{Destinations: dests, PublicOrigin: origin, Timeout: time.Second} // no test seam
		s, err := NewEventWebhook(EventWebhookConfig{Common: c, Stamper: &stamper{now: time.Now()}}, reg, srv.client())
		if err != nil {
			t.Fatal(err)
		}
		out, _ := s.Send(context.Background(), o.scope, mkEventDelivery(o.id, notify.EventIncidentOpened, evIncident, 1))
		if out.Kind != notify.OutcomeTerminal || out.Code != "egress_blocked" || srv.accepts.Load() != 0 {
			t.Fatalf("%+v accepts=%d", out, srv.accepts.Load())
		}
		// a name that resolves to loopback
		reg.put(o.id, recipient, notify.DestinationRecord{Type: "event_webhook", Endpoint: "https://events.example.test:" + portOf(srv.URL) + "/", Enabled: true}, currentSecret)
		c.Egress.Resolver = &fakeResolver{answers: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
		s, _ = NewEventWebhook(EventWebhookConfig{Common: c, Stamper: &stamper{now: time.Now()}}, reg, srv.client())
		if out, _ = s.Send(context.Background(), o.scope, mkEventDelivery(o.id, notify.EventIncidentOpened, evIncident, 1)); out.Code != "egress_blocked" || srv.accepts.Load() != 0 {
			t.Fatalf("%+v accepts=%d", out, srv.accepts.Load())
		}
	})
	t.Run("forbidden literals", func(t *testing.T) {
		for _, host := range []string{"10.0.0.5", "192.168.1.1", "172.16.0.9", "169.254.169.254", "[::1]", "[fe80::1]", "[fd00:ec2::254]", "100.100.100.200", "[::ffff:127.0.0.1]", "0.0.0.0"} {
			o := newOrg(t)
			reg := &eventReg{registry: newRegistry(), prev: map[[2]model.ID]string{}}
			reg.put(o.id, recipient, notify.DestinationRecord{Type: "event_webhook", Endpoint: "https://" + host + "/hook", Enabled: true}, currentSecret)
			dests, _ := notify.NewDestinations(reg, reg)
			s, err := NewEventWebhook(EventWebhookConfig{Common: Common{Destinations: dests, PublicOrigin: origin, Timeout: time.Second}, Stamper: &stamper{now: time.Now()}}, reg, nil)
			if err != nil {
				t.Fatal(err)
			}
			out, _ := s.Send(context.Background(), o.scope, mkEventDelivery(o.id, notify.EventIncidentOpened, evIncident, 1))
			if out.Kind != notify.OutcomeTerminal || out.Code != "egress_blocked" {
				t.Fatalf("%s: %+v", host, out)
			}
		}
	})
	t.Run("https only, no credentials, no query", func(t *testing.T) {
		for _, endpoint := range []string{"http://events.example.test/hook", "https://user:pw@events.example.test/hook", "https://events.example.test/hook?token=x", "https://events.example.test/hook#frag", "ftp://events.example.test/"} {
			o := newOrg(t)
			reg := &eventReg{registry: newRegistry(), prev: map[[2]model.ID]string{}}
			reg.put(o.id, recipient, notify.DestinationRecord{Type: "event_webhook", Endpoint: endpoint, Enabled: true}, currentSecret)
			dests, _ := notify.NewDestinations(reg, reg)
			s, _ := NewEventWebhook(EventWebhookConfig{Common: Common{Destinations: dests, PublicOrigin: origin, Timeout: time.Second}, Stamper: &stamper{now: time.Now()}}, reg, nil)
			out, _ := s.Send(context.Background(), o.scope, mkEventDelivery(o.id, notify.EventIncidentOpened, evIncident, 1))
			if out.Kind != notify.OutcomeTerminal || out.Code != "destination_invalid" {
				t.Fatalf("%s: %+v", endpoint, out)
			}
		}
	})
	t.Run("organization host allow-list", func(t *testing.T) {
		rig := newEventRig(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("receiver was contacted") }), nil)
		rig.sender.cfg.Egress.OrgHosts = map[model.ID][]string{rig.org.id: {"only.example.test"}}
		out := rig.send(1)
		if out.Kind != notify.OutcomeTerminal || out.Code != "host_not_allowed" || rig.srv.accepts.Load() != 0 {
			t.Fatalf("%+v accepts=%d", out, rig.srv.accepts.Load())
		}
	})
	t.Run("a redirect is refused and never followed", func(t *testing.T) {
		var followed int
		rig := newEventRig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/elsewhere" {
				followed++
			}
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}), nil)
		out := rig.send(1)
		if out.Kind != notify.OutcomeTerminal || out.Code != "redirect_refused" || followed != 0 || len(rig.cap.all()) != 1 {
			t.Fatalf("%+v followed=%d requests=%d", out, followed, len(rig.cap.all()))
		}
	})
}

// The outcomes table of docs/operations/notification-channels.md applies to events.
func TestEventOutcomesTable(t *testing.T) {
	status := func(code int, header map[string]string) *eventRig {
		return newEventRig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for k, v := range header {
				w.Header().Set(k, v)
			}
			w.WriteHeader(code)
		}), nil)
	}
	for _, tc := range []struct {
		code   int
		header map[string]string
		kind   notify.OutcomeKind
		out    string
	}{
		{200, nil, notify.OutcomeAccepted, ""},
		{202, map[string]string{HeaderReceiptID: "rcpt-7"}, notify.OutcomeAccepted, "rcpt-7"},
		{204, nil, notify.OutcomeAccepted, ""},
		{429, map[string]string{"Retry-After": "30"}, notify.OutcomeRetry, "rate_limited"},
		{503, nil, notify.OutcomeRetry, "rate_limited"},
		{500, nil, notify.OutcomeRetry, "http_500"},
		{502, nil, notify.OutcomeRetry, "http_502"},
		{408, nil, notify.OutcomeRetry, "http_408"},
		{400, nil, notify.OutcomeTerminal, "http_400"},
		{401, nil, notify.OutcomeTerminal, "http_401"},
		{403, nil, notify.OutcomeTerminal, "http_403"},
		{404, nil, notify.OutcomeTerminal, "http_404"},
		{410, nil, notify.OutcomeTerminal, "http_410"},
		{301, nil, notify.OutcomeTerminal, "redirect_refused"},
		{307, nil, notify.OutcomeTerminal, "redirect_refused"},
	} {
		rig := status(tc.code, tc.header)
		out := rig.send(1)
		if out.Kind != tc.kind {
			t.Fatalf("%d: %+v", tc.code, out)
		}
		switch tc.kind {
		case notify.OutcomeAccepted:
			if tc.out != "" && out.ProviderID != tc.out || tc.out == "" && !strings.HasPrefix(out.ProviderID, "webhook-"+strconv.Itoa(tc.code)+":") {
				t.Fatalf("%d: provider id %q", tc.code, out.ProviderID)
			}
		default:
			if out.Code != tc.out {
				t.Fatalf("%d: code %q", tc.code, out.Code)
			}
		}
		if tc.code == 429 && out.RetryAfter != model.UnixNano(30*time.Second) {
			t.Fatalf("retry after %d", out.RetryAfter)
		}
	}
	t.Run("a connection lost after the request is unknown", func(t *testing.T) {
		rig := newEventRig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				c.Close()
			}
		}), nil)
		if out := rig.send(1); out.Kind != notify.OutcomeUnknown || out.Code != "transport_error" {
			t.Fatalf("%+v", out)
		}
	})
	t.Run("a receiver that does not answer in time is unknown", func(t *testing.T) {
		rig := newEventRig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(600 * time.Millisecond) }), nil)
		rig.sender.cfg.Timeout = 150 * time.Millisecond
		rig.sender.client.Timeout = 150 * time.Millisecond
		if out := rig.send(1); out.Kind != notify.OutcomeUnknown || out.Code != "timeout" {
			t.Fatalf("%+v", out)
		}
	})
	t.Run("nothing listening is a definite retry", func(t *testing.T) {
		rig := newEventRig(t, http.HandlerFunc(accept), nil)
		rig.srv.Close()
		if out := rig.send(1); out.Kind != notify.OutcomeRetry || out.Code != "connect_failed" {
			t.Fatalf("%+v", out)
		}
	})
	t.Run("an untrusted certificate is a definite retry", func(t *testing.T) {
		rig := newEventRig(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("receiver saw a request") }), nil)
		s, err := newEventSender(EventWebhookConfig{Common: eventCommon(rig.reg), Stamper: rig.st}, rig.reg, nil) // system roots only
		if err != nil {
			t.Fatal(err)
		}
		out, _ := s.Send(context.Background(), rig.org.scope, mkEventDelivery(rig.org.id, notify.EventIncidentOpened, evIncident, 1))
		if out.Kind != notify.OutcomeRetry || out.Code != "tls_failed" {
			t.Fatalf("%+v", out)
		}
	})
	t.Run("a huge response is bounded", func(t *testing.T) {
		rig := newEventRig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			chunk := make([]byte, 1<<16)
			for range 64 {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
		}), nil)
		if out := rig.send(1); out.Kind != notify.OutcomeAccepted {
			t.Fatalf("%+v", out)
		}
	})
	t.Run("a failed stamp is a retry before anything is sent", func(t *testing.T) {
		rig := newEventRig(t, http.HandlerFunc(accept), nil)
		rig.st.err = errors.New("disk full")
		if out := rig.send(1); out.Kind != notify.OutcomeRetry || out.Code != "timestamp_unavailable" || len(rig.cap.all()) != 0 {
			t.Fatalf("%+v", out)
		}
	})
	t.Run("a missing or short secret is terminal", func(t *testing.T) {
		rig := newEventRig(t, http.HandlerFunc(accept), nil)
		rig.reg.put(rig.org.id, recipient, notify.DestinationRecord{Type: "event_webhook", Endpoint: rig.srv.URL, Enabled: true}, "")
		if out := rig.send(1); out.Kind != notify.OutcomeTerminal || out.Code != "secret_missing" {
			t.Fatalf("no secret: %+v", out)
		}
		rig.reg.put(rig.org.id, recipient, notify.DestinationRecord{Type: "event_webhook", Endpoint: rig.srv.URL, Enabled: true}, "short")
		if out := rig.send(1); out.Kind != notify.OutcomeTerminal || out.Code != "secret_missing" {
			t.Fatalf("short secret: %+v", out)
		}
		if len(rig.cap.all()) != 0 {
			t.Fatal("an unsigned request was sent")
		}
	})
	t.Run("a disabled endpoint is terminal", func(t *testing.T) {
		rig := newEventRig(t, http.HandlerFunc(accept), func(rec *notify.DestinationRecord, _ *eventReg, _ model.ID) { rec.Enabled = false })
		if out := rig.send(1); out.Kind != notify.OutcomeTerminal || out.Code != "destination_disabled" || len(rig.cap.all()) != 0 {
			t.Fatalf("%+v", out)
		}
	})
}

// An event never reaches a notification channel and a notification never reaches an event
// endpoint, in either direction, at every provider: zero requests are made.
func TestEventAndNotificationChannelsNeverCross(t *testing.T) {
	var hits int
	rig := newEventRig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; accept(w, r) }), nil)
	ctx := context.Background()
	scope, o := rig.org.scope, rig.org.id
	// The event sender refuses a notification.
	if out, _ := rig.sender.Send(ctx, scope, mkDelivery(o, 1)); out.Kind != notify.OutcomeTerminal || out.Code != "channel_mismatch" {
		t.Fatalf("a notification through the event sender: %+v", out)
	}
	// The notification senders refuse an event, even to a destination of their own type.
	reg := newRegistry()
	reg.put(o, recipient, notify.DestinationRecord{Type: "webhook", Endpoint: rig.srv.URL + "/hook", Enabled: true}, currentSecret)
	web, err := NewWebhook(WebhookConfig{Common: testCommon(reg), Stamper: rig.st}, reg, rig.srv.client())
	if err != nil {
		t.Fatal(err)
	}
	if out, _ := web.Send(ctx, scope, mkEventDelivery(o, notify.EventIncidentOpened, evIncident, 1)); out.Kind != notify.OutcomeTerminal || out.Code != "channel_mismatch" {
		t.Fatalf("an event through the webhook sender: %+v", out)
	}
	tg, err := NewTelegram(TelegramConfig{Common: testCommon(reg), APIBase: rig.srv.URL}, reg, rig.srv.client())
	if err == nil {
		if out, _ := tg.Send(ctx, scope, mkEventDelivery(o, notify.EventIncidentOpened, evIncident, 1)); out.Kind != notify.OutcomeTerminal || out.Code != "channel_mismatch" {
			t.Fatalf("an event through the telegram sender: %+v", out)
		}
	}
	// The webhook sender cannot send a notification to an event endpoint either: the
	// destination type is the registry's, and a webhook is not an event endpoint.
	reg.put(o, recipient, notify.DestinationRecord{Type: "event_webhook", Endpoint: rig.srv.URL + "/hook", Enabled: true}, currentSecret)
	if out, _ := web.Send(ctx, scope, mkDelivery(o, 1)); out.Kind != notify.OutcomeTerminal || out.Code != "no_destination" {
		t.Fatalf("a notification to an event endpoint: %+v", out)
	}
	// And an event addressed to a destination of another type finds no event endpoint.
	reg2 := &eventReg{registry: newRegistry(), prev: map[[2]model.ID]string{}}
	reg2.put(o, recipient, notify.DestinationRecord{Type: "webhook", Endpoint: rig.srv.URL + "/hook", Enabled: true}, currentSecret)
	ev, err := newEventSender(EventWebhookConfig{Common: eventCommon(reg2), Stamper: rig.st}, reg2, rig.srv.client())
	if err != nil {
		t.Fatal(err)
	}
	if out, _ := ev.Send(ctx, scope, mkEventDelivery(o, notify.EventIncidentOpened, evIncident, 1)); out.Kind != notify.OutcomeTerminal || out.Code != "no_destination" {
		t.Fatalf("an event to a notification destination: %+v", out)
	}
	if hits != 0 || len(rig.cap.all()) != 0 {
		t.Fatalf("a refused delivery reached a receiver: %d", hits)
	}
}

// Another organization's scope can neither resolve the endpoint nor read its secrets.
func TestEventEndpointOfAnotherOrganizationIsInvisible(t *testing.T) {
	rig := newEventRig(t, http.HandlerFunc(accept), nil)
	other := newOrg(t)
	out, _ := rig.sender.Send(context.Background(), other.scope, mkEventDelivery(rig.org.id, notify.EventIncidentOpened, evIncident, 1))
	if out.Kind != notify.OutcomeTerminal || out.Code != "scope_mismatch" || len(rig.cap.all()) != 0 {
		t.Fatalf("%+v", out)
	}
	out, _ = rig.sender.Send(context.Background(), other.scope, mkEventDelivery(other.id, notify.EventIncidentOpened, evIncident, 1))
	if out.Kind != notify.OutcomeTerminal || out.Code != "no_destination" || len(rig.cap.all()) != 0 {
		t.Fatalf("an endpoint ID of another organization: %+v", out)
	}
}

// Secrets and the endpoint path never appear in any outcome.
func TestEventOutcomesCarryNoSecretOrPath(t *testing.T) {
	for _, h := range []http.HandlerFunc{
		accept,
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) },
		func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/"+canaryPath, http.StatusFound) },
	} {
		rig := newEventRig(t, h, func(rec *notify.DestinationRecord, reg *eventReg, org model.ID) {
			rec.HasPrevious, rec.PreviousUntil = true, model.UnixNano(time.Unix(1_800_000_000, 0).Add(time.Hour).UnixNano())
			reg.prev[[2]model.ID{org, recipient}] = previousSecret
		})
		raw, _ := json.Marshal(rig.send(1))
		for _, secret := range []string{currentSecret, previousSecret, canaryPath} {
			if strings.Contains(string(raw), secret) {
				t.Fatalf("outcome %s contains %q", raw, secret)
			}
		}
	}
}
