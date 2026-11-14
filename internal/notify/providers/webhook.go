// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package providers

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// Webhook wire contract (version 1).
//
//	POST <destination endpoint>   Content-Type: application/json
//	Soundpost-Delivery-ID: <stable delivery id, hex>
//	Soundpost-Timestamp:   <unix seconds of THIS attempt>
//	Soundpost-Signature:   v1=<hex HMAC-SHA256(secret, "<ts>.<delivery-id>.<exact body bytes>")>
//
// The body is a pure function of the delivery, so every retry sends the exact
// same bytes; only the timestamp and therefore the signature change. A receiver
// accepts a timestamp within ReplayWindow of its clock and deduplicates by the
// stable delivery ID, independently of the signature's freshness.
const (
	WebhookVersion   = 1
	HeaderSignature  = "Soundpost-Signature"
	HeaderTimestamp  = "Soundpost-Timestamp"
	HeaderDeliveryID = "Soundpost-Delivery-ID"
	HeaderReceiptID  = "Soundpost-Receipt-ID"
	// ReplayWindow is the receiver's accepted clock skew / replay window.
	ReplayWindow = 5 * time.Minute
	// minSecretLen is the shortest accepted signing secret.
	minSecretLen = 16
)

// AttemptStamper persists the timestamp of one delivery attempt outside the
// deterministic control apply. AttemptTime MUST be idempotent per
// (delivery, attempt): the first call durably records the current time and
// every later call for the same attempt (a crash and re-send of the same claim)
// returns that recorded time; a new attempt gets a fresh one.
type AttemptStamper interface {
	AttemptTime(ctx context.Context, scope auth.Scope, delivery model.ID, attempt uint32) (time.Time, error)
}

// WebhookConfig configures the signed webhook sender.
type WebhookConfig struct {
	Common
	Stamper AttemptStamper
}

type webhookSender struct {
	cfg     WebhookConfig
	origin  string
	secrets SecretReader
	client  *http.Client
}

// NewWebhook returns the signed HTTPS webhook sender. client may carry TLS
// roots and a timeout; its dialer, proxy and redirect policy are replaced by
// the egress-checked ones.
func NewWebhook(config WebhookConfig, secrets SecretReader, client *http.Client) (notify.Sender, error) {
	origin, err := config.prepared()
	if err != nil {
		return nil, err
	}
	if secrets == nil || config.Stamper == nil {
		return nil, errors.New("providers: webhook needs secrets and an attempt stamper")
	}
	c, err := newHTTPClient(config.Common, client)
	if err != nil {
		return nil, err
	}
	return &webhookSender{cfg: config, origin: origin, secrets: secrets, client: c}, nil
}

type webhookBody struct {
	Version        int             `json:"version"`
	DeliveryID     string          `json:"delivery_id"`
	EventKind      notify.Kind     `json:"event_kind"`
	Org            model.ID        `json:"org_id"`
	Entity         notify.Entity   `json:"entity"`
	ImpactRevision uint64          `json:"impact_revision"`
	Ordinal        uint64          `json:"ordinal,omitempty"`
	Impact         notify.Template `json:"impact"`
	Link           string          `json:"link"`
}

// webhookBodyBytes is the deterministic body: no attempt number, no time.
func webhookBodyBytes(d notify.Delivery, origin string) ([]byte, error) {
	return json.Marshal(webhookBody{
		Version: WebhookVersion, DeliveryID: d.ID.String(), EventKind: d.Key.Kind, Org: d.Key.Org,
		Entity: d.Template.Entity, ImpactRevision: d.Key.ImpactRevision, Ordinal: d.Key.Ordinal,
		Impact: d.Template, Link: link(origin, d.Template.Entity),
	})
}

// Sign returns the signature header value for one attempt.
func Sign(secret []byte, unix int64, deliveryID string, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(strconv.FormatInt(unix, 10)))
	m.Write([]byte{'.'})
	m.Write([]byte(deliveryID))
	m.Write([]byte{'.'})
	m.Write(body)
	return "v1=" + hex.EncodeToString(m.Sum(nil))
}

func (s *webhookSender) Send(ctx context.Context, scope auth.Scope, d notify.Delivery) (notify.Outcome, error) {
	dest, secret, bad := resolve(ctx, s.cfg.Common, s.secrets, scope, d, notify.ChannelWebhook, true)
	if bad != nil {
		return *bad, nil
	}
	defer zero(secret)
	if len(secret) < minSecretLen {
		return terminal(codeSecretMissing), nil
	}
	u, err := url.Parse(dest.Target)
	if err != nil || u.Scheme != "https" {
		return terminal(codeDestInvalid), nil
	}
	if e := s.cfg.Egress.checkHost(scope.OrgID(), u.Hostname()); e != nil {
		if errors.Is(e, errHostNotAllowed) {
			return terminal(codeHostNotAllowed), nil
		}
		return terminal(codeEgressBlocked), nil
	}
	body, err := webhookBodyBytes(d, s.origin)
	if err != nil {
		return terminal(codeBadResponse), nil
	}
	ts, err := s.cfg.Stamper.AttemptTime(ctx, scope, d.ID, d.Attempt)
	if err != nil {
		return retry(codeTimestampMissing, 0), nil
	}
	id := d.ID.String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dest.Target, bytes.NewReader(body))
	if err != nil {
		return terminal(codeDestInvalid), nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Soundpost-Webhook/1")
	req.Header.Set(HeaderDeliveryID, id)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts.Unix(), 10))
	req.Header.Set(HeaderSignature, Sign(secret, ts.Unix(), id, body))
	res := roundTrip(s.client, req)
	if o, failed := transportOutcome(res, ctx.Err()); failed {
		return o, nil
	}
	switch st := res.status; {
	case st >= 200 && st < 300:
		// A 2xx is a receipt that the receiver took the notification, never
		// proof that anyone or anything acted on it.
		receipt := strings.TrimSpace(res.header.Get(HeaderReceiptID))
		if !receiptID(receipt) {
			receipt = "webhook-" + strconv.Itoa(st) + ":" + id
		}
		return notify.Outcome{Kind: notify.OutcomeAccepted, ProviderID: receipt}, nil
	case st == http.StatusTooManyRequests || st == http.StatusServiceUnavailable:
		return retry(codeRateLimited, retryAfter(res.header, s.cfg.now())), nil
	case st == http.StatusRequestTimeout || st >= 500:
		return retry("http_"+strconv.Itoa(st), retryAfter(res.header, s.cfg.now())), nil
	case st >= 300 && st < 400:
		return terminal(codeRedirectRefused), nil
	default:
		return terminal("http_" + strconv.Itoa(st)), nil
	}
}

func receiptID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- receiver

// Receipt is a verified webhook.
type Receipt struct {
	DeliveryID string
	// Duplicate says the stable delivery ID was already received: acknowledge
	// it with 2xx and do not act again.
	Duplicate bool
}

// Receiver errors.
var (
	ErrSignature    = errors.New("webhook: signature invalid")
	ErrReplayWindow = errors.New("webhook: timestamp outside the replay window")
	ErrMalformed    = errors.New("webhook: malformed request")
)

// Receiver is the reference verification and deduplication logic for a
// receiver of Soundpost webhooks.
type Receiver struct {
	secret []byte
	now    func() time.Time
	ttl    time.Duration
	mu     sync.Mutex
	seen   map[string]time.Time
}

// NewReceiver returns a receiver for secret. Delivery IDs are remembered for
// ttl (it must exceed the sender's 24 hour retry budget; zero means 25 hours).
func NewReceiver(secret []byte, now func() time.Time, ttl time.Duration) *Receiver {
	if now == nil {
		now = time.Now
	}
	if ttl <= 0 {
		ttl = 25 * time.Hour
	}
	return &Receiver{secret: append([]byte(nil), secret...), now: now, ttl: ttl, seen: map[string]time.Time{}}
}

// Receive verifies the signature over the exact body, the 5 minute window, and
// that the body names the signed delivery ID; only then does it record the ID.
// A retry of an already received delivery carries a fresh valid signature and
// is reported as a duplicate.
func (r *Receiver) Receive(h http.Header, body []byte) (Receipt, error) {
	id := h.Get(HeaderDeliveryID)
	unix, err := strconv.ParseInt(h.Get(HeaderTimestamp), 10, 64)
	if id == "" || err != nil {
		return Receipt{}, ErrMalformed
	}
	now := r.now()
	skew := now.Sub(time.Unix(unix, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > ReplayWindow {
		return Receipt{}, ErrReplayWindow
	}
	want := Sign(r.secret, unix, id, body)
	ok := false
	for _, got := range strings.Split(h.Get(HeaderSignature), ",") {
		if hmac.Equal([]byte(strings.TrimSpace(got)), []byte(want)) {
			ok = true
		}
	}
	if !ok {
		return Receipt{}, ErrSignature
	}
	var b struct {
		Version    int    `json:"version"`
		DeliveryID string `json:"delivery_id"`
	}
	if json.Unmarshal(body, &b) != nil || b.Version != WebhookVersion || b.DeliveryID != id {
		return Receipt{}, ErrMalformed
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, exp := range r.seen {
		if now.After(exp) {
			delete(r.seen, k)
		}
	}
	_, dup := r.seen[id]
	r.seen[id] = now.Add(r.ttl)
	return Receipt{DeliveryID: id, Duplicate: dup}, nil
}
