// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// Event webhook wire contract (docs/operations/event-webhooks.md), version 1:
// the signed webhook of webhook.go with an event body.
//
//	POST <endpoint url>           Content-Type: application/json
//	Soundpost-Event:       <event name>
//	Soundpost-Delivery-ID: <stable delivery id, hex>
//	Soundpost-Timestamp:   <unix seconds of THIS attempt>
//	Soundpost-Signature:   v1=<hex HMAC-SHA256(secret, "<ts>.<delivery-id>.<exact body>")>
//	                       [,v1=<the same with the previous secret, while it is valid>]
//
// The body is a pure function of the stored delivery: identifiers, an enum and a
// link, no text. A retry sends the same bytes and the same delivery ID.
const (
	// HeaderEvent names the event of the request.
	HeaderEvent = "Soundpost-Event"
	// EventWebhookVersion is the body version.
	EventWebhookVersion = 1

	// codeChannelMismatch is the closed code of a delivery whose kind does not match
	// the channel: the event sender sends events and nothing else.
	codeChannelMismatch = "channel_mismatch"
)

// EventWebhookConfig configures the event webhook sender.
type EventWebhookConfig struct {
	Common
	Stamper AttemptStamper
}

type eventSender struct {
	cfg     EventWebhookConfig
	origin  string
	secrets SecretReader
	client  *http.Client
	// header builds the Soundpost-Signature value of one attempt from the current
	// secret and, during a rotation, the previous one. It is the seam the signature
	// mutation tests replace; production is eventSignatureHeader.
	header func(current, previous []byte, unix int64, deliveryID string, body []byte) string
}

// NewEventWebhook returns the signed event webhook sender: the same egress rules,
// https only, no redirects and bounded responses as every webhook, and the outcomes
// table of exchangeOutcome. It sends KindEvent deliveries to event_webhook
// destinations and nothing else.
func NewEventWebhook(config EventWebhookConfig, secrets SecretReader, client *http.Client) (notify.Sender, error) {
	return newEventSender(config, secrets, client)
}

func newEventSender(config EventWebhookConfig, secrets SecretReader, client *http.Client) (*eventSender, error) {
	origin, err := config.prepared()
	if err != nil {
		return nil, err
	}
	if secrets == nil || config.Stamper == nil {
		return nil, errors.New("providers: event webhook needs secrets and an attempt stamper")
	}
	c, err := newHTTPClient(config.Common, client)
	if err != nil {
		return nil, err
	}
	return &eventSender{cfg: config, origin: origin, secrets: secrets, client: c, header: eventSignatureHeader}, nil
}

// eventSignatureHeader is the Soundpost-Signature value: the signature with the
// current secret and, when a previous secret is given, a second one with it.
func eventSignatureHeader(current, previous []byte, unix int64, deliveryID string, body []byte) string {
	h := Sign(current, unix, deliveryID, body)
	if len(previous) > 0 {
		h += "," + Sign(previous, unix, deliveryID, body)
	}
	return h
}

// eventBody is the wire body. Entity IDs are in the member of their kind; nothing
// here is text.
type eventBody struct {
	Version    int       `json:"version"`
	DeliveryID string    `json:"delivery_id"`
	Event      string    `json:"event"`
	OccurredAt string    `json:"occurred_at"`
	Org        model.ID  `json:"org"`
	Project    model.ID  `json:"project"`
	Incident   *model.ID `json:"incident,omitempty"`
	Issue      *model.ID `json:"issue,omitempty"`
	Release    *model.ID `json:"release,omitempty"`
	Endpoint   *model.ID `json:"endpoint,omitempty"`
	Severity   string    `json:"severity,omitempty"`
	ReleaseID  *model.ID `json:"release_id,omitempty"`
	Service    *model.ID `json:"service,omitempty"`
	Revision   string    `json:"revision,omitempty"`
	URL        string    `json:"url"`
}

var severityWords = [...]string{"", "minor", "major", "critical"}

// eventEntity is the entity kind each event is about.
var eventEntity = map[notify.EventName]notify.EntityKind{
	notify.EventIncidentOpened:       notify.EntityIncident,
	notify.EventIncidentAcknowledged: notify.EntityIncident,
	notify.EventIncidentResolved:     notify.EntityIncident,
	notify.EventIssueNew:             notify.EntityIssue,
	notify.EventIssueRegressed:       notify.EntityIssue,
	notify.EventIssueResolved:        notify.EntityIssue,
	notify.EventIssueReopened:        notify.EntityIssue,
	notify.EventReleaseRegistered:    notify.EntityRelease,
	notify.EventTestPing:             notify.EntityEndpoint,
}

var errNotEvent = errors.New("providers: not an event delivery")

// EventBody is the deterministic body of an event delivery: no attempt number, no
// time of the attempt. origin is the node's public https origin. It is exported for
// receivers' reference tests and the producer's golden vectors.
func EventBody(d notify.Delivery, origin string) ([]byte, error) {
	f := d.Template.Event
	if d.Key.Kind != notify.KindEvent || f == nil {
		return nil, errNotEvent
	}
	name := f.Event
	kind, known := eventEntity[name]
	if !known || d.Template.Entity.Kind != kind || d.Template.Entity.ID == (model.ID{}) || d.Template.Project == (model.ID{}) || int(d.Template.Severity) >= len(severityWords) {
		return nil, errNotEvent
	}
	id := d.Template.Entity.ID
	b := eventBody{Version: EventWebhookVersion, DeliveryID: d.ID.String(), Event: string(f.Event), OccurredAt: strconv.FormatInt(int64(f.OccurredAt), 10), Org: d.Key.Org, Project: d.Template.Project,
		Severity: severityWords[d.Template.Severity], ReleaseID: f.Release, URL: link(origin, d.Key.Org, d.Template)}
	switch kind {
	case notify.EntityIncident:
		b.Incident = &id
	case notify.EntityIssue:
		b.Issue = &id
	case notify.EntityRelease:
		b.Release = &id
	default:
		b.Endpoint = &id
	}
	if d.Template.Service != nil {
		service := d.Template.Service.ID
		b.Service = &service
	}
	if f.Revision != 0 {
		b.Revision = strconv.FormatUint(f.Revision, 10)
	}
	// The link carries & characters: they are written as they are, not as \u0026, so
	// the bytes a receiver signs over are the ones it reads.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(b); err != nil {
		return nil, errNotEvent
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func (s *eventSender) Send(ctx context.Context, scope auth.Scope, d notify.Delivery) (notify.Outcome, error) {
	if d.Key.Kind != notify.KindEvent {
		return terminal(codeChannelMismatch), nil
	}
	dest, secret, bad := resolve(ctx, s.cfg.Common, s.secrets, scope, d, notify.ChannelEventWebhook, true)
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
	body, err := EventBody(d, s.origin)
	if err != nil {
		return terminal(codeBadResponse), nil
	}
	ts, err := s.cfg.Stamper.AttemptTime(ctx, scope, d.ID, d.Attempt)
	if err != nil {
		return retry(codeTimestampMissing, 0), nil
	}
	// The previous secret signs only while its window is open, judged at the
	// attempt's own stamped time, so a re-sent claim signs with the same set.
	var previous []byte
	if dest.PreviousSecret != nil && dest.PreviousUntil > model.UnixNano(ts.UnixNano()) {
		previous, err = s.secrets.Read(ctx, scope, *dest.PreviousSecret)
		if err != nil {
			if o := secretOutcome(err); o.Kind == notify.OutcomeTerminal {
				previous = nil // the previous secret is gone: the current one still signs
			} else {
				return o, nil
			}
		}
		defer zero(previous)
	}
	id := d.ID.String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dest.Target, bytes.NewReader(body))
	if err != nil {
		return terminal(codeDestInvalid), nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Soundpost-Webhook/1")
	req.Header.Set(HeaderEvent, string(d.Template.Event.Event))
	req.Header.Set(HeaderDeliveryID, id)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts.Unix(), 10))
	req.Header.Set(HeaderSignature, s.header(secret, previous, ts.Unix(), id, body))
	return exchangeOutcome(roundTrip(s.client, req), ctx.Err(), s.cfg.now(), id), nil
}
