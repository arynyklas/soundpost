// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"net/url"
	"regexp"
	"strings"

	"soundpost/internal/auth"
	"soundpost/internal/model"
)

// Channel is the closed set of delivery channels.
type Channel string

const (
	ChannelSMTP     Channel = "smtp"
	ChannelTelegram Channel = "telegram"
	ChannelWebhook  Channel = "webhook"
)

// Destination errors. They carry no destination text.
var (
	// ErrNoDestination: the organization has no such configured destination.
	ErrNoDestination = errors.New("notify: no destination")
	// ErrDestinationDisabled: the destination exists and is disabled.
	ErrDestinationDisabled = errors.New("notify: destination disabled")
	// ErrDestinationInvalid: the stored destination fails validation.
	ErrDestinationInvalid = errors.New("notify: destination invalid")
)

// SecretRef names one org-owned destination secret. The organization is part
// of the reference so a cross-organization reference is detectable before any
// store access.
type SecretRef struct {
	Org model.ID
	ID  model.ID
}

// SecretReader is the narrow consumer-owned seam over the control group's
// sealed destination secrets (C02 AES-256-GCM envelope keys, rotated by key ID;
// the parent binds it to the control store's OpenSecret). Read returns the
// plaintext for the one attempt; callers must not retain, log or copy it. A
// reference outside scope.OrgID() MUST fail exactly like a missing one.
type SecretReader interface {
	Read(ctx context.Context, scope auth.Scope, ref SecretRef) ([]byte, error)
}

// DestinationRecord is one configured destination as the control state holds
// it (`destination:<id>` settings plus the presence of its sealed secret).
// Endpoint is the https URL of a webhook; Address is the e-mail recipient or the
// Telegram chat.
type DestinationRecord struct {
	Type      string
	Endpoint  string
	Address   string
	Enabled   bool
	HasSecret bool
}

// DestinationSource reads the configured destinations of one organization. A
// missing destination is (zero, false, nil). The parent binds it to committed
// control state; the destination ID is the recipient ID of the delivery.
type DestinationSource interface {
	Destination(ctx context.Context, scope auth.Scope, org, id model.ID) (DestinationRecord, bool, error)
}

// Destination is one resolved, validated, allow-listed destination. Target is
// the e-mail recipient, Telegram chat or webhook URL: it never appears in a
// String, JSON or log rendering.
type Destination struct {
	ID      model.ID
	Org     model.ID
	Channel Channel
	Target  string
	// Secret is set when the destination has a sealed secret.
	Secret *SecretRef
}

// DestinationView is the redacted DTO of a destination: identity, channel and
// a coarse display, never the target or a secret.
type DestinationView struct {
	ID        model.ID `json:"id"`
	Channel   Channel  `json:"channel"`
	Display   string   `json:"display"`
	HasSecret bool     `json:"has_secret"`
}

// View is the redacted DTO. A webhook shows its host only, an e-mail its
// domain only, a Telegram chat nothing.
func (d Destination) View() DestinationView {
	v := DestinationView{ID: d.ID, Channel: d.Channel, HasSecret: d.Secret != nil}
	switch d.Channel {
	case ChannelWebhook:
		if u, err := url.Parse(d.Target); err == nil {
			v.Display = u.Hostname()
		}
	case ChannelSMTP:
		if i := strings.LastIndexByte(d.Target, '@'); i >= 0 {
			v.Display = "***@" + d.Target[i+1:]
		}
	}
	return v
}

func (d Destination) String() string {
	v := d.View()
	return fmt.Sprintf("destination{%s %s %s secret=%t}", v.ID, v.Channel, v.Display, v.HasSecret)
}
func (d Destination) GoString() string             { return d.String() }
func (d Destination) MarshalJSON() ([]byte, error) { return json.Marshal(d.View()) }
func (d Destination) LogValue() slog.Value {
	v := d.View()
	return slog.GroupValue(slog.String("id", v.ID.String()), slog.String("channel", string(v.Channel)), slog.String("display", v.Display))
}

// Format keeps every fmt verb (%v, %+v, %#v) on the redacted rendering.
func (d Destination) Format(f fmt.State, _ rune) { _, _ = fmt.Fprint(f, d.String()) }

// Destinations is the registry of configured destinations: the only way a
// sender learns where to send. A delivery names a recipient ID and nothing
// else; no telemetry-supplied chat, token or URL can select a destination,
// because Delivery has no such field and the lookup key is (organization,
// recipient, channel) from committed control state.
type Destinations struct {
	src     DestinationSource
	secrets SecretReader
}

// NewDestinations binds the registry to its source and sealed-secret reader.
func NewDestinations(src DestinationSource, secrets SecretReader) (*Destinations, error) {
	if src == nil || secrets == nil {
		return nil, model.Fail(model.Invalid)
	}
	return &Destinations{src: src, secrets: secrets}, nil
}

var (
	chatPattern  = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z0-9_]{5,32})$`)
	emailPattern = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}$`)
)

// Resolve returns the destination of d's recipient on channel ch. The scope,
// the delivery's organization and the destination's organization must all be
// the same; the lookup is fresh at every attempt, so removal and disabling
// take effect at once.
func (r *Destinations) Resolve(ctx context.Context, scope auth.Scope, d Delivery, ch Channel) (Destination, error) {
	org := scope.OrgID()
	if d.Key.Org != org {
		return Destination{}, model.Fail(model.Forbidden)
	}
	if d.Key.Recipient == nil {
		return Destination{}, ErrNoDestination
	}
	id := *d.Key.Recipient
	rec, found, err := r.src.Destination(ctx, scope, org, id)
	if err != nil {
		return Destination{}, model.Fail(model.Unavailable)
	}
	if !found || rec.Type != string(ch) {
		return Destination{}, ErrNoDestination
	}
	if !rec.Enabled {
		return Destination{}, ErrDestinationDisabled
	}
	dest := Destination{ID: id, Org: org, Channel: ch}
	switch ch {
	case ChannelWebhook:
		u, e := url.Parse(rec.Endpoint)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return Destination{}, ErrDestinationInvalid
		}
		dest.Target = rec.Endpoint
	case ChannelTelegram:
		if !chatPattern.MatchString(rec.Address) {
			return Destination{}, ErrDestinationInvalid
		}
		dest.Target = rec.Address
	case ChannelSMTP:
		a, e := mail.ParseAddress(rec.Address)
		if e != nil || a.Address != rec.Address || a.Name != "" || !emailPattern.MatchString(rec.Address) {
			return Destination{}, ErrDestinationInvalid
		}
		dest.Target = rec.Address
	default:
		return Destination{}, ErrNoDestination
	}
	if rec.HasSecret {
		dest.Secret = &SecretRef{Org: org, ID: id}
	}
	return dest, nil
}

// Read implements SecretReader with the allow-list: only the secret of a
// destination that is configured in the scope's own organization can be read.
// A reference in another organization, an unknown destination and a
// destination without a secret all fail identically with Forbidden.
func (r *Destinations) Read(ctx context.Context, scope auth.Scope, ref SecretRef) ([]byte, error) {
	if ref.Org != scope.OrgID() {
		return nil, model.Fail(model.Forbidden)
	}
	rec, found, err := r.src.Destination(ctx, scope, ref.Org, ref.ID)
	if err != nil {
		return nil, model.Fail(model.Unavailable)
	}
	if !found || !rec.HasSecret {
		return nil, model.Fail(model.Forbidden)
	}
	secret, err := r.secrets.Read(ctx, scope, ref)
	if err != nil {
		// Whatever the reader printed is discarded: it may quote key material.
		var f *model.Fault
		if errors.As(err, &f) && (f.Code == model.Forbidden || f.Code == model.NotFound) {
			return nil, model.Fail(model.Forbidden)
		}
		return nil, model.Fail(model.Unavailable)
	}
	return secret, nil
}
