// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/notify"
	"soundpost/internal/notify/providers"
)

// SMTPSettings is the operator's SMTP submission relay. The destination's address
// is the recipient and its sealed secret is the relay password.
type SMTPSettings struct {
	Host        string
	Port        int
	TLS         providers.SMTPTLS
	Username    string
	RequireAuth bool
	From        string
	ServerName  string
}

// NotificationConfig is what a served process needs to deliver notifications
// through the real providers. Destinations themselves (type, https endpoint or
// address, enabled, sealed secret) are organization configuration in control
// state, written by the `destination` admin command; this is only the node's own
// delivery environment.
type NotificationConfig struct {
	// PublicOrigin is the https origin links in notifications are built from.
	PublicOrigin string
	// StateDir holds the per-attempt timestamps of signed webhooks (created, 0700).
	StateDir string
	// Egress is the outbound network policy; the default blocks loopback, private
	// and metadata addresses.
	Egress providers.EgressPolicy
	// RootCAs are extra trust roots for webhook, Telegram and SMTP TLS (the system
	// roots when nil). Verification can never be disabled.
	RootCAs *x509.CertPool
	// TelegramAPI is the Bot API origin (the public API when empty).
	TelegramAPI string
	// SMTP enables the e-mail channel; nil leaves it unconfigured.
	SMTP *SMTPSettings
	// Timeout bounds one send attempt (providers' default when zero).
	Timeout time.Duration
}

// controlDestinations reads the organization's configured destinations from
// committed control state: `destination:<id>` settings and the presence of the
// sealed secret `destination:<id>`.
type controlDestinations struct{ a *App }

func (c controlDestinations) Destination(ctx context.Context, scope auth.Scope, org, id model.ID) (notify.DestinationRecord, bool, error) {
	if scope.OrgID() != org {
		return notify.DestinationRecord{}, false, nil
	}
	var rec notify.DestinationRecord
	var found bool
	err := c.a.Control.View(ctx, func(st model.ControlState) error {
		if _, retired := st.RetiredOrgs[org.String()]; retired {
			return nil
		}
		o, ok := st.Orgs[org.String()]
		if !ok {
			return nil
		}
		raw, ok := o.Settings["destination:"+id.String()]
		if !ok {
			return nil
		}
		var cfg auth.DestinationConfig
		if json.Unmarshal(raw, &cfg) != nil {
			return model.Fail(model.Corrupt)
		}
		rec = notify.DestinationRecord{Type: cfg.Type, Endpoint: cfg.Endpoint, Address: cfg.Address, Enabled: cfg.Enabled, HasSecret: o.Secrets["destination:"+id.String()] != ""}
		found = true
		return nil
	})
	return rec, found, err
}

// controlSecrets opens the sealed destination secrets of the control store. The
// registry (notify.Destinations) has already refused any reference outside the
// scope's organization or without a configured destination before this runs.
type controlSecrets struct{ a *App }

func (c controlSecrets) Read(ctx context.Context, scope auth.Scope, ref notify.SecretRef) ([]byte, error) {
	if ref.Org != scope.OrgID() {
		return nil, model.Fail(model.Forbidden)
	}
	var sealed string
	err := c.a.Control.View(ctx, func(st model.ControlState) error {
		o, ok := st.Orgs[ref.Org.String()]
		if !ok {
			return model.Fail(model.Forbidden)
		}
		sealed, ok = o.Secrets["destination:"+ref.ID.String()]
		if !ok || sealed == "" {
			return model.Fail(model.Forbidden)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	plain, err := c.a.Control.OpenSecret(sealed)
	if err != nil {
		return nil, model.Fail(model.Unavailable)
	}
	return []byte(plain), nil
}

// attemptStamps durably records the instant of each delivery attempt, once, so a
// crashed and re-sent claim signs with the same timestamp (the signed webhook
// contract). It is node-local state outside the replicated control apply: one
// small file per (delivery, attempt), removed after two days (a delivery never
// outlives control.DeliveryMaxAge).
type attemptStamps struct {
	dir  string
	now  func() time.Time
	mu   sync.Mutex
	last time.Time
}

const (
	stampRetention = 48 * time.Hour
	stampSweep     = time.Hour
)

func newAttemptStamps(dir string, now func() time.Time) (*attemptStamps, error) {
	if dir == "" {
		return nil, model.Fail(model.Invalid)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, model.Fail(model.Unavailable)
	}
	return &attemptStamps{dir: dir, now: now}, nil
}

func (s *attemptStamps) AttemptTime(_ context.Context, scope auth.Scope, delivery model.ID, attempt uint32) (time.Time, error) {
	if scope.OrgID() == (model.ID{}) {
		return time.Time{}, model.Fail(model.Forbidden)
	}
	path := filepath.Join(s.dir, delivery.String()+"-"+strconv.FormatUint(uint64(attempt), 10))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep()
	if t, ok := readStamp(path); ok {
		return t, nil
	}
	at := s.now().UTC()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if t, ok := readStamp(path); ok {
			return t, nil
		}
		return time.Time{}, model.Fail(model.Unavailable)
	}
	_, werr := f.WriteString(strconv.FormatInt(at.UnixNano(), 10))
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(path)
		return time.Time{}, model.Fail(model.Unavailable)
	}
	return at, nil
}

func readStamp(path string) (time.Time, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}, false
	}
	return time.Unix(0, n).UTC(), true
}

func (s *attemptStamps) sweep() {
	now := s.now()
	if !s.last.IsZero() && now.Sub(s.last) < stampSweep {
		return
	}
	s.last = now
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		info, err := e.Info()
		if err == nil && !e.IsDir() && now.Sub(info.ModTime()) > stampRetention {
			_ = os.Remove(filepath.Join(s.dir, e.Name()))
		}
	}
}

// channelSender sends a delivery through the provider of its destination's
// channel. The destination is looked up fresh from control state on every attempt;
// a channel the operator has not configured is a terminal, visible failure (never
// a success and never a silent drop).
type channelSender struct {
	destinations notify.DestinationSource
	senders      map[notify.Channel]notify.Sender
}

func (c channelSender) Send(ctx context.Context, scope auth.Scope, d notify.Delivery) (notify.Outcome, error) {
	if d.Key.Recipient == nil || d.Key.Org != scope.OrgID() {
		return notify.Outcome{Kind: notify.OutcomeTerminal, Code: "no_destination"}, nil
	}
	rec, found, err := c.destinations.Destination(ctx, scope, scope.OrgID(), *d.Key.Recipient)
	if err != nil {
		return notify.Outcome{Kind: notify.OutcomeRetry, Code: "destination_lookup_failed"}, nil
	}
	if !found {
		return notify.Outcome{Kind: notify.OutcomeTerminal, Code: "no_destination"}, nil
	}
	sender, ok := c.senders[notify.Channel(rec.Type)]
	if !ok {
		return notify.Outcome{Kind: notify.OutcomeTerminal, Code: "channel_unconfigured"}, nil
	}
	return sender.Send(ctx, scope, d)
}

// NotificationSender builds the delivery Sender of a served node: the signed
// webhook, Telegram Bot API and SMTP providers (internal/notify/providers) behind
// the organization-scoped destination registry over committed control state and the
// control store's sealed secrets. SMTP is configured only when cfg.SMTP is set; a
// destination of an unconfigured channel fails visibly.
func (a *App) NotificationSender(cfg NotificationConfig) (notify.Sender, error) {
	source := controlDestinations{a}
	registry, err := notify.NewDestinations(source, controlSecrets{a})
	if err != nil {
		return nil, err
	}
	stamper, err := newAttemptStamps(cfg.StateDir, time.Now)
	if err != nil {
		return nil, err
	}
	common := providers.Common{Destinations: registry, PublicOrigin: cfg.PublicOrigin, Egress: cfg.Egress, Timeout: cfg.Timeout}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: cfg.RootCAs, MinVersion: tls.VersionTLS12}}}
	senders := map[notify.Channel]notify.Sender{}
	if senders[notify.ChannelWebhook], err = providers.NewWebhook(providers.WebhookConfig{Common: common, Stamper: stamper}, registry, client); err != nil {
		return nil, err
	}
	if senders[notify.ChannelTelegram], err = providers.NewTelegram(providers.TelegramConfig{Common: common, APIBase: cfg.TelegramAPI}, registry, client); err != nil {
		return nil, err
	}
	if s := cfg.SMTP; s != nil {
		smtp := providers.SMTPConfig{Common: common, Host: s.Host, Port: s.Port, TLS: s.TLS, Username: s.Username, RequireAuth: s.RequireAuth, From: s.From, RootCAs: cfg.RootCAs, ServerName: s.ServerName}
		if senders[notify.ChannelSMTP], err = providers.NewSMTP(smtp, registry); err != nil {
			return nil, err
		}
	}
	return channelSender{destinations: source, senders: senders}, nil
}

// orgRouting routes the conditions and incidents of every project to every
// enabled destination of the project's organization, under the approved default
// notification policy. There is no per-project policy catalogue: the organization's
// destinations are the routes (what `destination` admin commands configure), a new
// enabled destination is picked up at the next pass, and a project belongs to
// exactly one organization so no notification can cross one.
type orgRouting struct{ a *App }

// OrgRouting is the NotificationRouting of a served node (see orgRouting).
func (a *App) OrgRouting() NotificationRouting { return orgRouting{a} }

func (r orgRouting) Routing(ctx context.Context, scope auth.Scope, project model.ID) (NotificationBinding, bool, error) {
	var recipients []model.ID
	err := r.a.Control.View(ctx, func(st model.ControlState) error {
		if _, retired := st.RetiredOrgs[scope.OrgID().String()]; retired {
			return nil
		}
		o, ok := st.Orgs[scope.OrgID().String()]
		if !ok {
			return nil
		}
		for key, raw := range o.Settings {
			rest, ok := strings.CutPrefix(key, "destination:")
			if !ok {
				continue
			}
			id, err := model.ParseID(rest)
			if err != nil {
				continue
			}
			var cfg auth.DestinationConfig
			if json.Unmarshal(raw, &cfg) != nil || !cfg.Enabled {
				continue
			}
			switch notify.Channel(cfg.Type) {
			case notify.ChannelSMTP, notify.ChannelTelegram, notify.ChannelWebhook:
				recipients = append(recipients, id)
			}
		}
		return nil
	})
	if err != nil || len(recipients) == 0 {
		return NotificationBinding{}, false, err
	}
	sort.Slice(recipients, func(i, j int) bool { return recipients[i].String() < recipients[j].String() })
	org := scope.OrgID()
	policy := policyCommand([]byte("soundpost/default-notification-policy"), org[:], project[:])
	return NotificationBinding{Policy: policy, Revision: 1, Config: notify.DefaultConfig(), Recipients: recipients}, true, nil
}
