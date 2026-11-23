// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"encoding/json"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/arynyklas/soundpost/internal/model"
)

// This file is the event webhook endpoint's part of the `destination` admin command
// (docs/operations/event-webhooks.md). An endpoint is an ordinary destination of
// type event_webhook: the same `destination:<id>` setting, the same sealed secret
// slot and the same per-destination version. What is new is the subscription
// (Events), a display Name, and the secret rotation: a save that carries a new
// secret for an endpoint that already has one moves the old sealed secret to
// `destination_prev:<id>` and records PreviousUntil, 24 hours later; the sender
// signs with both while PreviousUntil is in the future.

// EventWebhookType is the destination type of an event endpoint.
const EventWebhookType = "event_webhook"

// SecretRotationWindow is how long the previous secret keeps signing after a rotation.
const SecretRotationWindow = int64(24 * time.Hour)

// Bounds of an event endpoint.
const (
	EventSecretMin    = 16
	EventSecretMax    = 256
	EventNameMax      = 80
	EventEndpointsMax = 32
)

// EventWebhookEvents are the events an endpoint may subscribe to. It mirrors
// notify.SubscribableEvents (a test in internal/notify keeps the two equal; auth
// cannot import notify).
var EventWebhookEvents = []string{"incident.opened", "incident.acknowledged", "incident.resolved", "issue.new", "issue.regressed", "issue.resolved", "release.registered", "issue.reopened"}

// EventTestConfig is the stored `event_test:<endpoint>` setting: the latest test
// request of an endpoint. The producer of the named project turns a command it has
// not handled yet into one test.ping delivery to that endpoint.
type EventTestConfig struct {
	Project model.ID `json:"project"`
	// Command and At are set by the transition, never by the client.
	Command *model.ID `json:"command,omitempty"`
	At      int64     `json:"at_ns"`
}

// validEventName is a display name: 1..80 bytes of valid UTF-8, no control characters.
func validEventName(s string) bool {
	if len(s) == 0 || len(s) > EventNameMax || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func storedDestination(o model.ControlOrg, id model.ID) (DestinationConfig, bool, error) {
	raw, ok := o.Settings["destination:"+id.String()]
	if !ok {
		return DestinationConfig{}, false, nil
	}
	var cfg DestinationConfig
	if json.Unmarshal(raw, &cfg) != nil {
		return DestinationConfig{}, false, model.Fail(model.Corrupt)
	}
	return cfg, true, nil
}

// validateEventDestination checks a destination config of type event_webhook, and
// that a config of any other type carries nothing of an event endpoint. A
// destination never changes between event_webhook and another type: an event
// delivery stored for it must never reach a notification channel.
func validateEventDestination(o *model.ControlOrg, id model.ID, cfg DestinationConfig) error {
	stored, exists, err := storedDestination(*o, id)
	if err != nil {
		return err
	}
	if exists && (stored.Type == EventWebhookType) != (cfg.Type == EventWebhookType) {
		return model.Fail(model.Invalid)
	}
	if cfg.Type != EventWebhookType {
		if cfg.Name != "" || len(cfg.Events) != 0 || cfg.PreviousUntil != 0 || cfg.SecretRotated != 0 {
			return model.Fail(model.Invalid)
		}
		return nil
	}
	u, e := url.Parse(cfg.Endpoint)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || cfg.Address != "" {
		return model.Fail(model.Invalid)
	}
	if cfg.Name != "" && !validEventName(cfg.Name) || len(cfg.Events) == 0 || len(cfg.Events) > len(EventWebhookEvents) {
		return model.Fail(model.Invalid)
	}
	seen := map[string]bool{}
	for _, ev := range cfg.Events {
		known := false
		for _, k := range EventWebhookEvents {
			known = known || k == ev
		}
		if !known || seen[ev] {
			return model.Fail(model.Invalid)
		}
		seen[ev] = true
	}
	if !exists {
		n := 0
		for key, raw := range o.Settings {
			if !strings.HasPrefix(key, "destination:") {
				continue
			}
			var other DestinationConfig
			if json.Unmarshal(raw, &other) == nil && other.Type == EventWebhookType {
				n++
			}
		}
		if n >= EventEndpointsMax {
			return model.Fail(model.Quota)
		}
	}
	return nil
}

// finishEventDestination completes the stored config of an event endpoint after the
// version stamp: the rotation fields are the transition's, never the client's, and a
// new secret on an endpoint that has one rotates it (the old sealed secret moves to
// `destination_prev:<id>` and keeps signing until PreviousUntil). It must run before
// the new sealed secret is stored. A previous secret whose window has passed is
// dropped. An enabled endpoint needs a secret: a delivery without one could never
// be signed.
func finishEventDestination(o *model.ControlOrg, p AdminPayload, raw json.RawMessage, now int64) (json.RawMessage, error) {
	var cfg DestinationConfig
	if err := strictConfig(raw, &cfg); err != nil {
		return nil, err
	}
	if cfg.Type != EventWebhookType {
		return raw, nil
	}
	stored, _, err := storedDestination(*o, p.ID)
	if err != nil {
		return nil, err
	}
	key, prev := "destination:"+p.ID.String(), "destination_prev:"+p.ID.String()
	cfg.PreviousUntil, cfg.SecretRotated = stored.PreviousUntil, stored.SecretRotated
	had := o.Secrets[key] != ""
	if o.Secrets == nil {
		o.Secrets = map[string]string{}
	}
	if p.Secret != "" {
		if len(p.Secret) < EventSecretMin || len(p.Secret) > EventSecretMax {
			return nil, model.Fail(model.Invalid)
		}
		if had {
			o.Secrets[prev] = o.Secrets[key]
			cfg.PreviousUntil = now + SecretRotationWindow
		}
		cfg.SecretRotated = now
		had = true
	}
	if cfg.PreviousUntil != 0 && cfg.PreviousUntil <= now {
		delete(o.Secrets, prev)
		cfg.PreviousUntil = 0
	}
	if cfg.Enabled && !had {
		return nil, model.Fail(model.Invalid)
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return nil, model.Fail(model.Invalid)
	}
	return out, nil
}

// validateEventTest checks an `event_test` command: the endpoint (the payload ID) is
// an enabled event endpoint of the organization, the project is one of its projects,
// and nothing else is carried.
func validateEventTest(o *model.ControlOrg, p AdminPayload) error {
	var cfg EventTestConfig
	if err := strictConfig(p.Config, &cfg); err != nil {
		return err
	}
	if p.Secret != "" || cfg.Command != nil || cfg.At != 0 {
		return model.Fail(model.Invalid)
	}
	if _, ok := o.Projects[cfg.Project.String()]; !ok {
		return model.Fail(model.NotFound)
	}
	dest, exists, err := storedDestination(*o, p.ID)
	if err != nil {
		return err
	}
	if !exists || dest.Type != EventWebhookType {
		return model.Fail(model.NotFound)
	}
	if !dest.Enabled {
		return model.Fail(model.Invalid)
	}
	return nil
}

// stampEventTest is the stored form of an `event_test` command: the command ID and
// the audit time are the transition's.
func stampEventTest(raw json.RawMessage, command model.ID, now int64) (json.RawMessage, error) {
	var cfg EventTestConfig
	if err := strictConfig(raw, &cfg); err != nil {
		return nil, err
	}
	cfg.Command, cfg.At = &command, now
	out, err := json.Marshal(cfg)
	if err != nil {
		return nil, model.Fail(model.Invalid)
	}
	return out, nil
}
