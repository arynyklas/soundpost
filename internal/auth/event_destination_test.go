// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// These tests cover the event webhook endpoint as an administration object: a destination
// of type event_webhook with a subscription, a name and a rotating secret, and the
// `event_test` request (docs/operations/event-webhooks.md).

const (
	secretOne   = "FIRST-EVENT-SECRET-0123456789"
	secretTwo   = "SECOND-EVENT-SECRET-0123456789"
	secretThree = "THIRD-EVENT-SECRET-0123456789"
	secretFour  = "FOURTH-EVENT-SECRET-0123456789"
)

// try runs one admin command of the fixture organization and returns its error.
func (f *cacheFixture) try(kind string, p auth.AdminPayload) error {
	return f.tryIn(f.org, f.actor, kind, p, model.NewID())
}

func (f *cacheFixture) tryIn(org model.ID, who auth.Credential, kind string, p auth.AdminPayload, command model.ID) error {
	f.t.Helper()
	var revision model.Revision
	_ = f.store.View(f.ctx, func(st control.State) error { revision = st.Revision; return nil })
	p.Reason = "event endpoint regression"
	raw, _ := json.Marshal(p)
	_, err := f.service.AdminCommand(f.ctx, who, auth.AdminCommandRequest{CommandID: command, ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw})
	return err
}

// advanceFresh moves the clock and logs the owner in again: a credential is fresh for five
// minutes and a session lasts twelve hours, and an administration command needs a fresh one.
func (f *cacheFixture) advanceFresh(d time.Duration) {
	f.t.Helper()
	f.advance(d)
	login, err := f.service.Login(f.ctx, "cache-owner@example.test", "cache owner password 2026", "")
	if err != nil {
		f.t.Fatal(err)
	}
	if f.actor, err = f.service.Authenticate(f.ctx, login.Token); err != nil {
		f.t.Fatal(err)
	}
}

func eventConfig(t *testing.T, mutate func(*auth.DestinationConfig)) json.RawMessage {
	t.Helper()
	cfg := auth.DestinationConfig{Type: auth.EventWebhookType, Endpoint: "https://events.example.test/hook", Enabled: true, Name: "ops hook", Events: []string{"incident.opened", "issue.new"}}
	if mutate != nil {
		mutate(&cfg)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type stored struct {
	cfg        auth.DestinationConfig
	found      bool
	secret     string // the opened current secret ("" when none)
	previous   string // the opened previous secret ("" when none)
	hasPrev    bool
	settingRaw string
}

func (f *cacheFixture) endpoint(org, id model.ID) stored {
	f.t.Helper()
	var out stored
	if err := f.store.View(f.ctx, func(st control.State) error {
		o := st.Orgs[org.String()]
		raw, ok := o.Settings["destination:"+id.String()]
		if !ok {
			return nil
		}
		out.found, out.settingRaw = true, string(raw)
		if err := json.Unmarshal(raw, &out.cfg); err != nil {
			return err
		}
		if sealed := o.Secrets["destination:"+id.String()]; sealed != "" {
			plain, err := f.store.OpenSecret(sealed)
			if err != nil {
				return err
			}
			out.secret = plain
		}
		if sealed := o.Secrets["destination_prev:"+id.String()]; sealed != "" {
			plain, err := f.store.OpenSecret(sealed)
			if err != nil {
				return err
			}
			out.previous, out.hasPrev = plain, true
		}
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return out
}

func (f *cacheFixture) auditText() string {
	var out string
	_ = f.store.View(f.ctx, func(st control.State) error {
		raw, _ := json.Marshal(st.Audits)
		out = string(raw)
		return nil
	})
	return out
}

// Saving an endpoint: the first secret is stored sealed; a save without a secret keeps it and
// the rotation state; a new secret on an endpoint that has one ROTATES (the old sealed secret
// moves to its previous slot and keeps signing for 24 hours); the rotation times are the
// transition's, never the client's; an expired previous secret is dropped by the next save; a
// second rotation inside the window replaces the previous slot; and no secret is ever in an
// audit entry.
func TestEventEndpointSecretRotation(t *testing.T) {
	f := newCacheFixture(t)
	id := model.NewID()
	t0 := f.at()

	if err := f.try("destination", auth.AdminPayload{ID: id, Config: eventConfig(t, nil), Secret: secretOne}); err != nil {
		t.Fatal(err)
	}
	s := f.endpoint(f.org, id)
	if !s.found || s.cfg.Type != auth.EventWebhookType || s.cfg.Name != "ops hook" || len(s.cfg.Events) != 2 || s.cfg.Revision != 1 || s.secret != secretOne || s.hasPrev ||
		s.cfg.PreviousUntil != 0 || s.cfg.SecretRotated != t0.UnixNano() {
		t.Fatalf("first save: %+v", s)
	}
	if strings.Contains(s.settingRaw, secretOne) {
		t.Fatal("the secret is in the stored setting")
	}

	// A save without a secret keeps the secret and the rotation state.
	f.advanceFresh(time.Hour)
	if err := f.try("destination", auth.AdminPayload{ID: id, Config: eventConfig(t, func(c *auth.DestinationConfig) { c.Events = []string{"release.registered"} })}); err != nil {
		t.Fatal(err)
	}
	s = f.endpoint(f.org, id)
	if s.cfg.Revision != 2 || s.secret != secretOne || s.hasPrev || s.cfg.SecretRotated != t0.UnixNano() || len(s.cfg.Events) != 1 {
		t.Fatalf("edit without a secret: %+v", s)
	}

	// A new secret rotates; a client-sent rotation time is overwritten.
	f.advanceFresh(time.Hour)
	rotated := f.at()
	if err := f.try("destination", auth.AdminPayload{ID: id, Secret: secretTwo, Config: eventConfig(t, func(c *auth.DestinationConfig) { c.PreviousUntil, c.SecretRotated = 5, 7 })}); err != nil {
		t.Fatal(err)
	}
	s = f.endpoint(f.org, id)
	if s.secret != secretTwo || !s.hasPrev || s.previous != secretOne || s.cfg.PreviousUntil != rotated.Add(24*time.Hour).UnixNano() || s.cfg.SecretRotated != rotated.UnixNano() || s.cfg.Revision != 3 {
		t.Fatalf("rotation: %+v", s)
	}

	// A save inside the window without a secret keeps both.
	f.advanceFresh(time.Hour)
	if err := f.try("destination", auth.AdminPayload{ID: id, Config: eventConfig(t, func(c *auth.DestinationConfig) { c.PreviousUntil = 1 })}); err != nil {
		t.Fatal(err)
	}
	if s = f.endpoint(f.org, id); !s.hasPrev || s.previous != secretOne || s.cfg.PreviousUntil != rotated.Add(24*time.Hour).UnixNano() {
		t.Fatalf("a save inside the window: %+v", s)
	}

	// A second rotation inside the window replaces the previous slot.
	f.advanceFresh(time.Hour)
	again := f.at()
	if err := f.try("destination", auth.AdminPayload{ID: id, Secret: secretThree, Config: eventConfig(t, nil)}); err != nil {
		t.Fatal(err)
	}
	if s = f.endpoint(f.org, id); s.secret != secretThree || s.previous != secretTwo || s.cfg.PreviousUntil != again.Add(24*time.Hour).UnixNano() {
		t.Fatalf("second rotation: %+v", s)
	}

	// Past the window the next save drops the previous secret.
	f.advanceFresh(25 * time.Hour)
	if err := f.try("destination", auth.AdminPayload{ID: id, Config: eventConfig(t, nil)}); err != nil {
		t.Fatal(err)
	}
	if s = f.endpoint(f.org, id); s.hasPrev || s.cfg.PreviousUntil != 0 || s.secret != secretThree || s.cfg.SecretRotated != again.UnixNano() {
		t.Fatalf("after the window: %+v", s)
	}

	// A rotation past the window starts a fresh window.
	if err := f.try("destination", auth.AdminPayload{ID: id, Secret: secretFour, Config: eventConfig(t, nil)}); err != nil {
		t.Fatal(err)
	}
	if s = f.endpoint(f.org, id); s.previous != secretThree || s.secret != secretFour {
		t.Fatalf("rotation after expiry: %+v", s)
	}
	text := f.auditText()
	for _, secret := range []string{secretOne, secretTwo, secretThree, secretFour} {
		if strings.Contains(text, secret) {
			t.Fatalf("secret %q is in the audit log", secret)
		}
	}
	// The version compare-and-set still guards the endpoint.
	stale := model.Uint64(1)
	if err := f.try("destination", auth.AdminPayload{ID: id, ExpectedVersion: &stale, Config: eventConfig(t, nil)}); !isCode(err, model.Conflict) {
		t.Fatalf("a stale endpoint version: %v", err)
	}
}

func isCode(err error, code model.Code) bool {
	var fault *model.Fault
	return errors.As(err, &fault) && fault.Code == code
}

// What can be saved is exactly what can be delivered to: every invalid endpoint commits
// nothing.
func TestEventEndpointValidationCommitsNothing(t *testing.T) {
	f := newCacheFixture(t)
	good := func(mutate func(*auth.DestinationConfig)) json.RawMessage { return eventConfig(t, mutate) }
	existing := model.NewID()
	if err := f.try("destination", auth.AdminPayload{ID: existing, Config: good(nil), Secret: secretOne}); err != nil {
		t.Fatal(err)
	}
	notification := model.NewID()
	if err := f.try("destination", auth.AdminPayload{ID: notification, Config: json.RawMessage(`{"type":"webhook","endpoint":"https://hooks.example.test/n","enabled":true}`), Secret: secretOne}); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		id      model.ID
		payload auth.AdminPayload
	}{
		"no events":                        {model.NewID(), auth.AdminPayload{Config: good(func(c *auth.DestinationConfig) { c.Events = nil }), Secret: secretTwo}},
		"unknown event":                    {model.NewID(), auth.AdminPayload{Config: good(func(c *auth.DestinationConfig) { c.Events = []string{"incident.exploded"} }), Secret: secretTwo}},
		"test.ping is not subscribable":    {model.NewID(), auth.AdminPayload{Config: good(func(c *auth.DestinationConfig) { c.Events = []string{"test.ping"} }), Secret: secretTwo}},
		"duplicate event":                  {model.NewID(), auth.AdminPayload{Config: good(func(c *auth.DestinationConfig) { c.Events = []string{"issue.new", "issue.new"} }), Secret: secretTwo}},
		"plain http":                       {model.NewID(), auth.AdminPayload{Config: good(func(c *auth.DestinationConfig) { c.Endpoint = "http://events.example.test/h" }), Secret: secretTwo}},
		"query in the url":                 {model.NewID(), auth.AdminPayload{Config: good(func(c *auth.DestinationConfig) { c.Endpoint = "https://events.example.test/h?token=x" }), Secret: secretTwo}},
		"credentials in the url":           {model.NewID(), auth.AdminPayload{Config: good(func(c *auth.DestinationConfig) { c.Endpoint = "https://u:p@events.example.test/h" }), Secret: secretTwo}},
		"no url":                           {model.NewID(), auth.AdminPayload{Config: good(func(c *auth.DestinationConfig) { c.Endpoint = "" }), Secret: secretTwo}},
		"an address":                       {model.NewID(), auth.AdminPayload{Config: good(func(c *auth.DestinationConfig) { c.Address = "ops@example.test" }), Secret: secretTwo}},
		"a control character name":         {model.NewID(), auth.AdminPayload{Config: good(func(c *auth.DestinationConfig) { c.Name = "ops\nhook" }), Secret: secretTwo}},
		"a padded name":                    {model.NewID(), auth.AdminPayload{Config: good(func(c *auth.DestinationConfig) { c.Name = " ops" }), Secret: secretTwo}},
		"a long name":                      {model.NewID(), auth.AdminPayload{Config: good(func(c *auth.DestinationConfig) { c.Name = strings.Repeat("n", 81) }), Secret: secretTwo}},
		"a short secret":                   {model.NewID(), auth.AdminPayload{Config: good(nil), Secret: "short"}},
		"a long secret":                    {model.NewID(), auth.AdminPayload{Config: good(nil), Secret: strings.Repeat("s", 257)}},
		"enabled without a secret":         {model.NewID(), auth.AdminPayload{Config: good(nil)}},
		"an event endpoint made a webhook": {existing, auth.AdminPayload{Config: json.RawMessage(`{"type":"webhook","endpoint":"https://hooks.example.test/n","enabled":true}`)}},
		"a webhook made an event endpoint": {notification, auth.AdminPayload{Config: good(nil)}},
		"events on a webhook":              {model.NewID(), auth.AdminPayload{Config: json.RawMessage(`{"type":"webhook","endpoint":"https://hooks.example.test/n","enabled":true,"events":["issue.new"]}`), Secret: secretTwo}},
		"a name on smtp":                   {model.NewID(), auth.AdminPayload{Config: json.RawMessage(`{"type":"smtp","address":"ops@example.test","enabled":true,"name":"x"}`)}},
	} {
		before := f.snapshot()
		tc.payload.ID = tc.id
		if err := f.try("destination", tc.payload); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if after := f.snapshot(); after != before {
			t.Errorf("%s: a refused save changed the organization", name)
		}
	}
	// 32 endpoints per organization.
	for i := 0; len(f.eventEndpoints()) < auth.EventEndpointsMax; i++ {
		if err := f.try("destination", auth.AdminPayload{ID: model.NewID(), Config: good(nil), Secret: secretOne}); err != nil {
			t.Fatalf("endpoint %d: %v", i, err)
		}
	}
	err := f.try("destination", auth.AdminPayload{ID: model.NewID(), Config: good(nil), Secret: secretOne})
	if !isCode(err, model.Quota) {
		t.Fatalf("the 33rd endpoint: %v", err)
	}
	// An existing endpoint can still be saved at the bound.
	if err = f.try("destination", auth.AdminPayload{ID: existing, Config: good(func(c *auth.DestinationConfig) { c.Name = "renamed" })}); err != nil {
		t.Fatalf("a save of an existing endpoint at the bound: %v", err)
	}
}

// snapshot is the organization's settings and secrets as one string.
func (f *cacheFixture) snapshot() string {
	var out string
	_ = f.store.View(f.ctx, func(st control.State) error {
		o := st.Orgs[f.org.String()]
		a, _ := json.Marshal(o.Settings)
		b, _ := json.Marshal(o.Secrets)
		out = string(a) + string(b) + fmt.Sprint(len(st.Audits))
		return nil
	})
	return out
}

func (f *cacheFixture) eventEndpoints() []model.ID {
	var out []model.ID
	_ = f.store.View(f.ctx, func(st control.State) error {
		for key, raw := range st.Orgs[f.org.String()].Settings {
			if !strings.HasPrefix(key, "destination:") {
				continue
			}
			var cfg auth.DestinationConfig
			if json.Unmarshal(raw, &cfg) == nil && cfg.Type == auth.EventWebhookType {
				id, _ := model.ParseID(strings.TrimPrefix(key, "destination:"))
				out = append(out, id)
			}
		}
		return nil
	})
	return out
}

// An `event_test` request names an enabled event endpoint of the organization and a project
// of it; the stored request carries the command ID and the audit time, set by the transition
// and not by the client; a replay of the command writes nothing; and only an organization
// administrator can make one.
func TestEventTestRequest(t *testing.T) {
	f := newCacheFixture(t)
	id, disabled := model.NewID(), model.NewID()
	_ = f.at()
	if err := f.try("destination", auth.AdminPayload{ID: id, Config: eventConfig(t, nil), Secret: secretOne}); err != nil {
		t.Fatal(err)
	}
	if err := f.try("destination", auth.AdminPayload{ID: disabled, Config: eventConfig(t, func(c *auth.DestinationConfig) { c.Enabled = false }), Secret: secretOne}); err != nil {
		t.Fatal(err)
	}
	request := func(project model.ID) json.RawMessage {
		raw, _ := json.Marshal(auth.EventTestConfig{Project: project})
		return raw
	}
	read := func() (auth.EventTestConfig, bool) {
		var cfg auth.EventTestConfig
		var found bool
		_ = f.store.View(f.ctx, func(st control.State) error {
			raw, ok := st.Orgs[f.org.String()].Settings["event_test:"+id.String()]
			found = ok
			if ok {
				_ = json.Unmarshal(raw, &cfg)
			}
			return nil
		})
		return cfg, found
	}
	command := model.NewID()
	at := f.at()
	if err := f.tryIn(f.org, f.actor, "event_test", auth.AdminPayload{ID: id, Config: request(f.project)}, command); err != nil {
		t.Fatal(err)
	}
	cfg, found := read()
	if !found || cfg.Project != f.project || cfg.Command == nil || *cfg.Command != command || cfg.At != at.UnixNano() {
		t.Fatalf("stored request: %+v", cfg)
	}
	// A replay of the same command changes nothing, even later.
	f.advanceFresh(time.Hour)
	if err := f.tryIn(f.org, f.actor, "event_test", auth.AdminPayload{ID: id, Config: request(f.project)}, command); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if again, _ := read(); again.At != cfg.At || again.Command == nil || *again.Command != *cfg.Command || again.Project != cfg.Project {
		t.Fatalf("a replayed command rewrote the request: %+v", again)
	}
	// A new command is a new request.
	second := model.NewID()
	if err := f.tryIn(f.org, f.actor, "event_test", auth.AdminPayload{ID: id, Config: request(f.project)}, second); err != nil {
		t.Fatal(err)
	}
	if next, _ := read(); next.Command == nil || *next.Command != second || next.At != f.at().UnixNano() {
		t.Fatalf("second request: %+v", next)
	}
	for name, tc := range map[string]struct {
		payload auth.AdminPayload
		code    model.Code
	}{
		"an unknown endpoint": {auth.AdminPayload{ID: model.NewID(), Config: request(f.project)}, model.NotFound},
		"a disabled endpoint": {auth.AdminPayload{ID: disabled, Config: request(f.project)}, model.Invalid},
		"a project of no one": {auth.AdminPayload{ID: id, Config: request(model.NewID())}, model.NotFound},
		"a secret":            {auth.AdminPayload{ID: id, Config: request(f.project), Secret: secretTwo}, model.Invalid},
		"a client command":    {auth.AdminPayload{ID: id, Config: json.RawMessage(fmt.Sprintf(`{"project":%q,"command":%q}`, f.project.String(), model.NewID().String()))}, model.Invalid},
		"a client time":       {auth.AdminPayload{ID: id, Config: json.RawMessage(fmt.Sprintf(`{"project":%q,"at_ns":5}`, f.project.String()))}, model.Invalid},
		"an unknown member":   {auth.AdminPayload{ID: id, Config: json.RawMessage(fmt.Sprintf(`{"project":%q,"x":1}`, f.project.String()))}, model.Invalid},
	} {
		if err := f.try("event_test", tc.payload); !isCode(err, tc.code) {
			t.Errorf("%s: %v, want %s", name, err, tc.code)
		}
	}
	// A notification destination is not an event endpoint.
	hook := model.NewID()
	if err := f.try("destination", auth.AdminPayload{ID: hook, Config: json.RawMessage(`{"type":"webhook","endpoint":"https://hooks.example.test/n","enabled":true}`), Secret: secretOne}); err != nil {
		t.Fatal(err)
	}
	if err := f.try("event_test", auth.AdminPayload{ID: hook, Config: request(f.project)}); !isCode(err, model.NotFound) {
		t.Fatalf("a webhook destination: %v", err)
	}
	// A non-administrator can neither test nor save (the cross-organization case is covered
	// at the route, where the organization is a request selector).
	reader, _ := f.reader("event-reader@example.test", auth.Read)
	if err := f.tryIn(f.org, reader, "event_test", auth.AdminPayload{ID: id, Config: request(f.project)}, model.NewID()); err == nil {
		t.Fatal("a reader requested a test")
	}
	if err := f.tryIn(f.org, reader, "destination", auth.AdminPayload{ID: model.NewID(), Config: eventConfig(t, nil), Secret: secretOne}, model.NewID()); err == nil {
		t.Fatal("a reader saved an endpoint")
	}
}
