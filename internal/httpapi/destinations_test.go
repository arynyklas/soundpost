// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

func (e *polEnv) postDestinations(who person, body any) (int, []byte) {
	e.t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/destinations", bytes.NewReader(raw))
	req.Header.Set("Cookie", "__Host-soundpost="+who.Session.Token)
	req.Header.Set("X-CSRF-Token", who.Session.CSRF)
	req.Header.Set("Origin", e.srv.URL)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func saveBody(org, project, command model.ID, expected uint64, reason string, dest map[string]any) map[string]any {
	return map[string]any{"org": org.String(), "project_id": project.String(), "operation": "save", "command_id": command.String(),
		"expected_version": decimalString(expected), "reason": reason, "destination": dest}
}

func decimalString(v uint64) string { return strconv.FormatUint(v, 10) }

func (e *polEnv) storedDestination(org, id model.ID) (auth.DestinationConfig, bool, bool) {
	e.t.Helper()
	var cfg auth.DestinationConfig
	var found, sealed bool
	if err := e.app.Control.View(e.ctx, func(st model.ControlState) error {
		o := st.Orgs[org.String()]
		raw, ok := o.Settings["destination:"+id.String()]
		if !ok {
			return nil
		}
		found = true
		sealed = o.Secrets["destination:"+id.String()] != ""
		return json.Unmarshal(raw, &cfg)
	}); err != nil {
		e.t.Fatal(err)
	}
	return cfg, found, sealed
}

// SaveDestination over the destination route: an administrator creates a
// destination (version 0 -> 1), changes it based on the version it read (-> 2,
// the endpoint it never saw stays), a stale version loses with a conflict, a
// replayed command commits once, each commit is audited, and no answer carries
// the endpoint path or the secret.
func TestDestinationSaveIsVersionedAuditedAndRedacted(t *testing.T) {
	e := newPolEnv(t)
	p1 := model.NewID()
	org := e.org("destination save org", p1)
	admin := e.user(org, "admin-ds@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	hook := model.NewID()
	webhook := func(enabled bool, secret string) map[string]any {
		return map[string]any{"id": hook.String(), "type": "webhook", "endpoint": endpointRaw, "enabled": enabled, "secret": secret}
	}
	first := model.NewID()
	status, raw := e.postDestinations(admin, saveBody(org, p1, first, 0, "create the pager hook", webhook(true, secretValue)))
	if status != http.StatusOK {
		t.Fatalf("create: %d %s", status, raw)
	}
	for _, leaked := range []string{"TOKEN-9f3a2c", "SECRETQ", secretValue, "/notify"} {
		if strings.Contains(string(raw), leaked) {
			t.Fatalf("the answer leaks %q: %s", leaked, raw)
		}
	}
	var saved httpapi.DestinationSaveAnswer
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if v := saved.Destination; v.ID != hook || v.Channel != notify.ChannelWebhook || v.Display != "hooks.example.test" || !v.HasSecret || v.Enabled == nil || !*v.Enabled || v.Version != 1 || saved.State != httpapi.ActionCommitted {
		t.Fatalf("created view: %+v", saved)
	}
	if cfg, found, sealed := e.storedDestination(org, hook); !found || !sealed || cfg.Revision != 1 || cfg.Endpoint != endpointRaw {
		t.Fatalf("stored: %+v found=%v sealed=%v", cfg, found, sealed)
	}

	// Creating it again at version 0 is a conflict: the destination exists.
	if status, raw = e.postDestinations(admin, saveBody(org, p1, model.NewID(), 0, "again", webhook(true, ""))); status != http.StatusConflict {
		t.Fatalf("create over an existing destination: %d %s", status, raw)
	}
	// A change from the version it read; the endpoint is left out and stays.
	second := model.NewID()
	disable := map[string]any{"id": hook.String(), "enabled": false}
	if status, raw = e.postDestinations(admin, saveBody(org, p1, second, 1, "pause while the receiver moves", disable)); status != http.StatusOK {
		t.Fatalf("disable: %d %s", status, raw)
	}
	var disabled httpapi.DestinationSaveAnswer
	if err := json.Unmarshal(raw, &disabled); err != nil || disabled.Destination.Version != 2 || disabled.Destination.Enabled == nil || *disabled.Destination.Enabled || !disabled.Destination.HasSecret {
		t.Fatalf("disabled view: %v %+v", err, disabled)
	}
	if cfg, _, sealed := e.storedDestination(org, hook); cfg.Endpoint != endpointRaw || cfg.Enabled || cfg.Revision != 2 || !sealed {
		t.Fatalf("stored after disable: %+v sealed=%v", cfg, sealed)
	}
	// A stale version loses; nothing changes.
	if status, raw = e.postDestinations(admin, saveBody(org, p1, model.NewID(), 1, "stale", webhook(true, ""))); status != http.StatusConflict {
		t.Fatalf("stale version: %d %s", status, raw)
	}
	if cfg, _, _ := e.storedDestination(org, hook); cfg.Enabled || cfg.Revision != 2 {
		t.Fatalf("a refused save changed the destination: %+v", cfg)
	}
	// Replaying the command that created it changes nothing.
	if status, raw = e.postDestinations(admin, saveBody(org, p1, first, 0, "create the pager hook", webhook(true, secretValue))); status != http.StatusOK {
		t.Fatalf("replay: %d %s", status, raw)
	}
	if cfg, _, _ := e.storedDestination(org, hook); cfg.Revision != 2 || cfg.Enabled {
		t.Fatalf("a replay committed again: %+v", cfg)
	}
	audits := e.audits(org, "destination")
	if len(audits) != 2 || audits[0].Principal != admin.ID || audits[0].Reason != "create the pager hook" || audits[1].Reason != "pause while the receiver moves" {
		t.Fatalf("audit: %+v", audits)
	}
	// The list shows the redacted destination with its version.
	status, raw = e.postDestinations(admin, map[string]any{"org": org.String(), "project_id": p1.String(), "operation": "list"})
	var list httpapi.DestinationListAnswer
	if err := json.Unmarshal(raw, &list); status != http.StatusOK || err != nil || len(list.Destinations) != 1 || list.Destinations[0].Version != 2 || strings.Contains(string(raw), "TOKEN-9f3a2c") {
		t.Fatalf("list: %d %v %s", status, err, raw)
	}
}

// Who may save and what is refused before anything commits: a policy.write
// holder is refused (a destination routes every project of the organization),
// a reader gets the one denial, and a destination that could never be
// delivered to, a missing version, reason or command are not committed.
func TestDestinationSaveRefusalsCommitNothing(t *testing.T) {
	e := newPolEnv(t)
	p1 := model.NewID()
	org := e.org("destination refusal org", p1)
	admin := e.user(org, "admin-dr@example.test")
	writer := e.user(org, "writer-dr@example.test")
	reader := e.user(org, "reader-dr@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	e.grant(org, writer, p1, true, auth.PolicyWrite)
	e.grant(org, reader, p1, true, auth.Read)
	id := model.NewID()
	hook := map[string]any{"id": id.String(), "type": "webhook", "endpoint": "https://hooks.example.test/x", "enabled": true}
	if status, raw := e.postDestinations(writer, saveBody(org, p1, model.NewID(), 0, "writer", hook)); status != http.StatusForbidden {
		t.Fatalf("policy.write holder: %d %s", status, raw)
	}
	if status, raw := e.postDestinations(reader, saveBody(org, p1, model.NewID(), 0, "reader", hook)); status != http.StatusNotFound {
		t.Fatalf("reader: %d %s", status, raw)
	}
	bad := map[string]struct {
		body map[string]any
		want int
	}{
		"plain http":          {saveBody(org, p1, model.NewID(), 0, "r", map[string]any{"id": id.String(), "type": "webhook", "endpoint": "http://hooks.example.test/x", "enabled": true}), http.StatusBadRequest},
		"query in the target": {saveBody(org, p1, model.NewID(), 0, "r", map[string]any{"id": id.String(), "type": "webhook", "endpoint": "https://hooks.example.test/x?token=1", "enabled": true}), http.StatusBadRequest},
		"address on webhook":  {saveBody(org, p1, model.NewID(), 0, "r", map[string]any{"id": id.String(), "type": "webhook", "endpoint": "https://hooks.example.test/x", "address": "a@example.test", "enabled": true}), http.StatusBadRequest},
		"bad recipient":       {saveBody(org, p1, model.NewID(), 0, "r", map[string]any{"id": id.String(), "type": "smtp", "address": "not an address", "enabled": true}), http.StatusBadRequest},
		"unknown channel":     {saveBody(org, p1, model.NewID(), 0, "r", map[string]any{"id": id.String(), "type": "sms", "address": "123", "enabled": true}), http.StatusBadRequest},
		"no reason":           {saveBody(org, p1, model.NewID(), 0, "", hook), http.StatusBadRequest},
		"no command":          {saveBody(org, p1, model.ID{}, 0, "r", hook), http.StatusBadRequest},
		"no version":          {map[string]any{"org": org.String(), "project_id": p1.String(), "operation": "save", "command_id": model.NewID().String(), "reason": "r", "destination": hook}, http.StatusBadRequest},
		"list with a change":  {map[string]any{"org": org.String(), "project_id": p1.String(), "operation": "list", "destination": hook}, http.StatusBadRequest},
	}
	for name, c := range bad {
		if status, raw := e.postDestinations(admin, c.body); status != c.want {
			t.Errorf("%s: %d %s", name, status, raw)
		}
	}
	if _, found, _ := e.storedDestination(org, id); found {
		t.Fatal("a refused save committed a destination")
	}
	if got := e.audits(org, "destination"); len(got) != 0 {
		t.Fatalf("refused saves were audited as commits: %+v", got)
	}
}
