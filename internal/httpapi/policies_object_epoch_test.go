// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// A policy write conflicts only when the setting it targets changed after the revision (organization epoch) the page read: a
// write to another project's setting in between is no reason to refuse it, a concurrent write of the SAME setting is.
func TestPolicyWriteConflictsOnlyOnTheSameSetting(t *testing.T) {
	e := newPolEnv(t)
	p1, p2 := model.NewID(), model.NewID()
	org := e.org("policy object epoch org", p1, p2)
	w1 := e.user(org, "w1-object@example.test")
	w2 := e.user(org, "w2-object@example.test")
	e.grant(org, w1, p1, true, auth.PolicyWrite)
	e.grant(org, w2, p2, true, auth.PolicyWrite)
	admin := e.user(org, "admin-object@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	hook := model.NewID()
	destination := func(enabled bool) map[string]any {
		return map[string]any{"kind": "destination", "destination": map[string]any{"id": hook.String(), "type": "webhook", "endpoint": endpointRaw, "enabled": enabled, "secret": secretValue}}
	}

	read := e.view(w1, org, p1).Revision
	// Another person changes project B's retention and notification policy, and an admin a destination, after the page read.
	if status, raw := e.post(w2, writeBody(org, p2, e.view(w2, org, p2).Revision, model.NewID(), retentionChange("logs", 10))); status != http.StatusOK {
		t.Fatalf("project B retention: %d %s", status, raw)
	}
	if status, raw := e.post(w2, writeBody(org, p2, e.view(w2, org, p2).Revision, model.NewID(), notificationChange(nil))); status != http.StatusOK {
		t.Fatalf("project B notification: %d %s", status, raw)
	}
	if status, raw := e.post(admin, writeBody(org, p1, e.view(admin, org, p1).Revision, model.NewID(), destination(true))); status != http.StatusOK {
		t.Fatalf("destination: %d %s", status, raw)
	}
	// A's save on the revision it read still commits: it touches none of those.
	if status, raw := e.post(w1, writeBody(org, p1, read, model.NewID(), retentionChange("metrics", 30))); status != http.StatusOK {
		t.Fatalf("project A retention after unrelated writes: %d %s", status, raw)
	}
	if status, raw := e.post(w1, writeBody(org, p1, read, model.NewID(), notificationChange(nil))); status != http.StatusOK {
		t.Fatalf("project A notification after unrelated writes: %d %s", status, raw)
	}

	// The same setting written since the read is a lost update: 409 and nothing changes.
	stale := e.view(w1, org, p1)
	for name, c := range map[string]struct {
		who    person
		change map[string]any
		first  map[string]any
	}{
		"retention":    {w1, retentionChange("metrics", 5), retentionChange("metrics", 60)},
		"notification": {w1, notificationChange(func(n map[string]any) { n["min_failures"] = 12 }), notificationChange(func(n map[string]any) { n["min_failures"] = 11 })},
		"destination":  {admin, destination(false), destination(true)},
	} {
		if status, raw := e.post(admin, writeBody(org, p1, e.view(admin, org, p1).Revision, model.NewID(), c.first)); status != http.StatusOK {
			t.Fatalf("%s: concurrent write: %d %s", name, status, raw)
		}
		before := e.view(w1, org, p1)
		if status, raw := e.post(c.who, writeBody(org, p1, stale.Revision, model.NewID(), c.change)); status != http.StatusConflict {
			t.Fatalf("%s: stale write of the same setting: %d %s, want 409", name, status, raw)
		}
		after := e.view(w1, org, p1)
		a, _ := json.Marshal(before)
		b, _ := json.Marshal(after)
		if string(a) != string(b) {
			t.Fatalf("%s: a refused write changed the policy:\n%s\n%s", name, a, b)
		}
	}
}
