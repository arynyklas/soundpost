// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

const (
	secretValue = "SECRET-VALUE-q1-never-returned"
	endpointRaw = "https://hooks.example.test/notify/TOKEN-9f3a2c/SECRETQ"
)

// polEnv serves POST /api/v1/policies over the real control store and auth.
type polEnv struct {
	*isoEnv
	srv *httptest.Server
}

func newPolEnv(t *testing.T) *polEnv {
	t.Helper()
	e := &polEnv{isoEnv: newIsoEnv(t)}
	policies, err := httpapi.NewPolicies(e.app.Control)
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterPolicyRoutes(mux, e.app.Auth, policies)
	}).Handler)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *polEnv) post(who person, body any) (int, []byte) {
	e.t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/policies", bytes.NewReader(raw))
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

func policyBody(org, project model.ID, op string) map[string]any {
	return map[string]any{"org": org.String(), "project_id": project.String(), "operation": op}
}

// The policy read shows the notification policy, the destinations and the
// project's retention without a secret, an endpoint path or a token, to the
// policy.write grant and organization administration only.
func TestPoliciesReadShowsSettingsWithoutSecretsToPolicyWriteOnly(t *testing.T) {
	e := newPolEnv(t)
	p1, p2 := model.NewID(), model.NewID()
	org := e.org("policies org", p1, p2)
	admin := e.user(org, "admin-pol@example.test")
	writer := e.user(org, "writer-pol@example.test")
	reader := e.user(org, "reader-pol@example.test")
	rules := e.user(org, "rules-pol@example.test")
	incidentsOnly := e.user(org, "incidents-pol@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	e.grant(org, writer, p1, true, auth.PolicyWrite)
	e.grant(org, reader, p1, true, auth.Read)
	e.grant(org, rules, p1, true, auth.RulesWrite)
	e.grant(org, incidentsOnly, p1, true, auth.IncidentsWrite)
	hook, mail := model.NewID(), model.NewID()
	e.cmd(org, "destination", auth.AdminPayload{ID: hook, Config: json.RawMessage(`{"type":"webhook","endpoint":"` + endpointRaw + `","enabled":true}`), Secret: secretValue})
	e.cmd(org, "destination", auth.AdminPayload{ID: mail, Config: json.RawMessage(`{"type":"smtp","address":"ops@example.test","enabled":false}`)})
	e.cmd(org, "retention", auth.AdminPayload{ID: model.NewID(), Config: json.RawMessage(`{"project_id":"` + p1.String() + `","signal":"metrics","days":14}`)})
	e.cmd(org, "retention", auth.AdminPayload{ID: model.NewID(), Config: json.RawMessage(`{"project_id":"` + p2.String() + `","signal":"logs","days":30}`)})

	for name, who := range map[string]person{"administrator": admin, "policy.write holder": writer} {
		status, raw := e.post(who, policyBody(org, p1, "read"))
		if status != 200 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		for _, leaked := range []string{secretValue, "TOKEN-9f3a2c", "SECRETQ", "/notify", "sig="} {
			if strings.Contains(string(raw), leaked) {
				t.Fatalf("%s: the answer leaks %q: %s", name, leaked, raw)
			}
		}
		var v httpapi.PolicyView
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		if v.Notification.Source != "default" || v.Notification.MinOperations != 20 || v.Notification.MinFailures != 5 || v.Notification.RateBasisPoints != 500 || v.Notification.FirstReminder != "900000000000" {
			t.Fatalf("%s: notification policy: %+v", name, v.Notification)
		}
		if len(v.Destinations) != 2 {
			t.Fatalf("%s: destinations: %+v", name, v.Destinations)
		}
		for _, d := range v.Destinations {
			switch d.ID {
			case hook:
				if d.Type != "webhook" || d.EndpointHost != "hooks.example.test" || !d.Enabled || !d.HasSecret || d.Address != "" {
					t.Fatalf("%s: webhook destination: %+v", name, d)
				}
			case mail:
				if d.Type != "smtp" || d.Address != "ops@example.test" || d.Enabled || d.HasSecret || d.EndpointHost != "" {
					t.Fatalf("%s: smtp destination: %+v", name, d)
				}
			default:
				t.Fatalf("%s: unknown destination %+v", name, d)
			}
		}
		if len(v.Retention) != 1 || v.Retention[0].Signal != "metrics" || v.Retention[0].Days != 14 {
			t.Fatalf("%s: only this project's retention is shown: %+v", name, v.Retention)
		}
	}

	// Everyone else, and the project they cannot name, is the one denial.
	var baseline string
	for name, c := range map[string]func() (int, []byte){
		"read only":        func() (int, []byte) { return e.post(reader, policyBody(org, p1, "read")) },
		"rules.write":      func() (int, []byte) { return e.post(rules, policyBody(org, p1, "read")) },
		"incidents.write":  func() (int, []byte) { return e.post(incidentsOnly, policyBody(org, p1, "read")) },
		"other project":    func() (int, []byte) { return e.post(writer, policyBody(org, p2, "read")) },
		"missing project":  func() (int, []byte) { return e.post(writer, policyBody(org, model.NewID(), "read")) },
		"write by reader":  func() (int, []byte) { return e.post(reader, policyBody(org, p1, "write")) },
		"write by missing": func() (int, []byte) { return e.post(writer, policyBody(org, model.NewID(), "write")) },
	} {
		status, raw := c()
		if status != http.StatusNotFound {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		if got := denial(t, status, raw); baseline == "" {
			baseline = got
		} else if got != baseline {
			t.Fatalf("%s is distinguishable: %s vs %s", name, got, baseline)
		}
	}

	// A write is an explicit not_available answer; nothing changes.
	status, raw := e.post(writer, policyBody(org, p1, "write"))
	var answer httpapi.PolicyWriteAnswer
	if status != http.StatusNotImplemented || json.Unmarshal(raw, &answer) != nil || answer.State != httpapi.ActionNotAvailable || answer.Reason != httpapi.ReasonPolicyWriteNotBuilt {
		t.Fatalf("write: %d %s", status, raw)
	}
	// The body is closed: an unknown field and an unknown operation are refused.
	for name, body := range map[string]any{
		"unknown field":     map[string]any{"org": org.String(), "project_id": p1.String(), "operation": "read", "secret": "x"},
		"unknown operation": policyBody(org, p1, "delete"),
	} {
		if status, raw := e.post(writer, body); status != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
	}
	// Revocation applies at once.
	e.grant(org, writer, p1, false)
	if status, raw := e.post(writer, policyBody(org, p1, "read")); status != http.StatusNotFound {
		t.Fatalf("revoked grant: %d %s", status, raw)
	}
}
