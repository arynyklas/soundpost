// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
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

	// An incomplete write is refused after the scope check, and a read carries no write fields.
	status, raw := e.post(writer, policyBody(org, p1, "write"))
	if status != http.StatusBadRequest {
		t.Fatalf("write without a change: %d %s", status, raw)
	}
	readWithChange := policyBody(org, p1, "read")
	readWithChange["reason"] = "x"
	if status, raw = e.post(writer, readWithChange); status != http.StatusBadRequest {
		t.Fatalf("read with write fields: %d %s", status, raw)
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

// writeBody is a complete write request.
func writeBody(org, project model.ID, revision model.Revision, command model.ID, change map[string]any) map[string]any {
	return map[string]any{"org": org.String(), "project_id": project.String(), "operation": "write", "command_id": command.String(), "expected_revision": revision, "reason": "policies e2e", "change": change}
}

func retentionChange(signal string, days uint32) map[string]any {
	return map[string]any{"kind": "retention", "retention": map[string]any{"signal": signal, "days": days}}
}

func notificationChange(mut func(map[string]any)) map[string]any {
	n := map[string]any{"min_operations": 30, "min_failures": 6, "rate_basis_points": 700, "regression_min": 4, "critical_codes": []string{"payment_failed", "auth_down", "auth_down"},
		"first_reminder_ns": "600000000000", "reminder_every_ns": "1800000000000", "max_suppression_ns": "86400000000000", "default_zone": "Asia/Almaty"}
	if mut != nil {
		mut(n)
	}
	return map[string]any{"kind": "notification_policy", "notification": n}
}

func (e *polEnv) view(who person, org, project model.ID) httpapi.PolicyView {
	e.t.Helper()
	status, raw := e.post(who, policyBody(org, project, "read"))
	if status != http.StatusOK {
		e.t.Fatalf("read: %d %s", status, raw)
	}
	var v httpapi.PolicyView
	if err := json.Unmarshal(raw, &v); err != nil {
		e.t.Fatal(err)
	}
	return v
}

func (e *polEnv) audits(org model.ID, action string) (out []model.ControlAudit) {
	e.t.Helper()
	if err := e.app.Control.View(e.ctx, func(st model.ControlState) error {
		for _, a := range st.Audits {
			if a.Org == org.String() && a.Action == action {
				out = append(out, a)
			}
		}
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
	return out
}

// A policy.write holder changes its project's retention and notification policy
// through the audited command path: the answer is the committed settings, the
// audit names the person, a stale revision loses, a replayed command commits
// once, and the notification worker's routing adopts the written policy as a
// newer revision.
func TestPolicyWriteCommitsAuditedRetentionAndNotificationPolicy(t *testing.T) {
	e := newPolEnv(t)
	p1, p2 := model.NewID(), model.NewID()
	org := e.org("policy write org", p1, p2)
	writer := e.user(org, "writer-pw@example.test")
	e.grant(org, writer, p1, true, auth.PolicyWrite)
	hook := model.NewID()
	e.cmd(org, "destination", auth.AdminPayload{ID: hook, Config: json.RawMessage(`{"type":"webhook","endpoint":"` + endpointRaw + `","enabled":true}`), Secret: secretValue})
	// A legacy retention setting written by the admin route under a random ID.
	e.cmd(org, "retention", auth.AdminPayload{ID: model.NewID(), Config: json.RawMessage(`{"project_id":"` + p1.String() + `","signal":"metrics","days":14}`)})

	v := e.view(writer, org, p1)
	if v.Notification.Source != "default" || v.Notification.Revision != 1 || v.ManageDestinations {
		t.Fatalf("before: %+v", v)
	}
	// A login elsewhere moves the control revision, not the organization's policy epoch: it is no reason to refuse this save.
	if _, err := e.app.Auth.Login(e.ctx, "writer-pw@example.test", "isolation reader password", ""); err != nil {
		t.Fatal(err)
	}
	command := model.NewID()
	status, raw := e.post(writer, writeBody(org, p1, v.Revision, command, retentionChange("metrics", 30)))
	if status != http.StatusOK {
		t.Fatalf("retention write: %d %s", status, raw)
	}
	var answer httpapi.PolicyWriteAnswer
	if err := json.Unmarshal(raw, &answer); err != nil || answer.State != httpapi.ActionCommitted || answer.Policy.Revision != v.Revision+1 || answer.Revision == 0 {
		t.Fatalf("answer: %v %s", err, raw)
	}
	if len(answer.Policy.Retention) != 1 || answer.Policy.Retention[0].Signal != "metrics" || answer.Policy.Retention[0].Days != 30 {
		t.Fatalf("the committed retention is the written one, not the older setting: %+v", answer.Policy.Retention)
	}
	for _, leaked := range []string{secretValue, "TOKEN-9f3a2c", "SECRETQ"} {
		if strings.Contains(string(raw), leaked) {
			t.Fatalf("a write answer leaks %q: %s", leaked, raw)
		}
	}
	audits := e.audits(org, "retention")
	last := audits[len(audits)-1]
	if last.Principal != writer.ID || last.Reason != "policies e2e" || !slices.Contains(last.Targets, p1) || last.Outcome != model.AuditAllowed {
		t.Fatalf("audit of the write: %+v", last)
	}

	// The same command again commits nothing new.
	before := len(e.audits(org, "retention"))
	if status, raw = e.post(writer, writeBody(org, p1, v.Revision, command, retentionChange("metrics", 30))); status != http.StatusOK {
		t.Fatalf("replay: %d %s", status, raw)
	}
	if after := len(e.audits(org, "retention")); after != before {
		t.Fatalf("a replayed command was committed twice: %d -> %d audits", before, after)
	}
	// A second signal is its own setting; the first is unchanged.
	now := e.view(writer, org, p1)
	if status, raw = e.post(writer, writeBody(org, p1, now.Revision, model.NewID(), retentionChange("logs", 90))); status != http.StatusOK {
		t.Fatalf("second signal: %d %s", status, raw)
	}
	got := e.view(writer, org, p1).Retention
	if len(got) != 2 || got[0] != (httpapi.RetentionView{Signal: "logs", Days: 90}) || got[1] != (httpapi.RetentionView{Signal: "metrics", Days: 30}) {
		t.Fatalf("two signals: %+v", got)
	}
	// A write based on an older revision loses and changes nothing.
	if status, raw = e.post(writer, writeBody(org, p1, v.Revision, model.NewID(), retentionChange("logs", 7))); status != http.StatusConflict {
		t.Fatalf("stale revision: %d %s", status, raw)
	}
	if got = e.view(writer, org, p1).Retention; got[0].Days != 90 {
		t.Fatalf("a refused write changed retention: %+v", got)
	}
	// Nothing outside the vocabulary is accepted, and nothing is changed by it.
	cur := e.view(writer, org, p1)
	for name, change := range map[string]map[string]any{
		"zero days":      retentionChange("logs", 0),
		"too many days":  retentionChange("logs", 3651),
		"unknown signal": retentionChange("secrets", 5),
		"no change kind": {"kind": "retention"},
		"two members":    {"kind": "retention", "retention": map[string]any{"signal": "logs", "days": 5}, "notification": notificationChange(nil)["notification"]},
	} {
		if status, raw = e.post(writer, writeBody(org, p1, cur.Revision, model.NewID(), change)); status != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
	}
	noReason := writeBody(org, p1, cur.Revision, model.NewID(), retentionChange("logs", 5))
	delete(noReason, "reason")
	if status, raw = e.post(writer, noReason); status != http.StatusBadRequest {
		t.Fatalf("no reason: %d %s", status, raw)
	}
	if after := e.view(writer, org, p1); after.Revision != cur.Revision {
		t.Fatalf("refused writes moved the control revision %d -> %d", cur.Revision, after.Revision)
	}

	// The notification policy: a new revision, normalized, adopted by the worker's routing.
	if status, raw = e.post(writer, writeBody(org, p1, cur.Revision, model.NewID(), notificationChange(nil))); status != http.StatusOK {
		t.Fatalf("notification write: %d %s", status, raw)
	}
	n := e.view(writer, org, p1).Notification
	if n.Source != "project" || n.Revision != 2 || n.MinOperations != 30 || n.MinFailures != 6 || n.RateBasisPoints != 700 || n.RegressionMin != 4 || n.FirstReminder != "600000000000" ||
		n.DefaultZone != "Asia/Almaty" || !slices.Equal(n.CriticalCodes, []string{"auth_down", "payment_failed"}) {
		t.Fatalf("notification policy: %+v", n)
	}
	admin, err := e.app.Auth.Authorize(e.ctx, e.actor.Cred, org, []model.ID{p1}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	binding, found, err := e.app.OrgRouting().Routing(e.ctx, admin, p1)
	if err != nil || !found || binding.Revision != 2 || binding.Config.MinOperations != 30 || binding.Config.MinFailures != 6 || binding.Config.RateBasisPoints != 700 ||
		binding.Config.FirstReminder != 600_000_000_000 || binding.Config.DefaultZone != "Asia/Almaty" || !slices.Equal(binding.Config.CriticalCodes, []string{"auth_down", "payment_failed"}) {
		t.Fatalf("routing did not adopt the written policy: %v %v %+v", err, found, binding)
	}
	other, _, err := e.app.OrgRouting().Routing(e.ctx, adminScope(t, e, org, p2), p2)
	if err != nil || other.Revision != 1 || other.Config.MinOperations != 20 {
		t.Fatalf("another project's policy changed: %v %+v", err, other)
	}
	// Rewriting the policy is the next revision.
	cur = e.view(writer, org, p1)
	if status, raw = e.post(writer, writeBody(org, p1, cur.Revision, model.NewID(), notificationChange(func(n map[string]any) { n["min_failures"] = 9 }))); status != http.StatusOK {
		t.Fatalf("second notification write: %d %s", status, raw)
	}
	if n = e.view(writer, org, p1).Notification; n.Revision != 3 || n.MinFailures != 9 {
		t.Fatalf("second revision: %+v", n)
	}
	// A policy the engine would refuse is refused before it is committed.
	cur = e.view(writer, org, p1)
	for name, mut := range map[string]func(map[string]any){
		"zero rate":         func(n map[string]any) { n["rate_basis_points"] = 0 },
		"rate over 100%":    func(n map[string]any) { n["rate_basis_points"] = 10001 },
		"zero operations":   func(n map[string]any) { n["min_operations"] = 0 },
		"unsafe code":       func(n map[string]any) { n["critical_codes"] = []string{"has space"} },
		"unknown zone":      func(n map[string]any) { n["default_zone"] = "Mars/Olympus" },
		"suppression > 90d": func(n map[string]any) { n["max_suppression_ns"] = "7776000000000001" },
		"reminder zero":     func(n map[string]any) { n["first_reminder_ns"] = "0" },
		"duration not int":  func(n map[string]any) { n["reminder_every_ns"] = "1.5e9" },
	} {
		if status, raw = e.post(writer, writeBody(org, p1, cur.Revision, model.NewID(), notificationChange(mut))); status != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
	}
	if after := e.view(writer, org, p1); after.Revision != cur.Revision || after.Notification.Revision != 3 {
		t.Fatalf("refused policies were committed: %+v", after.Notification)
	}
}

func adminScope(t *testing.T, e *polEnv, org, project model.ID) auth.Scope {
	t.Helper()
	scope, err := e.app.Auth.Authorize(e.ctx, e.actor.Cred, org, []model.ID{project}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

// Who may write: administrators and policy.write holders, for their own project; a
// destination routes the whole organization so it takes an administrator; and a
// grant revoked between the scope check and the commit refuses the commit.
func TestPolicyWriteAuthorizationAndWriteOnlySecrets(t *testing.T) {
	e := newPolEnv(t)
	p1, p2 := model.NewID(), model.NewID()
	org := e.org("policy authz org", p1, p2)
	admin := e.user(org, "admin-pa@example.test")
	writer := e.user(org, "writer-pa@example.test")
	reader := e.user(org, "reader-pa@example.test")
	rules := e.user(org, "rules-pa@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	e.grant(org, writer, p1, true, auth.PolicyWrite)
	e.grant(org, reader, p1, true, auth.Read)
	e.grant(org, rules, p1, true, auth.RulesWrite)

	// Not the grant: the one denial, and nothing is committed.
	start := e.view(writer, org, p1)
	var baseline string
	for name, c := range map[string]func() (int, []byte){
		"reader": func() (int, []byte) {
			return e.post(reader, writeBody(org, p1, start.Revision, model.NewID(), retentionChange("logs", 5)))
		},
		"rules.write": func() (int, []byte) {
			return e.post(rules, writeBody(org, p1, start.Revision, model.NewID(), retentionChange("logs", 5)))
		},
		"other project": func() (int, []byte) {
			return e.post(writer, writeBody(org, p2, start.Revision, model.NewID(), retentionChange("logs", 5)))
		},
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
	if after := e.view(writer, org, p1); after.Revision != start.Revision || len(after.Retention) != 0 {
		t.Fatalf("a denied write changed state: %+v", after)
	}

	// A destination takes an administrator; the secret is never returned.
	hook := model.NewID()
	destination := func(secret string, enabled bool) map[string]any {
		return map[string]any{"kind": "destination", "destination": map[string]any{"id": hook.String(), "type": "webhook", "endpoint": endpointRaw, "enabled": enabled, "secret": secret}}
	}
	if status, raw := e.post(writer, writeBody(org, p1, start.Revision, model.NewID(), destination(secretValue, true))); status != http.StatusForbidden {
		t.Fatalf("destination by a policy.write holder: %d %s", status, raw)
	}
	adminView := e.view(admin, org, p1)
	if !adminView.ManageDestinations {
		t.Fatalf("an administrator manages destinations: %+v", adminView)
	}
	status, raw := e.post(admin, writeBody(org, p1, adminView.Revision, model.NewID(), destination(secretValue, true)))
	if status != http.StatusOK {
		t.Fatalf("destination by an administrator: %d %s", status, raw)
	}
	var answer httpapi.PolicyWriteAnswer
	if err := json.Unmarshal(raw, &answer); err != nil || len(answer.Policy.Destinations) != 1 || !answer.Policy.Destinations[0].HasSecret || answer.Policy.Destinations[0].EndpointHost != "hooks.example.test" {
		t.Fatalf("destination answer: %v %s", err, raw)
	}
	// Replacing it without a secret keeps the sealed one; the secret is in no read or audit.
	cur := e.view(admin, org, p1)
	if status, raw = e.post(admin, writeBody(org, p1, cur.Revision, model.NewID(), destination("", false))); status != http.StatusOK {
		t.Fatalf("disable: %d %s", status, raw)
	}
	for _, who := range []person{admin, writer} {
		status, raw = e.post(who, policyBody(org, p1, "read"))
		if status != http.StatusOK || strings.Contains(string(raw), secretValue) || strings.Contains(string(raw), "TOKEN-9f3a2c") {
			t.Fatalf("read after the write: %d %s", status, raw)
		}
		var v httpapi.PolicyView
		if err := json.Unmarshal(raw, &v); err != nil || len(v.Destinations) != 1 || v.Destinations[0].Enabled || !v.Destinations[0].HasSecret {
			t.Fatalf("destination after disable: %v %s", err, raw)
		}
	}
	// The page never receives the endpoint path, so an enable names only the destination;
	// the committed endpoint (with its token path) and the sealed secret stay as they were.
	partial := func(id model.ID, d map[string]any) (int, []byte) {
		d["id"] = id.String()
		return e.post(admin, writeBody(org, p1, e.view(admin, org, p1).Revision, model.NewID(), map[string]any{"kind": "destination", "destination": d}))
	}
	if status, raw = partial(hook, map[string]any{"enabled": true}); status != http.StatusOK {
		t.Fatalf("partial enable: %d %s", status, raw)
	}
	if err := e.app.Control.View(e.ctx, func(st model.ControlState) error {
		var cfg auth.DestinationConfig
		if err := json.Unmarshal(st.Orgs[org.String()].Settings["destination:"+hook.String()], &cfg); err != nil || cfg.Endpoint != endpointRaw || !cfg.Enabled || cfg.Type != "webhook" {
			t.Fatalf("a partial change lost the committed endpoint or type: %v %+v", err, cfg)
		}
		if st.Orgs[org.String()].Secrets["destination:"+hook.String()] == "" {
			t.Fatalf("a partial change dropped the sealed secret")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if status, raw = partial(hook, map[string]any{"enabled": true, "type": "telegram"}); status != http.StatusBadRequest {
		t.Fatalf("a destination's type is fixed: %d %s", status, raw)
	}
	if status, raw = partial(model.NewID(), map[string]any{"enabled": true}); status != http.StatusBadRequest {
		t.Fatalf("a new destination must be given whole: %d %s", status, raw)
	}
	if err := e.app.Control.View(e.ctx, func(st model.ControlState) error {
		raw, _ := json.Marshal(st.Audits)
		if strings.Contains(string(raw), secretValue) {
			t.Fatalf("a secret reached the audit log")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// An administrator writing for a project with no grant of its own still writes it.
	if status, raw = e.post(admin, writeBody(org, p2, e.view(admin, org, p2).Revision, model.NewID(), retentionChange("traces", 11))); status != http.StatusOK {
		t.Fatalf("administrator retention write: %d %s", status, raw)
	}

	// The scope the route derived is checked again where the command commits: a grant
	// revoked after the scope was derived refuses the write.
	scope, err := e.app.Auth.AuthorizeWrite(e.ctx, writer.Cred, org, p1, auth.PolicyWrite)
	if err != nil {
		t.Fatal(err)
	}
	var rev model.Revision
	_ = e.app.Control.View(e.ctx, func(st model.ControlState) error { rev = model.Revision(st.Orgs[org.String()].Epoch); return nil })
	// The command path is narrow: no other admin kind (a policy.write holder must not grant
	// itself rights), no other project's settings, and no destination, under this scope.
	attempt := func(kind string, id model.ID, project model.ID, secret, config string, perms ...string) error {
		raw, _ := json.Marshal(auth.AdminPayload{ID: id, UserID: writer.ID, ProjectID: project, Permissions: perms, Enabled: true, Secret: secret, Reason: "narrow", Config: json.RawMessage(config)})
		_, err := e.app.Auth.PolicyCommand(e.ctx, writer.Cred, scope, p1, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: org, Kind: kind, Payload: raw})
		return err
	}
	notification := func(project model.ID) string {
		return `{"project_id":"` + project.String() + `","min_operations":30,"min_failures":6,"rate_basis_points":700,"regression_min":4,"critical_codes":[],"first_reminder_ns":1,"reminder_every_ns":1,"max_suppression_ns":1,"default_zone":""}`
	}
	for name, c := range map[string]struct {
		err  error
		want model.Code
	}{
		"grant":                   {attempt("grant", model.ID{}, p1, "", "", "issues.write", "policy.write"), model.Invalid},
		"org_admin":               {attempt("org_admin", model.ID{}, p1, "", ""), model.Invalid},
		"membership":              {attempt("membership", model.ID{}, p1, "", ""), model.Invalid},
		"retention of another":    {attempt("retention", model.NewID(), p1, "", `{"project_id":"`+p2.String()+`","signal":"logs","days":3}`), model.NotFound},
		"policy of another":       {attempt("notification_policy", p2, p1, "", notification(p2)), model.NotFound},
		"policy naming another":   {attempt("notification_policy", p1, p1, "", notification(p2)), model.Invalid},
		"policy with a secret":    {attempt("notification_policy", p1, p1, "x", notification(p1)), model.Invalid},
		"destination by a writer": {attempt("destination", model.NewID(), p1, "", `{"type":"smtp","address":"a@example.test","enabled":true}`), model.Forbidden},
	} {
		if faultCode(c.err) != c.want {
			t.Fatalf("%s: %v, want %s", name, c.err, c.want)
		}
	}
	pinned, _ := json.Marshal(auth.AdminPayload{ID: model.NewID(), ProjectID: p2, Reason: "narrow", Config: json.RawMessage(`{"project_id":"` + p2.String() + `","signal":"logs","days":3}`)})
	if _, err = e.app.Auth.PolicyCommand(e.ctx, writer.Cred, scope, p2, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: org, Kind: "retention", Payload: pinned}); faultCode(err) != model.Forbidden {
		t.Fatalf("a scope for one project wrote another: %v", err)
	}
	if err = e.app.Control.View(e.ctx, func(st model.ControlState) error {
		if model.Revision(st.Orgs[org.String()].Epoch) != rev || st.Orgs[org.String()].Grants[writer.ID.String()+":"+p1.String()][0] != "policy.write" {
			t.Fatalf("a refused command changed state")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e.grant(org, writer, p1, false)
	_ = e.app.Control.View(e.ctx, func(st model.ControlState) error { rev = model.Revision(st.Orgs[org.String()].Epoch); return nil })
	payload, _ := json.Marshal(auth.AdminPayload{ID: model.NewID(), ProjectID: p1, Reason: "late", Config: json.RawMessage(`{"project_id":"` + p1.String() + `","signal":"logs","days":3}`)})
	_, err = e.app.Auth.PolicyCommand(e.ctx, writer.Cred, scope, p1, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: org, Kind: "retention", Payload: payload})
	if faultCode(err) != model.NotFound {
		t.Fatalf("a revoked grant committed a write: %v", err)
	}
	// The generic admin route has no such kind: only the policy path writes one.
	_, err = e.app.Auth.AdminCommand(e.ctx, e.actor.Cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: org, Kind: "notification_policy", Payload: payload})
	if faultCode(err) != model.Invalid {
		t.Fatalf("admin route accepted a notification_policy: %v", err)
	}
}
