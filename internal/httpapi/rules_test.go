// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/rules"
)

const rulesProfile = "promql-prometheus-3.13.5"

// ruleEnv serves POST /api/v1/rules over the real control store and auth.
type ruleEnv struct {
	*isoEnv
	srv      *httptest.Server
	policies *httpapi.Policies
}

func newRuleEnv(t *testing.T) *ruleEnv {
	t.Helper()
	e := &ruleEnv{isoEnv: newIsoEnv(t)}
	var err error
	if e.policies, err = httpapi.NewPolicies(e.app.Control); err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterPolicyRoutes(mux, e.app.Auth, e.policies)
	}).Handler)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *ruleEnv) post(who person, body any) (int, []byte) {
	e.t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/rules", bytes.NewReader(raw))
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

// featureSet is a feature set of the pinned profile, as the list advertises it.
func (e *ruleEnv) featureSet(who person, org, project model.ID) string {
	e.t.Helper()
	status, raw := e.post(who, map[string]any{"org": org.String(), "project_id": project.String(), "operation": "list"})
	var list httpapi.RuleListAnswer
	if err := json.Unmarshal(raw, &list); status != http.StatusOK || err != nil {
		e.t.Fatalf("list: %d %v %s", status, err, raw)
	}
	for _, p := range list.Profiles {
		if p.ID == rulesProfile && len(p.FeatureSets) > 0 {
			return p.FeatureSets[0]
		}
	}
	e.t.Fatalf("the list does not advertise %s: %+v", rulesProfile, list.Profiles)
	return ""
}

func ruleSpec(featureSet, expression string) map[string]any {
	return map[string]any{"kind": "alert", "profile": rulesProfile, "feature_set": featureSet, "expression": expression, "interval_seconds": 60, "severity": "critical"}
}

func ruleSaveBody(org, project, command, rule model.ID, expected uint64, spec map[string]any) map[string]any {
	return map[string]any{"org": org.String(), "project_id": project.String(), "operation": "save", "command_id": command.String(), "rule_id": rule.String(),
		"expected_revision": decimalString(expected), "reason": "author the rule", "rule": spec}
}

func (e *ruleEnv) ruleAudits(org model.ID, prefix string) int {
	e.t.Helper()
	n := 0
	if err := e.app.Control.View(e.ctx, func(st model.ControlState) error {
		for _, a := range st.Audits {
			if strings.HasPrefix(a.Action, prefix) && a.Org == org.String() {
				n++
			}
		}
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// The rule route: an administrator saves a rule (assigned version 1, revision
// 1), changes it from the revision it read (version 2), a stale author loses, a
// replayed command commits once, an expression that does not check is refused and
// leaves nothing, a retirement keeps the record and a save brings it back; the
// list shows each rule with its revision and version, and every commit is audited
// with the reason, never the expression.
func TestRuleRouteSaveIsVersionedCheckedAndAudited(t *testing.T) {
	e := newRuleEnv(t)
	p1 := model.NewID()
	org := e.org("rule route org", p1)
	admin := e.user(org, "admin-rr@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	fs := e.featureSet(admin, org, p1)
	rule, first := model.NewID(), model.NewID()

	status, raw := e.post(admin, ruleSaveBody(org, p1, first, rule, 0, ruleSpec(fs, "up == 0")))
	if status != http.StatusOK {
		t.Fatalf("create: %d %s", status, raw)
	}
	var saved httpapi.RuleWriteAnswer
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if v := saved.Rule; saved.State != httpapi.ActionCommitted || v.RuleID != rule || v.Revision != 1 || v.Version != 1 || v.Retired || v.Rule.Expression != "up == 0" || v.Rule.IntervalSeconds != 60 || v.Rule.Severity != "critical" || v.Rule.FeatureSet != fs {
		t.Fatalf("created view: %+v", saved)
	}
	if status, raw = e.post(admin, ruleSaveBody(org, p1, model.NewID(), rule, 0, ruleSpec(fs, "up == 1"))); status != http.StatusConflict {
		t.Fatalf("create over an existing rule: %d %s", status, raw)
	}
	status, raw = e.post(admin, ruleSaveBody(org, p1, model.NewID(), rule, 1, ruleSpec(fs, "up == 2")))
	var second httpapi.RuleWriteAnswer
	if err := json.Unmarshal(raw, &second); err != nil || status != http.StatusOK || second.Rule.Version != 2 || second.Rule.Revision != 2 || second.Rule.Rule.Expression != "up == 2" {
		t.Fatalf("update: %d %v %s", status, err, raw)
	}
	// A stale revision loses and a replay of the first command commits nothing.
	if status, raw = e.post(admin, ruleSaveBody(org, p1, model.NewID(), rule, 1, ruleSpec(fs, "up == 3"))); status != http.StatusConflict {
		t.Fatalf("stale revision: %d %s", status, raw)
	}
	if status, raw = e.post(admin, ruleSaveBody(org, p1, first, rule, 0, ruleSpec(fs, "up == 0"))); status != http.StatusOK {
		t.Fatalf("replay: %d %s", status, raw)
	}
	// What does not check is refused before anything commits.
	for name, spec := range map[string]map[string]any{
		"does not parse":  ruleSpec(fs, "up =="),
		"is a scalar":     ruleSpec(fs, "1"),
		"unknown profile": func() map[string]any { s := ruleSpec(fs, "up"); s["profile"] = "promql-prometheus-9.9.9"; return s }(),
		"bad severity":    func() map[string]any { s := ruleSpec(fs, "up"); s["severity"] = "catastrophic"; return s }(),
		"huge interval":   func() map[string]any { s := ruleSpec(fs, "up"); s["interval_seconds"] = 4_000_000_000; return s }(),
		"no interval":     func() map[string]any { s := ruleSpec(fs, "up"); s["interval_seconds"] = 0; return s }(),
		"unknown field":   func() map[string]any { s := ruleSpec(fs, "up"); s["version"] = 9; return s }(),
	} {
		if status, raw = e.post(admin, ruleSaveBody(org, p1, model.NewID(), model.NewID(), 0, spec)); status != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, status, raw)
		}
	}
	// The closed shape of each operation.
	for name, body := range map[string]map[string]any{
		"list with a command": {"org": org.String(), "project_id": p1.String(), "operation": "list", "command_id": model.NewID().String()},
		"save with no rule":   {"org": org.String(), "project_id": p1.String(), "operation": "save", "command_id": model.NewID().String(), "rule_id": rule.String(), "expected_revision": "2", "reason": "x"},
		"save with no reason": func() map[string]any {
			b := ruleSaveBody(org, p1, model.NewID(), rule, 2, ruleSpec(fs, "up"))
			delete(b, "reason")
			return b
		}(),
		"unknown operation": {"org": org.String(), "project_id": p1.String(), "operation": "delete"},
		"no project":        {"org": org.String(), "operation": "list"},
		"replay backwards":  {"org": org.String(), "project_id": p1.String(), "operation": "replay", "rule_id": rule.String(), "reason": "x", "replay": map[string]any{"from_ns": "10", "to_ns": "5"}},
	} {
		if status, raw = e.post(admin, body); status != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, status, raw)
		}
	}

	// Retirement keeps the record; only a save at the new revision brings it back.
	retire := func(command model.ID, expected uint64) (int, []byte) {
		return e.post(admin, map[string]any{"org": org.String(), "project_id": p1.String(), "operation": "retire", "command_id": command.String(), "rule_id": rule.String(),
			"expected_revision": decimalString(expected), "reason": "stop it"})
	}
	if status, raw = retire(model.NewID(), 1); status != http.StatusConflict {
		t.Fatalf("stale retirement: %d %s", status, raw)
	}
	var retired httpapi.RuleWriteAnswer
	status, raw = retire(model.NewID(), 2)
	if err := json.Unmarshal(raw, &retired); err != nil || status != http.StatusOK || !retired.Rule.Retired || retired.Rule.Revision != 3 || retired.Rule.Version != 2 {
		t.Fatalf("retire: %d %v %s", status, err, raw)
	}
	if status, raw = e.post(admin, ruleSaveBody(org, p1, model.NewID(), rule, 2, ruleSpec(fs, "up == 4"))); status != http.StatusConflict {
		t.Fatalf("a save from before the retirement: %d %s", status, raw)
	}
	status, raw = e.post(admin, ruleSaveBody(org, p1, model.NewID(), rule, 3, ruleSpec(fs, "up == 4")))
	var back httpapi.RuleWriteAnswer
	if err := json.Unmarshal(raw, &back); err != nil || status != http.StatusOK || back.Rule.Retired || back.Rule.Version != 3 || back.Rule.Revision != 4 {
		t.Fatalf("save after retirement: %d %v %s", status, err, raw)
	}

	status, raw = e.post(admin, map[string]any{"org": org.String(), "project_id": p1.String(), "operation": "list"})
	var list httpapi.RuleListAnswer
	if err := json.Unmarshal(raw, &list); status != http.StatusOK || err != nil || !list.CanAuthor || list.RecordingAvailable || len(list.Rules) != 1 || list.Rules[0].RuleID != rule || list.Rules[0].Revision != 4 || list.Rules[0].Rule.Expression != "up == 4" {
		t.Fatalf("list: %d %v %s", status, err, raw)
	}
	if n := e.ruleAudits(org, "rules.define"); n != 3 {
		t.Fatalf("define audits: %d", n)
	}
	if n := e.ruleAudits(org, "rules.retire"); n != 1 {
		t.Fatalf("retire audits: %d", n)
	}
	e.app.Control.View(e.ctx, func(st model.ControlState) error {
		for _, a := range st.Audits {
			if strings.HasPrefix(a.Action, "rules.") && (strings.Contains(a.Reason, "up ==") || a.Principal != admin.ID) {
				t.Errorf("an audit carries the expression or the wrong actor: %+v", a)
			}
		}
		return nil
	})
}

// Who may do what: an administrator authors; a reader of the project lists and
// is told it may not author; policy.write and the reserved rules.write grant
// author nothing and read nothing; another project's and another organization's
// administrators see the same not-found an absent project gives; and nothing is
// committed by a refused request.
func TestRuleRouteAuthority(t *testing.T) {
	e := newRuleEnv(t)
	p1, p2 := model.NewID(), model.NewID()
	org := e.org("rule authority org", p1, p2)
	admin := e.user(org, "admin-ra@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	reader := e.user(org, "reader-ra@example.test")
	writer := e.user(org, "writer-ra@example.test")
	rulesOnly := e.user(org, "rules-ra@example.test")
	outsider := e.user(org, "outsider-ra@example.test")
	e.grant(org, reader, p1, true, auth.Read)
	e.grant(org, writer, p1, true, auth.PolicyWrite)
	e.grant(org, rulesOnly, p1, true, auth.RulesWrite)
	e.grant(org, outsider, p2, true, auth.Read, auth.PolicyWrite)
	foreignOrg := e.org("rule foreign org", model.NewID())
	foreign := e.user(foreignOrg, "admin-foreign@example.test")
	e.cmd(foreignOrg, "org_admin", auth.AdminPayload{UserID: foreign.ID, Enabled: true})
	fs := e.featureSet(admin, org, p1)
	rule := model.NewID()
	if status, raw := e.post(admin, ruleSaveBody(org, p1, model.NewID(), rule, 0, ruleSpec(fs, "up == 0"))); status != http.StatusOK {
		t.Fatalf("setup: %d %s", status, raw)
	}
	before := e.ruleAudits(org, "rules.")

	list := map[string]any{"org": org.String(), "project_id": p1.String(), "operation": "list"}
	status, raw := e.post(reader, list)
	var seen httpapi.RuleListAnswer
	if err := json.Unmarshal(raw, &seen); status != http.StatusOK || err != nil || seen.CanAuthor || len(seen.Rules) != 1 {
		t.Fatalf("a reader's list: %d %v %s", status, err, raw)
	}
	for name, who := range map[string]person{"policy.write": writer, "rules.write": rulesOnly, "another project": outsider} {
		if status, raw = e.post(who, list); status != http.StatusNotFound {
			t.Errorf("%s listed: %d %s", name, status, raw)
		}
	}
	write := map[string]func() map[string]any{
		"save": func() map[string]any {
			return ruleSaveBody(org, p1, model.NewID(), model.NewID(), 0, ruleSpec(fs, "up"))
		},
		"retire": func() map[string]any {
			return map[string]any{"org": org.String(), "project_id": p1.String(), "operation": "retire", "command_id": model.NewID().String(), "rule_id": rule.String(), "expected_revision": "1", "reason": "x"}
		},
		"replay": func() map[string]any {
			return map[string]any{"org": org.String(), "project_id": p1.String(), "operation": "replay", "rule_id": rule.String(), "reason": "x", "replay": map[string]any{"from_ns": "0", "to_ns": "60000000000"}}
		},
	}
	for op, body := range write {
		for name, who := range map[string]person{"reader": reader, "policy.write": writer, "rules.write": rulesOnly, "another project": outsider} {
			if status, raw = e.post(who, body()); status != http.StatusNotFound {
				t.Errorf("%s by %s: %d %s", op, name, status, raw)
			}
		}
	}
	// Another organization's administrator does not reach this project, and this
	// organization's does not reach a project of the other.
	for name, req := range map[string]struct {
		who  person
		body map[string]any
	}{
		"foreign admin, this project": {foreign, ruleSaveBody(org, p1, model.NewID(), model.NewID(), 0, ruleSpec(fs, "up"))},
		"admin, foreign org":          {admin, ruleSaveBody(foreignOrg, p1, model.NewID(), model.NewID(), 0, ruleSpec(fs, "up"))},
		"admin, unknown project":      {admin, ruleSaveBody(org, model.NewID(), model.NewID(), model.NewID(), 0, ruleSpec(fs, "up"))},
	} {
		if status, raw = e.post(req.who, req.body); status != http.StatusNotFound {
			t.Errorf("%s: %d %s", name, status, raw)
		}
	}
	if n := e.ruleAudits(org, "rules."); n != before {
		t.Fatalf("a refused request committed: %d audits, want %d", n, before)
	}
	// An unauthenticated caller reaches nothing.
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/rules", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("an anonymous request: %d", resp.StatusCode)
	}
}

type recordingStub struct{ target rules.RecordingTarget }

func (r recordingStub) Recording(context.Context) (rules.RecordingTarget, error) {
	return r.target, nil
}

// A recording rule needs the node's recording source: without one the route
// refuses it with the closed reason, with one for another project too; with one
// for the project it saves when its configured labels are enumerated by the
// source policy and is refused (and nothing is committed) when they are not.
func TestRuleRouteRecordingRulesNeedTheRecordingSource(t *testing.T) {
	e := newRuleEnv(t)
	p1 := model.NewID()
	org := e.org("rule recording org", p1)
	admin := e.user(org, "admin-rec@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	fs := e.featureSet(admin, org, p1)
	recording := func(labels ...map[string]string) map[string]any {
		s := ruleSpec(fs, "sum(up)")
		s["kind"], s["record_name"] = "recording", "job:up:sum"
		delete(s, "severity")
		if len(labels) > 0 {
			var ls []map[string]string
			ls = append(ls, labels...)
			s["labels"] = ls
		}
		return s
	}
	post := func(spec map[string]any) (int, string) {
		status, raw := e.post(admin, ruleSaveBody(org, p1, model.NewID(), model.NewID(), 0, spec))
		return status, string(raw)
	}
	if status, raw := post(recording()); status != http.StatusBadRequest || !strings.Contains(raw, rules.ReasonRecordingSourceUnavailable) {
		t.Fatalf("no recording source: %d %s", status, raw)
	}
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Kinds: []model.Kind{model.Metric}, Labels: map[string][]string{"env": {"prod"}}}
	e.policies.UseRecordingSource(recordingStub{target: rules.RecordingTarget{Project: model.NewID(), Policy: policy}})
	if status, raw := post(recording()); status != http.StatusBadRequest || !strings.Contains(raw, rules.ReasonRecordingSourceUnavailable) {
		t.Fatalf("a recording source of another project: %d %s", status, raw)
	}
	e.policies.UseRecordingSource(recordingStub{target: rules.RecordingTarget{Project: p1, Policy: policy}})
	if status, raw := post(recording(map[string]string{"name": "env", "value": "prod"})); status != http.StatusOK {
		t.Fatalf("enumerated label: %d %s", status, raw)
	}
	if status, raw := post(recording(map[string]string{"name": "env", "value": "staging"})); status != http.StatusBadRequest || !strings.Contains(raw, rules.ReasonRecordingLabelNotAllowed) {
		t.Fatalf("label outside the enumeration: %d %s", status, raw)
	}
	status, raw := e.post(admin, map[string]any{"org": org.String(), "project_id": p1.String(), "operation": "list"})
	var list httpapi.RuleListAnswer
	if err := json.Unmarshal(raw, &list); status != http.StatusOK || err != nil || !list.RecordingAvailable || len(list.Rules) != 1 || list.Rules[0].Rule.Kind != "recording" || len(list.Rules[0].Rule.Labels) != 1 {
		t.Fatalf("list: %d %v %s", status, err, raw)
	}
	e.policies.UseRecordingSource(nil)
	if status, raw := post(recording()); status != http.StatusBadRequest || !strings.Contains(raw, rules.ReasonRecordingSourceUnavailable) {
		t.Fatalf("a recording source that was unbound: %d %s", status, raw)
	}
}

// An operator replay declaration is an administrator's audited act on a rule of
// the catalogue, committed once however often it is repeated; the route refuses
// a rule that is not in the catalogue.
func TestRuleRouteDeclaresAnOperatorReplay(t *testing.T) {
	e := newRuleEnv(t)
	p1 := model.NewID()
	org := e.org("rule replay org", p1)
	admin := e.user(org, "admin-rp@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	fs := e.featureSet(admin, org, p1)
	rule := model.NewID()
	if status, raw := e.post(admin, ruleSaveBody(org, p1, model.NewID(), rule, 0, ruleSpec(fs, "up"))); status != http.StatusOK {
		t.Fatalf("setup: %d %s", status, raw)
	}
	replay := func(id model.ID) (int, []byte) {
		return e.post(admin, map[string]any{"org": org.String(), "project_id": p1.String(), "operation": "replay", "rule_id": id.String(), "reason": "reconcile after the outage",
			"replay": map[string]any{"from_ns": "1800000000000000000", "to_ns": "1800000060000000000"}})
	}
	for range 2 {
		status, raw := replay(rule)
		var answer httpapi.RuleReplayAnswer
		if err := json.Unmarshal(raw, &answer); status != http.StatusOK || err != nil || answer.State != httpapi.ActionCommitted || answer.RuleID != rule || answer.FromNS != 1_800_000_000_000_000_000 {
			t.Fatalf("replay: %d %v %s", status, err, raw)
		}
	}
	if n := e.ruleAudits(org, "rules.operator_replay"); n != 1 {
		t.Fatalf("operator replay audited %d times", n)
	}
	if status, raw := replay(model.NewID()); status != http.StatusNotFound {
		t.Fatalf("a replay of a rule that is not in the catalogue: %d %s", status, raw)
	}
}
