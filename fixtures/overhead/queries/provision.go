// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

const (
	provisionReason = "queries gate"
	promProfileID   = "promql-prometheus-3.13.5"
	logProfilePref  = "logql-"
	// ruleIntervalS is the evaluation grid of every rule: 100 rules at 60 s are 100 evaluations a minute; the flip rules at 30 s add
	// six more (their state turns every five minutes, a 60 s grid would sample it too coarsely to see a recovery).
	ruleIntervalS     = 60
	flipRuleIntervalS = 30
)

// post issues a JSON POST as the owner session (CSRF bound) or with a bearer.
func (s *server) post(path string, body any, bearer string) (int, []byte) {
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", "https://"+s.addr+path, bytes.NewReader(raw))
	must(err, "request")
	req.Header.Set("Content-Type", "application/json")
	client := s.client
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
		c := *client
		c.Jar = nil
		client = &c
	} else {
		req.Header.Set("Origin", "https://"+s.addr)
		req.Header.Set("X-CSRF-Token", s.csrf)
	}
	resp, err := client.Do(req)
	must(err, "POST "+path)
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return resp.StatusCode, out
}

func expectStatus(what string, status int, raw []byte, want int) {
	if status != want {
		msg := string(raw)
		if len(msg) > 300 {
			msg = msg[:300]
		}
		fatalf("%s: status %d (want %d): %s", what, status, want, msg)
	}
}

func (s *server) admin(org model.ID, kind string, p auth.AdminPayload) {
	s.adminCommand(org, kind, p, model.NewID())
}

// adminCommand posts one audited admin command under a caller-chosen command id.
func (s *server) adminCommand(org model.ID, kind string, p auth.AdminPayload, command model.ID) {
	p.Reason = provisionReason
	payload, _ := json.Marshal(p)
	// The product's preconditions: create_org and create_user are based on the global control revision, every other command on the
	// organization's policy epoch (only a change to the same object conflicts). Background commits move the revision between a read and a
	// command, so a 409 is a stale precondition, not a refusal; the fixed command ID makes the retry idempotent.
	orgScoped := kind != "create_org" && kind != "create_user"
	for attempt := 0; ; attempt++ {
		req := auth.AdminCommandRequest{CommandID: command, OrgID: org, Kind: kind, Payload: payload}
		if orgScoped {
			status, raw := s.post("/api/v1/admin/read", map[string]any{"org_id": org, "kind": "organization"}, "")
			expectStatus("admin_read_org", status, raw, 200)
			var view auth.AdminView
			must(json.Unmarshal(raw, &view), "admin org view")
			req.ExpectedRevision, req.ExpectedEpoch = view.Revision, &view.Epoch
		} else {
			status, raw := s.post("/api/v1/admin/read", map[string]string{"kind": "organizations"}, "")
			expectStatus("admin_read", status, raw, 200)
			var view auth.AdminView
			must(json.Unmarshal(raw, &view), "admin view")
			req.ExpectedRevision = view.Revision
		}
		status, raw := s.post("/api/v1/admin/commands", req, "")
		if status == http.StatusConflict && attempt < 300 {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		expectStatus("admin_"+kind, status, raw, 200)
		return
	}
}

// quota sets the admission quota of an organization. An organization quota nobody configured is the smallest of its sources' policies,
// the product's conservative default (one project's series budget here): an organization of ten projects is refused with 429 `quota`
// once it passes one project's worth. The command is based on the global control revision, so a 409 is a stale precondition and the
// fixed command ID makes the retry idempotent.
func (s *server) quota(org model.ID, maxBytes, maxSeries uint64) {
	command := model.NewID()
	for attempt := 0; ; attempt++ {
		status, raw := s.post("/api/v1/admin/read", map[string]string{"kind": "organizations"}, "")
		expectStatus("admin_read", status, raw, 200)
		var view auth.AdminView
		must(json.Unmarshal(raw, &view), "admin view")
		status, raw = s.post("/api/v1/quotas", auth.AdmissionQuotaChange{CommandID: command, ExpectedRevision: view.Revision, Org: org,
			MaxBytes: model.Uint64(maxBytes), MaxSeries: model.Uint64(maxSeries), Reason: provisionReason}, "")
		if status == http.StatusConflict && attempt < 300 {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		expectStatus("admission_quota", status, raw, 200)
		return
	}
}

// destinationConfig is the notification destination of one organization: the webhook receiver of the query host.
func destinationConfig(hookURL string) json.RawMessage {
	raw, err := json.Marshal(auth.DestinationConfig{Type: "webhook", Endpoint: hookURL, Enabled: true})
	if err != nil {
		panic(err)
	}
	return raw
}

// destinationPayload is the admin command of organization o's destination: identity and command id come from the estate's seed (a retried
// provisioning commits once), the signing secret is the plan's.
func destinationPayload(cfg Config, o int, w PlanWebhook) (command model.ID, p auth.AdminPayload) {
	return ident(cfg.Seed, "destination-command", o), auth.AdminPayload{ID: ident(cfg.Seed, "destination", o), Config: destinationConfig(w.URL), Secret: w.Secret}
}

// ruleExpression is the language, the expression and the grid of a rule class. A firing rule's expression always returns a series
// while the data it reads is readable (`>= 0` of an aggregate of counters and of a count of lines), a healthy rule's never does
// (a counter or a rate is never below zero): no data at all (the aggregate of nothing) is an empty vector for both, so only a complete
// evaluation of readable data tells them apart, and an evaluation that read incomplete data may not call either one healthy.
func ruleExpression(class string) (language, expression string, intervalS uint32) {
	switch class {
	case RuleFiringMetric:
		return "promql", "sum(app_m0) >= 0", ruleIntervalS
	case RuleFiringLog:
		return "logql", `sum(count_over_time({route="r0"}[5m])) >= 0`, ruleIntervalS
	case RuleHealthyMetric:
		return "promql", "sum(app_m0) < 0", ruleIntervalS
	case RuleHealthyHeavy:
		return "promql", "sum by (route) (rate(app_m1[1h])) < 0", ruleIntervalS
	case RuleFlip:
		return "promql", ctlMetric + " > 0", flipRuleIntervalS
	}
	panic("unknown rule class " + class)
}

// pickProfiles chooses what the rules pin from the product's own advertisement: the PromQL profile promql-prometheus-3.13.5 and the
// first LogQL profile, the first feature set of each (the baseline one, no optional features).
func pickProfiles(profiles []httpapi.RuleProfile) (promProfile, promFeatureSet, logProfile, logFeatureSet string, err error) {
	for _, p := range profiles {
		if len(p.FeatureSets) == 0 {
			continue
		}
		switch {
		case p.ID == promProfileID && promProfile == "":
			promProfile, promFeatureSet = p.ID, p.FeatureSets[0]
		case strings.HasPrefix(p.ID, logProfilePref) && logProfile == "":
			logProfile, logFeatureSet = p.ID, p.FeatureSets[0]
		}
	}
	if promProfile == "" || logProfile == "" {
		return "", "", "", "", fmt.Errorf("the product advertises no usable %s / %s* profile: %+v", promProfileID, logProfilePref, profiles)
	}
	return
}

// ruleSaveRequest is the POST /api/v1/rules body that saves the rule of project p (a new rule: expected revision 0). The command id is
// fixed by the estate so that a retry of a save that was committed but not answered replays instead of conflicting.
func ruleSaveRequest(plan *Plan, p int) (httpapi.RuleRequest, PlanRule) {
	pj := NewProject(plan.Config, p)
	class := RuleClass(p)
	language, expression, interval := ruleExpression(class)
	profile, featureSet := plan.PromProfile, plan.PromFeatureSet
	if language == "logql" {
		profile, featureSet = plan.LogProfile, plan.LogFeatureSet
	}
	rule := RuleID(plan.Config.Seed, p)
	zero := model.Uint64(0)
	req := httpapi.RuleRequest{Org: pj.Org, Project: pj.Project, Operation: httpapi.RuleSave, CommandID: ident(plan.Config.Seed, "rule-command", p), RuleID: rule,
		ExpectedRevision: &zero, Reason: provisionReason,
		Rule: &httpapi.RuleSpec{Kind: "alert", Profile: profile, FeatureSet: featureSet, Expression: expression, IntervalSeconds: interval, Severity: "warning"}}
	return req, PlanRule{Project: p, Rule: rule, Class: class, Language: language, Expression: expression, IntervalSeconds: interval}
}

// ruleProfiles asks the product which profiles and feature sets a rule may pin.
func (s *server) ruleProfiles(pj *Project) []httpapi.RuleProfile {
	// a map, not httpapi.RuleRequest: a list carries only its selectors, and the struct's zero command and rule ids are not omitted by encoding/json
	status, raw := s.post("/api/v1/rules", map[string]any{"org": pj.Org, "project_id": pj.Project, "operation": httpapi.RuleList}, "")
	expectStatus("rules list", status, raw, 200)
	var listed httpapi.RuleListAnswer
	must(json.Unmarshal(raw, &listed), "rules list answer")
	if !listed.CanAuthor {
		fatalf("rules list: the owner session may not author rules of project %d", pj.Index)
	}
	return listed.Profiles
}

// saveRule commits one rule. A 409 is a stale precondition of the control store (background commits move it between the read and the
// command); the fixed command id makes the retry idempotent.
func (s *server) saveRule(req httpapi.RuleRequest, project int) {
	for attempt := 0; ; attempt++ {
		status, raw := s.post("/api/v1/rules", req, "")
		if status == http.StatusConflict && attempt < 300 {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		expectStatus(fmt.Sprintf("rule save project %d", project), status, raw, 200)
		var answer httpapi.RuleWriteAnswer
		must(json.Unmarshal(raw, &answer), "rule save answer")
		if answer.State != httpapi.ActionCommitted || answer.Rule.RuleID != req.RuleID {
			fatalf("rule save project %d: not committed: %s", project, raw)
		}
		return
	}
}

// provision bootstraps the product and creates every org, project, read-only user, source credential and policy of the estate, a
// webhook destination per organization and one alert rule per project.
func (s *server) provision(cfg Config, plan *Plan) {
	token, err := os.ReadFile(filepath.Join(s.dataDir, "bootstrap.token"))
	must(err, "bootstrap token")
	status, raw := s.post("/api/v1/bootstrap", map[string]string{"Token": string(token), "Email": "owner@overhead.invalid", "Password": "queries gate owner password 2026"}, "")
	expectStatus("bootstrap", status, raw, 200)
	var session auth.Session
	must(json.Unmarshal(raw, &session), "session")
	s.csrf = session.CSRF
	perOrg := cfg.Projects / cfg.Orgs
	for o := 0; o < cfg.Orgs; o++ {
		first := NewProject(cfg, o*perOrg)
		s.admin(first.Org, "create_org", auth.AdminPayload{Name: fmt.Sprintf("queries-org-%d", o)})
		s.admin(first.Org, "create_user", auth.AdminPayload{ID: first.Reader, Email: fmt.Sprintf("reader%d@overhead.invalid", o), Password: "queries gate reader password 2026"})
		s.admin(first.Org, "membership", auth.AdminPayload{UserID: first.Reader, Enabled: true})
		var projects []model.ID
		for i := 0; i < perOrg; i++ {
			pj := NewProject(cfg, o*perOrg+i)
			projects = append(projects, pj.Project)
			s.admin(pj.Org, "create_project", auth.AdminPayload{ID: pj.Project, Name: fmt.Sprintf("queries-project-%d", pj.Index)})
			s.admin(pj.Org, "grant", auth.AdminPayload{UserID: pj.Reader, ProjectID: pj.Project, Enabled: true, Permissions: []string{string(auth.Read)}})
			ob := auth.SourceOnboarding{CommandID: model.NewID(), Org: pj.Org, Project: pj.Project, Source: pj.Source, Expires: model.UnixNano(time.Now().Add(policyCredential).UnixNano()), Policy: pj.Policy, Reason: provisionReason}
			status, raw := s.post("/api/v1/sources", ob, "")
			expectStatus(fmt.Sprintf("onboard project %d", pj.Index), status, raw, 200)
			var onboarded auth.SourceOnboarded
			must(json.Unmarshal(raw, &onboarded), "onboarded")
			if onboarded.Credential == "" {
				fatalf("project %d: empty credential", pj.Index)
			}
			plan.Sources = append(plan.Sources, PlanSource{Project: pj.Index, Credential: onboarded.Credential})
		}
		// the organization admits what its projects' policies admit together, the control series included
		s.quota(first.Org, 1<<40, uint64(first.Policy.MaxSeries)*uint64(perOrg))
		status, raw := s.post("/api/v1/admin/tokens/issue", map[string]any{"org_id": first.Org, "principal": first.Reader, "projects": projects, "permissions": []string{string(auth.Read)},
			"expires": fmt.Sprint(time.Now().Add(policyCredential).Unix()), "reason": provisionReason}, "")
		expectStatus("token_issue", status, raw, 200)
		var issued struct{ Token string }
		must(json.Unmarshal(raw, &issued), "token")
		plan.Readers = append(plan.Readers, PlanReader{Org: o, Token: issued.Token})

		command, dest := destinationPayload(cfg, o, plan.Webhook)
		s.adminCommand(first.Org, "destination", dest, command)

		if plan.PromProfile == "" {
			plan.PromProfile, plan.PromFeatureSet, plan.LogProfile, plan.LogFeatureSet, err = pickProfiles(s.ruleProfiles(first))
			must(err, "rule profiles")
		}
		for i := 0; i < perOrg; i++ {
			req, pr := ruleSaveRequest(plan, o*perOrg+i)
			s.saveRule(req, pr.Project)
			plan.Rules = append(plan.Rules, pr)
		}
		fmt.Fprintf(os.Stderr, "queries: org %d provisioned (%d projects, a destination, %d rules)\n", o, perOrg, perOrg)
	}
}
