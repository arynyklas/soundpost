// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (ReadOnlyTargets, Authorization) {
	t.Helper()
	repo := t.TempDir()
	for _, args := range [][]string{{"init", repo}, {"-C", repo, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty", "-m", "fixture"}} {
		cmd := exec.Command("git", args...)
		cmd.Env = cleanGitEnvironment()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git fixture: %s %v", out, err)
		}
	}
	cmd := exec.Command("git", "-C", repo, "rev-parse", "HEAD")
	cmd.Env = cleanGitEnvironment()
	ref, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	evidence := LiveEvidence{ObservedAt: now, CurrentRef: strings.TrimSpace(string(ref)), Source: SourceEvidence{Version: "fixture-1", Coverage: []string{"synthetic"}, Ordering: "monotonic-revision"}, Runtime: RuntimeEvidence{Name: "synthetic", Version: "1"}, Build: BuildEvidence{Release: "fixture", Ref: strings.TrimSpace(string(ref))}, Protocol: ProtocolEvidence{Name: "soundpost", Version: "1"}, Policy: PolicyEvidence{Registration: "fixture-policy", Template: "fixture-template"}, NotificationOwner: OwnerEvidence{Owner: "fixture-owner", Mode: "legacy"}, Retention: RetentionEvidence{Until: now.Add(time.Hour), ExportReference: "external:fixture-export", LegacyReadOnly: true}, Rollback: RollbackEvidence{Owner: "fixture-owner", ProcedureReference: "external:rollback"}, Deadman: DeadmanEvidence{Owner: "external-owner", FailureDomain: "external-domain", ProductFailureDomain: "product-domain", ProofReference: "external:proof"}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := evidence
		response.ReportedAt = time.Now().UTC()
		json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(server.Close)
	targets := ReadOnlyTargets{Targets: []Target{{ID: "fixture", Repository: repo, ExpectedRef: evidence.CurrentRef, EvidenceURL: server.URL, SecretReferences: []string{"external:fixture-secret"}}}}
	grant := Authorization{GrantID: "fixture-grant", Authority: "fixture-operator", ReadOnly: true, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), MaxEvidenceAgeSeconds: 300, Scopes: []TargetScope{{ID: "fixture", Repository: repo, EvidenceURL: server.URL, Collectors: []string{"git-current-ref", "http-live-evidence"}}}}
	return targets, grant
}

func TestIntakeRequiresReadOnlyAuthorizationAndCurrentEvidence(t *testing.T) {
	targets, grant := fixture(t)
	got, err := CollectIntake(context.Background(), targets, grant)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Targets) != 1 || got.Targets[0].ObservedRef == "" {
		t.Fatal("missing collected ref")
	}
	for _, mutate := range []func(*Authorization){func(a *Authorization) { a.ReadOnly = false }, func(a *Authorization) { a.ExpiresAt = time.Now().Add(-time.Hour) }, func(a *Authorization) { a.Scopes = nil }, func(a *Authorization) { a.MaxEvidenceAgeSeconds = 0 }} {
		bad := grant
		mutate(&bad)
		if _, err := CollectIntake(context.Background(), targets, bad); err == nil {
			t.Fatal("accepted invalid authorization")
		}
	}
	missing := got
	missing.Targets[0].Evidence.ObservedAt = time.Time{}
	if _, err := PublicSummary(missing); err == nil {
		t.Fatal("accepted missing observation")
	}
	missing = got
	missing.Targets[0].Evidence.CurrentRef = ""
	if _, err := PublicSummary(missing); err == nil {
		t.Fatal("accepted missing current ref")
	}
}

func TestPublicSummaryExcludesCustomerInventory(t *testing.T) {
	targets, grant := fixture(t)
	got, err := CollectIntake(context.Background(), targets, grant)
	if err != nil {
		t.Fatal(err)
	}
	secret := "internal.customer.local /srv/private/repo 10.22.33.44 ADR-PRIVATE-91 password=credential"
	got.Targets[0].Evidence.Runtime.Name = secret
	got.Targets[0].Evidence.Policy.Template = secret
	got.Targets[0].Evidence.Deadman.ProofReference = secret
	got.Targets[0].SecretReferences = []string{secret}
	summary, err := PublicSummary(got)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(summary)
	for _, s := range []string{"internal.customer.local", "/srv/private", "10.22.33.44", "ADR-PRIVATE", "credential", targets.Targets[0].Repository} {
		if strings.Contains(string(b), s) {
			t.Fatalf("leaked %q", s)
		}
	}
}
