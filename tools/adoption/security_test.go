// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIntakeRejectsTargetCommandsAndMismatchedScope(t *testing.T) {
	targets, grant := fixture(t)
	for _, alter := range []func(*ReadOnlyTargets, *Authorization){
		func(r *ReadOnlyTargets, a *Authorization) { r.Targets[0].EvidenceURL += "?token=private" },
		func(r *ReadOnlyTargets, a *Authorization) {
			a.Scopes[0].Collectors = append(a.Scopes[0].Collectors, "sh -c arbitrary")
		},
		func(r *ReadOnlyTargets, a *Authorization) { a.Scopes[0].Repository = t.TempDir() },
		func(r *ReadOnlyTargets, a *Authorization) {
			r.Targets[0].SecretReferences = []string{"password=private"}
		},
	} {
		var r ReadOnlyTargets
		var a Authorization
		b, _ := json.Marshal(targets)
		json.Unmarshal(b, &r)
		b, _ = json.Marshal(grant)
		json.Unmarshal(b, &a)
		alter(&r, &a)
		if _, err := CollectIntake(context.Background(), r, a); err == nil {
			t.Fatal("accepted unsafe target or scope")
		}
	}
	var r ReadOnlyTargets
	if err := decodeStrict(strings.NewReader(`{"Targets":[],"Command":"arbitrary"}`), &r); err == nil {
		t.Fatal("accepted arbitrary command")
	}
}

func TestIntakeDoesNotFollowRedirect(t *testing.T) {
	targets, grant := fixture(t)
	calls := 0
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(200) }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 302) }))
	defer redirect.Close()
	targets.Targets[0].EvidenceURL = redirect.URL
	grant.Scopes[0].EvidenceURL = redirect.URL
	if _, err := CollectIntake(context.Background(), targets, grant); err == nil {
		t.Fatal("accepted redirect")
	}
	if calls != 0 {
		t.Fatal("contacted unauthorized redirect endpoint")
	}
}

func TestPublicSummaryRejectsEveryMissingEvidenceCategory(t *testing.T) {
	targets, grant := fixture(t)
	intake, err := CollectIntake(context.Background(), targets, grant)
	if err != nil {
		t.Fatal(err)
	}
	cases := []func(*LiveEvidence){func(e *LiveEvidence) { e.ObservedAt = time.Now().Add(-time.Hour) }, func(e *LiveEvidence) { e.ObservedAt = time.Now().Add(time.Hour) }, func(e *LiveEvidence) { e.Source.Coverage = nil }, func(e *LiveEvidence) { e.Source.Ordering = "" }, func(e *LiveEvidence) { e.Runtime.Version = "" }, func(e *LiveEvidence) { e.Build.Ref = "" }, func(e *LiveEvidence) { e.Protocol.Version = "" }, func(e *LiveEvidence) { e.Policy.Registration = "" }, func(e *LiveEvidence) { e.NotificationOwner.Owner = "" }, func(e *LiveEvidence) { e.Retention.ExportReference = "" }, func(e *LiveEvidence) { e.Rollback.ProcedureReference = "" }, func(e *LiveEvidence) { e.Deadman.ProofReference = "" }, func(e *LiveEvidence) { e.Deadman.FailureDomain = e.Deadman.ProductFailureDomain }}
	for i, mutate := range cases {
		copy := intake
		copy.Targets = append([]CollectedTarget{}, intake.Targets...)
		mutate(&copy.Targets[0].Evidence)
		if _, err := PublicSummary(copy); err == nil {
			t.Fatalf("accepted incomplete category %d", i)
		}
	}
}

func TestIntakeRecordsCurrentRefDiscrepancy(t *testing.T) {
	targets, grant := fixture(t)
	targets.Targets[0].ExpectedRef = strings.Repeat("0", 40)
	got, err := CollectIntake(context.Background(), targets, grant)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Targets[0].Discrepancies) != 1 || got.Targets[0].Discrepancies[0] != "checkout-ref-differs-from-expected" {
		t.Fatal("missing explicit discrepancy")
	}
	summary, err := PublicSummary(got)
	if err != nil || summary.DiscrepancyCount != 1 || summary.CustomerAcceptance {
		t.Fatal("misrepresented discrepancy as customer acceptance")
	}
}
