// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestClockDiscrepancyPreservesIncompleteObservation(t *testing.T) {
	targets, grant := fixture(t)
	original, err := CollectIntake(context.Background(), targets, grant)
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []time.Duration{time.Minute, -time.Minute} {
		evidence := original.Targets[0].Evidence
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			e := evidence
			e.ReportedAt = time.Now().Add(offset)
			e.ObservedAt = e.ReportedAt
			json.NewEncoder(w).Encode(e)
		}))
		targets.Targets[0].EvidenceURL = server.URL
		grant.Scopes[0].EvidenceURL = server.URL
		got, err := CollectIntake(context.Background(), targets, grant)
		server.Close()
		if err == nil || len(got.Targets) != 1 {
			t.Fatal("clock discrepancy not preserved")
		}
		entry := got.Targets[0]
		if entry.CurrentEvidenceComplete || entry.CollectorStartedAt.IsZero() || entry.CollectorReceivedAt.Before(entry.CollectorStartedAt) || entry.ProducerClockDeltaNano == 0 || len(entry.Discrepancies) == 0 {
			t.Fatal("missing incomplete clock ledger")
		}
		if _, err := PublicSummary(got); err == nil {
			t.Fatal("clock discrepancy established current evidence")
		}
	}
}

func TestPrivateOutputFailsClosedWithoutGitContext(t *testing.T) {
	if _, err := privateDirectory(context.Background(), t.TempDir(), []string{t.TempDir()}, true); err == nil {
		t.Fatal("ignored worktree discovery error")
	}
}

func TestCLIContextCancelsBlockedEvidenceAndWritesNothing(t *testing.T) {
	targets, grant := fixture(t)
	entered := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() }))
	defer server.Close()
	targets.Targets[0].EvidenceURL = server.URL
	grant.Scopes[0].EvidenceURL = server.URL
	inputs := t.TempDir()
	private := privateTempDir(t)
	targetPath := filepath.Join(inputs, "targets.json")
	grantPath := filepath.Join(inputs, "grant.json")
	summary := filepath.Join(inputs, "summary.json")
	if err := writeExclusive(targetPath, targets); err != nil {
		t.Fatal(err)
	}
	if err := writeExclusive(grantPath, grant); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- run(ctx, []string{"intake", "--targets", targetPath, "--authorization", grantPath, "--private-output", private, "--public-summary", summary, "--private-directory-acl-confirmed", "--timeout", "10s"})
	}()
	select {
	case <-entered:
	case <-time.After(8 * time.Second):
		t.Fatal("collector did not reach fixture")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("accepted cancelled intake")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("CLI did not cancel blocked HTTP")
	}
	if _, err := os.Stat(filepath.Join(private, "intake.json")); !os.IsNotExist(err) {
		t.Fatal("cancelled collection wrote evidence")
	}
	if _, err := os.Stat(summary); !os.IsNotExist(err) {
		t.Fatal("cancelled collection wrote summary")
	}
}

// Standalone executed CLI smoke: only a newly initialized local repo and loopback HTTP.
// Parent invocation: go test ./tools/adoption -run '^TestExecutedSyntheticCLI$' -count=1 -v
func TestExecutedSyntheticCLI(t *testing.T) {
	targets, grant := fixture(t)
	inputs := t.TempDir()
	private := privateTempDir(t)
	binary := filepath.Join(t.TempDir(), "adoption")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v %s", err, out)
	}
	targetPath := filepath.Join(inputs, "targets.json")
	grantPath := filepath.Join(inputs, "grant.json")
	summary := filepath.Join(inputs, "summary.json")
	if err := writeExclusive(targetPath, targets); err != nil {
		t.Fatal(err)
	}
	if err := writeExclusive(grantPath, grant); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "intake", "--targets", targetPath, "--authorization", grantPath, "--private-output", private, "--public-summary", summary, "--private-directory-acl-confirmed", "--timeout", "20s")
	command.Env = cleanGitEnvironment()
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("executed synthetic CLI: %v %s", err, out)
	}
	var got PrivateIntake
	if err := readInput(filepath.Join(private, "intake.json"), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Targets) != 1 || got.Targets[0].ObservedRef != targets.Targets[0].ExpectedRef || !got.Targets[0].CurrentEvidenceComplete {
		t.Fatal("executed CLI omitted current observation")
	}
	var public SanitizedSummary
	if err := readInput(summary, &public); err != nil || public.TargetCount != 1 || !public.CurrentEvidenceComplete {
		t.Fatal("invalid executed CLI summary")
	}
}

func TestOperatorTimeoutBoundsBlockedEvidence(t *testing.T) {
	targets, grant := fixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	targets.Targets[0].EvidenceURL = server.URL
	grant.Scopes[0].EvidenceURL = server.URL
	inputs := t.TempDir()
	private := privateTempDir(t)
	targetPath := filepath.Join(inputs, "targets.json")
	grantPath := filepath.Join(inputs, "grant.json")
	summary := filepath.Join(inputs, "summary.json")
	if err := writeExclusive(targetPath, targets); err != nil {
		t.Fatal(err)
	}
	if err := writeExclusive(grantPath, grant); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	err := run(context.Background(), []string{"intake", "--targets", targetPath, "--authorization", grantPath, "--private-output", private, "--public-summary", summary, "--private-directory-acl-confirmed", "--timeout", "300ms"})
	if err == nil || time.Since(started) > 3*time.Second {
		t.Fatal("operator deadline failed to bound blocked collection")
	}
	if _, err := os.Stat(filepath.Join(private, "intake.json")); !os.IsNotExist(err) {
		t.Fatal("timed out operation wrote evidence")
	}
}

func TestDuplicateGrantScopeDenied(t *testing.T) {
	targets, grant := fixture(t)
	grant.Scopes = append(grant.Scopes, grant.Scopes[0])
	if _, err := CollectIntake(context.Background(), targets, grant); err == nil {
		t.Fatal("accepted ambiguous duplicate target authority")
	}
}
