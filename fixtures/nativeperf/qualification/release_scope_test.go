//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
)

// scopedManifest is testManifest with the release scope of decision D10 (linux/amd64 only) and one required scenario.
func scopedManifest() string {
	return strings.Replace(testManifest, `"advertised_fixtures":["cpu"]`, `"advertised_fixtures":["cpu"],"release_platforms":["linux/amd64"],"required_scenarios":["cpu_hotplug"]`, 1)
}

func withScenarios(r *qual.QualificationResult, rows map[string]qual.Row) *qual.QualificationResult {
	r.Scenarios = rows
	return r
}

func TestRequireAllPassesOnTheReleasePlatformAndNamesTheOutOfScopeRows(t *testing.T) {
	m := write(t, "manifest.json", scopedManifest())
	ok := map[string]qual.Row{"cpu_hotplug": qual.Supported([]string{"topology change reported"}, nil)}
	files := strings.Join([]string{
		write(t, "d12.json", withScenarios(supportedResult("6.1.0-54-amd64", "amd64"), ok)),
		write(t, "k66.json", withScenarios(supportedResult(k66, "amd64"), ok)),
	}, ",")
	out := t.TempDir() + "/gate.json"
	code, _, stderr := gate(t, "--manifest", m, "--results", files, "--require-all", "--out", out)
	if code != qual.ExitOK {
		t.Fatalf("the linux/amd64 release matrix exited %d:\n%s", code, stderr)
	}
	var c struct {
		Matrix     []matrixRow `json:"matrix"`
		OutOfScope []matrixRow `json:"out_of_release_scope_rows"`
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Matrix) != 2 {
		t.Fatalf("in-scope matrix rows = %+v, want the two amd64 LTS rows", c.Matrix)
	}
	if len(c.OutOfScope) != 2 {
		t.Fatalf("out-of-scope rows = %+v, want the two arm64 LTS rows", c.OutOfScope)
	}
	for _, row := range c.OutOfScope {
		if row.Arch != "arm64" || row.Qualified || !strings.Contains(row.Reason, "out_of_release_scope") || !strings.Contains(row.Reason, "D10") {
			t.Errorf("an arm64 row is not reported as out_of_release_scope citing D10 (never as passed): %+v", row)
		}
	}
}

func TestReleaseScopeNeverMakesAnInScopeRowPassAndAnArm64ResultStillDoesNotQualifyAmd64(t *testing.T) {
	m := write(t, "manifest.json", scopedManifest())
	ok := map[string]qual.Row{"cpu_hotplug": qual.Supported([]string{"e"}, nil)}
	// only the 6.1 amd64 result: the 6.6 amd64 row is in scope and unqualified
	files := write(t, "d12.json", withScenarios(supportedResult("6.1.0-54-amd64", "amd64"), ok))
	code, _, stderr := gate(t, "--manifest", m, "--results", files, "--require-all")
	if code != qual.ExitUnexercised || !strings.Contains(stderr, "matrix kernel 6.6 LTS amd64") {
		t.Fatalf("exit %d, want the unqualified in-scope 6.6 amd64 row:\n%s", code, stderr)
	}
	if strings.Contains(stderr, "arm64") {
		t.Errorf("an out-of-scope arm64 row is listed as unqualified:\n%s", stderr)
	}
}

func TestARequiredScenarioThatDidNotRunKeepsTheGateOpen(t *testing.T) {
	m := write(t, "manifest.json", scopedManifest())
	files := strings.Join([]string{
		write(t, "d12.json", supportedResult("6.1.0-54-amd64", "amd64")), // never reported cpu_hotplug
		write(t, "k66.json", withScenarios(supportedResult(k66, "amd64"), map[string]qual.Row{"cpu_hotplug": {State: qual.StateNotRun, Reason: "opt-in host scenario"}})),
	}, ",")
	code, _, stderr := gate(t, "--manifest", m, "--results", files, "--require-all")
	if code != qual.ExitUnexercised {
		t.Fatalf("exit %d:\n%s", code, stderr)
	}
	for _, want := range []string{"6.1.0-54-amd64/amd64 scenario cpu_hotplug: not_run", k66 + "/amd64 scenario cpu_hotplug: not_run (opt-in host scenario)"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("missing %q in:\n%s", want, stderr)
		}
	}
}
