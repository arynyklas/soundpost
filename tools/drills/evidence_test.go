// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"soundpost/internal/releaseevidence"
)

const drillCommit = "0123456789abcdef0123456789abcdef01234567"

const evidenceManifest = `version: 1
allowlist:
  data_roots: [/tmp/soundpost-drills]
  hosts: [127.0.0.1]
  forbidden_data_dirs: [/var/lib/soundpost]
scenarios:
  - name: kill
    evidence: node_loss
    needs_binary: true
    description: d
  - name: pause
    evidence: node_loss
    description: d
  - name: partition
    evidence: node_loss
    not_run: needs CAP_NET_ADMIN
    description: d
  - name: absent
    evidence: node_loss
    description: d
  - name: untagged
    description: d
`

func writeDrillReport(t *testing.T, dir string, rep Report) {
	t.Helper()
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, rep.Scenario+".json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func exportRows(t *testing.T, env releaseevidence.Report) map[string]releaseevidence.Row {
	t.Helper()
	m := map[string]releaseevidence.Row{}
	for _, r := range env.Rows {
		m[r.ID] = r
	}
	return m
}

func TestNodeLossEvidenceKeepsEveryDrillVerdict(t *testing.T) {
	m, err := ParseManifest([]byte(evidenceManifest))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeDrillReport(t, dir, Report{Scenario: "kill", Target: TargetName, Status: StatusPassed, Checks: []Check{{Name: "exact_reconciliation", OK: true}},
		NotRunItems: []NotRunItem{{Item: "leader identity", Reason: "not observable"}}})
	writeDrillReport(t, dir, Report{Scenario: "pause", Target: TargetName, Status: StatusFailed, Reason: "check exact_reconciliation failed",
		Checks: []Check{{Name: "exact_reconciliation", OK: false, Detail: "1 acknowledged id missing"}}})
	writeDrillReport(t, dir, Report{Scenario: "partition", Target: TargetName, Status: StatusNotRun, Reason: "needs CAP_NET_ADMIN"})
	// "absent" has no report; "untagged" has one but belongs to no gate report.
	writeDrillReport(t, dir, Report{Scenario: "untagged", Target: TargetName, Status: StatusFailed, Reason: "unrelated"})

	env, err := NodeLossEvidence(m, dir, drillCommit)
	if err != nil {
		t.Fatal(err)
	}
	if env.Kind != releaseevidence.KindNodeLoss || env.Commit != drillCommit {
		t.Fatalf("kind/commit %+v", env)
	}
	if got := strings.Join(env.Expected, ","); got != "absent,kill,partition,pause" {
		t.Fatalf("expected rows are the manifest's tagged scenarios: %s", got)
	}
	rows := exportRows(t, env)
	if rows["kill"].Status != releaseevidence.StatusPassed || !strings.Contains(rows["kill"].Detail, "leader identity") {
		t.Errorf("passed drill: %+v", rows["kill"])
	}
	if rows["pause"].Status != releaseevidence.StatusFailed || !strings.Contains(rows["pause"].Detail, "1 acknowledged id missing") {
		t.Errorf("failed drill must stay failed with its check text: %+v", rows["pause"])
	}
	if rows["partition"].Status != releaseevidence.StatusNotRun || rows["partition"].Detail != "needs CAP_NET_ADMIN" {
		t.Errorf("a not_run drill must stay not_run with its reason: %+v", rows["partition"])
	}
	if _, ok := rows["absent"]; ok {
		t.Error("a drill without a report was given a row")
	}
	if _, ok := rows["untagged"]; ok {
		t.Error("an untagged scenario entered the node_loss report")
	}
	if got := env.Missing(); len(got) != 1 || got[0] != "absent" {
		t.Errorf("missing %v", got)
	}
}

func TestNodeLossEvidenceDoesNotTrustAContradictoryPass(t *testing.T) {
	m, _ := ParseManifest([]byte(evidenceManifest))
	dir := t.TempDir()
	writeDrillReport(t, dir, Report{Scenario: "kill", Target: TargetName, Status: StatusPassed,
		Checks: []Check{{Name: "exact_reconciliation", OK: true}, {Name: "outage_timeline_verifies", OK: false, Detail: "state outage"}}})
	env, err := NodeLossEvidence(m, dir, drillCommit)
	if err != nil {
		t.Fatal(err)
	}
	if r := exportRows(t, env)["kill"]; r.Status != releaseevidence.StatusFailed || !strings.Contains(r.Detail, "outage_timeline_verifies") {
		t.Errorf("a passed report with a failed check: %+v", r)
	}
}

func TestNodeLossEvidenceRefusesForeignOrMalformedReports(t *testing.T) {
	m, _ := ParseManifest([]byte(evidenceManifest))
	for name, body := range map[string]string{
		"wrong scenario": `{"scenario":"pause","target":"isolated","status":"passed","ack_ledger":[],"failed_attempts":[],"checks":[]}`,
		"wrong target":   `{"scenario":"kill","target":"production","status":"passed","ack_ledger":[],"failed_attempts":[],"checks":[]}`,
		"unknown field":  `{"scenario":"kill","target":"isolated","status":"passed","passed":true,"ack_ledger":[],"failed_attempts":[],"checks":[]}`,
		"not json":       `passed`,
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "kill.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NodeLossEvidence(m, dir, drillCommit); err == nil {
			t.Errorf("%s: exported", name)
		}
	}
	// An unrecognised status is not a pass.
	dir := t.TempDir()
	writeDrillReport(t, dir, Report{Scenario: "kill", Target: TargetName, Status: "ok"})
	env, err := NodeLossEvidence(m, dir, drillCommit)
	if err != nil {
		t.Fatal(err)
	}
	if r := exportRows(t, env)["kill"]; r.Status == releaseevidence.StatusPassed {
		t.Errorf("status %q exported as a pass", "ok")
	}
}

func TestNodeLossEvidenceNeedsTaggedScenarios(t *testing.T) {
	m, err := ParseManifest([]byte(strings.ReplaceAll(evidenceManifest, "evidence: node_loss", "")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NodeLossEvidence(m, t.TempDir(), drillCommit); err == nil {
		t.Fatal("a manifest without node_loss scenarios exported a vacuous report")
	}
	if _, err := ParseManifest([]byte(strings.Replace(evidenceManifest, "evidence: node_loss", "evidence: everything", 1))); err == nil {
		t.Fatal("an unknown evidence tag was accepted")
	}
}

func TestCommittedManifestTagsTheNodeLossDrills(t *testing.T) {
	m, err := LoadManifest(filepath.Join("..", "..", "drills", "scenarios.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	want := "node-kill-restart,minority-pause,majority-pause,network-partition,power-loss,fsync-failure,disk-disappearance"
	if got := strings.Join(m.NodeLossScenarios(), ","); got != want {
		t.Fatalf("node_loss scenarios\n got %s\nwant %s", got, want)
	}
}

func TestEvidenceCommandWritesTheEnvelopeWhateverTheRowsSay(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "scenarios.yaml")
	if err := os.WriteFile(manifest, []byte(evidenceManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	reports := filepath.Join(dir, "reports")
	if err := os.Mkdir(reports, 0o700); err != nil {
		t.Fatal(err)
	}
	writeDrillReport(t, reports, Report{Scenario: "kill", Target: TargetName, Status: StatusFailed, Reason: "boom"})
	out := filepath.Join(dir, "node_loss.json")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"evidence", "--scenarios", manifest, "--reports", reports, "--commit", drillCommit, "--out", out}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var env releaseevidence.Report
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&env); err != nil {
		t.Fatalf("the gate decodes strictly: %v", err)
	}
	if !strings.Contains(stdout.String(), "NOT PASSED kill=failed") || !strings.Contains(stdout.String(), "MISSING absent") {
		t.Errorf("summary: %s", stdout.String())
	}
	if code := run([]string{"evidence", "--scenarios", manifest, "--reports", reports, "--commit", "main", "--out", out}, &stdout, &stderr); code != 2 {
		t.Errorf("a symbolic commit: exit %d", code)
	}
}
