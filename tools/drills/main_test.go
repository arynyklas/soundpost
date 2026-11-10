// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodManifest = `version: 1
allowlist:
  data_roots: [/tmp/soundpost-drills]
  hosts: [127.0.0.1]
  forbidden_data_dirs: [/var/lib/soundpost]
scenarios:
  - name: a
    description: d
  - name: b
    not_run: because
`

func TestManifestIsStrict(t *testing.T) {
	if _, err := ParseManifest([]byte(goodManifest)); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"unknown field":     strings.Replace(goodManifest, "version: 1", "version: 1\nextra: 1", 1),
		"wrong version":     strings.Replace(goodManifest, "version: 1", "version: 2", 1),
		"no data roots":     strings.Replace(goodManifest, "data_roots: [/tmp/soundpost-drills]", "data_roots: []", 1),
		"no forbidden dirs": strings.Replace(goodManifest, "forbidden_data_dirs: [/var/lib/soundpost]", "forbidden_data_dirs: []", 1),
		"duplicate":         goodManifest + "  - name: a\n    description: d\n",
		"no description":    strings.Replace(goodManifest, "description: d", "description: ''", 1),
	}
	for name, raw := range bad {
		if _, err := ParseManifest([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestCommittedManifestMatchesImplementations keeps drills/scenarios.yaml and the registry in step:
// every row is either implemented or carries an exact not_run reason, never both, never neither.
func TestCommittedManifestMatchesImplementations(t *testing.T) {
	m, err := LoadManifest(filepath.Join("..", "..", "drills", "scenarios.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, s := range m.Scenarios {
		listed[s.Name] = true
		switch {
		case s.NotRun != "" && registry[s.Name] != nil:
			t.Errorf("%s is implemented and also recorded not_run", s.Name)
		case s.NotRun == "" && registry[s.Name] == nil:
			t.Errorf("%s has neither an implementation nor a not_run reason", s.Name)
		}
	}
	for name := range registry {
		if !listed[name] {
			t.Errorf("implemented scenario %s is not in drills/scenarios.yaml", name)
		}
	}
	if err := CheckTarget(m.Allowlist, Target{Name: TargetName, DataDirs: []string{"/var/lib/soundpost"}}); err == nil {
		t.Error("the committed allowlist accepts the production data directory")
	}
}

func TestRunRefusesOtherTargetsAndWritesNotRunRows(t *testing.T) {
	manifest := filepath.Join("..", "..", "drills", "scenarios.yaml")
	dir := t.TempDir()
	for _, target := range []string{"production", "default", "", "Isolated", "isolated "} {
		var out, errOut bytes.Buffer
		if code := run([]string{"--scenario", "power-loss", "--target", target, "--report", dir, "--scenarios", manifest}, &out, &errOut); code != 2 {
			t.Errorf("target %q exited %d, want 2 (%s)", target, code, errOut.String())
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("a refused run wrote %d report files", len(entries))
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"--scenario", "power-loss", "--target", "isolated", "--report", dir, "--scenarios", manifest}, &out, &errOut); code != 10 {
		t.Fatalf("a not_run row exited %d, want 10: %s %s", code, out.String(), errOut.String())
	}
	raw, err := os.ReadFile(filepath.Join(dir, "power-loss.json"))
	if err != nil || !bytes.Contains(raw, []byte(`"status": "not_run"`)) || bytes.Contains(raw, []byte(`"status": "passed"`)) {
		t.Fatalf("not_run report: %v %s", err, raw)
	}
}
