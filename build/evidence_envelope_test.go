// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/releaseevidence"
)

// The producers' exporters write through internal/releaseevidence; the gate must read exactly that
// file, keep a failing row failing, and name a row the exporter could not produce.
func TestGateReadsWhatTheExportersWrite(t *testing.T) {
	dir := t.TempDir()
	write := func(kind string, expected []string, rows []releaseevidence.Row) Reports {
		rep, err := releaseevidence.New(kind, testCommit, expected, rows)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, kind+".json")
		if err = rep.Write(path); err != nil {
			t.Fatal(err)
		}
		return Reports{Evidence: map[string]string{kind: path}}
	}
	passed := releaseevidence.Row{ID: "a", Status: releaseevidence.StatusPassed}

	if c := checkEvidenceOf("browser", write("browser", []string{"a"}, []releaseevidence.Row{passed}), testCommit); len(c.Blocking) != 0 {
		t.Fatalf("a clean envelope blocks: %v", c.Blocking)
	}
	failed := write("node_loss", []string{"a", "b", "c"}, []releaseevidence.Row{
		passed,
		{ID: "b", Status: releaseevidence.StatusFailed, Detail: "1 acknowledged id missing"},
	})
	c := checkEvidenceOf("node_loss", failed, testCommit)
	got := strings.Join(c.Blocking, "\n")
	for _, want := range []string{"node_loss row b is failed 1 acknowledged id missing", "node_loss expected row c has no result"} {
		if !strings.Contains(got, want) {
			t.Errorf("gate output lacks %q:\n%s", want, got)
		}
	}
	if c := checkEvidenceOf("node_loss", failed, "1111111111111111111111111111111111111111"); !strings.Contains(strings.Join(c.Blocking, "\n"), "is for commit") {
		t.Errorf("a report for another commit passes: %v", c.Blocking)
	}
	for _, kind := range EvidenceKinds {
		if _, err := releaseevidence.New(kind, testCommit, []string{"a"}, nil); err != nil {
			t.Errorf("kind %s: %v", kind, err)
		}
	}
}
