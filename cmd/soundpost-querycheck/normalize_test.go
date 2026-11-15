// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	normalizeCorpus = filepath.Join("..", "..", "conformance", "query", "cases", "input-normalization.json")
	normalizeLock   = filepath.Join("..", "..", "conformance", "query", "source-lock.json")
)

type normalizeReport struct {
	Cases      int `json:"cases"`
	Positive   int `json:"positive"`
	Negative   int `json:"negative"`
	Records    int `json:"records"`
	Matched    int `json:"matched"`
	Mismatched int `json:"mismatched"`
	Rows       []struct {
		ID    string `json:"id"`
		Match bool   `json:"match"`
	} `json:"rows"`
	Mismatches []string `json:"mismatches"`
}

func TestNormalizeRunsLockedCorpusExactly(t *testing.T) {
	out, err := captureRun(t, "normalize", "--cases", normalizeCorpus, "--lock", normalizeLock, "--require-locked")
	if err != nil {
		t.Fatalf("normalize failed on the real corpus: %v\n%s", err, out)
	}
	var rep normalizeReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("report is not JSON: %v\n%s", err, out)
	}
	if rep.Cases != 30 || rep.Positive != 7 || rep.Negative != 23 || rep.Records != 33 || rep.Matched != 30 || rep.Mismatched != 0 || len(rep.Rows) != 30 || len(rep.Mismatches) != 0 {
		t.Fatalf("unexpected normalize report: %s", out)
	}
	for _, r := range rep.Rows {
		if r.ID == "" || !r.Match {
			t.Fatalf("row %q not matched", r.ID)
		}
	}
}

func TestNormalizeFailsClosedOnTamperedCorpus(t *testing.T) {
	raw, err := os.ReadFile(normalizeCorpus)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "query", "cases")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	tampered := filepath.Join(dir, "input-normalization.json")
	// Same bytes plus one trailing space: still valid JSON, different digest.
	if err := os.WriteFile(tampered, append(raw, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := captureRun(t, "normalize", "--cases", tampered, "--lock", normalizeLock, "--require-locked")
	if err == nil || !strings.Contains(err.Error(), "locked content changed") {
		t.Fatalf("tampered corpus must fail closed on the content lock: %v", err)
	}
	if out != "" {
		t.Fatalf("no report may be produced for an unlocked corpus: %s", out)
	}
}

func TestNormalizeFailsClosedWhenCorpusIsNotLocked(t *testing.T) {
	var lock map[string]any
	raw, err := os.ReadFile(normalizeLock)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		t.Fatal(err)
	}
	delete(lock["inventory_files"].(map[string]any), "cases/input-normalization.json")
	unlocked, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "source-lock.json")
	if err := os.WriteFile(path, unlocked, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := captureRun(t, "normalize", "--cases", normalizeCorpus, "--lock", path, "--require-locked"); err == nil {
		t.Fatal("corpus absent from the lock must fail closed")
	}
}

func TestNormalizeRefusesWithoutRequireLocked(t *testing.T) {
	out, err := captureRun(t, "normalize", "--cases", normalizeCorpus, "--lock", normalizeLock)
	if err == nil || !strings.Contains(err.Error(), "--require-locked") {
		t.Fatalf("normalize without --require-locked must refuse: %v", err)
	}
	if out != "" {
		t.Fatalf("no report may be produced without --require-locked: %s", out)
	}
}
