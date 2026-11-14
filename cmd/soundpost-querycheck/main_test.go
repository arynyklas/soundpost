// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOracleRejectsStaleInventoryBeforeExecution(t *testing.T) {
	ledger := filepath.Join(t.TempDir(), "obligations.json")
	if err := os.WriteFile(ledger, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	previous := os.Args
	t.Cleanup(func() { os.Args = previous })
	os.Args = []string{"soundpost-querycheck", "oracle", "--all-profiles", "--require-locked", "--lock", filepath.Join("..", "..", "conformance", "query", "source-lock.json"), "--ledger", ledger}
	err := run()
	if err == nil || !strings.Contains(err.Error(), "ledger content changed") {
		t.Fatalf("stale inventory must fail before oracle artifact/runtime execution: %v", err)
	}
}

func captureRun(t *testing.T, args ...string) (string, error) {
	t.Helper()
	previous, previousOut := os.Args, os.Stdout
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	collected := make(chan []byte)
	go func() { raw, _ := io.ReadAll(read); collected <- raw }() // drain while run writes: the full ledger exceeds the pipe buffer
	os.Args, os.Stdout = append([]string{"soundpost-querycheck"}, args...), write
	runErr := run()
	os.Args, os.Stdout = previous, previousOut
	write.Close()
	return string(<-collected), runErr
}

func TestInventoryCheckEmitsAcceptanceSummaryNotLedger(t *testing.T) {
	lock := filepath.Join("..", "..", "conformance", "query", "source-lock.json")
	ledger := filepath.Join("..", "..", "conformance", "query", "obligations.json")
	full, err := captureRun(t, "inventory", "--lock", lock, "--ledger", ledger)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := captureRun(t, "inventory", "--check", "--lock", lock, "--ledger", ledger)
	if err != nil {
		t.Fatal(err)
	}
	if checked == full || len(checked) > 512 || !strings.Contains(checked, `"complete":true`) || !strings.Contains(checked, `"obligations":785`) {
		t.Fatalf("--check must be a distinct acceptance assertion with a bounded summary: %q", checked)
	}
}

func TestOracleRefusesWithoutLockedAssertionFlags(t *testing.T) {
	lock := filepath.Join("..", "..", "conformance", "query", "source-lock.json")
	for _, args := range [][]string{{"oracle", "--lock", lock}, {"oracle", "--lock", lock, "--all-profiles"}, {"oracle", "--lock", lock, "--require-locked"}} {
		if _, err := captureRun(t, args...); err == nil || !strings.Contains(err.Error(), "oracle requires --all-profiles --require-locked") {
			t.Fatalf("%v: %v", args, err)
		}
	}
}

func TestSupersededDiscoveryArtifactsDeclareTheirAuthoritativeReplacements(t *testing.T) {
	for _, name := range []string{"flags.json", "semantic-scope.json"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "query", name))
		if err != nil {
			t.Fatal(err)
		}
		var note struct {
			Complete     bool     `json:"complete"`
			Status       string   `json:"status"`
			SupersededBy []string `json:"superseded_by"`
		}
		if err = json.Unmarshal(raw, &note); err != nil {
			t.Fatal(err)
		}
		if note.Complete || !strings.Contains(note.Status, "superseded") || len(note.SupersededBy) == 0 {
			t.Fatalf("%s must not read as an open or authoritative inventory: %+v", name, note)
		}
		for _, replacement := range note.SupersededBy {
			if _, err = os.Stat(filepath.Join("..", "..", "conformance", "query", replacement)); err != nil {
				t.Fatalf("%s names a missing replacement: %v", name, err)
			}
		}
	}
}
