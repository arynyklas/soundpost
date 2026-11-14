// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
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
