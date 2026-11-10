// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func queryDir(name string) string {
	return filepath.Join("..", "..", "conformance", "query", name)
}

func TestSmokeRefusesAnythingButRealStorageAndControl(t *testing.T) {
	for _, args := range [][]string{
		{"--cases", queryDir("cases/persisted-path.json")},
		{"--cases", queryDir("cases/persisted-path.json"), "--storage", "memory", "--control", "real"},
		{"--cases", queryDir("cases/persisted-path.json"), "--storage", "real", "--control", "fake"},
	} {
		if err := runSmoke(args); err == nil || !strings.Contains(err.Error(), "real") {
			t.Fatalf("%v: %v", args, err)
		}
	}
}

func TestReleaseRefusesAWeakerGateThanThePolicy(t *testing.T) {
	full := []string{"--all-profiles", "--all-feature-sets", "--require-locked", "--require-zero-unbound", "--require-zero-skips", "--require-zero-mismatches"}
	for i := range full {
		weaker := append(append([]string(nil), full[:i]...), full[i+1:]...)
		if err := runRelease(append([]string{"--policy", queryDir("release-policy.json")}, weaker...)); err == nil || !strings.Contains(err.Error(), "release requires") {
			t.Fatalf("dropping %s was accepted: %v", full[i], err)
		}
	}
}

// The real ledger is still entirely pending-bound: the gate must say so with
// exact counts and a nonzero outcome, never pass.
func TestReleaseFailsOnTheRealPendingLedger(t *testing.T) {
	err := runRelease([]string{"--policy", queryDir("release-policy.json"), "--all-profiles", "--all-feature-sets", "--require-locked", "--require-zero-unbound", "--require-zero-skips", "--require-zero-mismatches"})
	if err == nil || !strings.Contains(err.Error(), "release gate rejected") || !strings.Contains(err.Error(), "unbound 785") {
		t.Fatalf("the pending ledger passed or the count is wrong: %v", err)
	}
}
