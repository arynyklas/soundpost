// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"strings"
	"testing"
)

func TestEvaluationCompareRequiresCanonicalFlagsAndBothPins(t *testing.T) {
	for _, args := range [][]string{
		{"--phase", "evaluation"},
		{"--phase", "evaluation", "--require-locked", "--profiles", "promql-prometheus-3.1.0"},
		{"--phase", "evaluation", "--require-locked", "--profiles", "promql-prometheus-3.13.5"},
		{"--phase", "evaluation", "--require-locked", "--all-promql"},
	} {
		if err := runCompare(args); err == nil {
			t.Fatalf("invalid compare flags accepted: %v", args)
		}
	}
}
func TestEvaluationCompareRejectsMissingLockBeforeRuntime(t *testing.T) {
	err := runCompare([]string{"--phase", "evaluation", "--require-locked", "--cases", "a.json,b.json", "--lock", t.TempDir() + "/missing.json", "--runtime", "missing-runtime"})
	if err == nil || strings.Contains(err.Error(), "requires --phase") {
		t.Fatalf("evaluation phase not routed to real lock preflight: %v", err)
	}
}
