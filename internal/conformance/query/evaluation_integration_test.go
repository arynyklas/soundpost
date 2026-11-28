//go:build integration

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This is deliberately not in the default deterministic unit suite. Once this
// integration gate is requested, absent runtime/images/locks/cases are failures,
// never Skip or an empty successful report.
func TestEvaluationBothExactPins(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	var lock SourceLock
	if err := ReadJSON(filepath.Join(root, "conformance/query/source-lock.json"), &lock); err != nil {
		t.Fatal(err)
	}
	lock.LedgerPath = filepath.Join(root, "conformance/query/obligations.json")
	for i := range lock.Profiles {
		lock.Profiles[i].ConfigurationPath = filepath.Join(root, lock.Profiles[i].ConfigurationPath)
	}
	runtime := os.Getenv("SOUNDPOST_ORACLE_RUNTIME")
	if runtime == "" {
		t.Fatal("SOUNDPOST_ORACLE_RUNTIME must name an absolute OCI runtime; missing native references are not skips")
	}
	var paths []string
	for _, name := range []string{"promql-time-operators.json", "promql-functions.json", "promql-histograms.json", "promql-version-differences.json"} {
		paths = append(paths, filepath.Join(root, "conformance/query/cases", name))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	report, err := RunEvaluationPhase(ctx, lock, paths, filepath.Join(root, "profiles/query"), runtime)
	if err != nil {
		raw, _ := json.Marshal(report)
		t.Fatalf("real evaluation phase: %v; report=%s", err, raw)
	}
	if report.Compared == 0 || report.Failed != 0 {
		t.Fatalf("empty or mismatching actual report: %+v", report)
	}
}
