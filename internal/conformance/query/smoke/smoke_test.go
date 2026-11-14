// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smoke

import (
	"context"
	"path/filepath"
	"testing"
)

func caseFile(name string) string {
	return filepath.Join("..", "..", "..", "..", "conformance", "query", "cases", name)
}

func TestOwnedQuerySmokeRunsEveryStepOnARealNode(t *testing.T) {
	steps, err := RunOwned(context.Background(), t.TempDir(), caseFile("owned-query-smoke.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range steps {
		t.Logf("%v %s %s", s.Passed, s.Name, s.Detail)
	}
	if Failed(steps) != 0 || len(steps) < 10 {
		t.Fatalf("%d failing of %d steps", Failed(steps), len(steps))
	}
}

func TestPersistedPathAnswersAreIdenticalAtEveryStage(t *testing.T) {
	res, err := RunPersisted(context.Background(), t.TempDir(), caseFile("persisted-path.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range res.Steps {
		if !s.Passed {
			t.Errorf("FAIL %s %s", s.Name, s.Detail)
		}
	}
	for _, p := range res.Persistence {
		if !p.Passed {
			t.Errorf("persistence scenario %s failed", p.Name)
		}
	}
	t.Logf("%d steps, %d scenarios, %d normalization checks", len(res.Steps), len(res.Persistence), len(res.Normalization))
}

func TestRuleSmokeRunsEveryStepOnARealNodeWithRealControl(t *testing.T) {
	steps, err := RunRules(context.Background(), t.TempDir(), caseFile("rule-smoke.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range steps {
		t.Logf("%v %s %s", s.Passed, s.Name, s.Detail)
	}
	if Failed(steps) != 0 || len(steps) < 9 {
		t.Fatalf("%d failing of %d steps", Failed(steps), len(steps))
	}
}

func TestLiveSmokeRunsEveryStepOnARealNode(t *testing.T) {
	steps, notRun, err := RunLive(context.Background(), t.TempDir(), caseFile("live-smoke.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range steps {
		t.Logf("%v %s %s", s.Passed, s.Name, s.Detail)
	}
	for _, n := range notRun {
		t.Errorf("NOT RUN: %s", n)
	}
	if NotRunCount(steps) != 0 {
		t.Errorf("%d live steps were not measured", NotRunCount(steps))
	}
	if Failed(steps) != 0 || len(steps) < 10 {
		t.Fatalf("%d failing of %d steps", Failed(steps), len(steps))
	}
}

func TestProfileCrossProductsEachProfileKeepsItsOwnExpectation(t *testing.T) {
	steps, err := RunCross(context.Background(), t.TempDir(), caseFile("profile-cross-products.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range steps {
		if !s.Passed {
			t.Errorf("FAIL %s %s", s.Name, s.Detail)
		}
	}
	if len(steps) != 32 {
		t.Fatalf("%d steps, want 4 stages x 4 queries x 2 profiles", len(steps))
	}
	t.Logf("%d steps", len(steps))
}
