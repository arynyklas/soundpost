// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smoke

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func caseFile(name string) string {
	return filepath.Join("..", "..", "..", "..", "conformance", "query", "cases", name)
}

func TestOwnedQuerySmokeRunsEveryStepOnARealNode(t *testing.T) {
	steps, err := RunOwned(context.Background(), Single, t.TempDir(), caseFile("owned-query-smoke.json"))
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
	res, err := RunPersisted(context.Background(), Single, t.TempDir(), caseFile("persisted-path.json"))
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
	requirePersistedFamilies(t, res)
	t.Logf("%d steps, %d scenarios, %d normalization checks", len(res.Steps), len(res.Persistence), len(res.Normalization))
}

// crossSteps is the number of steps of profile-cross-products.json: four
// stages, each running 4 float queries and 5 native histogram queries under two
// PromQL profiles and 3 LogQL queries under the Loki profile.
const crossSteps = 4 * (4*2 + 5*2 + 3)

// requirePersistedFamilies fails when a family of persisted-path.json did not
// run at every stage: an input adapter, native histogram, LogQL logs or cache
// stage that is silently skipped must not read as a pass.
func requirePersistedFamilies(t *testing.T, res PersistedResult) {
	t.Helper()
	stages := []string{"hot", "flush", "multi-segment", "compaction", "restart", "restart-after-compaction", "after-conflict"}
	families := []string{
		"/adapter/remote-write-v1/stored-equals-admitted", "/adapter/remote-write-v2/stored-equals-admitted", "/adapter/openmetrics-scrape/stored-equals-admitted",
		"/adapter/loki-push/stored-equals-admitted", "/adapter/conditions-webhook/stored-equals-admitted",
		"/native/direct-ingest/stored-equals-admitted", "/native/remote-write-v1/stored-equals-admitted", "/native/remote-write-v2/stored-equals-admitted",
		"/logs/loki-push/stored-equals-admitted", "/logs/direct-ingest/stored-equals-admitted", "/logs/discovery/shard-values/pages", "/logs/rule/alert-over-logs", "/logs/live/append-is-delivered-once",
		"/cache/cold", "/cache/warm",
	}
	have := map[string]bool{}
	for _, s := range res.Steps {
		have[s.Name] = true
	}
	for _, stage := range stages {
		for _, f := range families {
			found := false
			for name := range have {
				if name == stage+f || strings.Contains(name, ":"+stage+f) {
					found = true
				}
			}
			if !found {
				t.Errorf("stage %s never ran %s", stage, f)
			}
		}
	}
	for _, f := range []string{"faults/warm-entry-dies-with-the-delete-generation", "faults/revoked-reader-is-never-served-a-warm-entry", "faults/missing-shard-is-unavailable-never-empty", "faults/corrupt-first-page-is-corrupt-never-empty", "faults/scan-cut-short-by-corruption-is-corrupt-never-empty", "faults/deletion-during-compute-is-stale-never-success/allow-partial=false", "faults/deletion-during-compute-is-stale-never-success/allow-partial=true"} {
		if !have[f] {
			t.Errorf("fault row %s never ran", f)
		}
	}
}

func TestRuleSmokeRunsEveryStepOnARealNodeWithRealControl(t *testing.T) {
	steps, err := RunRules(context.Background(), Single, t.TempDir(), caseFile("rule-smoke.json"))
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
	steps, notRun, err := RunLive(context.Background(), Single, t.TempDir(), caseFile("live-smoke.json"))
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
	steps, err := RunCross(context.Background(), Single, t.TempDir(), caseFile("profile-cross-products.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range steps {
		if !s.Passed {
			t.Errorf("FAIL %s %s", s.Name, s.Detail)
		}
	}
	if len(steps) != crossSteps {
		t.Fatalf("%d steps, want %d (4 stages x (4 + 5 native histogram queries x 2 PromQL profiles + 3 LogQL queries))", len(steps), crossSteps)
	}
	t.Logf("%d steps", len(steps))
}
