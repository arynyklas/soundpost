// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smoke

import (
	"context"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
)

func TestDistributedClusterScenarioHoldsAcrossNodesAndNodeLoss(t *testing.T) {
	steps, err := RunDistributed(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range steps {
		t.Logf("%v %s %s", s.Passed, s.Name, s.Detail)
		if !s.Passed {
			t.Errorf("FAIL %s %s", s.Name, s.Detail)
		}
	}
	want := []string{
		"three-voters-joined-over-mtls",
		"write-through-node-1-is-readable-on-every-node",
		"write-through-a-follower-is-readable-on-every-node",
		"discovery-and-format-routes-answer-on-every-node",
		"logql-query-answers-on-every-node",
		"live-stream-on-a-follower-delivers-writes-of-other-nodes",
		"foreign-project-fails-closed-on-every-node",
		"revocation-reaches-every-node",
		"leader-loss-survivors-answer-completely-and-acknowledge",
		"below-quorum-nothing-is-acknowledged-and-reads-fail-closed",
		"restarted-voters-rejoin-and-converge-on-every-acknowledgement",
		"teardown-releases-everything-on-every-node",
	}
	if len(steps) != len(want) {
		t.Fatalf("%d steps, want %d", len(steps), len(want))
	}
	for i, name := range want {
		if steps[i].Name != name {
			t.Errorf("step %d is %q, want %q", i, steps[i].Name, name)
		}
	}
}

// The case-file flows run unchanged on three voters: the same authored answers
// must hold, with the same teardown guarantees.
func TestDistributedOwnedQuerySmokeRunsEveryStepOnThreeVoters(t *testing.T) {
	steps, err := RunOwned(context.Background(), Distributed, t.TempDir(), caseFile("owned-query-smoke.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range steps {
		if !s.Passed {
			t.Errorf("FAIL %s %s", s.Name, s.Detail)
		}
	}
	if len(steps) < 10 {
		t.Fatalf("%d steps", len(steps))
	}
}

func TestDistributedPersistedPathAnswersAreIdenticalAtEveryStage(t *testing.T) {
	res, err := RunPersisted(context.Background(), Distributed, t.TempDir(), caseFile("persisted-path.json"))
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
	for _, n := range res.Normalization {
		if !strings.HasPrefix(n.ID, "persisted-path/distributed/") {
			t.Errorf("normalization check %q is not namespaced by its layout", n.ID)
		}
	}
	if len(res.Normalization) == 0 {
		t.Fatal("no normalization checks")
	}
}

func TestDistributedRuleSmokeRunsOnThreeVotersWithReplicatedControl(t *testing.T) {
	steps, err := RunRules(context.Background(), Distributed, t.TempDir(), caseFile("rule-smoke.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range steps {
		if !s.Passed {
			t.Errorf("FAIL %s %s", s.Name, s.Detail)
		}
	}
	if len(steps) < 9 {
		t.Fatalf("%d steps", len(steps))
	}
}

func TestDistributedLiveSmokeRunsOnThreeVoters(t *testing.T) {
	steps, notRun, err := RunLive(context.Background(), Distributed, t.TempDir(), caseFile("live-smoke.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range steps {
		if !s.Passed {
			t.Errorf("FAIL %s %s", s.Name, s.Detail)
		}
	}
	for _, n := range notRun {
		t.Errorf("NOT RUN: %s", n)
	}
	if len(steps) < 10 {
		t.Fatalf("%d steps", len(steps))
	}
}

func TestDistributedProfileCrossProductsKeepEachProfilesExpectation(t *testing.T) {
	steps, err := RunCross(context.Background(), Distributed, t.TempDir(), caseFile("profile-cross-products.json"))
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
}

func verdictEnv() (*Env, model.ID) {
	id := model.NewID()
	return &Env{Projects: map[string]model.ID{"project-a": id}}, id
}

func vectorResult(id model.ID, completeness string, bits ...uint64) query.Result {
	value := &query.Value{Type: query.ValueVector}
	for _, b := range bits {
		f := model.FloatBits(b)
		value.Vector = append(value.Vector, query.VectorElement{Sample: query.Sample{Float: &f}})
	}
	return query.Result{Projects: []query.ProjectResult{{ProjectID: id, Value: value, Completeness: completeness}}}
}

// The cross-node scenario may only accept the one complete correct answer or an
// error without a value. These cases are the fabricated answers it must refuse.
func TestDistributedVerdictRefusesEveryFabricatedAnswer(t *testing.T) {
	e, id := verdictEnv()
	want := []string{"4000000000000000"}
	good := answer{code: 200, raw: []byte(`{"projects":[{"value":{"vector":[{"sample":{"float":"4000000000000000"}}]}}]}`), res: vectorResult(id, query.CompletenessComplete, 0x4000000000000000)}
	if ok, why := e.verdict(good, "project-a", want); !ok || why != "" {
		t.Fatalf("the complete correct answer was refused: ok=%v %q", ok, why)
	}
	if ok, why := e.verdict(answer{code: 503, raw: []byte(`{"code":"unavailable"}`)}, "project-a", want); ok || why != "" {
		t.Fatalf("an honest error is neither a success nor a violation: ok=%v %q", ok, why)
	}
	for name, a := range map[string]answer{
		"empty complete success":       {code: 200, raw: []byte(`{}`), res: vectorResult(id, query.CompletenessComplete)},
		"wrong value":                  {code: 200, raw: []byte(`{}`), res: vectorResult(id, query.CompletenessComplete, 0x4008000000000000)},
		"partial success":              {code: 200, raw: []byte(`{}`), res: vectorResult(id, query.CompletenessPartial, 0x4000000000000000)},
		"stale success":                {code: 200, raw: []byte(`{}`), res: vectorResult(id, query.CompletenessStale, 0x4000000000000000)},
		"failure inside a 200":         {code: 200, raw: []byte(`{}`), res: query.Result{Projects: []query.ProjectResult{{ProjectID: id, Completeness: query.CompletenessComplete, Failure: &query.Failure{Code: "unavailable"}}}}},
		"error that carries a value":   {code: 503, raw: []byte(`{"projects":[{"value":{"vector":[]}}]}`)},
		"answer for another project":   {code: 200, raw: []byte(`{}`), res: vectorResult(model.NewID(), query.CompletenessComplete, 0x4000000000000000)},
		"answer for no project at all": {code: 200, raw: []byte(`{}`), res: query.Result{}},
	} {
		if ok, why := e.verdict(a, "project-a", want); ok || why == "" {
			t.Errorf("%s: accepted (ok=%v violation=%q)", name, ok, why)
		}
	}
}

// A request names each group at most once, so the fence of several
// acknowledgements keeps the highest cursor of every group.
func TestDistributedReadFenceNamesEachGroupOnceAtItsHighestCursor(t *testing.T) {
	g1, g2 := model.NewID(), model.NewID()
	at := func(group model.ID, index model.Uint64) ackedMetric {
		return ackedMetric{receipt: model.Receipt{Cursor: model.Cursor{Group: group, Index: index}}}
	}
	got := cursorsOf([]ackedMetric{at(g1, 3), at(g2, 9), at(g1, 7), at(g1, 5), at(g2, 2)})
	if len(got) != 2 || got[0] != (model.Cursor{Group: g1, Index: 7}) || got[1] != (model.Cursor{Group: g2, Index: 9}) {
		t.Fatalf("fence %v", got)
	}
}
