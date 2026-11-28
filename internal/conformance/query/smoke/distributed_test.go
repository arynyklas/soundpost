// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smoke

import (
	"context"
	"strings"
	"testing"
	"time"

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
		if lapsedUnderRace(s) {
			t.Logf("NOT OBSERVED %s %s", s.Name, s.Detail)
			continue
		}
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
	requirePersistedFamilies(t, res)
	requireHistogramNormalization(t, res, Distributed)
}

// A host that starves the voters for an election timeout makes the leader of a group step down between two
// stages (the full `go test ./internal/...` of an 8-vCPU VM did it: the control group's lead left voter 1 and
// the log-based alert rule, which holds a leadership fence, answered `replica unavailable` at every later stage).
// Every stage must absorb a lead that sits on another voter: the writes and reads are forwarded or fenced, and the
// rule evaluation first waits for voter 1 to lead the control group again. Here the lead of every group moves to
// voter 2 before the first flushed stage, on purpose.
func TestDistributedPersistedPathAbsorbsALeadMovedBetweenStages(t *testing.T) {
	moved := false
	res, err := runPersisted(context.Background(), Distributed, t.TempDir(), caseFile("persisted-path.json"), func(env *Env, stage string) {
		if stage != "flush" {
			return
		}
		moved = true
		moveEveryLead(t, env, 1, 2)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !moved {
		t.Fatal("the flush stage never ran")
	}
	for _, s := range res.Steps {
		if lapsedUnderRace(s) {
			t.Logf("NOT OBSERVED %s %s", s.Name, s.Detail)
			continue
		}
		if !s.Passed {
			t.Errorf("FAIL %s %s", s.Name, s.Detail)
		}
	}
	for _, p := range res.Persistence {
		if !p.Passed {
			t.Errorf("persistence scenario %s failed", p.Name)
		}
	}
}

// The rule smoke takes its leadership fence of the control group when it wires rule evaluation, at the start and after
// a restart. Only a leader grants a fence, so a window in which no voter leads (an election on a starved host) must be
// waited out there like everywhere else. Here voters 2 and 3 are cut off from voter 1 for 15 s at the first wiring,
// on purpose: nobody leads for longer than the product waits.
func TestDistributedRuleSmokeWaitsOutAnElectionWindowAtItsFence(t *testing.T) {
	cut := false
	steps, err := runRules(context.Background(), Distributed, t.TempDir(), caseFile("rule-smoke.json"), func(env *Env) {
		if cut {
			return
		}
		cut = true
		env.Cluster().Partition(2, true)
		env.Cluster().Partition(3, true)
		time.AfterFunc(15*time.Second, func() {
			env.Cluster().Partition(2, false)
			env.Cluster().Partition(3, false)
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cut {
		t.Fatal("the rules were never wired")
	}
	for _, s := range steps {
		if !s.Passed {
			t.Errorf("FAIL %s %s", s.Name, s.Detail)
		}
	}
}

// The stage rows commit control writes (a deletion generation advance) through voter 1. A write that meets an
// election window answers `unavailable` for as long as no voter leads, and the product waits at most 8 s for it
// (the full-suite failure of faults/deletion-during-compute-is-stale-never-success/allow-partial=true on a starved
// host was `unavailable: unavailable` out of the advance, not a wrong answer): the row waits the window out as
// state. Here voters 2 and 3 are cut off from voter 1 for 15 s, on purpose: nobody leads for longer than the product waits.
func TestDistributedDeleteGenerationAdvanceWaitsOutAnElectionWindow(t *testing.T) {
	env, err := NewEnv(context.Background(), Distributed, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer env.Close()
	env.AddProject("project-a")
	env.Cluster().Partition(2, true)
	env.Cluster().Partition(3, true)
	time.AfterFunc(15*time.Second, func() {
		env.Cluster().Partition(2, false)
		env.Cluster().Partition(3, false)
	})
	var advanced error
	func() {
		defer recoverFailure(&advanced)
		env.advanceDeleteGeneration()
	}()
	if advanced != nil {
		t.Fatalf("the advance did not wait the election window out: %v", advanced)
	}
}

// An ingest that meets an election window is refused with a retryable `unavailable` (503): the contract of the route
// is that the client posts the very same batch again, and the batch id makes that idempotent (the full-suite
// run under -race on a starved host failed with `ingest status 503: {"code":"unavailable","retryable":true}` out of
// the harness's one-shot ingest). The harness acknowledges a batch the way a client does, and waits the window out.
// Here voters 2 and 3 are cut off from voter 1 for 15 s, on purpose.
func TestDistributedIngestRepostsTheSameBatchThroughAnElectionWindow(t *testing.T) {
	env, err := NewEnv(context.Background(), Distributed, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer env.Close()
	env.AddProject("project-a")
	source := env.AddSource(SourceSpec{Name: "window", Project: "project-a", Kinds: []model.Kind{model.Metric}, Labels: map[string][]string{"job": {"api"}}})
	env.Cluster().Partition(2, true)
	env.Cluster().Partition(3, true)
	time.AfterFunc(15*time.Second, func() {
		env.Cluster().Partition(2, false)
		env.Cluster().Partition(3, false)
	})
	var acked error
	func() {
		defer recoverFailure(&acked)
		env.Ingest(source, env.MetricRecord(source, "window_metric", map[string]string{"job": "api"}, 1_000_000_000, FloatBitsOf(1.5), nil))
	}()
	if acked != nil {
		t.Fatalf("the ingest did not wait the election window out: %v", acked)
	}
	if rows := distinct(env.scanMetrics("project-a")); len(rows) != 1 || rows[0].Name != "window_metric" {
		t.Fatalf("the acknowledged sample is stored as %v, want exactly one window_metric", rows)
	}
}

// moveEveryLead hands the lead of every group voter from leads to voter to and waits until voter from sees it.
func moveEveryLead(t *testing.T, env *Env, from, to uint64) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		pending := 0
		for _, s := range env.NodeApp(from).ReplicationStatus() {
			if s.Leader != from {
				continue
			}
			pending++
			g, err := env.NodeApp(from).ReplicaNode().Group(s.Group)
			if err != nil {
				t.Fatalf("group %s: %v", s.Group, err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = g.TransferLeadership(ctx, to)
			cancel()
		}
		if pending == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("voter %d still leads %d groups after the lead was handed to voter %d", from, pending, to)
		}
		time.Sleep(50 * time.Millisecond)
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
	if len(steps) != crossSteps {
		t.Fatalf("%d steps, want %d", len(steps), crossSteps)
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
