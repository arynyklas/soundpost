// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// A committed evaluation whose payload was released (its version was superseded)
// is refused as stale, never answered "not found" and never recomputed; a grid
// point that was never committed is simply absent.
func TestReadEvaluationOfAReleasedPayloadIsStale(t *testing.T) {
	c := newCtl(t)
	rule := c.alert(0, 0)
	var calls []int64
	clock := newClock(65)
	e := c.evaluator(presentWhile(c.project, &calls, func(int64) bool { return true }), clock)
	committer := c.committer()
	lease := c.lease()
	ev, err := e.Evaluate(c.ctx, c.reader(), rule, 60*sec, lease)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = committer.Commit(c.ctx, c.admin(), ev, lease); err != nil {
		t.Fatal(err)
	}
	next := rule
	next.Version = 2
	clock.set(125)
	if ev, err = e.Evaluate(c.ctx, c.reader(), next, 120*sec, lease); err != nil {
		t.Fatal(err)
	}
	if _, err = committer.Commit(c.ctx, c.admin(), ev, lease); err != nil {
		t.Fatal(err)
	}
	store := NewStateStore(c.store)
	if _, found, err := store.ReadEvaluation(c.ctx, c.reader(), rule.ID, 1, 60*sec); code(err) != model.Stale || found {
		t.Fatalf("the released evaluation of the superseded version: found=%v %v", found, err)
	}
	if _, found, err := store.ReadEvaluation(c.ctx, c.reader(), rule.ID, 1, 30*sec); err != nil || found {
		t.Fatalf("a grid point never committed: found=%v %v", found, err)
	}
	if got, found, err := store.ReadEvaluation(c.ctx, c.reader(), rule.ID, 2, 120*sec); err != nil || !found || got.Version != 2 {
		t.Fatalf("the retained evaluation: found=%v %v", found, err)
	}
}

// The read adapter refuses a rule book whose retained payload and advertised
// state revision disagree: serving the older state would make the next commit's
// compare-and-set be computed from it.
func TestReadRefusesAStateWhoseRevisionDisagreesWithTheBook(t *testing.T) {
	c := newCtl(t)
	rule := c.alert(0, 0)
	var calls []int64
	e := c.evaluator(presentWhile(c.project, &calls, func(int64) bool { return true }), newClock(65))
	lease := c.lease()
	ev, err := e.Evaluate(c.ctx, c.reader(), rule, 60*sec, lease)
	if err != nil {
		t.Fatal(err)
	}
	ev.State.Revision = 7 // the payload claims 7 evaluations; control will count 1
	canonical, _, err := ev.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(json.RawMessage(canonical))
	if err != nil {
		t.Fatal(err)
	}
	apply := &control.RuleEvaluationApply{Project: ev.Project, Rule: ev.Rule, Version: ev.Version, At: ev.At, Mode: control.RuleModeLive, Health: control.RuleHealthOK,
		Digest: model.Hash(sha256.Sum256(payload)), Payload: payload, Cursors: []model.Cursor{}, Outputs: []control.RuleOutputIntent{}}
	raw, err := json.Marshal(control.RuleCommand{Operation: control.RuleOpEvaluation, Lease: &lease, Evaluation: apply})
	if err != nil {
		t.Fatal(err)
	}
	var revision model.Revision
	if err = c.store.View(c.ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err = c.store.Transact(c.ctx, c.admin(), control.Command{CommandID: model.NewID(), ExpectedRevision: revision, Kind: string(control.KindApplyRuleEvaluation), Payload: raw}); err != nil {
		t.Fatal(err)
	}
	if _, err = NewStateStore(c.store).Read(c.ctx, c.reader(), rule.ID); code(err) != model.Corrupt {
		t.Fatalf("a state whose revision disagrees with its book: %v", err)
	}
}

// capture records the command IDs a committer derives.
type capture struct {
	ids []model.ID
}

func (c *capture) Transact(_ context.Context, _ auth.Scope, cmd control.Command) (control.Result, error) {
	c.ids = append(c.ids, cmd.CommandID)
	return control.Result{}, nil
}
func (c *capture) View(_ context.Context, fn func(control.State) error) error {
	return fn(control.State{})
}

// Every identity the package derives is a pure function of its inputs, fixed
// forever: an upgrade that changed the domain string, the byte order or the
// series encoding would give an already-applied grid point a new identity, and a
// replay of it would create fresh effects. These are the golden values.
func TestDerivedIdentitiesAreFrozen(t *testing.T) {
	org, project, ruleID := model.ID{1}, model.ID{2}, model.ID{3}
	got := map[string]string{}
	got["evaluation"] = EvaluationID(org, project, ruleID, 4, 5*sec).String()
	got["series-key"] = seriesKey(labels("a", "b", "c", "d"))

	rule := Rule{ID: ruleID, Project: project, Version: 4, Kind: KindAlert, Profile: "promql-prometheus-3.13.5", FeatureSet: "fs", Expression: "up", Interval: time.Minute, Severity: "critical"}
	ev := Evaluation{Org: org, Project: project, Rule: ruleID, Version: 4, At: 5 * sec, Mode: ModeLive, Kind: KindAlert, Outcome: OutcomeComplete, Members: []model.Labels{labels("a", "b")}}
	tr, err := Reduce(State{}, ev, rule)
	if err != nil || len(tr.Conditions) != 1 {
		t.Fatalf("reduce: %v", err)
	}
	got["condition-intent"] = tr.Conditions[0].ID.String()
	got["condition"] = tr.Conditions[0].Event.Condition.String()
	got["epoch"] = tr.Conditions[0].Event.Epoch.String()

	one := model.FloatBits(math.Float64bits(1))
	rec := Rule{ID: ruleID, Project: project, Version: 4, Kind: KindRecording, RecordName: "job:up:sum"}
	revn := Evaluation{Org: org, Project: project, Rule: ruleID, Version: 4, At: 5 * sec, Kind: KindRecording, Outcome: OutcomeComplete,
		Producer: &ProducerIdentity{Source: model.ID{4}, Producer: model.ID{5}, PolicyRevision: 1, Resource: producer().Resource},
		Recorded: []Recorded{{Labels: labels("a", "b"), SampleKind: "float", Value: &one}}}
	batches, err := RecordingBatches(revn, rec)
	if err != nil || len(batches) != 1 {
		t.Fatalf("batches: %v", err)
	}
	got["batch"] = batches[0].ID.String()
	got["record"] = batches[0].Records[0].ID.String()
	got["slot"] = fmt.Sprint(batches[0].RouteSlot)

	want := map[string]string{
		"evaluation":       "39dc50ec1962b96671ea584abdd7bc48",
		"series-key":       `["a","b"]["c","d"]`,
		"condition-intent": "750d35790e690850102de18131920459",
		"condition":        "3a37c888a55e4b46e5cf2e7c94fbac7c",
		"epoch":            "137c1594e203c220fd1f6df3a30b1953",
		"batch":            "6fd175b94b5c0401fe230921926c25cb",
		"record":           "a8bc7d083b163953fbf98fb59fe460f4",
		"slot":             "42",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %s, frozen value %s", k, got[k], v)
		}
	}
}

// The command identities carry their own domains: a replayed command must reach
// control under the ID its first attempt had.
func TestCommandIdentitiesAreDerivedFromTheirTransition(t *testing.T) {
	c := newCtl(t)
	rule := c.alert(0, 0)
	var calls []int64
	e := c.evaluator(presentWhile(c.project, &calls, func(int64) bool { return true }), newClock(65))
	lease := c.lease()
	ev, err := e.Evaluate(c.ctx, c.reader(), rule, 60*sec, lease)
	if err != nil {
		t.Fatal(err)
	}
	var cap capture
	committer := NewCommitter(&cap, nil)
	scope := c.admin()
	org := scope.OrgID()
	// The digest control verifies is over the transported payload, not the canonical one.
	canonical, _, err := ev.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(json.RawMessage(canonical))
	if err != nil {
		t.Fatal(err)
	}
	digest := model.Hash(sha256.Sum256(payload))
	if _, err = committer.Commit(c.ctx, scope, ev, lease); err != nil {
		t.Fatal(err)
	}
	if _, err = committer.RecordMissed(c.ctx, scope, rule, MissedInterval{From: 60 * sec, To: 120 * sec, Count: 2}, 200*sec, lease); err != nil {
		t.Fatal(err)
	}
	if _, err = committer.DeclareReplay(c.ctx, scope, rule, 60*sec, 120*sec, "reason", 200*sec); err != nil {
		t.Fatal(err)
	}
	want := []model.ID{
		derive("apply", org[:], c.project[:], rule.ID[:], u64(1), u64(uint64(60*sec)), digest[:]),
		derive("missed", org[:], c.project[:], rule.ID[:], u64(1), u64(uint64(60*sec)), u64(uint64(120*sec))),
		derive("replay", org[:], c.project[:], rule.ID[:], u64(uint64(60*sec)), u64(uint64(120*sec))),
	}
	if len(cap.ids) != len(want) {
		t.Fatalf("%d commands", len(cap.ids))
	}
	for i := range want {
		if cap.ids[i] != want[i] {
			t.Errorf("command %d: %s, want %s", i, cap.ids[i], want[i])
		}
	}
}
