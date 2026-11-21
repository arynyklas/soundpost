// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// stage sends one staging command for the evaluation identity (version, at) and
// the digest of payload.
func (f *ruleFx) stage(lease replica.FenceToken, version, at uint64, mode, payload string, outputs []control.RuleOutputIntent) (control.Result, error) {
	f.t.Helper()
	return f.apply(control.RuleCommand{Operation: control.RuleOpStage, Lease: &lease, Stage: &control.RuleStageApply{
		Project: f.project, Rule: f.rule, Version: model.Revision(version), At: model.UnixNano(at), Mode: mode, Digest: digestOf(payload), Outputs: outputs}})
}

// An evaluation with more outputs than one command may carry commits them in
// several commands under one identity: nothing is visible until the finalizing
// evaluation command, which promotes every staged output with the evaluation.
func TestRuleEvaluationStagesAndPromotesOutputsBeyondOneCommand(t *testing.T) {
	f := newRuleFx(t)
	lease := f.lease()
	all := bulkConditions(1, 0, 600)
	const payload = `{"n":1}`
	if res, err := f.stage(lease, 1, 60, control.RuleModeLive, payload, all[256:512]); err != nil || res.Phase != "staged" {
		t.Fatalf("first staging command: %+v %v", res, err)
	}
	if res, err := f.stage(lease, 1, 60, control.RuleModeLive, payload, all[512:]); err != nil || res.Phase != "staged" {
		t.Fatalf("second staging command: %+v %v", res, err)
	}
	// Staged outputs are inert: no consumer sees them and no evaluation exists.
	if got := f.outputs(""); len(got) != 0 {
		t.Fatalf("%d staged outputs are visible to consumers", len(got))
	}
	if got := f.outputs(control.RulePhasePending); len(got) != 0 {
		t.Fatalf("%d staged outputs are pending", len(got))
	}
	if got := f.outputs(control.RulePhaseStaged); len(got) != 344 {
		t.Fatalf("%d staged outputs, want 344", len(got))
	}
	e := f.evaluation(1, 60, 0, control.RuleModeLive, payload, all[:256]...)
	e.Staged = 344
	res, err := f.eval(lease, e)
	if err != nil || res.Phase != "applied" {
		t.Fatalf("finalizing command: %+v %v", res, err)
	}
	pending := f.outputs(control.RulePhasePending)
	if len(pending) != 600 {
		t.Fatalf("%d pending outputs after the evaluation, want 600", len(pending))
	}
	if staged := f.outputs(control.RulePhaseStaged); len(staged) != 0 {
		t.Fatalf("%d outputs are still staged", len(staged))
	}
	revisions := map[model.Revision]bool{}
	for _, o := range pending {
		if o.Version != 1 || o.At != 60 || o.Mode != control.RuleModeLive {
			t.Fatalf("output %s lost the evaluation identity: %+v", o.ID, o)
		}
		revisions[o.Created] = true
	}
	if len(revisions) != 1 {
		t.Fatalf("one evaluation's outputs were created in %d transitions, want the finalizing one", len(revisions))
	}
	if book := f.book(); book.Versions[0].StateRevision != 1 {
		t.Fatalf("the evaluation was applied %d times", book.Versions[0].StateRevision)
	}
	// A retry of the whole sequence, after a lost response, changes nothing.
	if res, err = f.stage(lease, 1, 60, control.RuleModeLive, payload, all[256:512]); err != nil || res.Phase != "unchanged" {
		t.Fatalf("staging after the evaluation committed: %+v %v", res, err)
	}
	if res, err = f.eval(lease, e); err != nil || res.Phase != "replayed" {
		t.Fatalf("retry of the finalizing command: %+v %v", res, err)
	}
	if got := f.outputs(control.RulePhaseStaged); len(got) != 0 {
		t.Fatalf("a late staging command re-created %d staged outputs", len(got))
	}
}

// An evaluation staged and then abandoned leaves nothing a consumer can see; the
// next evaluation of the rule garbage-collects it.
func TestAbandonedStagedOutputsAreNeverVisibleAndAreCollected(t *testing.T) {
	f := newRuleFx(t)
	lease := f.lease()
	if _, err := f.stage(lease, 1, 60, control.RuleModeLive, `{"n":"abandoned"}`, bulkConditions(1, 0, 10)); err != nil {
		t.Fatal(err)
	}
	if got := f.outputs(""); len(got) != 0 {
		t.Fatalf("%d outputs of an unfinalized evaluation are visible", len(got))
	}
	// The next evaluation (another digest, no staging) commits and drops the orphans.
	if _, err := f.eval(lease, f.evaluation(1, 60, 0, control.RuleModeLive, `{"n":"retried"}`, conditionIntent(0xEE, false))); err != nil {
		t.Fatal(err)
	}
	if got := f.outputs(control.RulePhaseStaged); len(got) != 0 {
		t.Fatalf("%d orphaned staged outputs survived the next evaluation", len(got))
	}
	if got := f.outputs(control.RulePhasePending); len(got) != 1 || got[0].ID != (model.ID{0xEE}) {
		t.Fatalf("pending outputs: %+v", got)
	}
}

// The finalizing command promotes exactly what was staged under its identity and
// digest: another count or another digest commits nothing.
func TestFinalizingCommandMustMatchTheStagedOutputs(t *testing.T) {
	f := newRuleFx(t)
	lease := f.lease()
	const payload = `{"n":1}`
	if _, err := f.stage(lease, 1, 60, control.RuleModeLive, payload, bulkConditions(1, 0, 5)); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		staged uint32
		body   string
	}{
		{"too few promised", 4, payload},
		{"too many promised", 6, payload},
		{"none promised", 0, payload},
		{"another digest", 5, `{"n":2}`},
	} {
		e := f.evaluation(1, 60, 0, control.RuleModeLive, c.body, conditionIntent(0xEE, false))
		e.Staged = c.staged
		if _, err := f.eval(lease, e); faultDetail(err) != "rule_staged_outputs_missing" {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
	if got := f.outputs(""); len(got) != 0 {
		t.Fatalf("a mismatching finalizing command committed %d outputs", len(got))
	}
	// A mismatching finalizing command that carries no staging (Staged 0) and the
	// right digest leaves the staged outputs of the other digest orphaned, not
	// promoted: it commits only its own outputs.
	if _, err := f.eval(lease, f.evaluation(1, 60, 0, control.RuleModeLive, `{"n":3}`, conditionIntent(0xEF, false))); err != nil {
		t.Fatal(err)
	}
	if got := f.outputs(control.RulePhasePending); len(got) != 1 || got[0].ID != (model.ID{0xEF}) {
		t.Fatalf("pending outputs: %+v", got)
	}
}

// Staging is as strict as the evaluation: bounded, validated, idempotent only for
// identical content, fenced and never a way around the backfill rule.
func TestStagingCommandIsBoundedValidatedAndIdempotent(t *testing.T) {
	f := newRuleFx(t)
	lease := f.lease()
	const payload = `{"n":1}`
	if _, err := f.stage(lease, 1, 60, control.RuleModeLive, payload, bulkConditions(1, 0, 257)); code(err) != model.Invalid {
		t.Fatalf("a staging command over the per-command bound: %v", err)
	}
	if _, err := f.stage(lease, 1, 60, control.RuleModeLive, payload, nil); code(err) != model.Invalid {
		t.Fatalf("an empty staging command: %v", err)
	}
	if _, err := f.stage(lease, 1, 60, control.RuleModeBackfill, payload, []control.RuleOutputIntent{conditionIntent(1, true)}); faultDetail(err) != "backfill_cannot_notify" {
		t.Fatalf("a backfill stage that notifies: %v", err)
	}
	if _, err := f.stage(lease, 1, 60, control.RuleModeLive, payload, []control.RuleOutputIntent{conditionIntent(1, false), conditionIntent(1, false)}); code(err) != model.Invalid {
		t.Fatalf("a duplicate output ID inside one command: %v", err)
	}
	same := bulkConditions(1, 0, 3)
	if res, err := f.stage(lease, 1, 60, control.RuleModeLive, payload, same); err != nil || res.Phase != "staged" {
		t.Fatalf("staging: %+v %v", res, err)
	}
	if res, err := f.stage(lease, 1, 60, control.RuleModeLive, payload, same); err != nil || res.Phase != "unchanged" {
		t.Fatalf("an identical staging command is not idempotent: %+v %v", res, err)
	}
	changed := bulkConditions(1, 0, 3)
	changed[1].Payload = json.RawMessage(`{"condition":"other"}`)
	if _, err := f.stage(lease, 1, 60, control.RuleModeLive, payload, changed); faultDetail(err) != "rule_output_exists" {
		t.Fatalf("an output ID restaged with other content: %v", err)
	}
	// An ID that already exists as a real output cannot be staged again.
	finalize := f.evaluation(1, 60, 0, control.RuleModeLive, payload, conditionIntent(0x77, false))
	finalize.Staged = 3 // the three outputs staged above
	if _, err := f.eval(lease, finalize); err != nil {
		t.Fatal(err)
	}
	if _, err := f.stage(lease, 1, 120, control.RuleModeLive, `{"n":2}`, []control.RuleOutputIntent{conditionIntent(0x77, false)}); faultDetail(err) != "rule_output_exists" {
		t.Fatalf("staging the ID of a pending output: %v", err)
	}
	// The committed identity answers a staging command with another digest as a conflict.
	if _, err := f.stage(lease, 1, 60, control.RuleModeLive, `{"n":"other"}`, same); faultDetail(err) != "rule_evaluation_conflict" {
		t.Fatalf("staging against a committed identity with another digest: %v", err)
	}
	// The total of one evaluation is bounded.
	e := f.evaluation(1, 240, 1, control.RuleModeLive, `{"n":4}`, bulkConditions(2, 0, 256)...)
	e.Staged = control.MaxRuleEvaluationOutputs - 255
	if _, err := f.eval(lease, e); code(err) != model.Invalid {
		t.Fatalf("an evaluation over the total bound: %v", err)
	}
}

// A retirement suppresses the staged outputs of an unfinalized evaluation too.
func TestRetiredProjectSuppressesStagedOutputs(t *testing.T) {
	f := newRuleFx(t)
	lease := f.lease()
	if _, err := f.eval(lease, f.evaluation(1, 60, 0, control.RuleModeLive, `{"n":1}`, recordingIntent(1))); err != nil {
		t.Fatal(err)
	}
	if _, err := f.stage(lease, 1, 120, control.RuleModeLive, `{"n":2}`, bulkConditions(3, 0, 4)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.del(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.apply(control.RuleCommand{Operation: control.RuleOpRetire, Retire: &control.RuleRetireApply{Project: f.project}}); err != nil {
		t.Fatal(err)
	}
	if got := f.outputs(control.RulePhaseStaged); len(got) != 0 {
		t.Fatalf("%d staged outputs survived the retirement", len(got))
	}
	suppressed := 0
	for _, o := range f.outputs(control.RulePhaseSuppress) {
		if o.Stage != (model.Hash{}) {
			suppressed++
			if bytes.Contains(o.Payload, []byte("condition")) {
				t.Fatalf("suppressed staged output %s kept its payload", o.ID)
			}
		}
	}
	if suppressed != 4 {
		t.Fatalf("%d staged outputs were suppressed, want 4", suppressed)
	}
}
