// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

// ruleFx is the real control store (activated single-voter Raft group, real auth
// scopes) with the rule dispatcher bound. Nothing here fakes a fence: leases
// come from the group.
type ruleFx struct {
	*fenceFx
	rule model.ID
}

func newRuleFx(t *testing.T) *ruleFx {
	t.Helper()
	f := &ruleFx{fenceFx: newFenceFx(t), rule: model.NewID()}
	if err := f.store.BindRuleEvaluation(); err != nil {
		t.Fatal(err)
	}
	return f
}

// lease is the group's current fence: the token a scheduler leader holds.
func (f *ruleFx) lease() replica.FenceToken {
	f.t.Helper()
	token, err := f.store.ReplicaGroup().Fence(f.ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	return token
}

func digestOf(payload string) model.Hash { return model.Hash(sha256.Sum256([]byte(payload))) }

func (f *ruleFx) evaluation(version, at, expected uint64, mode, payload string, outputs ...control.RuleOutputIntent) *control.RuleEvaluationApply {
	return &control.RuleEvaluationApply{
		Project: f.project, Rule: f.rule, Version: model.Revision(version), At: model.UnixNano(at), ExpectedStateRevision: model.Revision(expected),
		Mode: mode, Health: control.RuleHealthOK, Digest: digestOf(payload), Payload: json.RawMessage(payload),
		Cursors: []model.Cursor{{Group: model.ID{9}, Index: model.Uint64(at)}}, Outputs: outputs,
	}
}

func recordingIntent(seed byte) control.RuleOutputIntent {
	return control.RuleOutputIntent{ID: model.ID{seed}, Kind: control.RuleOutputRecording, Payload: json.RawMessage(fmt.Sprintf(`{"batch":%d}`, seed)), Inputs: []model.Cursor{{Group: model.ID{9}, Index: 1}}}
}
func conditionIntent(seed byte, notify bool) control.RuleOutputIntent {
	return control.RuleOutputIntent{ID: model.ID{seed}, Kind: control.RuleOutputCondition, Notify: notify, Payload: json.RawMessage(fmt.Sprintf(`{"condition":%d}`, seed)), Inputs: []model.Cursor{}}
}

// apply sends one RuleCommand under a fresh command ID.
func (f *ruleFx) apply(c control.RuleCommand) (control.Result, error) {
	return f.applyAs(model.NewID(), c)
}
func (f *ruleFx) applyAs(id model.ID, c control.RuleCommand) (control.Result, error) {
	f.t.Helper()
	return f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindApplyRuleEvaluation, id, c))
}
func (f *ruleFx) eval(lease replica.FenceToken, e *control.RuleEvaluationApply) (control.Result, error) {
	return f.apply(control.RuleCommand{Operation: control.RuleOpEvaluation, Lease: &lease, Evaluation: e})
}
func (f *ruleFx) book() control.RuleBook {
	f.t.Helper()
	b, ok, err := f.store.RuleBook(f.ctx, f.adminScope(), f.project, f.rule)
	if err != nil || !ok {
		f.t.Fatalf("rule book: found=%v err=%v", ok, err)
	}
	return b
}
func (f *ruleFx) outputs(phase string) []control.RuleOutput {
	f.t.Helper()
	out, err := f.store.RuleOutputs(f.ctx, f.adminScope(), f.project, f.rule, phase, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

func faultDetail(err error) string {
	if fault, ok := err.(*model.Fault); ok {
		return fault.SafeDetail
	}
	return ""
}

// Without the dispatcher a rule command has no durable behavior at all.
func TestRuleEvaluationRequiresBoundDispatcher(t *testing.T) {
	f := newFenceFx(t)
	lease, err := f.store.ReplicaGroup().Fence(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	e := &control.RuleEvaluationApply{Project: f.project, Rule: model.NewID(), Version: 1, At: 60, Mode: control.RuleModeLive, Health: control.RuleHealthOK, Digest: digestOf(`{}`), Payload: json.RawMessage(`{}`)}
	_, err = f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindApplyRuleEvaluation, model.NewID(), control.RuleCommand{Operation: control.RuleOpEvaluation, Lease: &lease, Evaluation: e}))
	if code(err) != model.Unsupported {
		t.Fatalf("an unbound rule dispatcher committed: %v", err)
	}
	if err = f.store.BindRuleEvaluation(); err != nil {
		t.Fatal(err)
	}
	if code(f.store.BindRuleEvaluation()) != model.Conflict {
		t.Fatal("the dispatcher bound twice")
	}
}

// One committed (version, at): replays change nothing, a different payload for
// the same identity is rejected, and the outbox has each intent exactly once.
func TestFenceAndIdempotentRuleEvaluationIdentity(t *testing.T) {
	f := newRuleFx(t)
	lease := f.lease()
	first := f.evaluation(1, 60, 0, control.RuleModeLive, `{"n":1}`, recordingIntent(1), conditionIntent(2, true))
	id := model.NewID()
	res, err := f.applyAs(id, control.RuleCommand{Operation: control.RuleOpEvaluation, Lease: &lease, Evaluation: first})
	if err != nil || res.Phase != "applied" {
		t.Fatalf("first evaluation: %+v %v", res, err)
	}
	if book := f.book(); book.Head != 1 || book.Versions[0].StateRevision != 1 || book.Versions[0].Last.At != 60 {
		t.Fatalf("book after first: %+v", book)
	}
	// Same command ID: the original result, byte for byte, no new transition.
	again, err := f.applyAs(id, control.RuleCommand{Operation: control.RuleOpEvaluation, Lease: &lease, Evaluation: first})
	if err != nil || again.Revision != res.Revision || again.Phase != "applied" {
		t.Fatalf("command replay changed the result: %+v vs %+v (%v)", again, res, err)
	}
	// A new command carrying the identical evaluation: replayed, state untouched.
	other, err := f.eval(lease, first)
	if err != nil || other.Phase != "replayed" {
		t.Fatalf("identical evaluation under a new command: %+v %v", other, err)
	}
	if book := f.book(); book.Versions[0].StateRevision != 1 {
		t.Fatalf("replay advanced the state: %+v", book.Versions[0])
	}
	if got := f.outputs(""); len(got) != 2 {
		t.Fatalf("outbox has %d intents after replays, want 2", len(got))
	}
	// A different payload for the committed identity never overwrites it.
	conflicting := f.evaluation(1, 60, 0, control.RuleModeLive, `{"n":2}`, recordingIntent(3))
	if _, err = f.eval(lease, conflicting); code(err) != model.Conflict || faultDetail(err) != "rule_evaluation_conflict" {
		t.Fatalf("conflicting payload accepted: %v", err)
	}
	book := f.book()
	if !bytes.Equal(compact(t, book.Versions[0].Recent[0].Payload), []byte(`{"n":1}`)) {
		t.Fatalf("committed payload overwritten: %s", book.Versions[0].Recent[0].Payload)
	}
	if len(f.outputs("")) != 2 {
		t.Fatal("conflicting evaluation produced effects")
	}
	// The next evaluation must be computed from the committed state.
	if _, err = f.eval(lease, f.evaluation(1, 120, 0, control.RuleModeLive, `{"n":3}`)); code(err) != model.Conflict || faultDetail(err) != "rule_state_conflict" {
		t.Fatalf("evaluation from an older state accepted: %v", err)
	}
	if _, err = f.eval(lease, f.evaluation(1, 120, 1, control.RuleModeLive, `{"n":3}`)); err != nil {
		t.Fatal(err)
	}
	// Time moves forward only: an unrecorded identity at or before the last one is stale.
	if _, err = f.eval(lease, f.evaluation(1, 30, 2, control.RuleModeLive, `{"n":0}`)); code(err) != model.Stale || faultDetail(err) != "rule_evaluation_out_of_order" {
		t.Fatalf("out-of-order evaluation accepted: %v", err)
	}
}

func compact(t *testing.T, raw json.RawMessage) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := json.Compact(&out, raw); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestFenceRuleEvaluationLeaseAndVersions(t *testing.T) {
	f := newRuleFx(t)
	lease := f.lease()
	if _, err := f.eval(lease, f.evaluation(1, 60, 0, control.RuleModeLive, `{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	// A newer leader commits; the older leader is then fenced out of the rule.
	newer := lease
	newer.Term++
	if _, err := f.eval(newer, f.evaluation(1, 120, 1, control.RuleModeLive, `{"n":2}`, recordingIntent(1))); err != nil {
		t.Fatal(err)
	}
	if _, err := f.eval(lease, f.evaluation(1, 180, 2, control.RuleModeLive, `{"n":3}`)); code(err) != model.Stale || faultDetail(err) != "rule_lease_stale" {
		t.Fatalf("stale lease accepted: %v", err)
	}
	// Every arm is fenced, output updates included.
	staleOutput := control.RuleCommand{Operation: control.RuleOpOutput, Lease: &lease, Output: &control.RuleOutputApply{Project: f.project, Rule: f.rule, Output: model.ID{1}, To: control.RulePhaseSuppress, Reason: "stale worker"}}
	if _, err := f.apply(staleOutput); code(err) != model.Stale {
		t.Fatalf("stale lease updated the outbox: %v", err)
	}
	staleMissed := control.RuleCommand{Operation: control.RuleOpMissed, Lease: &lease, Missed: &control.RuleMissedApply{Project: f.project, Rule: f.rule, Version: 1, From: 130, To: 150, Count: 2, At: 200}}
	if _, err := f.apply(staleMissed); code(err) != model.Stale {
		t.Fatalf("stale lease recorded a missed interval: %v", err)
	}
	// Another group's token, and a zero-term token, are never rule leases.
	foreign := lease
	foreign.Group = model.NewID()
	if _, err := f.eval(foreign, f.evaluation(1, 180, 2, control.RuleModeLive, `{"n":3}`)); code(err) != model.Invalid {
		t.Fatalf("foreign group lease accepted: %v", err)
	}
	zero := lease
	zero.Term = 0
	if _, err := f.eval(zero, f.evaluation(1, 180, 2, control.RuleModeLive, `{"n":3}`)); code(err) != model.Invalid {
		t.Fatalf("zero-term lease accepted: %v", err)
	}
	if book := f.book(); book.Fence == nil || book.Fence.Term != newer.Term || book.Versions[0].StateRevision != 2 {
		t.Fatalf("a rejected command changed the book: %+v", book)
	}
	// A new rule version starts its own record; the old one keeps its history
	// but not its retained payloads, and can no longer evaluate.
	if _, err := f.eval(newer, f.evaluation(2, 240, 0, control.RuleModeLive, `{"v":2}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.eval(newer, f.evaluation(1, 300, 2, control.RuleModeLive, `{"n":4}`)); code(err) != model.Stale || faultDetail(err) != "rule_version_superseded" {
		t.Fatalf("superseded version evaluated: %v", err)
	}
	book := f.book()
	v1, _ := book.Version(1)
	v2, _ := book.Version(2)
	if book.Head != 2 || v1.StateRevision != 2 || v1.Last == nil || v1.Last.At != 120 || len(v1.Recent) != 0 || v2.StateRevision != 1 || len(v2.Recent) != 1 {
		t.Fatalf("version history: head=%d v1=%+v v2=%+v", book.Head, v1, v2)
	}
	// Replaying the old version's last evaluation is still answered from identity.
	if res, err := f.eval(newer, f.evaluation(1, 120, 1, control.RuleModeLive, `{"n":2}`, recordingIntent(1))); err != nil || res.Phase != "replayed" {
		t.Fatalf("old version replay: %+v %v", res, err)
	}
	if _, err := f.eval(newer, f.evaluation(1, 120, 1, control.RuleModeLive, `{"n":9}`)); code(err) != model.Conflict {
		t.Fatalf("old version conflicting replay: %v", err)
	}
}

func TestRuleEvaluationScopeAndShape(t *testing.T) {
	f := newRuleFx(t)
	lease := f.lease()
	ok := f.evaluation(1, 60, 0, control.RuleModeLive, `{"n":1}`)
	// A read scope is not control authority.
	reader, err := f.readScope(f.project)
	if err != nil {
		t.Fatal(err)
	}
	cmd := f.cmd(control.KindApplyRuleEvaluation, model.NewID(), control.RuleCommand{Operation: control.RuleOpEvaluation, Lease: &lease, Evaluation: ok})
	if _, err = f.store.Transact(f.ctx, reader, cmd); code(err) != model.Forbidden {
		t.Fatalf("read scope committed a rule evaluation: %v", err)
	}
	// A project of the org the scope does not name is not found, never "forbidden".
	foreign := *ok
	foreign.Project = f.otherProject
	scoped, err := f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{f.project}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	cmd = f.cmd(control.KindApplyRuleEvaluation, model.NewID(), control.RuleCommand{Operation: control.RuleOpEvaluation, Lease: &lease, Evaluation: &foreign})
	if _, err = f.store.Transact(f.ctx, scoped, cmd); code(err) != model.NotFound {
		t.Fatalf("project-scoped administrator wrote another project: %v", err)
	}
	unknown := *ok
	unknown.Project = model.NewID()
	if _, err = f.eval(lease, &unknown); code(err) != model.NotFound {
		t.Fatalf("unknown project accepted: %v", err)
	}
	bad := map[string]func(e *control.RuleEvaluationApply){
		"digest mismatch":  func(e *control.RuleEvaluationApply) { e.Digest = digestOf(`{"n":2}`) },
		"zero version":     func(e *control.RuleEvaluationApply) { e.Version = 0 },
		"one-byte payload": func(e *control.RuleEvaluationApply) { e.Payload = json.RawMessage(`1`); e.Digest = digestOf(`1`) },
		"unknown mode":     func(e *control.RuleEvaluationApply) { e.Mode = "now" },
		"unknown health":   func(e *control.RuleEvaluationApply) { e.Health = "recovered" },
		"duplicate output": func(e *control.RuleEvaluationApply) {
			e.Outputs = []control.RuleOutputIntent{recordingIntent(1), recordingIntent(1)}
		},
		"notifying recording": func(e *control.RuleEvaluationApply) {
			o := recordingIntent(1)
			o.Notify = true
			e.Outputs = []control.RuleOutputIntent{o}
		},
		"duplicate cursor group": func(e *control.RuleEvaluationApply) {
			e.Cursors = []model.Cursor{{Group: model.ID{1}, Index: 1}, {Group: model.ID{1}, Index: 2}}
		},
	}
	names := make([]string, 0, len(bad))
	for name := range bad {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		e := *ok
		bad[name](&e)
		if _, err = f.eval(lease, &e); code(err) != model.Invalid {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
	// Two arms, or an operation naming the wrong arm, are never interpreted.
	cmd = f.cmd(control.KindApplyRuleEvaluation, model.NewID(), control.RuleCommand{Operation: control.RuleOpEvaluation, Lease: &lease, Evaluation: ok, Missed: &control.RuleMissedApply{Project: f.project, Rule: f.rule}})
	if _, err = f.store.Transact(f.ctx, f.adminScope(), cmd); code(err) != model.Invalid {
		t.Fatalf("two arms accepted: %v", err)
	}
	cmd = f.cmd(control.KindApplyRuleEvaluation, model.NewID(), control.RuleCommand{Operation: control.RuleOpMissed, Lease: &lease, Evaluation: ok})
	if _, err = f.store.Transact(f.ctx, f.adminScope(), cmd); code(err) != model.Invalid {
		t.Fatalf("operation/arm mismatch accepted: %v", err)
	}
	if _, found, err := f.store.RuleBook(f.ctx, f.adminScope(), f.project, f.rule); err != nil || found {
		t.Fatalf("rejected commands left a rule book: found=%v err=%v", found, err)
	}
	// Reads of a project the read scope does not name are indistinguishable from absent.
	if _, _, err = f.store.RuleBook(f.ctx, reader, f.otherProject, f.rule); code(err) != model.NotFound {
		t.Fatalf("read of an unnamed project: %v", err)
	}
}

// Backfilled evaluations can never notify; replay needs a committed, audited
// operator declaration whose window covers the scheduled time.
func TestMissedBackfillAndReplayRuleEvaluation(t *testing.T) {
	f := newRuleFx(t)
	lease := f.lease()
	if _, err := f.eval(lease, f.evaluation(1, 60, 0, control.RuleModeBackfill, `{"n":1}`, conditionIntent(1, true))); code(err) != model.Invalid || faultDetail(err) != "backfill_cannot_notify" {
		t.Fatalf("a backfilled evaluation carried a notifying intent: %v", err)
	}
	if _, err := f.eval(lease, f.evaluation(1, 60, 0, control.RuleModeBackfill, `{"n":1}`, conditionIntent(1, false))); err != nil {
		t.Fatal(err)
	}
	// Replay mode without a declaration is refused whatever the intents say.
	if _, err := f.eval(lease, f.evaluation(1, 120, 1, control.RuleModeReplay, `{"n":2}`, conditionIntent(2, true))); code(err) != model.Forbidden || faultDetail(err) != "replay_not_committed" {
		t.Fatalf("replay without a committed declaration: %v", err)
	}
	// A leader's lease is not an operator's declaration, and the reverse.
	declare := control.RuleCommand{Operation: control.RuleOpReplay, Replay: &control.RuleReplayApply{Project: f.project, Rule: f.rule, From: 100, To: 200, Reason: "reconcile after outage", At: 1000}}
	withLease := declare
	withLease.Lease = &lease
	if _, err := f.apply(withLease); code(err) != model.Invalid {
		t.Fatalf("a replay declaration carried a lease: %v", err)
	}
	if _, err := f.apply(declare); err != nil {
		t.Fatal(err)
	}
	if res, err := f.apply(declare); err != nil || res.Phase != "unchanged" {
		t.Fatalf("declaration not idempotent: %+v %v", res, err)
	}
	if book := f.book(); len(book.Replays) != 1 || book.Replays[0].From != 100 || book.Replays[0].To != 200 || book.Replays[0].Operator == (model.ID{}) {
		t.Fatalf("declaration not recorded: %+v", book.Replays)
	}
	audited := 0
	if err := f.store.View(f.ctx, func(st control.State) error {
		for _, a := range st.Audits {
			if a.Action == "rules.operator_replay" {
				audited++
			}
		}
		return nil
	}); err != nil || audited != 1 {
		t.Fatalf("operator replay audited %d times: %v", audited, err)
	}
	// Inside the window replay may notify; outside it, still refused.
	if _, err := f.eval(lease, f.evaluation(1, 120, 1, control.RuleModeReplay, `{"n":2}`, conditionIntent(2, true))); err != nil {
		t.Fatal(err)
	}
	if _, err := f.eval(lease, f.evaluation(1, 300, 2, control.RuleModeReplay, `{"n":3}`, conditionIntent(3, true))); code(err) != model.Forbidden {
		t.Fatalf("replay outside its declared window: %v", err)
	}
	if got := f.outputs(control.RulePhasePending); len(got) != 2 || got[0].Notify || !got[1].Notify || got[0].Mode != control.RuleModeBackfill || got[1].Mode != control.RuleModeReplay {
		t.Fatalf("outbox modes: %+v", got)
	}
	// A missed interval is evidence, idempotent by its identity.
	missed := control.RuleCommand{Operation: control.RuleOpMissed, Lease: &lease, Missed: &control.RuleMissedApply{Project: f.project, Rule: f.rule, Version: 1, From: 180, To: 240, Count: 2, At: 300}}
	if _, err := f.apply(missed); err != nil {
		t.Fatal(err)
	}
	if res, err := f.apply(missed); err != nil || res.Phase != "unchanged" {
		t.Fatalf("missed record not idempotent: %+v %v", res, err)
	}
	conflict := missed
	conflict.Missed = &control.RuleMissedApply{Project: f.project, Rule: f.rule, Version: 1, From: 180, To: 240, Count: 3, At: 300}
	if _, err := f.apply(conflict); code(err) != model.Conflict {
		t.Fatalf("a different count for one missed interval: %v", err)
	}
	if book := f.book(); len(book.Missed) != 1 || book.Missed[0].Count != 2 || book.Versions[0].StateRevision != 2 {
		t.Fatalf("missed record changed the evaluation state: %+v", book)
	}
}

func TestRecordingRuleOutputLifecycle(t *testing.T) {
	f := newRuleFx(t)
	lease := f.lease()
	if _, err := f.eval(lease, f.evaluation(1, 60, 0, control.RuleModeLive, `{"n":1}`, recordingIntent(1), recordingIntent(2), conditionIntent(3, true))); err != nil {
		t.Fatal(err)
	}
	receipt := model.Cursor{Group: model.ID{7}, Index: 11}
	hash := digestOf("batch-1")
	update := func(id byte, to string, r *model.Cursor, h *model.Hash, reason string) (control.Result, error) {
		return f.apply(control.RuleCommand{Operation: control.RuleOpOutput, Lease: &lease, Output: &control.RuleOutputApply{Project: f.project, Rule: f.rule, Output: model.ID{id}, To: to, Receipt: r, Hash: h, Reason: reason}})
	}
	if _, err := update(1, control.RulePhaseAdmitted, nil, nil, ""); code(err) != model.Invalid {
		t.Fatalf("admission without a receipt: %v", err)
	}
	if _, err := update(1, control.RulePhaseAdmitted, &receipt, &hash, ""); err != nil {
		t.Fatal(err)
	}
	if res, err := update(1, control.RulePhaseAdmitted, &receipt, &hash, ""); err != nil || res.Phase != "unchanged" {
		t.Fatalf("admission not idempotent: %+v %v", res, err)
	}
	other := model.Cursor{Group: model.ID{7}, Index: 12}
	if _, err := update(1, control.RulePhaseAdmitted, &other, &hash, ""); code(err) != model.Conflict {
		t.Fatalf("a second receipt for one intent: %v", err)
	}
	if _, err := update(1, control.RulePhaseFinalized, &other, &hash, ""); code(err) != model.Conflict {
		t.Fatalf("finalized with another receipt: %v", err)
	}
	if _, err := update(1, control.RulePhaseSuppress, nil, nil, "obsolete"); code(err) != model.Conflict {
		t.Fatalf("an admitted intent was suppressed: %v", err)
	}
	if _, err := update(1, control.RulePhaseFinalized, &receipt, &hash, ""); err != nil {
		t.Fatal(err)
	}
	// A late duplicate of the earlier step is a no-op, not a regression.
	if res, err := update(1, control.RulePhaseAdmitted, &receipt, &hash, ""); err != nil || res.Phase != "unchanged" {
		t.Fatalf("late admission duplicate: %+v %v", res, err)
	}
	if _, err := update(2, control.RulePhaseSuppress, nil, nil, ""); code(err) != model.Invalid {
		t.Fatalf("suppression without a reason: %v", err)
	}
	if _, err := update(2, control.RulePhaseSuppress, nil, nil, "project retired"); err != nil {
		t.Fatal(err)
	}
	if _, err := update(2, control.RulePhaseFinalized, &receipt, &hash, ""); code(err) != model.Conflict {
		t.Fatalf("a suppressed intent was finalized: %v", err)
	}
	// A condition output is finalized by its consumer without a data receipt.
	if _, err := update(3, control.RulePhaseAdmitted, &receipt, &hash, ""); code(err) != model.Invalid {
		t.Fatalf("a condition was receipted: %v", err)
	}
	if _, err := update(3, control.RulePhaseFinalized, nil, nil, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := update(99, control.RulePhaseFinalized, nil, nil, ""); code(err) != model.NotFound {
		t.Fatalf("unknown output: %v", err)
	}
	if got := f.outputs(control.RulePhasePending); len(got) != 0 {
		t.Fatalf("pending after settling everything: %+v", got)
	}
	settled := f.outputs(control.RulePhaseFinalized)
	if len(settled) != 2 || settled[0].Receipt == nil || *settled[0].Receipt != receipt || *settled[0].Hash != hash || len(settled[0].Inputs) != 1 {
		t.Fatalf("finalized provenance: %+v", settled)
	}
	if sup := f.outputs(control.RulePhaseSuppress); len(sup) != 1 || sup[0].Reason != "project retired" {
		t.Fatalf("suppressed: %+v", sup)
	}
}

// A committed deletion that covers an intent's origin makes it obsolete at read.
func TestRuleOutputObsoleteAfterDeletion(t *testing.T) {
	f := newRuleFx(t)
	lease := f.lease()
	at := f.now.UnixNano()
	if _, err := f.eval(lease, f.evaluation(1, uint64(at), 0, control.RuleModeLive, `{"n":1}`, recordingIntent(1))); err != nil {
		t.Fatal(err)
	}
	if got := f.outputs(""); len(got) != 1 || got[0].Obsolete {
		t.Fatalf("obsolete before any deletion: %+v", got)
	}
	if _, _, err := f.del(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: model.UnixNano(at - 1000), End: model.UnixNano(at + 1000)}); err != nil {
		t.Fatal(err)
	}
	if got := f.outputs(""); len(got) != 1 || !got[0].Obsolete {
		t.Fatalf("an intent whose origin was deleted stayed releasable: %+v", got)
	}
}

// semantic reduces the committed rule state to what must be identical however
// the same evaluations were retried. Control revisions, and the identities that
// belong to one fixture (organization, project, group, operator), are the only
// things that legitimately differ between two stores.
func semantic(t *testing.T, st control.State) string {
	t.Helper()
	var books []control.RuleBook
	for _, raw := range st.RuleBooks {
		var b control.RuleBook
		if err := json.Unmarshal(raw, &b); err != nil {
			t.Fatal(err)
		}
		b.Org, b.Project = model.ID{1}, model.ID{2}
		if b.Fence != nil {
			fence := *b.Fence
			fence.Group = model.ID{3}
			b.Fence = &fence
		}
		for i := range b.Versions {
			if b.Versions[i].Last != nil {
				b.Versions[i].Last.Revision = 0
			}
			for j := range b.Versions[i].Recent {
				b.Versions[i].Recent[j].Revision = 0
			}
		}
		for i := range b.Replays {
			b.Replays[i].Revision = 0
			b.Replays[i].Operator = model.ID{4}
		}
		books = append(books, b)
	}
	sort.Slice(books, func(i, j int) bool { return books[i].Rule.String() < books[j].Rule.String() })
	var outputs []control.RuleOutput
	for _, raw := range st.RuleOutputs {
		var o control.RuleOutput
		if err := json.Unmarshal(raw, &o); err != nil {
			t.Fatal(err)
		}
		o.Created, o.Org, o.Project = 0, model.ID{1}, model.ID{2}
		outputs = append(outputs, o)
	}
	sort.Slice(outputs, func(i, j int) bool { return outputs[i].ID.String() < outputs[j].ID.String() })
	raw, err := json.Marshal(struct {
		Books   []control.RuleBook
		Outputs []control.RuleOutput
	}{books, outputs})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func (f *ruleFx) semantic() string {
	f.t.Helper()
	var out string
	if err := f.store.View(f.ctx, func(st control.State) error { out = semantic(f.t, st); return nil }); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// Two stores receive the same evaluations: one in order, one with early, late
// and duplicated retries interleaved. Both must end in the same state.
func TestRuleEvaluationDeterministicUnderReorderedRetries(t *testing.T) {
	type step struct {
		version, at, expected uint64
		payload               string
		outputs               []control.RuleOutputIntent
	}
	steps := []step{
		{1, 60, 0, `{"n":1}`, []control.RuleOutputIntent{recordingIntent(1)}},
		{1, 120, 1, `{"n":2}`, []control.RuleOutputIntent{conditionIntent(2, true)}},
		{1, 180, 2, `{"n":3}`, []control.RuleOutputIntent{recordingIntent(3), conditionIntent(4, false)}},
	}
	run := func(order []int) string {
		f := newRuleFx(t)
		f.rule = model.ID{0xaa}
		lease := f.lease()
		for _, i := range order {
			s := steps[i]
			e := f.evaluation(s.version, s.at, s.expected, control.RuleModeLive, s.payload, s.outputs...)
			if _, err := f.eval(lease, e); err != nil {
				// An out-of-order first delivery is rejected; the in-order one lands.
				if code(err) != model.Conflict && code(err) != model.Stale {
					t.Fatal(err)
				}
			}
		}
		return f.semantic()
	}
	ordered := run([]int{0, 1, 2})
	// Step 2 arrives before step 1 (rejected, retried later); 0 and 1 are
	// duplicated after they committed; 2 is retried after it committed.
	reordered := run([]int{0, 2, 1, 0, 2, 1, 0, 2, 2})
	if ordered != reordered {
		t.Fatalf("state depends on retry order:\n%s\n%s", ordered, reordered)
	}
}

// The rule state survives restart and a control snapshot import byte for byte,
// and a restarted store still recognizes committed evaluations.
func TestRuleEvaluationSurvivesRestartAndSnapshotImport(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	now := time.Unix(1_800_000_000, 0)
	open := func() (*control.Store, *auth.Service) {
		store, err := control.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		svc, err := auth.NewService(auth.AuthDependencies{Control: store, Now: func() time.Time { return now }})
		if err != nil {
			store.Close()
			t.Fatal(err)
		}
		if err = store.EnableSingle(ctx, filepath.Join(dir, "raft-control")); err != nil {
			store.Close()
			t.Fatal(err)
		}
		if err = store.BindRuleEvaluation(); err != nil {
			store.Close()
			t.Fatal(err)
		}
		return store, svc
	}
	store, svc := open()
	boot, _ := store.BootstrapToken()
	session, err := svc.Bootstrap(ctx, boot, "owner@example.test", "a long test password 2026")
	if err != nil {
		t.Fatal(err)
	}
	token := session.Token
	cred, err := svc.Authenticate(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	org, project, rule := model.NewID(), model.NewID(), model.NewID()
	admin := func(kind string, p auth.AdminPayload) {
		var revision model.Revision
		_ = store.View(ctx, func(st control.State) error { revision = st.Revision; return nil })
		raw, _ := json.Marshal(p)
		if _, err := svc.AdminCommand(ctx, cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); err != nil {
			t.Fatal(kind, err)
		}
	}
	admin("create_org", auth.AdminPayload{Name: "restart", Reason: "fixture"})
	admin("create_project", auth.AdminPayload{ID: project, Name: "p1", Reason: "fixture"})
	send := func(store *control.Store, svc *auth.Service, cred auth.Credential, id model.ID, c control.RuleCommand) (control.Result, error) {
		scope, err := svc.Authorize(ctx, cred, org, nil, auth.OrgAdmin)
		if err != nil {
			t.Fatal(err)
		}
		var revision model.Revision
		_ = store.View(ctx, func(st control.State) error { revision = st.Revision; return nil })
		raw, _ := json.Marshal(c)
		return store.Transact(ctx, scope, control.Command{CommandID: id, ExpectedRevision: revision, Kind: string(control.KindApplyRuleEvaluation), Payload: raw})
	}
	lease, err := store.ReplicaGroup().Fence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(at, expected uint64, payload string, outs ...control.RuleOutputIntent) control.RuleCommand {
		return control.RuleCommand{Operation: control.RuleOpEvaluation, Lease: &lease, Evaluation: &control.RuleEvaluationApply{Project: project, Rule: rule, Version: 1, At: model.UnixNano(at), ExpectedStateRevision: model.Revision(expected), Mode: control.RuleModeLive, Health: control.RuleHealthOK, Digest: digestOf(payload), Payload: json.RawMessage(payload), Cursors: []model.Cursor{{Group: model.ID{9}, Index: model.Uint64(at)}}, Outputs: outs}}
	}
	id1 := model.NewID()
	first, err := send(store, svc, cred, id1, mk(60, 0, `{"n":1}`, recordingIntent(1)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = send(store, svc, cred, model.NewID(), mk(120, 1, `{"n":2}`, conditionIntent(2, true))); err != nil {
		t.Fatal(err)
	}
	var before string
	if err = store.View(ctx, func(st control.State) error { before = semantic(t, st); return nil }); err != nil {
		t.Fatal(err)
	}
	// Snapshot import: the real control snapshot, restored into a fresh store.
	seed, _, err := store.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	imported, err := control.OpenSeed(filepath.Join(t.TempDir(), "imported"), seed)
	if err != nil {
		t.Fatal(err)
	}
	var restored string
	if err = imported.View(ctx, func(st control.State) error { restored = semantic(t, st); return nil }); err != nil {
		t.Fatal(err)
	}
	imported.Close()
	if restored != before {
		t.Fatalf("snapshot import changed the rule state:\n%s\n%s", before, restored)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	// Restart: same state, and the committed command is still answered once.
	store, svc = open()
	defer store.Close()
	cred, err = svc.Authenticate(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	var after string
	if err = store.View(ctx, func(st control.State) error { after = semantic(t, st); return nil }); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("restart changed the rule state:\n%s\n%s", before, after)
	}
	lease, err = store.ReplicaGroup().Fence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	again, err := send(store, svc, cred, id1, mk(60, 0, `{"n":1}`, recordingIntent(1)))
	if err != nil || again.Revision != first.Revision {
		t.Fatalf("committed command not recognized after restart: %+v vs %+v (%v)", again, first, err)
	}
	// The restarted group's lease is newer; the pre-restart term is now stale for the rule.
	stale := mk(180, 2, `{"n":3}`)
	if _, err = send(store, svc, cred, model.NewID(), mk(180, 2, `{"n":3}`)); err != nil {
		t.Fatal(err)
	}
	old := *stale.Lease
	old.Term--
	stale.Lease = &old
	if _, err = send(store, svc, cred, model.NewID(), stale); code(err) != model.Stale && code(err) != model.Conflict {
		t.Fatalf("a pre-restart lease committed: %v", err)
	}
}
