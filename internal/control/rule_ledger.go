// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync/atomic"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The rule books and the rule outbox are records of the ledger (D108).
//
// A rule evaluation is committed about a hundred times a minute at the Queries gate, and each commit went through the
// whole-state funnel: it decoded the blob of the control state (the rule books are most of it: 17 MB of the 20 MB blob at
// 100 rules, more as the retained evaluations grow), encoded it again, diffed the two encodings, proposed the one record
// that changed and had every voter splice and hash the blob and write it back through bolt (100 MB of pages per commit
// beside 96 MB of rule books, TestARuleCommitCostsWhatItsOwnRecordsCostWhateverTheStateHolds). One worker goroutine serves
// the projects one after the other, so every commit waited for the one before it: 1.7 evaluations a minute against the
// 100 the gate needs.
//
// Once every member of the control group declared protocol 10 (the gate of the compact admission ops, D104) and the
// installation is contracted, one replicated command marks the installation (model.RuleLedgerKey in State.OIDC). Every voter
// applies it by moving the two members out of its blob into two tables of control.db, rule_books (one record per rule,
// keyed "org:project:rule") and rule_outputs (one per outbox entry, keyed "org:project:rule:id"), in the transaction that
// applies it (migrateRules), so the digest a patch names is the same on every voter before and after, as the
// contraction's was (D72). From then on a rule command is an item of the group commit (sparse.go): it reads the records of
// its own rule, runs the handler of the unchanged semantics on them and writes the records that changed, its own command
// record and the revision step, and a voter applies those ops to its tables without reading or writing the blob.
//
// Until the mark is committed the two members are members of the blob, as every release holds them, and a rule command is
// the whole-state transition it always was: a group with a member below protocol 10, an installation that is not contracted
// and a store without the gates keep today's form byte for byte, so the previous release and a voter that declared 9
// interoperate exactly as before. The mark is a one-way point like protocol 10 itself; docs/operations/upgrade.md says so.

// ruleLedgerMark is how the encoding of a state names the mark.
var ruleLedgerMark = []byte(`"` + model.RuleLedgerKey + `"`)

// allScope is every member this file keeps in the ledger.
func (l *ledgerTx) allScope() memberScope {
	if l.rules {
		return scopeAll | scopeRules
	}
	return scopeAll
}

// setRules records in the file whether it keeps the rule facts in the ledger.
func (l *ledgerTx) setRules(on bool) error {
	l.rules = on
	if on {
		return l.ctrl.Put(ledgerRulesKey, []byte{1})
	}
	return l.ctrl.Delete(ledgerRulesKey)
}

// ruleOutputKey is the key of an outbox entry in a file that keeps the rule facts in the ledger: the outputs of one rule
// are one run of keys, and so are those of one project.
func ruleOutputKey(org, project, rule, id model.ID) string {
	return ruleKey(org, project, rule) + ":" + id.String()
}

// ruleOutputPrefix is the prefix of the keys of the outbox entries of one rule.
func ruleOutputPrefix(org, project, rule model.ID) string { return ruleKey(org, project, rule) + ":" }

// ruleOutputKeyIn is the key an outbox entry is stored under in st: its ID in a state that holds the outbox as a member of
// the blob, the key of the ledger in a state of an installation that keeps it there.
func ruleOutputKeyIn(st *State, org, project, rule, id model.ID) string {
	if st.RulesInLedger() {
		return ruleOutputKey(org, project, rule, id)
	}
	return id.String()
}

// commandNamesRuleLedger says whether a control command writes the mark of an installation that keeps the rule facts in the
// ledger. A patch names it in an op on OIDC; a replacement carries it in the state.
func commandNamesRuleLedger(cmd *controlCommand) bool {
	switch {
	case cmd.patch != nil:
		for _, op := range cmd.patch.Ops {
			if len(op.Path) > 0 && op.Path[0] == "OIDC" && (slices.Contains(op.Path, model.RuleLedgerKey) || bytes.Contains(op.Value, ruleLedgerMark)) {
				return true
			}
		}
	case cmd.replacement != nil:
		return cmd.replacement.State.RulesInLedger()
	}
	return false
}

// migrateRules moves the rule books and the rule outbox out of the blob into the ledger, in the transaction that applies the
// command that marked the installation. It does nothing for a file that already keeps them there or whose state does not
// carry the mark. The outbox entries are keyed by their rule from here on (ruleOutputKey); the logical state, its revision
// and its digest are what they were: a voter that applied the same commands holds the same bytes.
func migrateRules(tx *bolt.Tx) error {
	ctrl := tx.Bucket([]byte("control"))
	if ctrl == nil || !ledgerLayout(ctrl) || ctrl.Get(ledgerRulesKey) != nil {
		return nil
	}
	raw, err := stateRaw(ctrl)
	if err != nil {
		return err
	}
	var st State
	if json.Unmarshal(raw, &st) != nil {
		return model.Fail(model.Corrupt)
	}
	if !st.RulesInLedger() {
		return nil
	}
	books, outputs := st.RuleBooks, st.RuleOutputs
	st.RuleBooks, st.RuleOutputs = nil, nil
	whole, err := json.Marshal(st)
	if err != nil {
		return model.Fail(model.Corrupt)
	}
	if err = putStateLayout(ctrl, whole); err != nil {
		return err
	}
	if err = markerFault(ruleMarkerSplit); err != nil {
		return err
	}
	l, err := openLedger(tx)
	if err != nil {
		return err
	}
	for key, rec := range books {
		if err = l.putBook(tableRuleBooks, key, rec); err != nil {
			return err
		}
	}
	for id, rec := range outputs {
		var o RuleOutput
		if json.Unmarshal(rec, &o) != nil {
			return model.Fail(model.Corrupt)
		}
		key := id
		if o.ID != (model.ID{}) {
			key = ruleOutputKey(o.Org, o.Project, o.Rule, o.ID)
		}
		if err = l.putBook(tableRuleOutputs, key, rec); err != nil {
			return err
		}
	}
	if err = l.flush(); err != nil {
		return err
	}
	return l.setRules(true)
}

// The points of the apply of the mark a test stops the process at (ruleMarkerFault): before the move starts, between the blob
// without the rule facts and the tables that hold them (both inside the transaction that applies the command, so a stop
// there leaves the file as it was), and after the transaction committed (so a stop there leaves it moved).
const (
	ruleMarkerBefore = "rule_marker_before"
	ruleMarkerSplit  = "rule_marker_split"
	ruleMarkerAfter  = "rule_marker_after"
)

// ruleMarkerFault is the stop of a crash test at a point of the apply of the mark; nil in every process but a test's.
var ruleMarkerFault atomic.Pointer[func(point string) error]

func markerFault(point string) error {
	if f := ruleMarkerFault.Load(); f != nil {
		return (*f)(point)
	}
	return nil
}

// RuleLayout is where this file keeps the rule facts and the revision of the command that moved them: "blob" and 0 until the
// mark is applied, "ledger" and the revision of the mark after it (0 when the mark names none). The revision is read from the
// state once and kept: the mark never changes. A diagnostic build reports it (registerDiag), so a drill can tell which side of
// the one-way point a voter is on.
func (s *Store) RuleLayout() (layout string, markerIndex uint64) {
	if !s.ruleLedger.Load() {
		return "blob", 0
	}
	if known := s.ruleMarker.Load(); known != 0 {
		return "ledger", known - 1
	}
	var st State
	if s.db.View(func(tx *bolt.Tx) error { return readState(tx.Bucket([]byte("control")), &st) }) != nil {
		return "ledger", 0
	}
	at := st.RulesMarkedAt()
	s.ruleMarker.Store(at + 1)
	return "ledger", at
}

// ensureRuleLedger proposes the mark of the installation when the file may keep the rule facts in the ledger and does not
// yet: every member of the group declared protocol 10 (the compact gate) and the installation is contracted. It is the
// first rule command's cost, once; a store that cannot (the gate is closed, the group does not lead, the proposal was
// refused) leaves the rule command to the whole-state funnel, which is correct in either layout. committed says that this
// call committed the mark, and from is the revision it left: the mark changes no fact, so a command that named from as
// the revision it read still reads the state it meant (transactRule).
func (s *Store) ensureRuleLedger(ctx context.Context) (from model.Revision, committed bool) {
	if s.ruleLedger.Load() || s.repl == nil || !s.layoutLedger.Load() || !s.compactAdmission() {
		return 0, false
	}
	err := s.updateAs(ctx, writerRuleLedgerMark, func(st *State) error {
		if st.RulesInLedger() {
			return errNothingToSettle
		}
		from = st.Revision
		st.MarkRulesInLedger(st.Revision + 1) // the revision this command commits at: the one-way point every voter names alike
		return nil
	})
	if err == nil || errors.Is(err, errNothingToSettle) {
		s.noteLayout()
	}
	return from, err == nil
}

// transactRule commits a rule command as the records of its rule when the file keeps them in the ledger; handled is false
// when it does not (or the command is not one the plan can write as records), and the caller runs the whole-state funnel.
// Only a command the plan can write moves the file: the others (the catalogue, a replay declaration, a retirement) name the
// revision they read, and a command that moved it under them would be refused as stale for nothing. The mark itself is
// such a move for the command that proposes it: a plan ignores the revision, but a command the plan leaves to the funnel
// (a late erasure may apply, the handler wrote an audit) names the revision it read, so it is rebased onto the one the
// mark made when that was the revision it named (cmd is the caller's copy, run by the funnel after this).
func (s *Store) transactRule(ctx context.Context, scope auth.Scope, cmd *Command) (out Result, handled bool, err error) {
	if s.repl == nil || s.handler(KindApplyRuleEvaluation) == nil {
		return Result{}, false, nil
	}
	var c RuleCommand
	if strictPayload(cmd.Payload, &c) != nil {
		return Result{}, false, nil
	}
	if _, rule, ok := ruleCommandTarget(&c); !ok || rule == (model.ID{}) {
		return Result{}, false, nil
	}
	if from, committed := s.ensureRuleLedger(ctx); committed && cmd.ExpectedRevision == from {
		cmd.ExpectedRevision = from + 1
	}
	if !s.ruleLedger.Load() {
		return Result{}, false, nil
	}
	handled, err = s.sparseUpdate(ctx, func(core *State, l *ledgerTx) ([]patchOp, error) {
		return planRuleCommand(scope, *cmd, core, l, &out)
	})
	return out, handled, err
}

// ruleCommandTarget is the project and rule a rule command of the arms a plan writes names.
func ruleCommandTarget(c *RuleCommand) (project, rule model.ID, ok bool) {
	arms := 0
	for _, present := range []bool{c.Evaluation != nil, c.Missed != nil, c.Replay != nil, c.Output != nil, c.Stage != nil, c.Retire != nil, c.Definition != nil} {
		if present {
			arms++
		}
	}
	if arms != 1 {
		return model.ID{}, model.ID{}, false
	}
	switch {
	case c.Operation == RuleOpEvaluation && c.Evaluation != nil:
		return c.Evaluation.Project, c.Evaluation.Rule, true
	case c.Operation == RuleOpMissed && c.Missed != nil:
		return c.Missed.Project, c.Missed.Rule, true
	case c.Operation == RuleOpOutput && c.Output != nil:
		return c.Output.Project, c.Output.Rule, true
	case c.Operation == RuleOpStage && c.Stage != nil:
		return c.Stage.Project, c.Stage.Rule, true
	}
	return model.ID{}, model.ID{}, false // the replay declaration audits, the catalogue and the retirement span rules: the funnel
}

// planRuleCommand is the plan of a rule command: applyRuleEvaluation, the handler every release runs, on a state that holds
// the rule book and the outbox entries of the rule the command names and nothing the handler writes besides, and what it
// left written as records: the book, the entries it added, changed or dropped, and the command's own record. The command
// names no revision (the strict whole-revision compare of the funnel is what made a rule commit lose to every other
// commit): the records it reads are its precondition, judged by the handler (the evaluation's state revision, the
// evaluation identity, the lease), and a plan of a round sees the records the plans before it left.
func planRuleCommand(scope auth.Scope, cmd Command, core *State, l *ledgerTx, out *Result) ([]patchOp, error) {
	if !l.rules {
		return nil, errSparseFallback
	}
	var c RuleCommand
	if strictPayload(cmd.Payload, &c) != nil {
		return nil, errSparseFallback
	}
	project, rule, ok := ruleCommandTarget(&c)
	if !ok || rule == (model.ID{}) {
		return nil, errSparseFallback
	}
	org := scope.OrgID()
	if lateErasureMayApply(core, org, project) {
		return nil, errSparseFallback
	}
	if err := scope.ValidateControlState(*core); err != nil {
		return nil, err
	}
	binding := scope.PrincipalID().String() + ":" + org.String() + ":" + cmd.Kind
	id := cmd.CommandID.String()
	if recorded := l.t[tableCommands].Get([]byte(id)); recorded != nil {
		if string(l.t[tableCommandOwners].Get([]byte(id))) != binding {
			return nil, model.Fail(model.NotFound)
		}
		var v Result
		if json.Unmarshal(recorded, &v) != nil {
			return nil, model.Fail(model.Corrupt)
		}
		*out = v
		return nil, nil
	}
	key := ruleKey(org, project, rule)
	before := l.t[tableRuleBooks].Get([]byte(key))
	held := l.bookRecords(tableRuleOutputs, ruleOutputPrefix(org, project, rule))
	ov := *core
	ov.Audits = nil
	ov.RuleBooks = map[string]json.RawMessage{}
	if before != nil {
		ov.RuleBooks[key] = before
	}
	ov.RuleOutputs = make(map[string]json.RawMessage, len(held))
	for k, v := range held {
		ov.RuleOutputs[k] = v
	}
	effect, err := applyRuleEvaluation(scope, &ov, cmd)
	if err != nil {
		return nil, err
	}
	if len(ov.Audits) != 0 {
		return nil, errSparseFallback
	}
	*out = Result{AffectedIDs: append([]model.ID(nil), effect.AffectedIDs...), Phase: effect.Phase, Revision: core.Revision + 1, Cursor: model.Cursor{Group: core.Installation, Index: model.Uint64(core.Revision + 1)}}
	var ops []patchOp
	if after, ok := ov.RuleBooks[key]; ok {
		if !bytes.Equal(before, after) {
			ops = append(ops, patchOp{Op: opSet, Path: []string{"RuleBooks", key}, Value: after})
		}
	} else if before != nil {
		return nil, errSparseFallback // a handler that drops the book is not one a plan writes
	}
	for k, v := range ov.RuleOutputs {
		if prev, ok := held[k]; !ok || !bytes.Equal(prev, v) {
			ops = append(ops, patchOp{Op: opSet, Path: []string{"RuleOutputs", k}, Value: v})
		}
	}
	for k := range held {
		if _, ok := ov.RuleOutputs[k]; !ok {
			ops = append(ops, patchOp{Op: opDelete, Path: []string{"RuleOutputs", k}})
		}
	}
	result, err := json.Marshal(*out)
	if err != nil {
		return nil, model.Fail(model.Invalid)
	}
	owner, err := json.Marshal(binding)
	if err != nil {
		return nil, model.Fail(model.Invalid)
	}
	ops = append(ops, patchOp{Op: opSet, Path: []string{"Commands", id}, Value: result}, patchOp{Op: opSet, Path: []string{"CommandOwners", id}, Value: owner})
	slices.SortFunc(ops, func(a, b patchOp) int {
		if pathLess(a.Path, b.Path) {
			return -1
		}
		if pathLess(b.Path, a.Path) {
			return 1
		}
		return 0
	})
	return ops, nil
}
