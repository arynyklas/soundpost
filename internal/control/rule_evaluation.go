// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sort"
	"strconv"

	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

// This file is the C05 half of C07 rule evaluation: the KindApplyRuleEvaluation
// dispatcher. It stores only leaf DTOs. The evaluated state, the committed
// evaluation and every output payload are opaque JSON that the rules package
// writes and its read adapter decodes; control never imports the rules package
// and never interprets a rule. What control owns, atomically in one command:
//
//   - the fence: a lease older than the highest one the rule has accepted is
//     stale, and a lease of another group is never a rule lease;
//   - the version: a rule version lower than one already evaluated is stale, and
//     a new version starts its own immutable record;
//   - the evaluation identity (version, at): committed once, replayed verbatim,
//     and a different payload for the same identity is a conflict;
//   - the state compare-and-set: an evaluation computed from an older state is
//     rejected, never merged;
//   - the internal output outbox: recording and condition intents created in the
//     same transition as the evaluation, advanced by fenced output updates.
//
// The outbox is deliberately not an external-notification Delivery.

// RuleCommand is the closed KindApplyRuleEvaluation payload: exactly one arm,
// the one named by Operation. Lease is required by every arm except the
// operator's replay declaration, which is made by an administrator, not by the
// scheduler leader.
type RuleCommand struct {
	Operation  string               `json:"operation"`
	Lease      *replica.FenceToken  `json:"lease,omitempty"`
	Evaluation *RuleEvaluationApply `json:"evaluation,omitempty"`
	Missed     *RuleMissedApply     `json:"missed,omitempty"`
	Replay     *RuleReplayApply     `json:"replay,omitempty"`
	Output     *RuleOutputApply     `json:"output,omitempty"`
}

// The operations of a RuleCommand.
const (
	RuleOpEvaluation = "evaluation"
	RuleOpMissed     = "missed_interval"
	RuleOpReplay     = "operator_replay"
	RuleOpOutput     = "output"
)

// How an evaluation relates to its scheduled time. Only live and an explicitly
// committed replay may carry notifying condition intents.
const (
	RuleModeLive     = "live"
	RuleModeBackfill = "backfill"
	RuleModeReplay   = "replay"
)

// Input health of an evaluation.
const (
	RuleHealthOK      = "ok"
	RuleHealthUnknown = "unknown"
	RuleHealthError   = "error"
)

// Output kinds and phases.
const (
	RuleOutputRecording = "recording"
	RuleOutputCondition = "condition"

	RulePhasePending   = "pending"
	RulePhaseAdmitted  = "admitted"
	RulePhaseFinalized = "finalized"
	RulePhaseSuppress  = "suppressed"
)

const (
	maxRuleEvaluationBytes = 1 << 20
	maxRuleOutputBytes     = 1 << 20
	maxRuleOutputs         = 256
	maxRuleCursors         = 256
	maxRuleRecent          = 16
	maxRuleMissed          = 16
	maxRuleReplays         = 16
	maxRuleSettledOutputs  = 256
)

// RuleEvaluationApply commits one evaluation: its identity (rule, version, at),
// the opaque committed payload and its digest, the state revision it was
// computed from, and the outputs it produced.
type RuleEvaluationApply struct {
	Project model.ID       `json:"project"`
	Rule    model.ID       `json:"rule"`
	Version model.Revision `json:"version"`
	At      model.UnixNano `json:"at_ns"`
	// ExpectedStateRevision is the number of evaluations already applied to this
	// version (0 for a version's first). A mismatch is a conflict, never a merge.
	ExpectedStateRevision model.Revision `json:"expected_state_revision"`
	Mode                  string         `json:"mode"`
	Health                string         `json:"health"`
	// Digest is the SHA-256 of Payload; control verifies it so a replay can be
	// told from a conflicting payload without interpreting either.
	Digest  model.Hash         `json:"digest"`
	Payload json.RawMessage    `json:"payload"`
	Cursors []model.Cursor     `json:"cursors"`
	Outputs []RuleOutputIntent `json:"outputs"`
}

// RuleOutputIntent is one internal output created by an evaluation.
type RuleOutputIntent struct {
	ID      model.ID        `json:"id"`
	Kind    string          `json:"kind"`
	Signal  model.Kind      `json:"signal,omitempty"`
	Notify  bool            `json:"notify,omitempty"`
	Payload json.RawMessage `json:"payload"`
	Inputs  []model.Cursor  `json:"inputs"`
}

// RuleMissedApply records evaluation grid points [From, To] that were not
// evaluated on time. It is evidence, not a state transition.
type RuleMissedApply struct {
	Project model.ID       `json:"project"`
	Rule    model.ID       `json:"rule"`
	Version model.Revision `json:"version"`
	From    model.UnixNano `json:"from_ns"`
	To      model.UnixNano `json:"to_ns"`
	Count   model.Uint64   `json:"count"`
	At      model.UnixNano `json:"at_ns"`
}

// RuleReplayApply is the explicit operator replay mode: late evaluations whose
// scheduled time lies in [From, To] may then carry notifying condition intents.
type RuleReplayApply struct {
	Project model.ID       `json:"project"`
	Rule    model.ID       `json:"rule"`
	From    model.UnixNano `json:"from_ns"`
	To      model.UnixNano `json:"to_ns"`
	Reason  string         `json:"reason"`
	At      model.UnixNano `json:"at_ns"`
}

// RuleOutputApply advances one outbox record. pending->admitted records the
// durable data-group receipt; pending|admitted->finalized completes it;
// pending->suppressed retires an obsolete intent without data admission. A
// repeated identical update is idempotent; a different one is a conflict.
type RuleOutputApply struct {
	Project model.ID      `json:"project"`
	Rule    model.ID      `json:"rule"`
	Output  model.ID      `json:"output"`
	To      string        `json:"to"`
	Receipt *model.Cursor `json:"receipt,omitempty"`
	Hash    *model.Hash   `json:"receipt_hash,omitempty"`
	Reason  string        `json:"reason,omitempty"`
}

// RuleEvaluationRecord is the identity of one committed evaluation. Payload is
// retained for the newest evaluations of the newest version only.
type RuleEvaluationRecord struct {
	At       model.UnixNano  `json:"at_ns"`
	Digest   model.Hash      `json:"digest"`
	Revision model.Revision  `json:"revision"`
	Mode     string          `json:"mode"`
	Health   string          `json:"health"`
	Cursors  []model.Cursor  `json:"cursors"`
	Payload  json.RawMessage `json:"payload,omitempty"`
}

// RuleVersionRecord is the immutable per-version history. A later version never
// edits an earlier one apart from releasing its retained payloads.
type RuleVersionRecord struct {
	Version       model.Revision         `json:"version"`
	StateRevision model.Revision         `json:"state_revision"`
	Last          *RuleEvaluationRecord  `json:"last,omitempty"`
	Recent        []RuleEvaluationRecord `json:"recent,omitempty"`
}

// RuleMissedRecord and RuleReplayWindow are the committed missed-interval facts
// and operator replay declarations of one rule.
type RuleMissedRecord struct {
	Version model.Revision `json:"version"`
	From    model.UnixNano `json:"from_ns"`
	To      model.UnixNano `json:"to_ns"`
	Count   model.Uint64   `json:"count"`
	At      model.UnixNano `json:"at_ns"`
}
type RuleReplayWindow struct {
	From     model.UnixNano `json:"from_ns"`
	To       model.UnixNano `json:"to_ns"`
	Reason   string         `json:"reason"`
	Operator model.ID       `json:"operator"`
	At       model.UnixNano `json:"at_ns"`
	Revision model.Revision `json:"revision"`
}

// RuleBook is everything control holds for one rule ID.
type RuleBook struct {
	Org      model.ID            `json:"org"`
	Project  model.ID            `json:"project"`
	Rule     model.ID            `json:"rule"`
	Fence    *replica.FenceToken `json:"fence,omitempty"`
	Head     model.Revision      `json:"head"`
	Versions []RuleVersionRecord `json:"versions"`
	Missed   []RuleMissedRecord  `json:"missed,omitempty"`
	Replays  []RuleReplayWindow  `json:"replays,omitempty"`
}

// Version returns the record of one rule version.
func (b RuleBook) Version(v model.Revision) (RuleVersionRecord, bool) {
	for _, r := range b.Versions {
		if r.Version == v {
			return r, true
		}
	}
	return RuleVersionRecord{}, false
}

// RuleOutput is one internal output outbox record. Obsolete is computed at read
// from the committed deletion and retirement facts: an obsolete intent must be
// suppressed, never released.
type RuleOutput struct {
	ID       model.ID        `json:"id"`
	Org      model.ID        `json:"org"`
	Project  model.ID        `json:"project"`
	Rule     model.ID        `json:"rule"`
	Version  model.Revision  `json:"version"`
	At       model.UnixNano  `json:"at_ns"`
	Kind     string          `json:"kind"`
	Signal   model.Kind      `json:"signal"`
	Notify   bool            `json:"notify,omitempty"`
	Mode     string          `json:"mode"`
	Phase    string          `json:"phase"`
	Digest   model.Hash      `json:"digest"`
	Payload  json.RawMessage `json:"payload"`
	Inputs   []model.Cursor  `json:"inputs"`
	Receipt  *model.Cursor   `json:"receipt,omitempty"`
	Hash     *model.Hash     `json:"receipt_hash,omitempty"`
	Reason   string          `json:"reason,omitempty"`
	Created  model.Revision  `json:"created"`
	Obsolete bool            `json:"obsolete,omitempty"`
}

// BindRuleEvaluation installs the KindApplyRuleEvaluation dispatcher on this
// Store only, like the other Bind* methods; it is a conflict to bind twice.
func (s *Store) BindRuleEvaluation() error {
	return s.RegisterHandler(KindApplyRuleEvaluation, applyRuleEvaluation)
}

func ruleKey(org, project, rule model.ID) string {
	return org.String() + ":" + project.String() + ":" + rule.String()
}

func ruleFault(code model.Code, detail string) error {
	f := model.Fail(code)
	f.SafeDetail = detail
	return f
}

// fenceBefore orders two leases of one group: by election term, then membership
// revision.
func fenceBefore(a, b replica.FenceToken) bool {
	return a.Term < b.Term || a.Term == b.Term && a.Revision < b.Revision
}

func loadRuleBook(st *State, key string) (RuleBook, bool, error) {
	raw, ok := st.RuleBooks[key]
	if !ok {
		return RuleBook{}, false, nil
	}
	var b RuleBook
	if err := json.Unmarshal(raw, &b); err != nil {
		return RuleBook{}, false, model.Fail(model.Corrupt)
	}
	return b, true, nil
}

func storeRuleBook(st *State, key string, b RuleBook) error {
	raw, err := json.Marshal(b)
	if err != nil {
		return model.Fail(model.Invalid)
	}
	if st.RuleBooks == nil {
		st.RuleBooks = map[string]json.RawMessage{}
	}
	st.RuleBooks[key] = raw
	return nil
}

func loadRuleOutput(st *State, id model.ID) (RuleOutput, bool, error) {
	raw, ok := st.RuleOutputs[id.String()]
	if !ok {
		return RuleOutput{}, false, nil
	}
	var o RuleOutput
	if err := json.Unmarshal(raw, &o); err != nil {
		return RuleOutput{}, false, model.Fail(model.Corrupt)
	}
	return o, true, nil
}

func storeRuleOutput(st *State, o RuleOutput) error {
	raw, err := json.Marshal(o)
	if err != nil {
		return model.Fail(model.Invalid)
	}
	if st.RuleOutputs == nil {
		st.RuleOutputs = map[string]json.RawMessage{}
	}
	st.RuleOutputs[o.ID.String()] = raw
	return nil
}

func validRuleCursors(in []model.Cursor) bool {
	if len(in) > maxRuleCursors {
		return false
	}
	seen := make(map[model.ID]bool, len(in))
	for _, c := range in {
		if c.Group == (model.ID{}) || seen[c.Group] {
			return false
		}
		seen[c.Group] = true
	}
	return true
}

func applyRuleEvaluation(scope auth.Scope, st *State, cmd Command) (Effect, error) {
	var c RuleCommand
	if err := strictPayload(cmd.Payload, &c); err != nil {
		return Effect{}, err
	}
	arms := 0
	for _, present := range []bool{c.Evaluation != nil, c.Missed != nil, c.Replay != nil, c.Output != nil} {
		if present {
			arms++
		}
	}
	if arms != 1 {
		return Effect{}, model.Fail(model.Invalid)
	}
	var project, rule model.ID
	switch {
	case c.Operation == RuleOpEvaluation && c.Evaluation != nil:
		project, rule = c.Evaluation.Project, c.Evaluation.Rule
	case c.Operation == RuleOpMissed && c.Missed != nil:
		project, rule = c.Missed.Project, c.Missed.Rule
	case c.Operation == RuleOpReplay && c.Replay != nil:
		project, rule = c.Replay.Project, c.Replay.Rule
	case c.Operation == RuleOpOutput && c.Output != nil:
		project, rule = c.Output.Project, c.Output.Rule
	default:
		return Effect{}, model.Fail(model.Invalid)
	}
	org := scope.OrgID()
	if rule == (model.ID{}) {
		return Effect{}, model.Fail(model.Invalid)
	}
	if err := releaseScope(scope, st, org, project); err != nil {
		return Effect{}, err
	}
	key := ruleKey(org, project, rule)
	book, exists, err := loadRuleBook(st, key)
	if err != nil {
		return Effect{}, err
	}
	if !exists {
		book = RuleBook{Org: org, Project: project, Rule: rule}
	}
	if c.Operation != RuleOpReplay {
		if c.Lease == nil || c.Lease.Group != st.Installation || c.Lease.Term == 0 {
			return Effect{}, model.Fail(model.Invalid)
		}
		if book.Fence != nil && fenceBefore(*c.Lease, *book.Fence) {
			return Effect{}, ruleFault(model.Stale, "rule_lease_stale")
		}
	} else if c.Lease != nil {
		return Effect{}, model.Fail(model.Invalid)
	}
	var effect Effect
	switch c.Operation {
	case RuleOpEvaluation:
		effect, err = applyRuleEvaluationArm(st, &book, *c.Evaluation)
	case RuleOpMissed:
		effect, err = applyRuleMissedArm(&book, *c.Missed)
	case RuleOpReplay:
		effect, err = applyRuleReplayArm(scope, st, cmd, &book, *c.Replay)
	default:
		effect, err = applyRuleOutputArm(st, &book, *c.Output)
	}
	if err != nil {
		return Effect{}, err
	}
	if c.Lease != nil && effect.Phase != "replayed" && effect.Phase != "unchanged" {
		lease := *c.Lease
		book.Fence = &lease
	}
	if err = storeRuleBook(st, key, book); err != nil {
		return Effect{}, err
	}
	return effect, nil
}

func applyRuleEvaluationArm(st *State, book *RuleBook, e RuleEvaluationApply) (Effect, error) {
	if e.Version == 0 || e.At < 0 || e.Digest == (model.Hash{}) || len(e.Payload) < 2 || len(e.Payload) > maxRuleEvaluationBytes || !json.Valid(e.Payload) ||
		model.Hash(sha256.Sum256(e.Payload)) != e.Digest || !validRuleCursors(e.Cursors) || len(e.Outputs) > maxRuleOutputs {
		return Effect{}, model.Fail(model.Invalid)
	}
	switch e.Mode {
	case RuleModeLive, RuleModeBackfill, RuleModeReplay:
	default:
		return Effect{}, model.Fail(model.Invalid)
	}
	switch e.Health {
	case RuleHealthOK, RuleHealthUnknown, RuleHealthError:
	default:
		return Effect{}, model.Fail(model.Invalid)
	}
	ids := make(map[model.ID]bool, len(e.Outputs))
	for _, o := range e.Outputs {
		if o.ID == (model.ID{}) || ids[o.ID] || len(o.Payload) < 2 || len(o.Payload) > maxRuleOutputBytes || !json.Valid(o.Payload) || !validRuleCursors(o.Inputs) {
			return Effect{}, model.Fail(model.Invalid)
		}
		ids[o.ID] = true
		if o.Kind != RuleOutputRecording && o.Kind != RuleOutputCondition || o.Signal != "" && !o.Signal.Valid() || o.Notify && o.Kind != RuleOutputCondition {
			return Effect{}, model.Fail(model.Invalid)
		}
		// A backfilled evaluation can never notify: retroactive live notification
		// needs the explicit replay mode, which needs a committed declaration.
		if o.Notify && e.Mode == RuleModeBackfill {
			return Effect{}, ruleFault(model.Invalid, "backfill_cannot_notify")
		}
	}
	idx := -1
	for i := range book.Versions {
		if book.Versions[i].Version == e.Version {
			idx = i
		}
	}
	// Replay of an applied identity: the committed payload wins. The same digest is
	// a no-op; any other payload for (version, at) is a conflict.
	if idx >= 0 {
		v := book.Versions[idx]
		var known *RuleEvaluationRecord
		if v.Last != nil && v.Last.At == e.At {
			known = v.Last
		}
		for i := range v.Recent {
			if v.Recent[i].At == e.At {
				known = &v.Recent[i]
			}
		}
		if known != nil {
			if known.Digest != e.Digest {
				return Effect{}, ruleFault(model.Conflict, "rule_evaluation_conflict")
			}
			return Effect{AffectedIDs: []model.ID{book.Rule}, Phase: "replayed"}, nil
		}
	}
	if e.Version < book.Head {
		return Effect{}, ruleFault(model.Stale, "rule_version_superseded")
	}
	if idx >= 0 && book.Versions[idx].Last != nil && e.At <= book.Versions[idx].Last.At {
		return Effect{}, ruleFault(model.Stale, "rule_evaluation_out_of_order")
	}
	var have model.Revision
	if idx >= 0 {
		have = book.Versions[idx].StateRevision
	}
	if e.ExpectedStateRevision != have {
		return Effect{}, ruleFault(model.Conflict, "rule_state_conflict")
	}
	if e.Mode == RuleModeReplay {
		covered := false
		for _, w := range book.Replays {
			if w.From <= e.At && e.At <= w.To {
				covered = true
			}
		}
		if !covered {
			return Effect{}, ruleFault(model.Forbidden, "replay_not_committed")
		}
	}
	for _, o := range e.Outputs {
		if _, ok, err := loadRuleOutput(st, o.ID); err != nil {
			return Effect{}, err
		} else if ok {
			return Effect{}, ruleFault(model.Conflict, "rule_output_exists")
		}
	}
	if idx < 0 {
		book.Versions = append(book.Versions, RuleVersionRecord{Version: e.Version})
		sort.Slice(book.Versions, func(i, j int) bool { return book.Versions[i].Version < book.Versions[j].Version })
		for i := range book.Versions {
			if book.Versions[i].Version == e.Version {
				idx = i
			}
		}
	}
	revision := st.Revision + 1
	rec := RuleEvaluationRecord{At: e.At, Digest: e.Digest, Revision: revision, Mode: e.Mode, Health: e.Health, Cursors: append([]model.Cursor(nil), e.Cursors...), Payload: append(json.RawMessage(nil), e.Payload...)}
	v := &book.Versions[idx]
	v.StateRevision++
	last := rec
	last.Payload = nil
	v.Last = &last
	v.Recent = append(v.Recent, rec)
	if len(v.Recent) > maxRuleRecent {
		v.Recent = append([]RuleEvaluationRecord(nil), v.Recent[len(v.Recent)-maxRuleRecent:]...)
	}
	book.Head = e.Version
	// A superseded version keeps its identity and last evaluation, not its payloads.
	for i := range book.Versions {
		if book.Versions[i].Version != e.Version {
			book.Versions[i].Recent = nil
		}
	}
	for _, o := range e.Outputs {
		signal := o.Signal
		if signal == "" {
			signal = model.Metric
		}
		raw, err := json.Marshal(struct {
			ID      model.ID        `json:"id"`
			Kind    string          `json:"kind"`
			Notify  bool            `json:"notify"`
			Payload json.RawMessage `json:"payload"`
		}{o.ID, o.Kind, o.Notify, o.Payload})
		if err != nil {
			return Effect{}, model.Fail(model.Invalid)
		}
		out := RuleOutput{ID: o.ID, Org: book.Org, Project: book.Project, Rule: book.Rule, Version: e.Version, At: e.At, Kind: o.Kind, Signal: signal, Notify: o.Notify, Mode: e.Mode, Phase: RulePhasePending,
			Digest: model.HashCanonical(raw), Payload: append(json.RawMessage(nil), o.Payload...), Inputs: append([]model.Cursor(nil), o.Inputs...), Created: revision}
		if out.Inputs == nil {
			out.Inputs = []model.Cursor{}
		}
		if err = storeRuleOutput(st, out); err != nil {
			return Effect{}, err
		}
	}
	if err := pruneRuleOutputs(st, book); err != nil {
		return Effect{}, err
	}
	affected := []model.ID{book.Rule}
	for _, o := range e.Outputs {
		affected = append(affected, o.ID)
	}
	return Effect{AffectedIDs: affected, Phase: "applied"}, nil
}

// pruneRuleOutputs bounds the settled (finalized or suppressed) outbox history
// of one rule to the newest maxRuleSettledOutputs, ordered by (at, ID). Pending
// and admitted records are never dropped.
func pruneRuleOutputs(st *State, book *RuleBook) error {
	var settled []RuleOutput
	for _, raw := range st.RuleOutputs {
		var o RuleOutput
		if err := json.Unmarshal(raw, &o); err != nil {
			return model.Fail(model.Corrupt)
		}
		if o.Rule == book.Rule && o.Project == book.Project && o.Org == book.Org && (o.Phase == RulePhaseFinalized || o.Phase == RulePhaseSuppress) {
			settled = append(settled, o)
		}
	}
	if len(settled) <= maxRuleSettledOutputs {
		return nil
	}
	sort.Slice(settled, func(i, j int) bool {
		if settled[i].At != settled[j].At {
			return settled[i].At < settled[j].At
		}
		return settled[i].ID.String() < settled[j].ID.String()
	})
	for _, o := range settled[:len(settled)-maxRuleSettledOutputs] {
		delete(st.RuleOutputs, o.ID.String())
	}
	return nil
}

func applyRuleMissedArm(book *RuleBook, m RuleMissedApply) (Effect, error) {
	if m.Version == 0 || m.From < 0 || m.To < m.From || m.Count == 0 || m.At <= 0 {
		return Effect{}, model.Fail(model.Invalid)
	}
	for _, r := range book.Missed {
		if r.Version == m.Version && r.From == m.From && r.To == m.To {
			if r.Count != m.Count {
				return Effect{}, ruleFault(model.Conflict, "rule_missed_conflict")
			}
			return Effect{AffectedIDs: []model.ID{book.Rule}, Phase: "unchanged"}, nil
		}
	}
	book.Missed = append(book.Missed, RuleMissedRecord{Version: m.Version, From: m.From, To: m.To, Count: m.Count, At: m.At})
	if len(book.Missed) > maxRuleMissed {
		book.Missed = append([]RuleMissedRecord(nil), book.Missed[len(book.Missed)-maxRuleMissed:]...)
	}
	return Effect{AffectedIDs: []model.ID{book.Rule}, Phase: "missed_recorded"}, nil
}

func applyRuleReplayArm(scope auth.Scope, st *State, cmd Command, book *RuleBook, r RuleReplayApply) (Effect, error) {
	reason, ok := cleanReason(r.Reason)
	if !ok || r.From < 0 || r.To < r.From || r.At <= 0 {
		return Effect{}, model.Fail(model.Invalid)
	}
	for _, w := range book.Replays {
		if w.From == r.From && w.To == r.To {
			return Effect{AffectedIDs: []model.ID{book.Rule}, Phase: "unchanged"}, nil
		}
	}
	book.Replays = append(book.Replays, RuleReplayWindow{From: r.From, To: r.To, Reason: reason, Operator: scope.PrincipalID(), At: r.At, Revision: st.Revision + 1})
	if len(book.Replays) > maxRuleReplays {
		book.Replays = append([]RuleReplayWindow(nil), book.Replays[len(book.Replays)-maxRuleReplays:]...)
	}
	// An operator replay lets old evaluations notify again: it is always audited,
	// with the operator and the window, never with rule content.
	st.Audits = append(st.Audits, model.ControlAudit{ID: cmd.CommandID, Principal: scope.PrincipalID(), Action: "rules.operator_replay",
		Reason: reason + " from=" + strconv.FormatInt(int64(r.From), 10) + " to=" + strconv.FormatInt(int64(r.To), 10), Time: int64(r.At), Org: scope.OrgID().String(), PolicyEpoch: scope.PolicyEpoch(),
		Targets: []model.ID{book.Rule}, RequestID: cmd.CommandID, Outcome: model.AuditAllowed})
	return Effect{AffectedIDs: []model.ID{book.Rule}, Phase: "replay_declared"}, nil
}

func applyRuleOutputArm(st *State, book *RuleBook, u RuleOutputApply) (Effect, error) {
	if u.Output == (model.ID{}) {
		return Effect{}, model.Fail(model.Invalid)
	}
	out, found, err := loadRuleOutput(st, u.Output)
	if err != nil {
		return Effect{}, err
	}
	if !found || out.Org != book.Org || out.Project != book.Project || out.Rule != book.Rule {
		return Effect{}, model.Fail(model.NotFound)
	}
	reason := ""
	if u.Reason != "" {
		var ok bool
		if reason, ok = cleanReason(u.Reason); !ok {
			return Effect{}, model.Fail(model.Invalid)
		}
	}
	switch u.To {
	case RulePhaseAdmitted, RulePhaseFinalized:
		if out.Kind == RuleOutputRecording {
			if u.Receipt == nil || u.Hash == nil || u.Receipt.Group == (model.ID{}) {
				return Effect{}, model.Fail(model.Invalid)
			}
		} else if u.To == RulePhaseAdmitted || u.Receipt != nil || u.Hash != nil {
			// A condition output has no data admission to receipt.
			return Effect{}, model.Fail(model.Invalid)
		}
	case RulePhaseSuppress:
		if u.Receipt != nil || u.Hash != nil || reason == "" {
			return Effect{}, model.Fail(model.Invalid)
		}
	default:
		return Effect{}, model.Fail(model.Invalid)
	}
	same := func() bool {
		switch {
		case u.To == RulePhaseSuppress:
			return out.Reason == reason
		case out.Kind != RuleOutputRecording:
			return true
		default:
			return out.Receipt != nil && *out.Receipt == *u.Receipt && out.Hash != nil && *out.Hash == *u.Hash
		}
	}
	switch {
	case out.Phase == u.To:
		if !same() {
			return Effect{}, ruleFault(model.Conflict, "rule_output_conflict")
		}
		return Effect{AffectedIDs: []model.ID{out.ID}, Phase: "unchanged"}, nil
	case out.Phase == RulePhaseFinalized && u.To == RulePhaseAdmitted:
		// A late duplicate of an earlier step: the receipt must be the recorded one.
		if !same() {
			return Effect{}, ruleFault(model.Conflict, "rule_output_conflict")
		}
		return Effect{AffectedIDs: []model.ID{out.ID}, Phase: "unchanged"}, nil
	case out.Phase == RulePhasePending && (u.To == RulePhaseAdmitted || u.To == RulePhaseFinalized || u.To == RulePhaseSuppress):
	case out.Phase == RulePhaseAdmitted && u.To == RulePhaseFinalized:
		if out.Receipt == nil || *out.Receipt != *u.Receipt || *out.Hash != *u.Hash {
			return Effect{}, ruleFault(model.Conflict, "rule_output_conflict")
		}
	default:
		return Effect{}, ruleFault(model.Conflict, "rule_output_transition")
	}
	out.Phase = u.To
	switch {
	case u.To == RulePhaseSuppress:
		out.Reason = reason
	case out.Kind == RuleOutputRecording:
		receipt, hash := *u.Receipt, *u.Hash
		out.Receipt, out.Hash = &receipt, &hash
	}
	if err = storeRuleOutput(st, out); err != nil {
		return Effect{}, err
	}
	return Effect{AffectedIDs: []model.ID{out.ID}, Phase: u.To}, nil
}

// ruleReadScope admits a scope to read one project's rule facts: a current,
// unretired project of the scope's organization and a read-class permission. A
// project the scope does not name is indistinguishable from an absent one.
func ruleReadScope(scope auth.Scope, st State, project model.ID) error {
	if project == (model.ID{}) {
		return model.Fail(model.Invalid)
	}
	switch scope.Permission() {
	case auth.Read, auth.PolicyWrite, auth.OrgAdmin:
	default:
		return model.Fail(model.Forbidden)
	}
	if err := scope.ValidateControlState(st); err != nil {
		return err
	}
	org, ok := st.Orgs[scope.OrgID().String()]
	if !ok {
		return model.Fail(model.NotFound)
	}
	if _, ok = org.Projects[project.String()]; !ok {
		return model.Fail(model.NotFound)
	}
	if len(scope.ProjectIDs()) > 0 && !scope.AllowsProject(project) {
		return model.Fail(model.NotFound)
	}
	return nil
}

// RuleBook reads one rule's committed facts through a linearizable control read.
func (s *Store) RuleBook(ctx context.Context, scope auth.Scope, project, rule model.ID) (out RuleBook, found bool, err error) {
	err = s.View(ctx, func(st State) error {
		if e := ruleReadScope(scope, st, project); e != nil {
			return e
		}
		var e error
		out, found, e = loadRuleBook(&st, ruleKey(scope.OrgID(), project, rule))
		return e
	})
	return
}

// RuleOutputs lists one project's outbox records, in (at, ID) order, optionally
// only those in one phase (all when phase is empty) and for one rule (all when
// rule is zero). limit <= 0 means every match.
func (s *Store) RuleOutputs(ctx context.Context, scope auth.Scope, project, rule model.ID, phase string, limit int) (out []RuleOutput, err error) {
	err = s.View(ctx, func(st State) error {
		if e := ruleReadScope(scope, st, project); e != nil {
			return e
		}
		for _, raw := range st.RuleOutputs {
			var o RuleOutput
			if e := json.Unmarshal(raw, &o); e != nil {
				return model.Fail(model.Corrupt)
			}
			if o.Org != scope.OrgID() || o.Project != project || rule != (model.ID{}) && o.Rule != rule || phase != "" && o.Phase != phase {
				continue
			}
			o.Obsolete = ruleOutputObsolete(st, o)
			out = append(out, o)
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].At != out[j].At {
				return out[i].At < out[j].At
			}
			return out[i].ID.String() < out[j].ID.String()
		})
		if limit > 0 && len(out) > limit {
			out = out[:limit]
		}
		return nil
	})
	return
}

// ruleOutputObsolete reports whether a committed retirement or deletion now
// covers an output's origin, so the intent must be suppressed before release.
func ruleOutputObsolete(st State, o RuleOutput) bool {
	if _, retired := st.RetiredOrgs[o.Org.String()]; retired {
		return true
	}
	if _, retired := st.RetiredProjects[o.Org.String()+":"+o.Project.String()]; retired {
		return true
	}
	for _, op := range st.Deletions {
		if op.Phase != model.DeletePhaseFencing && op.Phase != model.DeletePhaseComplete {
			continue
		}
		if op.Predicate.CoversOrigin(o.Org, o.Project, o.Signal, o.At, nil) {
			return true
		}
	}
	return false
}
