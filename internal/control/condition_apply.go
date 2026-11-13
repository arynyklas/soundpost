// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sort"
	"strings"

	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

// This file is the C05 half of C07/C08 condition lifecycle: the
// KindApplyCondition dispatcher. Like incident response and rule evaluation it
// stores only leaf DTOs. The condition state is opaque JSON that the conditions
// package computes with its pure reducer; control never imports that package and
// never interprets a state beyond the closed header (condition_id, org_id,
// project_id, version). What control owns, atomically in one command:
//
//   - scope: an organization administrator of exactly this organization and
//     project, checked before any condition is looked up, with a wrong-scope and
//     a missing condition indistinguishable;
//   - the fence: a lease of another group is never a condition lease, and a lease
//     older than the highest one the condition has accepted is a deposed
//     leader's and is stale;
//   - the version compare-and-set: two commands that both expect version N cannot
//     both commit; the loser is a conflict the worker re-reduces against the new
//     state, never a merge;
//   - the audit of a lifecycle phase change, in the same transition.
//
// The condition source order (epoch, sequence, event time) is the reducer's, not
// control's: control stores whatever the leader's reducer decided and rejects
// whatever was computed from an older version.

// ConditionCommand is the closed KindApplyCondition payload.
type ConditionCommand struct {
	Project   model.ID `json:"project"`
	Condition model.ID `json:"condition"`
	// Lease is the scheduler/worker leader's fence; required.
	Lease           *replica.FenceToken `json:"lease"`
	ExpectedVersion model.Revision      `json:"expected_version"`
	NewVersion      model.Revision      `json:"new_version"`
	// At is the worker's arrival time of the evidence, used for the audit only.
	At model.UnixNano `json:"at"`
	// Change names the lifecycle phase the transition entered; it is empty for a
	// change that moved no phase (a freshness observation) and is the only thing
	// audited.
	Change string          `json:"change,omitempty"`
	State  json.RawMessage `json:"state"`
	Digest model.Hash      `json:"digest"`
}

// ConditionRecord is everything control holds for one condition.
type ConditionRecord struct {
	Org     model.ID            `json:"org"`
	Project model.ID            `json:"project"`
	ID      model.ID            `json:"id"`
	Version model.Revision      `json:"version"`
	Digest  model.Hash          `json:"digest"`
	State   json.RawMessage     `json:"state"`
	Fence   *replica.FenceToken `json:"fence,omitempty"`
}

// Erased reports whether a deletion replaced the record's state by its
// tombstone: the identity, version and fence remain, the state derived from
// telemetry is gone. It is not storage damage.
func (r ConditionRecord) Erased() bool { return stateIsTombstone(r.State) }

const (
	maxConditionStateBytes = 32 << 10
	maxConditionToken      = 32
	// MaxConditionsPerProject bounds the condition records of one project. The
	// bound is a visible quota error; settled conditions are never evicted,
	// because a late event for an evicted condition would read as a new one.
	MaxConditionsPerProject = 4096
)

// ConditionVersionConflict is the SafeDetail of a lost condition version race.
const ConditionVersionConflict = "condition_version_conflict"

// ConditionLeaseStale is the SafeDetail of a deposed leader's lease.
const ConditionLeaseStale = "condition_lease_stale"

// BindConditionApply installs the KindApplyCondition dispatcher on this Store
// only, like the other Bind* methods; it is a conflict to bind twice.
func (s *Store) BindConditionApply() error {
	return s.RegisterHandler(KindApplyCondition, applyCondition)
}

func conditionKey(org, project, condition model.ID) string {
	return org.String() + ":" + project.String() + ":" + condition.String()
}

func loadCondition(st *State, key string) (ConditionRecord, bool, error) {
	raw, ok := st.ConditionBooks[key]
	if !ok {
		return ConditionRecord{}, false, nil
	}
	var r ConditionRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return ConditionRecord{}, false, model.Fail(model.Corrupt)
	}
	return r, true, nil
}

func applyCondition(scope auth.Scope, st *State, cmd Command) (Effect, error) {
	var c ConditionCommand
	if err := strictPayload(cmd.Payload, &c); err != nil {
		return Effect{}, err
	}
	org := scope.OrgID()
	// Scope and grants first: nothing about the target is looked up, parsed or
	// answered for a scope that may not act in this project.
	if err := projectAdminScope(scope, st, org, c.Project); err != nil {
		return Effect{}, err
	}
	if c.Condition == (model.ID{}) || c.At <= 0 || c.NewVersion != c.ExpectedVersion+1 || len(c.State) < 2 || len(c.State) > maxConditionStateBytes ||
		c.Digest != model.Hash(sha256.Sum256(c.State)) || c.Change != "" && !incidentToken(c.Change) {
		return Effect{}, model.Fail(model.Invalid)
	}
	if c.Lease == nil || c.Lease.Group != st.Installation || c.Lease.Term == 0 {
		return Effect{}, model.Fail(model.Invalid)
	}
	var header struct {
		ID      model.ID       `json:"condition_id"`
		Org     model.ID       `json:"org_id"`
		Project model.ID       `json:"project_id"`
		Version model.Revision `json:"version"`
	}
	if json.Unmarshal(c.State, &header) != nil || header.ID != c.Condition || header.Org != org || header.Project != c.Project || header.Version != c.NewVersion {
		return Effect{}, model.Fail(model.Invalid)
	}
	key := conditionKey(org, c.Project, c.Condition)
	rec, exists, err := loadCondition(st, key)
	if err != nil {
		return Effect{}, err
	}
	switch {
	case !exists && c.ExpectedVersion != 0:
		return Effect{}, model.Fail(model.NotFound) // a missing condition
	case exists && rec.Fence != nil && fenceBefore(*c.Lease, *rec.Fence):
		return Effect{}, ruleFault(model.Stale, ConditionLeaseStale)
	case exists && rec.Version != c.ExpectedVersion:
		return Effect{}, ruleFault(model.Conflict, ConditionVersionConflict)
	case !exists:
		prefix := org.String() + ":" + c.Project.String() + ":"
		n := 0
		for k := range st.ConditionBooks {
			if strings.HasPrefix(k, prefix) {
				n++
			}
		}
		if n >= MaxConditionsPerProject {
			return Effect{}, model.Fail(model.Quota)
		}
		rec = ConditionRecord{Org: org, Project: c.Project, ID: c.Condition}
	}
	lease := *c.Lease
	rec.Version, rec.Digest, rec.State, rec.Fence = c.NewVersion, c.Digest, c.State, &lease
	raw, err := json.Marshal(rec)
	if err != nil {
		return Effect{}, model.Fail(model.Invalid)
	}
	if st.ConditionBooks == nil {
		st.ConditionBooks = map[string]json.RawMessage{}
	}
	st.ConditionBooks[key] = raw
	if c.Change != "" {
		st.Audits = append(st.Audits, model.ControlAudit{ID: cmd.CommandID, Principal: scope.PrincipalID(), Action: "conditions." + c.Change, Reason: "condition lifecycle change", Time: int64(c.At),
			Org: org.String(), PolicyEpoch: scope.PolicyEpoch(), Targets: []model.ID{c.Condition}, RequestID: cmd.CommandID, Outcome: model.AuditAllowed})
	}
	if err = eraseLateEffect(st, org, c.Project); err != nil {
		return Effect{}, err
	}
	return Effect{AffectedIDs: []model.ID{c.Condition}, Phase: "applied"}, nil
}

// Condition reads one condition's committed record through a linearizable
// control read. The scope is checked before the condition is looked up; a
// project the scope does not name is indistinguishable from an absent one.
func (s *Store) Condition(ctx context.Context, scope auth.Scope, project, condition model.ID) (out ConditionRecord, found bool, err error) {
	err = s.View(ctx, func(st State) error {
		if e := ruleReadScope(scope, st, project); e != nil {
			return e
		}
		var e error
		out, found, e = loadCondition(&st, conditionKey(scope.OrgID(), project, condition))
		return e
	})
	return
}

// Conditions lists one project's condition records in ID order.
func (s *Store) Conditions(ctx context.Context, scope auth.Scope, project model.ID) (out []ConditionRecord, err error) {
	err = s.View(ctx, func(st State) error {
		if e := ruleReadScope(scope, st, project); e != nil {
			return e
		}
		prefix := scope.OrgID().String() + ":" + project.String() + ":"
		for key, raw := range st.ConditionBooks {
			if !strings.HasPrefix(key, prefix) {
				continue
			}
			var r ConditionRecord
			if e := json.Unmarshal(raw, &r); e != nil {
				return model.Fail(model.Corrupt)
			}
			out = append(out, r)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
		return nil
	})
	return
}

// eraseConditions drops the condition state a deletion covers, in the caller's
// transition, by the same rule as eraseIncidents: the labels and recent events
// of a state derive from telemetry, so a covered state is replaced by a
// tombstone carrying only the closed header and the erasing operation. The
// record's identity, version, digest and fence stay.
func eraseConditions(st *State, p model.DeletePredicate) (dropped int, err error) {
	dropped, _, err = eraseConditionsBy(st, p, stateErased)
	return dropped, err
}

// eraseConditionsBy is eraseConditions with the rule that covers an opaque
// state; over counts the covered states that had no recorded window (CD-9).
func eraseConditionsBy(st *State, p model.DeletePredicate, rule stateRule) (dropped, over int, err error) {
	keys := make([]string, 0, len(st.ConditionBooks))
	for key := range st.ConditionBooks {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		rec, _, err := loadCondition(st, key)
		if err != nil {
			return 0, 0, err
		}
		if !rule(p, rec.Org, rec.Project, rec.State) {
			continue
		}
		if overErasure(p, rec.State) {
			over++
		}
		rec.State = tombstoneState("condition_id", rec.ID, rec.Org, rec.Project, rec.Version, p.Operation)
		raw, err := json.Marshal(rec)
		if err != nil {
			return 0, 0, model.Fail(model.Corrupt)
		}
		st.ConditionBooks[key] = raw
		dropped++
	}
	return dropped, over, nil
}
