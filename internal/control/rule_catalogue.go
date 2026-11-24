// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sort"
	"strings"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// This file is the rule catalogue: the committed definitions the background
// runner evaluates (plan 02 task 11, 11.01-W1). It is two more arms of the
// KindApplyRuleEvaluation command, so the catalogue is written by the same
// dispatcher, with the same command-ID binding, retry table and audit as every
// other rule fact, and no alternate store. Like the evaluation arms it stores
// only a leaf DTO: the rule definition is opaque JSON that the rules package
// validates (Rule.Check, pinned profile and feature set) before it commits, and
// control never imports the rules package. What control owns, atomically in one
// command:
//
//   - the author: an organization administrator of the organization, in the
//     human scope of their own session or token. The runner's system scope is
//     refused (it evaluates rules, it never authors one), and so is every other
//     permission: rules.write is a reserved grant and the control gate
//     (auth.Scope.ControlAuthorize) admits administrators for this kind;
//   - the revision: the compare-and-set token of one rule's catalogue record
//     (0 = it must not exist yet). It moves at every change, so a retirement
//     can never be silently undone by a save made from an older read;
//   - the version: the pinned rule version evaluation commits under. It moves
//     only when a definition is saved, by exactly one, and the definition must
//     name that version, its own rule and its own project; a definition is
//     never edited in place;
//   - the digest: the definition bytes control stored are the bytes the author
//     hashed;
//   - the bounds: definition size and rules per project;
//   - the audit: every save and retirement records actor, rule and reason, never
//     the definition.
//
// A catalogue write moves neither the organization's policy epoch nor
// AuthorityRevision (KindApplyRuleEvaluation is on nonAuthorityKinds). A
// retirement of the owning project drops the definitions (eraseRuleDefinitions):
// an expression is project-owned query text.

// The operations of a RuleCommand that write the catalogue.
const (
	// RuleOpDefine saves a new version of a rule (or the first one).
	RuleOpDefine = "define_rule"
	// RuleOpRetireRule takes a rule out of evaluation. The record and its history
	// stay; saving a new version brings the rule back.
	RuleOpRetireRule = "retire_rule"
)

// The SafeDetail of the faults of a catalogue command.
const (
	RuleDefinitionConflict = "rule_definition_conflict"
	RuleDefinitionQuota    = "rule_definition_quota"
)

const (
	// MaxRuleDefinitionBytes bounds one definition (an expression is at most 64 KiB).
	MaxRuleDefinitionBytes = 128 << 10
	// MaxRuleDefinitionsPerProject bounds the catalogue of one project, retired
	// rules included.
	MaxRuleDefinitionsPerProject = 256

	ruleDefineAction = "rules.define"
	ruleRetireAction = "rules.retire"
)

// RuleDefinitionApply is the closed arm of RuleOpDefine and RuleOpRetireRule.
// A save carries the definition and its digest; a retirement neither.
// ExpectedRevision is the catalogue revision the author read (0 = the rule must
// not exist yet).
type RuleDefinitionApply struct {
	Project          model.ID        `json:"project"`
	Rule             model.ID        `json:"rule"`
	ExpectedRevision model.Revision  `json:"expected_revision"`
	Definition       json.RawMessage `json:"definition,omitempty"`
	Digest           model.Hash      `json:"digest"`
	Reason           string          `json:"reason"`
	At               model.UnixNano  `json:"at_ns"`
}

// RuleDefinitionRecord is the committed catalogue entry of one rule.
type RuleDefinitionRecord struct {
	Org        model.ID        `json:"org"`
	Project    model.ID        `json:"project"`
	Rule       model.ID        `json:"rule"`
	Revision   model.Revision  `json:"revision"`
	Version    model.Revision  `json:"version"`
	Digest     model.Hash      `json:"digest"`
	Definition json.RawMessage `json:"definition"`
	Retired    bool            `json:"retired,omitempty"`
	CreatedNS  model.UnixNano  `json:"created_ns"`
	UpdatedNS  model.UnixNano  `json:"updated_ns"`
}

// ruleDefinitionHeader is the part of a definition control reads: who it is for
// and the version it pins.
type ruleDefinitionHeader struct {
	ID      model.ID       `json:"id"`
	Project model.ID       `json:"project"`
	Version model.Revision `json:"version"`
}

func loadRuleDefinition(st *State, key string) (RuleDefinitionRecord, bool, error) {
	raw, ok := st.RuleDefinitions[key]
	if !ok {
		return RuleDefinitionRecord{}, false, nil
	}
	var rec RuleDefinitionRecord
	if json.Unmarshal(raw, &rec) != nil || ruleKey(rec.Org, rec.Project, rec.Rule) != key {
		return RuleDefinitionRecord{}, false, model.Fail(model.Corrupt)
	}
	return rec, true, nil
}

// loadRuleDefinitionRO is loadRuleDefinition against a read-only control state; the record is decoded from a
// copy of the stored bytes.
func loadRuleDefinitionRO(ro model.ReadOnlyControl, key string) (RuleDefinitionRecord, bool, error) {
	raw, ok := ro.BookRecord(model.BookRuleDefinition, key)
	if !ok {
		return RuleDefinitionRecord{}, false, nil
	}
	var rec RuleDefinitionRecord
	if json.Unmarshal(raw, &rec) != nil || ruleKey(rec.Org, rec.Project, rec.Rule) != key {
		return RuleDefinitionRecord{}, false, model.Fail(model.Corrupt)
	}
	return rec, true, nil
}

// applyRuleDefinitionArm commits one catalogue command (see the file comment).
func applyRuleDefinitionArm(scope auth.Scope, st *State, cmd Command, operation string, d RuleDefinitionApply) (Effect, error) {
	reason, ok := cleanReason(d.Reason)
	if !ok || d.Project == (model.ID{}) || d.Rule == (model.ID{}) || d.At <= 0 {
		return Effect{}, model.Fail(model.Invalid)
	}
	var header ruleDefinitionHeader
	if operation == RuleOpDefine {
		if len(d.Definition) > MaxRuleDefinitionBytes {
			return Effect{}, model.Fail(model.TooLarge)
		}
		if len(d.Definition) < 2 || !json.Valid(d.Definition) || d.Digest == (model.Hash{}) || model.Hash(sha256.Sum256(d.Definition)) != d.Digest || json.Unmarshal(d.Definition, &header) != nil {
			return Effect{}, model.Fail(model.Invalid)
		}
	} else if len(d.Definition) != 0 || d.Digest != (model.Hash{}) {
		return Effect{}, model.Fail(model.Invalid)
	}
	// The author before anything about the rule is looked up: a human
	// organization administrator of a live project, never the runner.
	if scope.IsSystem() {
		return Effect{}, model.Fail(model.NotFound)
	}
	org := scope.OrgID()
	if err := releaseScope(scope, st, org, d.Project); err != nil {
		return Effect{}, err
	}
	key := ruleKey(org, d.Project, d.Rule)
	rec, exists, err := loadRuleDefinition(st, key)
	if err != nil {
		return Effect{}, err
	}
	if !exists && operation == RuleOpRetireRule {
		return Effect{}, model.Fail(model.NotFound)
	}
	if exists && rec.Revision != d.ExpectedRevision || !exists && d.ExpectedRevision != 0 {
		return Effect{}, ruleFault(model.Conflict, RuleDefinitionConflict)
	}
	phase, action := "defined", ruleDefineAction
	if operation == RuleOpRetireRule {
		if rec.Retired {
			return Effect{AffectedIDs: []model.ID{d.Rule}, Phase: "unchanged"}, nil
		}
		rec.Retired, phase, action = true, "rule_retired", ruleRetireAction
	} else {
		version := rec.Version + 1
		if header.ID != d.Rule || header.Project != d.Project || header.Version != version {
			return Effect{}, model.Fail(model.Invalid)
		}
		if !exists {
			prefix, n := org.String()+":"+d.Project.String()+":", 0
			for k := range st.RuleDefinitions {
				if strings.HasPrefix(k, prefix) {
					n++
				}
			}
			if n >= MaxRuleDefinitionsPerProject {
				return Effect{}, ruleFault(model.Quota, RuleDefinitionQuota)
			}
			rec = RuleDefinitionRecord{Org: org, Project: d.Project, Rule: d.Rule, CreatedNS: d.At}
		}
		rec.Version, rec.Digest, rec.Retired = version, d.Digest, false
		rec.Definition = append(json.RawMessage(nil), d.Definition...)
	}
	rec.Revision++
	rec.UpdatedNS = d.At
	raw, err := json.Marshal(rec)
	if err != nil {
		return Effect{}, model.Fail(model.Invalid)
	}
	if st.RuleDefinitions == nil {
		st.RuleDefinitions = map[string]json.RawMessage{}
	}
	st.RuleDefinitions[key] = raw
	st.Audits = append(st.Audits, model.ControlAudit{ID: cmd.CommandID, Principal: scope.PrincipalID(), Action: action, Reason: reason, Time: int64(d.At), Org: org.String(),
		PolicyEpoch: scope.PolicyEpoch(), Targets: []model.ID{d.Project, d.Rule}, RequestID: cmd.CommandID, Outcome: model.AuditAllowed})
	return Effect{AffectedIDs: []model.ID{d.Rule}, Phase: phase}, nil
}

// RuleDefinitions lists one project's catalogue (retired rules included), in
// rule ID order, through a linearizable control read, to a scope that may read
// the project's rule facts. A project the scope does not name is
// indistinguishable from an absent one.
func (s *Store) RuleDefinitions(ctx context.Context, scope auth.Scope, project model.ID) (out []RuleDefinitionRecord, err error) {
	err = s.ViewShared(ctx, func(st model.ReadOnlyControl) error {
		if e := ruleReadScopeRO(scope, st, project); e != nil {
			return e
		}
		for _, key := range st.BookKeys(model.BookRuleDefinition, scope.OrgID().String()+":"+project.String()+":") {
			rec, found, e := loadRuleDefinitionRO(st, key)
			if e != nil {
				return e
			}
			if found {
				out = append(out, rec)
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Rule.String() < out[j].Rule.String() })
		return nil
	})
	return
}

// RuleDefinition reads one rule's catalogue record.
func (s *Store) RuleDefinition(ctx context.Context, scope auth.Scope, project, rule model.ID) (out RuleDefinitionRecord, found bool, err error) {
	err = s.ViewShared(ctx, func(st model.ReadOnlyControl) error {
		if e := ruleReadScopeRO(scope, st, project); e != nil {
			return e
		}
		var e error
		out, found, e = loadRuleDefinitionRO(st, ruleKey(scope.OrgID(), project, rule))
		return e
	})
	return
}

// eraseRuleDefinitions is the deletion hook's half for the rule catalogue, a pure
// function of the state and the predicate like eraseSavedViews: a retirement of
// a project (or of its organization) drops every definition of the covered
// projects whole, since an expression is project-owned query text. A range or
// entity deletion erases telemetry, which no definition holds. The owner is read
// from the key ("org:project:rule"), so a record that cannot be decoded is still
// dropped with its project. It returns how many definitions it dropped and is
// idempotent.
func eraseRuleDefinitions(st *State, p model.DeletePredicate) (dropped int, err error) {
	keys := make([]string, 0, len(st.RuleDefinitions))
	for key := range st.RuleDefinitions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts := strings.Split(key, ":")
		if len(parts) != 3 {
			continue
		}
		org, e1 := model.ParseID(parts[0])
		project, e2 := model.ParseID(parts[1])
		if e1 != nil || e2 != nil || !p.RetiresProject(org, project) {
			continue
		}
		delete(st.RuleDefinitions, key)
		dropped++
	}
	return dropped, nil
}
