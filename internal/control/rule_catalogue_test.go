// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// definition is the closed header control reads of a definition, plus the
// expression the tests use as the sensitive text.
type definition struct {
	ID         model.ID       `json:"id"`
	Project    model.ID       `json:"project"`
	Version    model.Revision `json:"version"`
	Expression string         `json:"expression"`
}

// define builds the catalogue command that saves version `version` of the rule,
// seen by an author who read revision `expected`.
func (f *ruleFx) define(project, rule model.ID, expected, version uint64, expression string) control.RuleCommand {
	f.t.Helper()
	raw, err := json.Marshal(definition{ID: rule, Project: project, Version: model.Revision(version), Expression: expression})
	if err != nil {
		f.t.Fatal(err)
	}
	return control.RuleCommand{Operation: control.RuleOpDefine, Definition: &control.RuleDefinitionApply{
		Project: project, Rule: rule, ExpectedRevision: model.Revision(expected), Definition: raw, Digest: digestOf(string(raw)), Reason: "author a rule", At: 100}}
}

func (f *ruleFx) retireRule(project, rule model.ID, expected uint64) control.RuleCommand {
	return control.RuleCommand{Operation: control.RuleOpRetireRule, Definition: &control.RuleDefinitionApply{
		Project: project, Rule: rule, ExpectedRevision: model.Revision(expected), Reason: "stop it", At: 200}}
}

func (f *ruleFx) definitionOf(project, rule model.ID) control.RuleDefinitionRecord {
	f.t.Helper()
	rec, found, err := f.store.RuleDefinition(f.ctx, f.adminScope(), project, rule)
	if err != nil || !found {
		f.t.Fatalf("definition: found=%v err=%v", found, err)
	}
	return rec
}

// One rule's catalogue record: the revision is the compare-and-set token and
// moves at every change, the version only when a definition is saved; a replay
// of a committed command answers the first result; a retirement is not undone by
// a save made from an older read; and nothing here touches authority.
func TestRuleCatalogueDefineVersionAndRevision(t *testing.T) {
	f := newRuleFx(t)
	authority, epoch := f.authorityRevision(), f.state().Orgs[f.org.String()].Epoch
	id := model.NewID()
	res, err := f.applyAs(id, f.define(f.project, f.rule, 0, 1, "up == 0"))
	if err != nil || res.Phase != "defined" {
		t.Fatalf("create: %+v %v", res, err)
	}
	rec := f.definitionOf(f.project, f.rule)
	if rec.Revision != 1 || rec.Version != 1 || rec.Retired || rec.CreatedNS != 100 || rec.Org != f.org || !strings.Contains(string(rec.Definition), "up == 0") {
		t.Fatalf("record after create: %+v", rec)
	}
	if again, err := f.applyAs(id, f.define(f.project, f.rule, 0, 1, "up == 0")); err != nil || again.Phase != "defined" || again.Revision != res.Revision {
		t.Fatalf("a replayed command answered %+v %v, want the first result %+v", again, err, res)
	}
	if f.definitionOf(f.project, f.rule).Revision != 1 {
		t.Fatal("a replayed command changed the record")
	}
	// A save made from a state older than the committed one loses; so does one that
	// treats an existing rule as new.
	if _, err = f.apply(f.define(f.project, f.rule, 0, 1, "up == 1")); code(err) != model.Conflict || faultDetail(err) != control.RuleDefinitionConflict {
		t.Fatalf("a save of an existing rule as new: %v", err)
	}
	if _, err = f.apply(f.define(f.project, model.NewID(), 5, 1, "up == 1")); code(err) != model.Conflict || faultDetail(err) != control.RuleDefinitionConflict {
		t.Fatalf("a save of a missing rule at a revision it never had: %v", err)
	}
	// The definition names the version control would assign, its own rule and its own project.
	for name, c := range map[string]control.RuleCommand{
		"version skipped":  f.define(f.project, f.rule, 1, 3, "up == 1"),
		"version repeated": f.define(f.project, f.rule, 1, 1, "up == 1"),
		"another rule": func() control.RuleCommand {
			c := f.define(f.project, f.rule, 0, 1, "up == 1")
			c.Definition.Rule = model.NewID()
			return c
		}(),
		"another project": func() control.RuleCommand {
			c := f.define(f.project, model.NewID(), 0, 1, "up == 1")
			c.Definition.Project = f.otherProject
			return c
		}(),
		"no definition":     {Operation: control.RuleOpDefine, Definition: &control.RuleDefinitionApply{Project: f.project, Rule: f.rule, ExpectedRevision: 1, Reason: "x", At: 100}},
		"retire with body":  {Operation: control.RuleOpRetireRule, Definition: &control.RuleDefinitionApply{Project: f.project, Rule: f.rule, ExpectedRevision: 1, Definition: json.RawMessage(`{}`), Reason: "x", At: 100}},
		"no reason":         {Operation: control.RuleOpDefine, Definition: &control.RuleDefinitionApply{Project: f.project, Rule: f.rule, ExpectedRevision: 1, Reason: " ", At: 100}},
		"missing timestamp": {Operation: control.RuleOpRetireRule, Definition: &control.RuleDefinitionApply{Project: f.project, Rule: f.rule, ExpectedRevision: 1, Reason: "x"}},
	} {
		if _, err = f.apply(c); code(err) != model.Invalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := f.define(f.project, f.rule, 1, 2, "up == 1")
	bad.Definition.Digest = digestOf("other bytes")
	if _, err = f.apply(bad); code(err) != model.Invalid {
		t.Errorf("a digest that is not the stored bytes: %v", err)
	}
	huge := f.define(f.project, f.rule, 1, 2, strings.Repeat("x", control.MaxRuleDefinitionBytes))
	if _, err = f.apply(huge); code(err) != model.TooLarge {
		t.Errorf("an oversized definition: %v", err)
	}
	if rec = f.definitionOf(f.project, f.rule); rec.Revision != 1 || rec.Version != 1 {
		t.Fatalf("a refused command changed the record: %+v", rec)
	}

	if _, err = f.apply(f.define(f.project, f.rule, 1, 2, "up == 2")); err != nil {
		t.Fatal(err)
	}
	if rec = f.definitionOf(f.project, f.rule); rec.Revision != 2 || rec.Version != 2 || rec.UpdatedNS != 100 || !strings.Contains(string(rec.Definition), "up == 2") {
		t.Fatalf("record after the second save: %+v", rec)
	}

	// Retirement: the record stays, the revision moves, the version does not.
	if _, err = f.apply(f.retireRule(f.project, f.rule, 1)); code(err) != model.Conflict {
		t.Fatalf("a retirement from a stale read: %v", err)
	}
	if _, err = f.apply(f.retireRule(f.project, model.NewID(), 0)); code(err) != model.NotFound {
		t.Fatalf("a retirement of an unknown rule: %v", err)
	}
	if res, err = f.apply(f.retireRule(f.project, f.rule, 2)); err != nil || res.Phase != "rule_retired" {
		t.Fatalf("retire: %+v %v", res, err)
	}
	if rec = f.definitionOf(f.project, f.rule); !rec.Retired || rec.Revision != 3 || rec.Version != 2 || rec.UpdatedNS != 200 {
		t.Fatalf("record after retirement: %+v", rec)
	}
	if res, err = f.apply(f.retireRule(f.project, f.rule, 3)); err != nil || res.Phase != "unchanged" {
		t.Fatalf("a second retirement: %+v %v", res, err)
	}
	// An author who read the rule before it was retired cannot silently bring it back.
	if _, err = f.apply(f.define(f.project, f.rule, 2, 3, "up == 3")); code(err) != model.Conflict {
		t.Fatalf("a save from before the retirement: %v", err)
	}
	if _, err = f.apply(f.define(f.project, f.rule, 3, 3, "up == 3")); err != nil {
		t.Fatal(err)
	}
	if rec = f.definitionOf(f.project, f.rule); rec.Retired || rec.Revision != 4 || rec.Version != 3 {
		t.Fatalf("record after the save that brings it back: %+v", rec)
	}

	st := f.state()
	if countAudits(st, "rules.define") != 3 || countAudits(st, "rules.retire") != 1 {
		t.Fatalf("audits: define=%d retire=%d", countAudits(st, "rules.define"), countAudits(st, "rules.retire"))
	}
	for _, a := range st.Audits {
		if strings.HasPrefix(a.Action, "rules.") && (strings.Contains(a.Reason, "up ==") || a.Principal != f.user) {
			t.Fatalf("an audit carries the definition or the wrong actor: %+v", a)
		}
	}
	if f.authorityRevision() != authority {
		t.Fatal("a catalogue write moved the authority revision")
	}
	if f.state().Orgs[f.org.String()].Epoch != epoch {
		t.Fatal("a catalogue write moved the organization's policy epoch")
	}
}

// Only a human organization administrator of the project authors: not the
// runner's scope, not a member who merely reads or holds policy.write, not an
// administrator confined to another project, and never with a lease or beside
// another arm.
func TestRuleCatalogueAuthor(t *testing.T) {
	f := newRuleFx(t)
	define := f.define(f.project, f.rule, 0, 1, "up == 0")

	read, err := f.readScope(f.project)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.Transact(f.ctx, read, f.cmd(control.KindApplyRuleEvaluation, model.NewID(), define)); code(err) != model.Forbidden {
		t.Fatalf("a reader authored: %v", err)
	}
	other, err := f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{f.otherProject}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.Transact(f.ctx, other, f.cmd(control.KindApplyRuleEvaluation, model.NewID(), define)); code(err) != model.NotFound {
		t.Fatalf("an administrator confined to another project authored: %v", err)
	}
	system, err := f.svc.AuthorizeSystem(f.ctx, f.org, []model.ID{f.project}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.Transact(f.ctx, system, f.cmd(control.KindApplyRuleEvaluation, model.NewID(), define)); code(err) != model.NotFound {
		t.Fatalf("the runner authored: %v", err)
	}
	unknown := f.define(model.NewID(), f.rule, 0, 1, "up == 0")
	if _, err = f.apply(unknown); code(err) != model.NotFound {
		t.Fatalf("a rule of an unknown project: %v", err)
	}
	withLease := define
	lease := f.lease()
	withLease.Lease = &lease
	if _, err = f.apply(withLease); code(err) != model.Invalid {
		t.Fatalf("a definition carried a lease: %v", err)
	}
	two := define
	two.Replay = &control.RuleReplayApply{Project: f.project, Rule: f.rule, From: 1, To: 2, Reason: "x", At: 1}
	if _, err = f.apply(two); code(err) != model.Invalid {
		t.Fatalf("two arms: %v", err)
	}
	wrong := define
	wrong.Operation = control.RuleOpEvaluation
	if _, err = f.apply(wrong); code(err) != model.Invalid {
		t.Fatalf("an operation naming the wrong arm: %v", err)
	}
	if n := len(f.state().RuleDefinitions); n != 0 {
		t.Fatalf("refused commands left %d definitions", n)
	}

	// Reading: the project's readers see the catalogue; another project's do not.
	if _, err = f.apply(define); err != nil {
		t.Fatal(err)
	}
	recs, err := f.store.RuleDefinitions(f.ctx, read, f.project)
	if err != nil || len(recs) != 1 || recs[0].Rule != f.rule {
		t.Fatalf("a reader lists %+v %v", recs, err)
	}
	if _, err = f.store.RuleDefinitions(f.ctx, read, f.otherProject); code(err) != model.NotFound {
		t.Fatalf("a reader of one project listed another's rules: %v", err)
	}
	if recs, err = f.store.RuleDefinitions(f.ctx, f.adminScope(), f.project); err != nil || len(recs) != 1 {
		t.Fatalf("an administrator lists %+v %v", recs, err)
	}
}

// A project holds at most MaxRuleDefinitionsPerProject rules, retired ones
// included; the quota is per project.
func TestRuleCatalogueQuotaIsPerProject(t *testing.T) {
	f := newRuleFx(t)
	if err := f.store.Update(f.ctx, func(st *control.State) error {
		st.RuleDefinitions = map[string]json.RawMessage{}
		for i := range control.MaxRuleDefinitionsPerProject {
			rule := model.ID{0xc0, byte(i >> 8), byte(i)}
			raw, _ := json.Marshal(control.RuleDefinitionRecord{Org: f.org, Project: f.project, Rule: rule, Revision: 1, Version: 1, Definition: json.RawMessage(`{}`), Retired: i%2 == 0})
			st.RuleDefinitions[f.org.String()+":"+f.project.String()+":"+rule.String()] = raw
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.apply(f.define(f.project, f.rule, 0, 1, "up == 0")); code(err) != model.Quota || faultDetail(err) != control.RuleDefinitionQuota {
		t.Fatalf("the 257th rule of a project: %v", err)
	}
	if _, err := f.apply(f.define(f.otherProject, f.rule, 0, 1, "up == 0")); err != nil {
		t.Fatalf("another project is not affected by a full catalogue: %v", err)
	}
	// Changing an existing rule of the full project is not a new rule.
	existing := model.ID{0xc0, 0, 1}
	if _, err := f.apply(f.define(f.project, existing, 1, 2, "up == 0")); err != nil {
		t.Fatalf("a new version of an existing rule of a full catalogue: %v", err)
	}
}

// A corrupt record is never trusted: one that does not name its own key is
// reported, not returned.
func TestRuleCatalogueCorruptRecordIsNotServed(t *testing.T) {
	f := newRuleFx(t)
	key := f.org.String() + ":" + f.project.String() + ":" + f.rule.String()
	if err := f.store.Update(f.ctx, func(st *control.State) error {
		st.RuleDefinitions = map[string]json.RawMessage{key: json.RawMessage(fmt.Sprintf(`{"org":%q,"project":%q,"rule":%q}`, f.org, f.project, model.NewID()))}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RuleDefinitions(f.ctx, f.adminScope(), f.project); code(err) != model.Corrupt {
		t.Fatalf("a record naming another rule: %v", err)
	}
	if _, _, err := f.store.RuleDefinition(f.ctx, f.adminScope(), f.project, f.rule); code(err) != model.Corrupt {
		t.Fatalf("a record naming another rule: %v", err)
	}
}

// The catalogue is covered by the real deletion path: a retirement of its
// project (or of its organization) drops every definition of the covered
// projects, from the committed state, the snapshot and control.db, and nothing
// of another project; a range or entity deletion erases telemetry, which no
// definition holds.
func TestDeletionErasesRuleDefinitions(t *testing.T) {
	const (
		mine, other = "CANARYRULEMINEa1b2c3d4e5f60718", "CANARYRULEOTHERa1b2c3d4e5f6071"
	)
	seed := func(f *eraseFx) {
		for project, canary := range map[model.ID]string{f.project: mine, f.otherProject: other} {
			rule := model.NewID()
			raw, err := json.Marshal(definition{ID: rule, Project: project, Version: 1, Expression: canary})
			if err != nil {
				t.Fatal(err)
			}
			cmd := control.RuleCommand{Operation: control.RuleOpDefine, Definition: &control.RuleDefinitionApply{Project: project, Rule: rule, Definition: raw, Digest: digestOf(string(raw)), Reason: "seed", At: 100}}
			if _, err = f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindApplyRuleEvaluation, model.NewID(), cmd)); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Run("retire project", func(t *testing.T) {
		f := newEraseFx(t)
		seed(f)
		f.expectKept(mine)
		f.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
		f.expectGone(mine)
		f.expectKept(other)
	})
	t.Run("retire org", func(t *testing.T) {
		f := newEraseFx(t)
		seed(f)
		f.saga(control.DeleteScope{Mode: model.DeleteRetireOrg})
		f.expectGone(mine)
		f.expectGone(other)
	})
	t.Run("range and entity", func(t *testing.T) {
		f := newEraseFx(t)
		seed(f)
		f.saga(f.lateRange())
		f.saga(control.DeleteScope{Mode: model.DeleteEntity, Projects: []model.ID{f.project}, Entities: []model.ID{model.NewID()}})
		f.expectKept(mine)
		f.expectKept(other)
	})
}
