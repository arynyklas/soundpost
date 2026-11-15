// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package rules_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/rules"
)

const promql = "promql-prometheus-3.13.5"

func (n *node) alert(expression string) rules.Rule {
	return rules.Rule{ID: model.NewID(), Kind: rules.KindAlert, Profile: promql, FeatureSet: n.features[promql], Expression: expression, Interval: time.Minute, Severity: "critical"}
}

func (n *node) recording(labels model.Labels) rules.Rule {
	return rules.Rule{ID: model.NewID(), Kind: rules.KindRecording, Profile: promql, FeatureSet: n.features[promql], Expression: "sum(up)", Interval: time.Minute, RecordName: "job:up:sum", Labels: labels}
}

func (n *node) catalogue(options ...rules.CatalogueOption) *rules.Catalogue {
	n.t.Helper()
	c, err := rules.NewCatalogue(n.app.Control, n.registry, options...)
	if err != nil {
		n.t.Fatal(err)
	}
	return c
}

func (n *node) save(c *rules.Catalogue, scope auth.Scope, r rules.Rule, expected model.Revision) (rules.Definition, error) {
	return c.Save(n.ctx, scope, rules.SaveCommand{Command: model.NewID(), Project: n.project, Rule: r, ExpectedRevision: expected, Reason: "author a rule"})
}

func faultOf(err error) (model.Code, string) {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.Code, f.SafeDetail
	}
	return "", ""
}

func (n *node) mustFail(err error, code model.Code, detail string, what string) {
	n.t.Helper()
	if c, d := faultOf(err); c != code || detail != "" && d != detail {
		n.t.Fatalf("%s: %v (code %q detail %q), want %q %q", what, err, c, d, code, detail)
	}
}

// Saving is the one moment a definition is judged: a rule that does not parse,
// does not yield an instant vector, pins a profile or feature set that does not
// exist or carries a severity outside the closed set is refused and commits
// nothing. A saved rule is the next version (previous + 1) under the author's
// revision, a replayed command answers the first result, a stale author loses,
// and only a retired rule drops out of what the workers evaluate.
func TestCatalogueSavesOnlyCheckedDefinitionsAndPinsVersions(t *testing.T) {
	n := newNode(t)
	c := n.catalogue()
	admin := n.scope(auth.OrgAdmin)

	for name, r := range map[string]rules.Rule{
		"does not parse":         n.alert("up =="),
		"is a scalar":            n.alert("1"),
		"is a range":             n.alert("up[5m]"),
		"unknown profile":        func() rules.Rule { r := n.alert("up"); r.Profile = "promql-prometheus-9.9.9"; return r }(),
		"foreign feature set":    func() rules.Rule { r := n.alert("up"); r.FeatureSet = "no-such-feature-set"; return r }(),
		"log profile on metrics": func() rules.Rule { r := n.alert("up"); r.Profile = "logql-loki-3.5.2"; return r }(),
		"empty expression":       n.alert(""),
		"interval too short":     func() rules.Rule { r := n.alert("up"); r.Interval = time.Millisecond; return r }(),
	} {
		if _, err := n.save(c, admin, r, 0); err == nil {
			t.Errorf("%s: accepted", name)
		} else if code, _ := faultOf(err); code != model.Invalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := n.alert("up")
	bad.Severity = "catastrophic"
	_, err := n.save(c, admin, bad, 0)
	n.mustFail(err, model.Invalid, rules.ReasonUnknownSeverity, "an unknown severity")
	if defs, err := c.List(n.ctx, admin, n.project); err != nil || len(defs) != 0 {
		t.Fatalf("a refused rule was committed: %+v %v", defs, err)
	}

	rule := n.alert("up == 0")
	cmd := rules.SaveCommand{Command: model.NewID(), Project: n.project, Rule: rule, ExpectedRevision: 0, Reason: "author a rule"}
	first, err := c.Save(n.ctx, admin, cmd)
	if err != nil {
		t.Fatal(err)
	}
	if first.Rule.Version != 1 || first.Revision != 1 || first.Retired || first.Rule.ID != rule.ID || first.Rule.Project != n.project || first.Rule.Expression != "up == 0" || first.Digest == (model.Hash{}) {
		t.Fatalf("first save: %+v", first)
	}
	// The command ID makes a repeated request a replay of the first answer.
	if again, err := c.Save(n.ctx, admin, cmd); err != nil || again.Revision != 1 || again.Rule.Version != 1 {
		t.Fatalf("a replayed save: %+v %v", again, err)
	}
	// The author's own Version and Project are ignored: the version is assigned, the project is the command's.
	spoof := rule
	spoof.Version, spoof.Project, spoof.Expression = 77, model.NewID(), "up == 1"
	second, err := n.save(c, admin, spoof, 1)
	if err != nil {
		t.Fatal(err)
	}
	if second.Rule.Version != 2 || second.Revision != 2 || second.Rule.Project != n.project || second.Rule.Expression != "up == 1" || second.Digest == first.Digest {
		t.Fatalf("second save: %+v", second)
	}
	// A save from a stale read, or one that treats an existing rule as new, loses.
	_, err = n.save(c, admin, rule, 1)
	n.mustFail(err, model.Conflict, control.RuleDefinitionConflict, "a stale revision")
	_, err = n.save(c, admin, rule, 0)
	n.mustFail(err, model.Conflict, control.RuleDefinitionConflict, "an existing rule as new")
	if got, err := c.Definition(n.ctx, admin, n.project, rule.ID); err != nil || got.Revision != 2 || got.Rule.Expression != "up == 1" {
		t.Fatalf("a refused save changed the rule: %+v %v", got, err)
	}

	// Retired rules are listed for the author and never evaluated.
	other, err := n.save(c, admin, n.alert("vector(1)"), 0)
	if err != nil {
		t.Fatal(err)
	}
	read := n.scope(auth.Read)
	active, err := c.Rules(n.ctx, read, n.project)
	if err != nil || len(active) != 2 {
		t.Fatalf("active rules: %+v %v", active, err)
	}
	retired, err := c.Retire(n.ctx, admin, rules.RetireCommand{Command: model.NewID(), Project: n.project, Rule: rule.ID, ExpectedRevision: 2, Reason: "stop it"})
	if err != nil || !retired.Retired || retired.Revision != 3 || retired.Rule.Version != 2 {
		t.Fatalf("retire: %+v %v", retired, err)
	}
	if active, err = c.Rules(n.ctx, read, n.project); err != nil || len(active) != 1 || active[0].ID != other.Rule.ID {
		t.Fatalf("active rules after a retirement: %+v %v", active, err)
	}
	if defs, err := c.List(n.ctx, read, n.project); err != nil || len(defs) != 2 {
		t.Fatalf("a reader lists %+v %v", defs, err)
	}
	// Saving again is the only way back, as a new version.
	_, err = n.save(c, admin, rule, 2)
	n.mustFail(err, model.Conflict, control.RuleDefinitionConflict, "a save from before the retirement")
	back, err := n.save(c, admin, rule, 3)
	if err != nil || back.Retired || back.Rule.Version != 3 || back.Revision != 4 {
		t.Fatalf("save after retirement: %+v %v", back, err)
	}
	_, err = c.Retire(n.ctx, admin, rules.RetireCommand{Command: model.NewID(), Project: n.project, Rule: model.NewID(), ExpectedRevision: 0, Reason: "x"})
	n.mustFail(err, model.NotFound, "", "a retirement of an unknown rule")
}

// Only an organization administrator of exactly the project authors; a reader
// lists and nothing else, and no scope reaches another project's rules.
func TestCatalogueAuthorityAndRuleSource(t *testing.T) {
	n := newNode(t)
	c := n.catalogue()
	read := n.scope(auth.Read)
	rule := n.alert("up")
	_, err := n.save(c, read, rule, 0)
	n.mustFail(err, model.Forbidden, "", "a reader saving")
	_, err = c.Retire(n.ctx, read, rules.RetireCommand{Command: model.NewID(), Project: n.project, Rule: rule.ID, ExpectedRevision: 1, Reason: "x"})
	n.mustFail(err, model.Forbidden, "", "a reader retiring")
	n.mustFail(c.DeclareReplay(n.ctx, read, n.project, rule.ID, 0, 1, "x"), model.Forbidden, "", "a reader declaring a replay")
	// An administrator's scope that names no single project is not an author's.
	wide, err := n.app.Auth.Authorize(n.ctx, n.actor, n.org, nil, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	_, err = n.save(c, wide, rule, 0)
	n.mustFail(err, model.NotFound, "", "an organization-wide scope")
	// Another project's selector is the same not-found an absent project gives.
	admin := n.scope(auth.OrgAdmin)
	_, err = c.Save(n.ctx, admin, rules.SaveCommand{Command: model.NewID(), Project: model.NewID(), Rule: rule, Reason: "x"})
	n.mustFail(err, model.NotFound, "", "a project the scope does not name")
	if _, err = c.List(n.ctx, read, model.NewID()); err == nil {
		t.Fatal("a reader listed the rules of a project it does not name")
	}
	if defs, err := c.List(n.ctx, read, n.project); err != nil || len(defs) != 0 {
		t.Fatalf("nothing was saved: %+v %v", defs, err)
	}
	// The worker principal reads the catalogue through its own project-scoped read scope.
	system, err := n.app.Auth.AuthorizeSystem(n.ctx, n.org, []model.ID{n.project}, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = n.save(c, admin, rule, 0); err != nil {
		t.Fatal(err)
	}
	if got, err := c.Rules(n.ctx, system, n.project); err != nil || len(got) != 1 || got[0].ID != rule.ID || got[0].Version != 1 {
		t.Fatalf("the runner's rule source: %+v %v", got, err)
	}
	systemAdmin, err := n.app.Auth.AuthorizeSystem(n.ctx, n.org, []model.ID{n.project}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	_, err = n.save(c, systemAdmin, n.alert("up"), 0)
	if code, _ := faultOf(err); code != model.Forbidden && code != model.NotFound {
		t.Fatalf("the runner authored a rule: %v", err)
	}
}

// A recording rule is judged against the recording source the node writes
// through: it needs one, for its own project, allowed to write metrics, and
// every configured label must be a value the source policy enumerates (the test
// C03 applies to each record), so a rule that saves is not one whose output is
// refused for its configured labels (02.11 review M-4).
func TestCatalogueRecordingRulesAreCheckedAgainstTheRecordingSource(t *testing.T) {
	n := newNode(t)
	admin := n.scope(auth.OrgAdmin)

	// No recording source: a recording rule cannot be saved, an alert rule can.
	bare := n.catalogue()
	_, err := n.save(bare, admin, n.recording(model.Labels{}), 0)
	n.mustFail(err, model.Invalid, rules.ReasonRecordingSourceUnavailable, "a recording rule with no recording source")
	if _, err = n.save(bare, admin, n.alert("up"), 0); err != nil {
		t.Fatal(err)
	}

	source, err := n.app.NewRecordingSource(n.ctx, n.issued)
	if err != nil {
		t.Fatal(err)
	}
	c := n.catalogue(rules.WithRecordingSource(source))
	saved, err := n.save(c, admin, n.recording(lbl("env", "prod", "job", "api")), 0)
	if err != nil || saved.Rule.Kind != rules.KindRecording || saved.Rule.RecordName != "job:up:sum" {
		t.Fatalf("a recording rule with enumerated labels: %+v %v", saved, err)
	}
	if _, err = n.save(c, admin, n.recording(model.Labels{}), 0); err != nil {
		t.Fatalf("a recording rule with no configured label: %v", err)
	}
	for name, labels := range map[string]model.Labels{
		"value not enumerated": lbl("env", "staging"),
		"name not enumerated":  lbl("region", "eu"),
		"one bad of two":       lbl("env", "prod", "job", "scheduler"),
	} {
		_, err = n.save(c, admin, n.recording(labels), 0)
		n.mustFail(err, model.Invalid, rules.ReasonRecordingLabelNotAllowed, name)
	}
	// The source belongs to one project: it cannot record another project's rule.
	otherProject := model.NewID()
	n.command("create_project", auth.AdminPayload{ID: otherProject, Name: "other"})
	otherAdmin, err := n.app.Auth.Authorize(n.ctx, n.actor, n.org, []model.ID{otherProject}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	// Creating the project moved the organization's policy epoch: the earlier scope is stale.
	admin = n.scope(auth.OrgAdmin)
	_, err = c.Save(n.ctx, otherAdmin, rules.SaveCommand{Command: model.NewID(), Project: otherProject, Rule: n.recording(model.Labels{}), Reason: "x"})
	n.mustFail(err, model.Invalid, rules.ReasonRecordingSourceUnavailable, "a recording rule of a project the source does not belong to")
	// A source that is not enabled writes nothing.
	disabled := n.catalogue(rules.WithRecordingSource(fixedRecording{target: rules.RecordingTarget{Project: n.project, Policy: model.SourcePolicy{Enabled: false, Kinds: []model.Kind{model.Metric}}}}))
	_, err = n.save(disabled, admin, n.recording(model.Labels{}), 0)
	n.mustFail(err, model.Invalid, rules.ReasonRecordingSourceUnavailable, "a disabled source")
	logsOnly := n.catalogue(rules.WithRecordingSource(fixedRecording{target: rules.RecordingTarget{Project: n.project, Policy: model.SourcePolicy{Enabled: true, Kinds: []model.Kind{model.Log}}}}))
	_, err = n.save(logsOnly, admin, n.recording(model.Labels{}), 0)
	n.mustFail(err, model.Invalid, rules.ReasonRecordingSourceUnavailable, "a source that may not write metrics")
	broken := n.catalogue(rules.WithRecordingSource(fixedRecording{err: model.Fail(model.Forbidden)}))
	_, err = n.save(broken, admin, n.recording(model.Labels{}), 0)
	n.mustFail(err, model.Invalid, rules.ReasonRecordingSourceUnavailable, "a source whose credential was revoked")
}

type fixedRecording struct {
	target rules.RecordingTarget
	err    error
}

func (f fixedRecording) Recording(context.Context) (rules.RecordingTarget, error) {
	return f.target, f.err
}

// An operator's replay declaration is an administrator's audited act on a rule
// of the catalogue, and it is reachable before the rule's first evaluation: the
// book it leaves holds the window and no version, which is no state yet and not
// a corrupt one (the scheduler reads it at every pass).
func TestCatalogueReplayDeclarationIsAuditedAndLeavesTheRuleEvaluable(t *testing.T) {
	n := newNode(t)
	c := n.catalogue()
	admin := n.scope(auth.OrgAdmin)
	rule := n.alert("up")
	_, err := n.save(c, admin, rule, 0)
	if err != nil {
		t.Fatal(err)
	}
	n.mustFail(c.DeclareReplay(n.ctx, admin, n.project, model.NewID(), 60*sec, 120*sec, "x"), model.NotFound, "", "a replay of an unknown rule")
	if err = c.DeclareReplay(n.ctx, admin, n.project, rule.ID, 60*sec, 120*sec, "reconcile after an outage"); err != nil {
		t.Fatal(err)
	}
	if err = c.DeclareReplay(n.ctx, admin, n.project, rule.ID, 60*sec, 120*sec, "reconcile after an outage"); err != nil {
		t.Fatalf("a repeated declaration: %v", err)
	}
	state, err := rules.NewStateStore(n.app.Control).Read(n.ctx, n.scope(auth.Read), rule.ID)
	if err != nil {
		t.Fatalf("a rule with only a replay declaration cannot be read: %v", err)
	}
	if len(state.Replays) != 1 || state.Replays[0].From != 60*sec || state.Replays[0].To != 120*sec || state.Revision != 0 {
		t.Fatalf("state: %+v", state)
	}
	audited := 0
	if err = n.app.Control.View(n.ctx, func(st model.ControlState) error {
		for _, a := range st.Audits {
			if a.Action == "rules.operator_replay" {
				audited++
			}
		}
		return nil
	}); err != nil || audited != 1 {
		t.Fatalf("operator replay audited %d times: %v", audited, err)
	}
}
