// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Interaction coverage is not a claim anybody supplies: the gate derives it from
// the generated cases whose every row was executed and matched. A release whose
// rows were never run, disagreed, or are not the valid case carrying an
// interaction does not cover that interaction, whatever a planner computed.
func TestInteractionCoverageIsDerivedFromExecutedAndMatchedRows(t *testing.T) {
	rep, err := runGate(t, releaseFixture(t))
	if err != nil || rep.InteractionRequired != 1 || rep.InteractionCovered != 1 {
		t.Fatalf("the baseline must cover its one required interaction: %v %d/%d", err, rep.InteractionCovered, rep.InteractionRequired)
	}
	notObserved := errors.Join(ErrNotObserved, errors.New("not run"))
	// ownedAnswers wraps the owned engine so that it answers err for the row with this ID.
	ownedAnswers := func(c *ReleaseConfig, id string, err error) {
		inner := c.Generated[0].Own
		c.Generated[0].Own = func(ctx context.Context, rc ReleaseCase) (SemanticResult, error) {
			if rc.ID == id {
				return SemanticResult{}, err
			}
			return inner(ctx, rc)
		}
	}
	// secondRow adds a second row of the same case, as a second feature set would.
	secondRow := func(c *ReleaseConfig) string {
		row := c.Generated[0].Rows[0]
		row.Row.ID += "#second-feature-set"
		c.Generated[0].Rows = append(c.Generated[0].Rows, row)
		return row.Row.ID
	}
	faults := []struct {
		name   string
		mutate func(c *ReleaseConfig)
	}{
		{"the owned engine never observed the carrying row", func(c *ReleaseConfig) {
			ownedAnswers(c, c.Generated[0].Rows[0].Row.ID, notObserved)
		}},
		{"the pinned oracle never observed the carrying row", func(c *ReleaseConfig) {
			inner, id := c.Generated[0].Oracle, c.Generated[0].Rows[0].Row.ID
			c.Generated[0].Oracle = func(ctx context.Context, p SourceProfile, rc ReleaseCase) (SemanticResult, error) {
				if rc.ID == id {
					return SemanticResult{}, notObserved
				}
				return inner(ctx, p, rc)
			}
		}},
		{"the oracle answered the carrying row with another identity", func(c *ReleaseConfig) {
			inner, id := c.Generated[0].Oracle, c.Generated[0].Rows[0].Row.ID
			c.Generated[0].Oracle = func(ctx context.Context, p SourceProfile, rc ReleaseCase) (SemanticResult, error) {
				r, err := inner(ctx, p, rc)
				if rc.ID == id {
					r.Oracle.ImageSHA256 = strings.Repeat("0", 64)
				}
				return r, err
			}
		}},
		{"the owned engine disagreed on the carrying row", func(c *ReleaseConfig) {
			ownedAnswers(c, c.Generated[0].Rows[0].Row.ID, PhaseProblems{"value: reference 1, owned 2"})
		}},
		{"a second row of the carrying case disagreed", func(c *ReleaseConfig) {
			ownedAnswers(c, secondRow(c), errors.New("value: reference 1, owned 2"))
		}},
		{"a second row of the carrying case was never observed", func(c *ReleaseConfig) {
			ownedAnswers(c, secondRow(c), notObserved)
		}},
		// The row that disagrees comes first and the one that matches comes last: neither the last row
		// nor the number of matched rows alone may stand for the case.
		{"the first of two rows of the carrying case disagreed", func(c *ReleaseConfig) {
			first := c.Generated[0].Rows[0].Row.ID
			secondRow(c)
			ownedAnswers(c, first, errors.New("value: reference 1, owned 2"))
		}},
		{"the first of two rows of the carrying case was never observed", func(c *ReleaseConfig) {
			first := c.Generated[0].Rows[0].Row.ID
			secondRow(c)
			ownedAnswers(c, first, notObserved)
		}},
		{"the carrying case is a negative case", func(c *ReleaseConfig) { c.Generated[0].Rows[0].Source.Kind = "negative" }},
		{"the carrying case is a gate probe", func(c *ReleaseConfig) { c.Generated[0].Rows[0].Source.Kind = "gate" }},
		{"the carrying case belongs to the language's second profile", func(c *ReleaseConfig) {
			c.Generated[0].Rows[0].Source.Profile = "promql-prometheus-3.13.5"
		}},
		{"the carrying case belongs to another language", func(c *ReleaseConfig) { c.Generated[0].Rows[0].Source.Language = "logql" }},
		{"the carrying case sits at other coordinates", func(c *ReleaseConfig) {
			c.Generated[0].Rows[0].Source.Coordinate = map[string]string{"a": "x", "b": "q"}
		}},
		{"the carrying case states no coordinates", func(c *ReleaseConfig) { c.Generated[0].Rows[0].Source.Coordinate = nil }},
		{"no generated run at all", func(c *ReleaseConfig) { c.Generated = nil }},
	}
	for _, f := range faults {
		t.Run(f.name, func(t *testing.T) {
			cfg := releaseFixture(t)
			f.mutate(&cfg)
			rep, err := runGate(t, cfg)
			requireRejected(t, rep, err, "interaction coverage 0 of 1")
			if rep.InteractionRequired != 1 || rep.InteractionCovered != 0 {
				t.Fatalf("the report states %d of %d interactions covered, want 0 of 1", rep.InteractionCovered, rep.InteractionRequired)
			}
		})
	}
	// Only the first profile of a language stands for it: rows of its other profiles
	// that did not match do not uncover what the first profile's matched rows carry
	// (they reject the release on their own).
	t.Run("a mismatch on another profile does not uncover an interaction", func(t *testing.T) {
		cfg := releaseFixture(t)
		ownedAnswers(&cfg, cfg.Generated[0].Rows[1].Row.ID, PhaseProblems{"value: reference 1, owned 2"})
		rep, err := runGate(t, cfg)
		requireRejected(t, rep, err, "")
		if failureContains(rep, "interaction coverage") || rep.InteractionCovered != 1 {
			t.Fatalf("interaction coverage %d of %d, failures %q", rep.InteractionCovered, rep.InteractionRequired, rep.Failures)
		}
	})
	// Coverage is what ran: a case matched in one seed covers its interactions
	// although another seed never ran it (which rejects the release on its own).
	t.Run("a case matched in one seed covers although another seed did not run it", func(t *testing.T) {
		cfg := releaseFixture(t)
		other := fixtureGeneratedRun(cfg, 20270101, 3)
		other.Own = func(context.Context, ReleaseCase) (SemanticResult, error) { return SemanticResult{}, notObserved }
		cfg.Generated = append(cfg.Generated, other)
		rep, err := runGate(t, cfg)
		requireRejected(t, rep, err, "")
		if failureContains(rep, "interaction coverage") || rep.InteractionCovered != 1 {
			t.Fatalf("interaction coverage %d of %d, failures %q", rep.InteractionCovered, rep.InteractionRequired, rep.Failures)
		}
	})
	t.Run("a case matched only in the second seed covers", func(t *testing.T) {
		cfg := releaseFixture(t)
		cfg.Generated[0].Own = func(context.Context, ReleaseCase) (SemanticResult, error) { return SemanticResult{}, notObserved }
		cfg.Generated = append(cfg.Generated, fixtureGeneratedRun(cfg, 20270101, 3))
		rep, err := runGate(t, cfg)
		requireRejected(t, rep, err, "")
		if rep.InteractionCovered != 1 {
			t.Fatalf("interaction coverage %d of %d", rep.InteractionCovered, rep.InteractionRequired)
		}
	})
}

// agreeingRun is a run of the planned rows in which the pinned oracle and the
// owned engine observed every row and agreed on it.
func agreeingRun(cfg ReleaseConfig, seed uint64, rows []GeneratedRow) GeneratedRun {
	identities := map[string]*OracleIdentity{}
	for _, p := range cfg.Lock.Profiles {
		identities[p.ID] = &OracleIdentity{Profile: p.ID, Revision: p.Commit, Version: strings.TrimPrefix(strings.TrimPrefix(p.ID, "promql-prometheus-"), "logql-loki-"), ImageSHA256: p.Artifact.SHA256, ConfigurationSHA256: p.Artifact.ConfigurationSHA256}
	}
	res := PhaseResults{}
	for _, r := range rows {
		res[PhaseKey(r.Row.Profile, r.Row.ID)] = PhaseOutcome{Phase: r.Phase, Identity: identities[r.Row.Profile]}
	}
	return GeneratedRun{Seed: seed, Rows: rows, Oracle: res.PhaseOracle(), Own: res.PhaseOwn()}
}

// The real locked spec and the real planned rows: once every row ran and matched
// the release covers every interaction the spec requires, as many as the planner
// computed from the cases; and a release whose rows leave one higher-order tuple
// out is told so by name.
func TestRealPlannedRowsCoverEveryRequiredInteractionOnceTheyRunAndMatch(t *testing.T) {
	spec, ledger, domains := loadPlanInputs(t)
	const seed = 20261110
	cases, err := generateForRelease(spec, ledger, domains, seed)
	if err != nil {
		t.Fatal(err)
	}
	planned := Coverage(spec, cases)
	if planned.Required < 100 || planned.Covered != planned.Required {
		t.Fatalf("the planner's own accounting is not complete: %+v", planned)
	}
	rows, err := PlanGenerated(spec, ledger, domains, seed)
	if err != nil {
		t.Fatal(err)
	}
	cfg := releaseFixture(t)
	cfg.Spec = spec
	cfg.Generated = []GeneratedRun{agreeingRun(cfg, seed, rows)}
	rep, err := runGate(t, cfg)
	if err != nil || rep.InteractionRequired != planned.Required || rep.InteractionCovered != planned.Required {
		t.Fatalf("rows that all ran and matched cover %d of %d interactions, the planner computed %d: %v %q", rep.InteractionCovered, rep.InteractionRequired, planned.Required, err, rep.Failures)
	}
	// Leave out every case carrying one higher-order tuple.
	tuple := spec.HigherOrder[1]
	carries := func(c Case) bool {
		if c.Kind != "valid" || c.Language != tuple.Language {
			return false
		}
		for _, kv := range tuple.Tuple {
			axis, value, _ := strings.Cut(kv, "=")
			if c.Coordinate[axis] != value {
				return false
			}
		}
		return true
	}
	var kept []GeneratedRow
	for _, r := range rows {
		if !carries(r.Source) {
			kept = append(kept, r)
		}
	}
	if len(kept) == len(rows) {
		t.Fatalf("no planned row carries the tuple %v", tuple.Tuple)
	}
	cfg.Generated = []GeneratedRun{agreeingRun(cfg, seed, kept)}
	rep, err = runGate(t, cfg)
	requireRejected(t, rep, err, "interaction coverage")
	want := tuple.Language + ":" + strings.Join(tuple.Tuple, "|")
	if rep.InteractionRequired != planned.Required || rep.InteractionCovered != planned.Required-1 || !failureContains(rep, want) {
		t.Fatalf("covered %d of %d, want %d of %d missing exactly %s: %q", rep.InteractionCovered, rep.InteractionRequired, planned.Required-1, planned.Required, want, rep.Failures)
	}
}
