// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"strings"
	"testing"
)

func validPolicy() ReleasePolicy {
	return ReleasePolicy{
		Schema: "soundpost-query-release-policy/1", RequireLocked: true, RequireZeroUnbound: true, RequireZeroSkips: true,
		RequireZeroMismatch: true, RequireZeroUnrun: true, RequireOracle: true, RequireLosslessInput: true,
		AllProfiles:         []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5", "logql-loki-3.5.2"},
		RequiredPersistence: requiredPersistenceNames(),
		RequiredIsolation:   requiredIsolationNames(),
	}
}

func without(names []string, drop string) []string {
	var out []string
	for _, n := range names {
		if n != drop {
			out = append(out, n)
		}
	}
	return out
}

// Every requirement of the policy is mandatory: a policy that turns one off,
// names a pinned profile twice (so another one silently drops out), or shrinks
// the persistence/isolation scenarios the plan requires is refused, never honoured.
func TestReleasePolicyValidateRejectsEveryWeakening(t *testing.T) {
	if err := validPolicy().Validate(); err != nil {
		t.Fatalf("the reference policy must validate: %v", err)
	}
	type fault struct {
		name   string
		mutate func(p *ReleasePolicy)
		want   string
	}
	faults := []fault{
		{"schema", func(p *ReleasePolicy) { p.Schema = "soundpost-query-release-policy/2" }, "schema"},
		{"require_locked", func(p *ReleasePolicy) { p.RequireLocked = false }, "weaken"},
		{"require_zero_unbound", func(p *ReleasePolicy) { p.RequireZeroUnbound = false }, "weaken"},
		{"require_zero_skips", func(p *ReleasePolicy) { p.RequireZeroSkips = false }, "weaken"},
		{"require_zero_mismatches", func(p *ReleasePolicy) { p.RequireZeroMismatch = false }, "weaken"},
		{"require_zero_unrun", func(p *ReleasePolicy) { p.RequireZeroUnrun = false }, "weaken"},
		{"require_oracle_observation", func(p *ReleasePolicy) { p.RequireOracle = false }, "weaken"},
		{"require_lossless_input_normalization", func(p *ReleasePolicy) { p.RequireLosslessInput = false }, "weaken"},
		{"a profile named twice", func(p *ReleasePolicy) {
			p.AllProfiles = []string{"promql-prometheus-3.1.0", "promql-prometheus-3.1.0", "logql-loki-3.5.2"}
		}, "twice"},
		{"an unknown profile", func(p *ReleasePolicy) { p.AllProfiles[2] = "logql-loki-9.9.9" }, "unknown profile"},
		{"too few profiles", func(p *ReleasePolicy) { p.AllProfiles = p.AllProfiles[:2] }, "all three"},
		{"no profiles", func(p *ReleasePolicy) { p.AllProfiles = nil }, "all three"},
		{"no persistence scenarios", func(p *ReleasePolicy) { p.RequiredPersistence = nil }, "persistence"},
		{"no isolation scenarios", func(p *ReleasePolicy) { p.RequiredIsolation = nil }, "isolation"},
		{"a persistence scenario listed twice", func(p *ReleasePolicy) {
			p.RequiredPersistence = append(p.RequiredPersistence, "flush")
		}, "persistence scenario flush twice"},
		{"an isolation scenario listed twice", func(p *ReleasePolicy) {
			p.RequiredIsolation = append(p.RequiredIsolation, "foreign-project-fails-closed")
		}, "isolation scenario foreign-project-fails-closed twice"},
		{"an unnamed persistence scenario", func(p *ReleasePolicy) { p.RequiredPersistence = append(p.RequiredPersistence, "") }, "persistence scenario"},
		{"an unnamed isolation scenario", func(p *ReleasePolicy) { p.RequiredIsolation = append(p.RequiredIsolation, "") }, "isolation scenario"},
	}
	for _, name := range requiredPersistenceNames() {
		name := name
		faults = append(faults, fault{"persistence scenario " + name + " dropped", func(p *ReleasePolicy) {
			p.RequiredPersistence = without(p.RequiredPersistence, name)
		}, "persistence scenario " + name})
	}
	for _, name := range requiredIsolationNames() {
		name := name
		faults = append(faults, fault{"isolation scenario " + name + " dropped", func(p *ReleasePolicy) {
			p.RequiredIsolation = without(p.RequiredIsolation, name)
		}, "isolation scenario " + name})
	}
	for _, f := range faults {
		p := validPolicy()
		f.mutate(&p)
		err := p.Validate()
		if err == nil {
			t.Errorf("%s: the weakened policy validated", f.name)
		} else if !strings.Contains(err.Error(), f.want) {
			t.Errorf("%s: error %q does not mention %q", f.name, err, f.want)
		}
	}
	// A policy may demand more than the floor.
	p := validPolicy()
	p.RequiredPersistence = append(p.RequiredPersistence, "warm-and-cold-caches")
	p.RequiredIsolation = append(p.RequiredIsolation, "scan-corruption-is-an-error")
	if err := p.Validate(); err != nil {
		t.Errorf("a stricter policy was refused: %v", err)
	}
}
