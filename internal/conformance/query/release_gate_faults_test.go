// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func runGate(t *testing.T, cfg ReleaseConfig) (Report, error) {
	t.Helper()
	rep, err := ReleaseGate(context.Background(), cfg)
	requireReportInvariants(t, rep)
	return rep, err
}

func requireRejected(t *testing.T, rep Report, err error, want string) {
	t.Helper()
	if !errors.Is(err, ErrReleaseRejected) || rep.UnresolvedCount == 0 {
		t.Fatalf("the gate accepted a deliberately faulty configuration: err=%v unresolved=%d", err, rep.UnresolvedCount)
	}
	if want != "" && !failureContains(rep, want) {
		t.Fatalf("no gate failure mentions %q (the check that owns this fault did not fire): %q", want, rep.Failures)
	}
}

// requiredCases is how many (profile, case) rows the fixture's obligations name.
func requiredCases(t *testing.T) int {
	t.Helper()
	rep, err := runGate(t, releaseFixture(t))
	if err != nil || rep.RequiredCaseCount == 0 {
		t.Fatalf("the baseline fixture must pass: %v", err)
	}
	return rep.RequiredCaseCount
}

func TestReleaseRejectsEachPolicySourceAndDomainFault(t *testing.T) {
	faults := []struct {
		name   string
		mutate func(c *ReleaseConfig)
		want   string
	}{
		{"policy schema", func(c *ReleaseConfig) { c.Policy.Schema = "soundpost-query-release-policy/2" }, "policy: unknown release policy schema"},
		{"policy flag off", func(c *ReleaseConfig) { c.Policy.RequireZeroUnrun = false }, "policy: release policy may not weaken"},
		{"policy names a profile twice", func(c *ReleaseConfig) {
			c.Policy.AllProfiles = []string{"promql-prometheus-3.1.0", "promql-prometheus-3.1.0", "logql-loki-3.5.2"}
		}, "policy: release policy names profile promql-prometheus-3.1.0 twice"},
		{"policy drops a required persistence scenario", func(c *ReleaseConfig) {
			c.Policy.RequiredPersistence = without(c.Policy.RequiredPersistence, "restart")
		}, "policy: release policy must require persistence scenario restart"},
		{"policy drops a required isolation scenario", func(c *ReleaseConfig) {
			c.Policy.RequiredIsolation = without(c.Policy.RequiredIsolation, "revocation-during-compute")
		}, "policy: release policy must require isolation scenario revocation-during-compute"},
		{"lock manifest version", func(c *ReleaseConfig) { c.Lock.ManifestVersion = 2 }, "source lock:"},
		{"lock commit differs from the pin", func(c *ReleaseConfig) { c.Lock.Profiles[0].Commit = strings.Repeat("0", 40) }, "source lock:"},
		{"lock lacks a profile", func(c *ReleaseConfig) { c.Lock.Profiles = c.Lock.Profiles[:2] }, "is not in the source lock"},
		{"artifact missing", func(c *ReleaseConfig) { c.Lock.Profiles[1].Artifact = nil }, "lacks a locked oracle artifact"},
		{"artifact path disagrees with its digest", func(c *ReleaseConfig) {
			c.Lock.Profiles[1].Artifact.Path = "sha256:" + strings.Repeat("1", 64)
		}, "lacks a locked oracle artifact"},
		{"artifact adapter", func(c *ReleaseConfig) { c.Lock.Profiles[1].Artifact.Adapter = "other" }, "lacks a locked oracle artifact"},
		{"artifact architecture", func(c *ReleaseConfig) { c.Lock.Profiles[1].Artifact.Architecture = "linux/arm64" }, "lacks a locked oracle artifact"},
		{"configuration digest too short", func(c *ReleaseConfig) {
			a := c.Lock.Profiles[1].Artifact
			a.ConfigurationSHA256 = a.ConfigurationSHA256[:63]
		}, "lacks a locked oracle artifact"},
		{"image digest is not hexadecimal", func(c *ReleaseConfig) {
			a := c.Lock.Profiles[1].Artifact
			a.SHA256 = strings.Repeat("z", 64)
			a.Path = "sha256:" + a.SHA256
		}, "lacks a locked oracle artifact"},
		{"configuration digest is not hexadecimal", func(c *ReleaseConfig) {
			c.Lock.Profiles[1].Artifact.ConfigurationSHA256 = strings.Repeat("z", 64)
		}, "lacks a locked oracle artifact"},
		{"duplicate gate domain", func(c *ReleaseConfig) { c.GateDomains = append(c.GateDomains, c.GateDomains[0]) }, "duplicate gate domain"},
		{"gate closure broken", func(c *ReleaseConfig) {
			c.GateDomains[0].FeatureSets = c.GateDomains[0].FeatureSets[1:]
		}, "missing feature combinations"},
		{"profile without a gate domain", func(c *ReleaseConfig) { c.GateDomains = c.GateDomains[:2] }, "has no gate domain"},
		{"ledger not complete", func(c *ReleaseConfig) { c.Ledger.Complete = false }, "inventory ledger incomplete"},
		{"ledger lists missing items", func(c *ReleaseConfig) { c.Ledger.Missing = []string{"a grammar rule"} }, "inventory ledger incomplete"},
		{"ledger without obligations", func(c *ReleaseConfig) { c.Ledger.Obligations = nil }, "inventory ledger incomplete"},
		{"duplicate binding", func(c *ReleaseConfig) { c.Bindings = append(c.Bindings, c.Bindings[0]) }, "duplicate binding"},
		{"binding for an unknown obligation", func(c *ReleaseConfig) {
			c.Bindings = append(c.Bindings, Binding{ObligationID: "promql-prometheus-3.13.5/nothing/here"})
		}, "binding for unknown obligation"},
		{"duplicate authored case", func(c *ReleaseConfig) { c.Cases = append(c.Cases, c.Cases[0]) }, "duplicate authored case"},
		{"authored case without an expected result", func(c *ReleaseConfig) { c.Cases[0].Expected = SemanticResult{} }, "declares no expected result"},
		{"no provenance decisions", func(c *ReleaseConfig) { c.Provenance = nil }, "no provenance decisions"},
		{"provenance rejected", func(c *ReleaseConfig) {
			c.Provenance = append(c.Provenance, ProvenanceDecision{File: "audits/x.json", Reason: "digest differs"})
		}, "provenance audits/x.json rejected: digest differs"},
		{"interaction coverage absent", func(c *ReleaseConfig) { c.Spec = GenerationSpec{} }, "interaction coverage 0 of 0"},
		{"generation spec unsound", func(c *ReleaseConfig) { c.Spec.Languages[0].Axes = c.Spec.Languages[0].Axes[:1] }, "generation spec: language promql needs two or more axes"},
		{"no generated row carries the required interaction", func(c *ReleaseConfig) { c.Generated[0].Rows = c.Generated[0].Rows[1:] }, "interaction coverage 0 of 1"},
		{"the row carrying the required interaction is not a valid case", func(c *ReleaseConfig) { c.Generated[0].Rows[0].Source.Kind = "negative" }, "interaction coverage 0 of 1"},
	}
	for _, f := range faults {
		t.Run(f.name, func(t *testing.T) {
			cfg := releaseFixture(t)
			f.mutate(&cfg)
			rep, err := runGate(t, cfg)
			requireRejected(t, rep, err, f.want)
		})
	}
}

func TestReleaseBindingFaultsLeaveExactlyOneObligationUnbound(t *testing.T) {
	omit := func(c *ReleaseConfig, ids []string) {
		for _, id := range ids {
			c.Bindings[0].Cases = without(c.Bindings[0].Cases, id)
		}
	}
	faults := []struct {
		name   string
		mutate func(c *ReleaseConfig)
	}{
		{"no binding at all", func(c *ReleaseConfig) { c.Bindings = c.Bindings[1:] }},
		{"empty implementation", func(c *ReleaseConfig) { c.Bindings[0].Implementation = "" }},
		{"pending implementation", func(c *ReleaseConfig) { c.Bindings[0].Implementation = "pending" }},
		{"pending-prefixed implementation", func(c *ReleaseConfig) { c.Bindings[0].Implementation = "pending-evaluator-binding" }},
		{"no go tests", func(c *ReleaseConfig) { c.Bindings[0].GoTests = nil }},
		{"go test without the Test prefix", func(c *ReleaseConfig) { c.Bindings[0].GoTests = []string{"Bound"} }},
		{"go test named just Test", func(c *ReleaseConfig) { c.Bindings[0].GoTests = []string{"Test"} }},
		{"lowercase go test", func(c *ReleaseConfig) { c.Bindings[0].GoTests = []string{"testBound"} }},
		{"binding lists no cases", func(c *ReleaseConfig) { c.Bindings[0].Cases = nil }},
		{"ledger positive class empty", func(c *ReleaseConfig) { c.Ledger.Obligations[0].PositiveCases = nil }},
		{"ledger negative class empty", func(c *ReleaseConfig) { c.Ledger.Obligations[0].NegativeCases = nil }},
		{"ledger interaction class empty", func(c *ReleaseConfig) { c.Ledger.Obligations[0].InteractionCases = nil }},
		{"binding omits a positive case", func(c *ReleaseConfig) { omit(c, c.Ledger.Obligations[0].PositiveCases[:1]) }},
		{"binding omits a negative case", func(c *ReleaseConfig) { omit(c, c.Ledger.Obligations[0].NegativeCases[:1]) }},
		{"binding omits an interaction case", func(c *ReleaseConfig) { omit(c, c.Ledger.Obligations[0].InteractionCases[:1]) }},
	}
	for _, f := range faults {
		t.Run(f.name, func(t *testing.T) {
			cfg := releaseFixture(t)
			f.mutate(&cfg)
			rep, err := runGate(t, cfg)
			requireRejected(t, rep, err, "")
			if rep.UnboundCount != 1 || rep.BoundCount != 4 || rep.ObligationCount != 5 {
				t.Fatalf("one obligation must be unbound, got %d unbound %d bound of %d", rep.UnboundCount, rep.BoundCount, rep.ObligationCount)
			}
		})
	}
}

func TestReleaseCountsGoTestsNoEvidenceBacksAsUnobservedNotUnbound(t *testing.T) {
	cfg := releaseFixture(t)
	cfg.Bindings[0].GoTests = append(cfg.Bindings[0].GoTests, "TestNeverObserved")
	rep, err := runGate(t, cfg)
	requireRejected(t, rep, err, "")
	if rep.UnobservedTests != 1 || rep.UnboundCount != 0 || rep.BoundCount != 5 {
		t.Fatalf("unobserved %d unbound %d bound %d", rep.UnobservedTests, rep.UnboundCount, rep.BoundCount)
	}
}

func TestReleaseCaseVerdicts(t *testing.T) {
	required := requiredCases(t)
	wrongValues := []Value{{Timestamp: "1", Bits: "4000000000000000"}}
	type verdict struct {
		name   string
		mutate func(c *ReleaseConfig)
		check  func(t *testing.T, rep Report)
	}
	allUnrun := func(t *testing.T, rep Report) {
		t.Helper()
		if rep.MatchedCaseCount != 0 || len(rep.UnrunCases) != required {
			t.Fatalf("matched %d unrun %d of %d", rep.MatchedCaseCount, len(rep.UnrunCases), required)
		}
	}
	verdicts := []verdict{
		{"a required case that was never authored", func(c *ReleaseConfig) { c.Cases = c.Cases[1:] }, func(t *testing.T, rep Report) {
			if rep.MatchedCaseCount != required-1 || len(rep.UnrunCases) != 1 || rep.OracleRuns != required-1 {
				t.Fatalf("matched %d unrun %v oracle runs %d", rep.MatchedCaseCount, rep.UnrunCases, rep.OracleRuns)
			}
		}},
		{"a skipped case", func(c *ReleaseConfig) { c.Cases[0].Skip = "flaky" }, func(t *testing.T, rep Report) {
			if rep.SkippedCount != 1 || rep.MatchedCaseCount != required-1 || len(rep.UnrunCases) != 1 || rep.OracleRuns != required-1 {
				t.Fatalf("skipped %d matched %d unrun %d oracle runs %d", rep.SkippedCount, rep.MatchedCaseCount, len(rep.UnrunCases), rep.OracleRuns)
			}
		}},
		{"a case without an expected result", func(c *ReleaseConfig) { c.Cases[0].Expected = SemanticResult{} }, func(t *testing.T, rep Report) {
			if rep.MatchedCaseCount != required-1 || len(rep.UnrunCases) != 1 || rep.OracleRuns != required-1 {
				t.Fatalf("matched %d unrun %d oracle runs %d: an empty expectation must not be run, let alone matched", rep.MatchedCaseCount, len(rep.UnrunCases), rep.OracleRuns)
			}
		}},
		{"no oracle at all", func(c *ReleaseConfig) { c.Oracle = nil }, func(t *testing.T, rep Report) {
			allUnrun(t, rep)
			if rep.OracleUnavailable != required || rep.OracleRuns != 0 {
				t.Fatalf("unavailable %d runs %d", rep.OracleUnavailable, rep.OracleRuns)
			}
		}},
		{"an oracle that errors", func(c *ReleaseConfig) {
			c.Oracle = func(context.Context, SourceProfile, ReleaseCase) (SemanticResult, error) {
				return SemanticResult{}, errors.New("runtime unavailable")
			}
		}, func(t *testing.T, rep Report) {
			allUnrun(t, rep)
			if rep.OracleUnavailable != required || rep.OracleRuns != required || len(rep.Mismatches) != 0 {
				t.Fatalf("unavailable %d runs %d mismatches %d", rep.OracleUnavailable, rep.OracleRuns, len(rep.Mismatches))
			}
		}},
		{"an oracle that never observed the row", func(c *ReleaseConfig) {
			c.Oracle = func(context.Context, SourceProfile, ReleaseCase) (SemanticResult, error) {
				return SemanticResult{}, errors.Join(ErrNotObserved, errors.New("not run"))
			}
		}, func(t *testing.T, rep Report) {
			allUnrun(t, rep)
			if rep.OracleUnavailable != required || len(rep.Mismatches) != 0 {
				t.Fatalf("unavailable %d mismatches %d", rep.OracleUnavailable, len(rep.Mismatches))
			}
		}},
		{"an oracle answer that carries no identity", func(c *ReleaseConfig) {
			inner := c.Oracle
			c.Oracle = func(ctx context.Context, p SourceProfile, rc ReleaseCase) (SemanticResult, error) {
				r, err := inner(ctx, p, rc)
				r.Oracle = nil
				return r, err
			}
		}, func(t *testing.T, rep Report) {
			allUnrun(t, rep)
			if rep.OracleUnverified != required || rep.OracleUnavailable != 0 {
				t.Fatalf("unverified %d unavailable %d", rep.OracleUnverified, rep.OracleUnavailable)
			}
		}},
		{"an oracle that disagrees with the authored expectation", func(c *ReleaseConfig) {
			inner := c.Oracle
			c.Oracle = func(ctx context.Context, p SourceProfile, rc ReleaseCase) (SemanticResult, error) {
				r, err := inner(ctx, p, rc)
				r.Values = wrongValues
				return r, err
			}
		}, func(t *testing.T, rep Report) {
			allUnrun(t, rep)
			if len(rep.Mismatches) != required {
				t.Fatalf("mismatches %d", len(rep.Mismatches))
			}
			for _, m := range rep.Mismatches {
				if m.Side != "oracle" || m.Field != "values" {
					t.Fatalf("mismatch %+v", m)
				}
			}
		}},
		{"an owned engine that disagrees", func(c *ReleaseConfig) {
			c.Own = func(_ context.Context, rc ReleaseCase) (SemanticResult, error) {
				r := rc.Expected
				r.Values = wrongValues
				return r, nil
			}
		}, func(t *testing.T, rep Report) {
			allUnrun(t, rep)
			if len(rep.Mismatches) != required {
				t.Fatalf("mismatches %d", len(rep.Mismatches))
			}
			for _, m := range rep.Mismatches {
				if m.Side != "owned" || m.Field != "values" {
					t.Fatalf("mismatch %+v", m)
				}
			}
		}},
		{"both sides disagree", func(c *ReleaseConfig) {
			inner := c.Oracle
			c.Oracle = func(ctx context.Context, p SourceProfile, rc ReleaseCase) (SemanticResult, error) {
				r, err := inner(ctx, p, rc)
				r.Type = "vector"
				return r, err
			}
			c.Own = func(_ context.Context, rc ReleaseCase) (SemanticResult, error) {
				r := rc.Expected
				r.Kind = "vector"
				return r, nil
			}
		}, func(t *testing.T, rep Report) {
			allUnrun(t, rep)
			sides := map[string]int{}
			for _, m := range rep.Mismatches {
				sides[m.Side+"/"+m.Field]++
			}
			if sides["oracle/type"] != required || sides["owned/kind"] != required || len(rep.Mismatches) != 2*required {
				t.Fatalf("mismatches %v", sides)
			}
		}},
		{"no owned engine", func(c *ReleaseConfig) { c.Own = nil }, func(t *testing.T, rep Report) {
			allUnrun(t, rep)
			if len(rep.Mismatches) != 0 {
				t.Fatalf("a missing owned engine is unrun, not %d mismatches", len(rep.Mismatches))
			}
		}},
		{"an owned engine that errors", func(c *ReleaseConfig) {
			c.Own = func(context.Context, ReleaseCase) (SemanticResult, error) {
				return SemanticResult{}, errors.New("boom")
			}
		}, func(t *testing.T, rep Report) {
			allUnrun(t, rep)
			if len(rep.Mismatches) != required {
				t.Fatalf("mismatches %d", len(rep.Mismatches))
			}
			for _, m := range rep.Mismatches {
				if m.Side != "owned" || m.Field != "error: boom" {
					t.Fatalf("mismatch %+v", m)
				}
			}
		}},
		{"an owned engine that never observed the row", func(c *ReleaseConfig) {
			c.Own = func(context.Context, ReleaseCase) (SemanticResult, error) {
				return SemanticResult{}, errors.Join(ErrNotObserved, errors.New("not run"))
			}
		}, func(t *testing.T, rep Report) {
			allUnrun(t, rep)
			if len(rep.Mismatches) != 0 {
				t.Fatalf("an engine that never ran is unrun, not a mismatch of the engines: %d", len(rep.Mismatches))
			}
		}},
	}
	for _, v := range verdicts {
		t.Run(v.name, func(t *testing.T) {
			cfg := releaseFixture(t)
			v.mutate(&cfg)
			rep, err := runGate(t, cfg)
			requireRejected(t, rep, err, "")
			v.check(t, rep)
		})
	}
}

func TestReleaseCaseOfAnUnknownProfileIsUnrun(t *testing.T) {
	required := requiredCases(t)
	cfg := releaseFixture(t)
	o := &cfg.Ledger.Obligations[0]
	ids := map[string]bool{}
	for _, group := range [][]string{o.PositiveCases, o.NegativeCases, o.InteractionCases} {
		for _, id := range group {
			ids[id] = true
		}
	}
	o.Profile = "promql-prometheus-9.9.9"
	for i := range cfg.Cases {
		if ids[cfg.Cases[i].ID] {
			cfg.Cases[i].Profile = o.Profile
		}
	}
	rep, err := runGate(t, cfg)
	requireRejected(t, rep, err, "")
	if rep.OracleUnavailable != len(ids) || len(rep.UnrunCases) != len(ids) || rep.OracleRuns != required-len(ids) || rep.MatchedCaseCount != required-len(ids) {
		t.Fatalf("unavailable %d unrun %d oracle runs %d matched %d (a profile outside the lock has no oracle)", rep.OracleUnavailable, len(rep.UnrunCases), rep.OracleRuns, rep.MatchedCaseCount)
	}
}

func TestReleaseHonoursOrderingFreedomOnlyWhereTheCaseGrantsIt(t *testing.T) {
	a, b := Value{Timestamp: "1", Bits: "3ff0000000000000", Labels: map[string]string{"job": "a"}}, Value{Timestamp: "1", Bits: "4000000000000000", Labels: map[string]string{"job": "b"}}
	for _, free := range []bool{true, false} {
		cfg := releaseFixture(t)
		required := requiredCases(t)
		target := cfg.Cases[0].ID
		cfg.Cases[0].Expected = SemanticResult{Kind: "vector", Type: "vector", Values: []Value{a, b}}
		cfg.Cases[0].Ordering = OrderingFreedom{UnorderedVector: free}
		permute := func(r SemanticResult, id string) SemanticResult {
			if id == target {
				r.Values = []Value{b, a}
			}
			return r
		}
		innerOracle := cfg.Oracle
		cfg.Oracle = func(ctx context.Context, p SourceProfile, rc ReleaseCase) (SemanticResult, error) {
			r, err := innerOracle(ctx, p, rc)
			return permute(r, rc.ID), err
		}
		cfg.Own = func(_ context.Context, rc ReleaseCase) (SemanticResult, error) {
			return permute(rc.Expected, rc.ID), nil
		}
		rep, err := runGate(t, cfg)
		if free && (err != nil || rep.MatchedCaseCount != required) {
			t.Fatalf("a permuted vector was refused although the case grants unordered vectors: %v %d/%d", err, rep.MatchedCaseCount, required)
		}
		if !free && (err == nil || rep.MatchedCaseCount != required-1 || len(rep.Mismatches) != 2) {
			t.Fatalf("a permuted vector was accepted without the freedom: %v matched %d mismatches %d", err, rep.MatchedCaseCount, len(rep.Mismatches))
		}
	}
}

func TestReleaseStopsOnACancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep, err := ReleaseGate(ctx, releaseFixture(t))
	if !errors.Is(err, context.Canceled) || rep.MatchedCaseCount != 0 {
		t.Fatalf("a cancelled gate must stop with the context's error and match nothing: %v matched %d", err, rep.MatchedCaseCount)
	}
}

func TestReleaseRejectionNamesTheCounts(t *testing.T) {
	cfg := releaseFixture(t)
	cfg.Bindings = cfg.Bindings[1:]
	cfg.Cases[0].Skip = "flaky"
	cfg.Smoke.Normalization[0].Normalized = cfg.Smoke.Normalization[0].Normalized[:1]
	rep, err := runGate(t, cfg)
	requireRejected(t, rep, err, "")
	for _, want := range []string{"unbound 1,", "skipped 1,", "normalization loss 1", "seed 20261110 generated 3 executed 3 matched 3 mismatched 0 unrun 0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the rejection %q does not state %q", err, want)
		}
	}
	if !strings.Contains(err.Error(), "unrun ") || !strings.Contains(err.Error(), "mismatches 0,") {
		t.Errorf("the rejection %q does not state the unrun and mismatch counts", err)
	}
}

func TestReleaseReportCarriesTheIdentitiesOfItsInputs(t *testing.T) {
	cfg := releaseFixture(t)
	rep, err := runGate(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range cfg.Lock.Profiles {
		if rep.Profiles[p.ID] != p.Commit || rep.Configs[p.ID] != p.Artifact.ConfigurationSHA256 {
			t.Errorf("%s: report commit %q config %q", p.ID, rep.Profiles[p.ID], rep.Configs[p.ID])
		}
	}
	for _, d := range cfg.GateDomains {
		if rep.FeatureSets[d.Profile] != len(d.FeatureSets) || rep.FeatureSets[d.Profile] == 0 {
			t.Errorf("%s: report feature sets %d, domain %d", d.Profile, rep.FeatureSets[d.Profile], len(d.FeatureSets))
		}
	}
	raw, _ := json.Marshal(cfg.Smoke.Normalization)
	sum := sha256.Sum256(raw)
	if rep.InputNormalizationID != hex.EncodeToString(sum[:]) {
		t.Errorf("input normalization identity %s is not the digest of the checks", rep.InputNormalizationID)
	}
	if rep.Build.GoVersion == "" || rep.Resources.DurationNS <= 0 || rep.Resources.TotalAllocated == 0 || rep.Resources.Goroutines == 0 || rep.Resources.PeakHeapBytes == 0 {
		t.Errorf("build or resource statistics missing: %+v %+v", rep.Build, rep.Resources)
	}
	if rep.InteractionRequired != 1 || rep.InteractionCovered != 1 || len(rep.Provenance) != 1 || !rep.Provenance[0].Accepted {
		t.Errorf("interaction or provenance not echoed: %d/%d %v", rep.InteractionCovered, rep.InteractionRequired, rep.Provenance)
	}
	if len(rep.Persistence) != len(cfg.Smoke.Persistence) || len(rep.Isolation) != len(cfg.Smoke.Isolation) || rep.ScenarioFailures != 0 {
		t.Errorf("scenarios not echoed: %v %v %d", rep.Persistence, rep.Isolation, rep.ScenarioFailures)
	}
	if rep.ObligationCount != 5 || rep.BoundCount != 5 || rep.OracleRuns != rep.RequiredCaseCount || rep.OracleUnavailable != 0 || rep.OracleUnverified != 0 || rep.UnobservedTests != 0 || rep.SkippedCount != 0 {
		t.Errorf("counts of a passing gate: %+v", rep)
	}
	// The machine-readable report must round-trip through its own JSON.
	raw, err = MarshalReport(rep)
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err = json.Unmarshal(raw, &back); err != nil || back.UnresolvedCount != 0 || back.RequiredCaseCount != rep.RequiredCaseCount || back.InputNormalizationID != rep.InputNormalizationID {
		t.Fatalf("report does not round-trip: %v", err)
	}
}
