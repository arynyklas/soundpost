// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/profiles"
)

func queryRoot(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "..", "conformance", "query"}, parts...)...)
}

func loadRealLock(t testing.TB) SourceLock {
	t.Helper()
	var lock SourceLock
	if err := ReadJSON(queryRoot("source-lock.json"), &lock); err != nil {
		t.Fatal(err)
	}
	return lock
}

// pickedKinds are one grammar, function, stage, flag and template obligation.
var pickedKinds = map[string]string{
	"promql-prometheus-3.13.5": "grammar-obligation function-signature contextual-gate",
	"logql-loki-3.5.2":         "filter template-function",
}

// releaseFixture is the smallest ledger that still holds one obligation of
// each kind the brief names, taken from the REAL ledger, fully bound, with
// every authored case run against a fake oracle that returns the locked
// identity. The oracle and owned evaluator are fakes: this exercises the gate,
// not the engines.
func releaseFixture(t testing.TB) ReleaseConfig {
	t.Helper()
	var real Ledger
	if err := ReadJSON(queryRoot("obligations.json"), &real); err != nil {
		t.Fatal(err)
	}
	picked := Ledger{ManifestVersion: 1, Complete: true, Missing: []string{}}
	used := map[string]bool{}
	for _, o := range real.Obligations {
		for _, k := range strings.Fields(pickedKinds[o.Profile]) {
			if o.Kind == k && !used[o.Profile+k] {
				used[o.Profile+k] = true
				picked.Obligations = append(picked.Obligations, o)
			}
		}
	}
	if len(picked.Obligations) != 5 {
		t.Fatalf("fixture picked %d obligations", len(picked.Obligations))
	}
	var domains struct {
		Domains []GateDomain `json:"domains"`
	}
	if err := ReadJSON(queryRoot("gate-domains.json"), &domains); err != nil {
		t.Fatal(err)
	}
	cfg := ReleaseConfig{Lock: loadRealLock(t), Ledger: picked, GateDomains: domains.Domains}
	cfg.Policy = ReleasePolicy{Schema: "soundpost-query-release-policy/1", RequireLocked: true, RequireZeroUnbound: true, RequireZeroSkips: true, RequireZeroMismatch: true, RequireZeroUnrun: true, RequireOracle: true, RequireLosslessInput: true,
		AllProfiles: []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5", "logql-loki-3.5.2"}, RequiredPersistence: []string{"flush"}, RequiredIsolation: []string{"foreign-project"}}
	for i, o := range picked.Obligations {
		test := "TestBound" + strings.ReplaceAll(strings.ReplaceAll(o.Kind, "-", ""), "_", "") + string(rune('A'+i))
		b := Binding{ObligationID: o.ID, Implementation: "internal/query/example.go", GoTests: []string{test}}
		for _, group := range [][]string{o.PositiveCases, o.NegativeCases, o.InteractionCases} {
			for _, c := range group {
				b.Cases = append(b.Cases, c)
				cfg.Cases = append(cfg.Cases, ReleaseCase{ID: c, Profile: o.Profile, Expected: SemanticResult{Kind: "scalar", Type: "scalar", Values: []Value{{Timestamp: "1", Bits: "3ff0000000000000"}}}})
			}
		}
		cfg.Bindings = append(cfg.Bindings, b)
		cfg.Tests = append(cfg.Tests, TestObservation{Name: test, Passed: true, Command: "go test", EvidenceSHA256: strings.Repeat("ab", 32)})
	}
	fake := func(p SourceProfile, c ReleaseCase) SemanticResult {
		r := c.Expected
		version := strings.TrimPrefix(strings.TrimPrefix(p.ID, "promql-prometheus-"), "logql-loki-")
		r.Oracle = &OracleIdentity{Profile: p.ID, Revision: p.Commit, Version: version, ImageSHA256: p.Artifact.SHA256, ConfigurationSHA256: p.Artifact.ConfigurationSHA256}
		return r
	}
	cfg.Oracle = func(_ context.Context, p SourceProfile, c ReleaseCase) (SemanticResult, error) {
		return fake(p, c), nil
	}
	cfg.Own = func(_ context.Context, c ReleaseCase) (SemanticResult, error) { return c.Expected, nil }
	stale := InputRecord{Kind: "float", Timestamp: "10", Name: "m", Bits: StaleBits}
	hist := InputRecord{Kind: "histogram", Timestamp: "10", Name: "h", Histogram: &Histogram{Kind: "integer", Schema: 0, Count: "3", ZeroCount: "1", PositiveSpans: []HistogramSpan{{Offset: 0, Length: 1}}, NegativeSpans: []HistogramSpan{}, PositiveDeltas: []string{"2"}}}
	cfg.Inputs = []NormalizationCheck{{ID: "stale-and-histogram", Profile: "promql-prometheus-3.13.5", Source: []InputRecord{stale, hist}, Normalized: []InputRecord{stale, hist}}}
	cfg.Persistence = []ScenarioOutcome{{Name: "flush", Passed: true}}
	cfg.Isolation = []ScenarioOutcome{{Name: "foreign-project", Passed: true}}
	cfg.Provenance = []ProvenanceDecision{{File: "provenance.json", Accepted: true}}
	cfg.Interaction = InteractionCoverage{Required: 4, Covered: 4}
	return cfg
}

func TestReleaseAcceptsAFullyBoundFixture(t *testing.T) {
	rep, err := ReleaseGate(context.Background(), releaseFixture(t))
	if err != nil || rep.UnresolvedCount != 0 || rep.ObligationCount != 5 || rep.BoundCount != 5 || rep.MatchedCaseCount != rep.RequiredCaseCount || rep.OracleRuns != rep.RequiredCaseCount {
		t.Fatalf("baseline must pass for the negative tests to mean anything: %v %+v", err, rep)
	}
	if len(rep.Profiles) != 3 || len(rep.Configs) != 3 || rep.InputNormalizationID == "" || rep.Resources.PeakHeapBytes == 0 {
		t.Fatalf("report lacks identities or resource stats: %+v", rep)
	}
}

func TestReleaseRejectsOneMissingObligation(t *testing.T) {
	base := releaseFixture(t)
	for i, o := range base.Ledger.Obligations {
		cfg := releaseFixture(t)
		cfg.Bindings = append(append([]Binding(nil), cfg.Bindings[:i]...), cfg.Bindings[i+1:]...)
		report, err := ReleaseGate(context.Background(), cfg)
		if err == nil || !errors.Is(err, ErrReleaseRejected) || report.UnboundCount != 1 {
			t.Fatalf("release accepted an unbound promised-language obligation %s (%s): %v %d", o.ID, o.Kind, err, report.UnboundCount)
		}
		// A binding that names a case set missing one class is also unbound.
		cfg = releaseFixture(t)
		cfg.Bindings[i].Cases = cfg.Bindings[i].Cases[1:]
		if report, err = ReleaseGate(context.Background(), cfg); err == nil || report.UnboundCount != 1 {
			t.Fatalf("release accepted %s with an unbound case", o.ID)
		}
		cfg = releaseFixture(t)
		cfg.Bindings[i].Implementation = "pending-evaluator-binding"
		if report, err = ReleaseGate(context.Background(), cfg); err == nil || report.UnboundCount != 1 {
			t.Fatalf("release accepted %s bound to a pending implementation", o.ID)
		}
	}
	kinds := map[string]bool{}
	for _, o := range base.Ledger.Obligations {
		kinds[o.Kind] = true
	}
	for _, k := range []string{"grammar-obligation", "function-signature", "filter", "contextual-gate", "template-function"} {
		if !kinds[k] {
			t.Fatalf("fixture lost obligation kind %s", k)
		}
	}
}

func TestReleaseRejectsAGoTestThatNeverPassed(t *testing.T) {
	cfg := releaseFixture(t)
	cfg.Tests[0].Passed = false
	if rep, err := ReleaseGate(context.Background(), cfg); err == nil || rep.UnobservedTests != 1 {
		t.Fatalf("an unobserved Go test was accepted: %v %+v", err, rep.UnobservedTests)
	}
}

func TestReleaseRejectsSkipAndNormalizationLoss(t *testing.T) {
	ctx := context.Background()
	unavailable := releaseFixture(t)
	unavailable.Oracle = func(context.Context, SourceProfile, ReleaseCase) (SemanticResult, error) {
		return SemanticResult{}, errors.New("oracle runtime unavailable")
	}
	if rep, err := ReleaseGate(ctx, unavailable); err == nil || rep.MatchedCaseCount != 0 || rep.OracleUnavailable != rep.RequiredCaseCount || len(rep.UnrunCases) != rep.RequiredCaseCount {
		t.Fatalf("an unavailable oracle counted as a match: %v matched=%d", err, rep.MatchedCaseCount)
	}
	none := releaseFixture(t)
	none.Oracle = nil
	if rep, err := ReleaseGate(ctx, none); err == nil || rep.MatchedCaseCount != 0 {
		t.Fatalf("a missing oracle counted as a match: %v", err)
	}
	skipped := releaseFixture(t)
	skipped.Cases[0].Skip = "flaky"
	if rep, err := ReleaseGate(ctx, skipped); err == nil || rep.SkippedCount != 1 || rep.MatchedCaseCount != rep.RequiredCaseCount-1 {
		t.Fatalf("a skipped case counted as a match: %v %+v", err, rep.SkippedCount)
	}
	// A wrong-identity oracle observation is never a match either.
	wrong := releaseFixture(t)
	inner := wrong.Oracle
	wrong.Oracle = func(c context.Context, p SourceProfile, rc ReleaseCase) (SemanticResult, error) {
		r, e := inner(c, p, rc)
		r.Oracle.ImageSHA256 = strings.Repeat("0", 64)
		return r, e
	}
	if rep, err := ReleaseGate(ctx, wrong); err == nil || rep.OracleUnverified != rep.RequiredCaseCount {
		t.Fatalf("oracle with the wrong image digest accepted: %v", err)
	}
	// One stale input demoted to an ordinary NaN, and one histogram demoted to a
	// float, are each normalization loss: neither is a match.
	for name, mutate := range map[string]func(*NormalizationCheck){
		"stale-to-nan": func(c *NormalizationCheck) { c.Normalized[0].Bits = "7ff8000000000001" },
		"histogram-float": func(c *NormalizationCheck) {
			c.Normalized[1] = InputRecord{Kind: "float", Timestamp: "10", Name: "h", Bits: "4008000000000000"}
		},
		"histogram-count": func(c *NormalizationCheck) {
			h := *c.Normalized[1].Histogram
			h.Count = "4"
			c.Normalized[1].Histogram = &h
		},
		"timestamp-drift": func(c *NormalizationCheck) { c.Normalized[0].Timestamp = "11" },
		"dropped-record":  func(c *NormalizationCheck) { c.Normalized = c.Normalized[:1] },
	} {
		cfg := releaseFixture(t)
		cfg.Inputs[0].Normalized = append([]InputRecord(nil), cfg.Inputs[0].Normalized...)
		mutate(&cfg.Inputs[0])
		if rep, err := ReleaseGate(ctx, cfg); err == nil || rep.NormalizationLoss != 1 {
			t.Fatalf("%s: normalization loss accepted: %v", name, err)
		}
	}
	cfg := releaseFixture(t)
	cfg.Inputs = nil
	if _, err := ReleaseGate(ctx, cfg); err == nil {
		t.Fatal("a gate with no normalization evidence passed")
	}
}

func TestReleaseRejectsMismatchPolicyAndScenarioFailures(t *testing.T) {
	ctx := context.Background()
	cfg := releaseFixture(t)
	cfg.Own = func(_ context.Context, c ReleaseCase) (SemanticResult, error) {
		r := c.Expected
		r.Values = []Value{{Timestamp: "1", Bits: "7ff8000000000001"}}
		return r, nil
	}
	if rep, err := ReleaseGate(ctx, cfg); err == nil || len(rep.Mismatches) == 0 || rep.MatchedCaseCount != 0 {
		t.Fatalf("owned mismatch accepted: %v", err)
	}
	for name, mutate := range map[string]func(*ReleaseConfig){
		"policy-weakened":     func(c *ReleaseConfig) { c.Policy.RequireZeroSkips = false },
		"persistence-missing": func(c *ReleaseConfig) { c.Persistence = nil },
		"persistence-failed":  func(c *ReleaseConfig) { c.Persistence[0].Passed = false },
		"isolation-failed":    func(c *ReleaseConfig) { c.Isolation[0].Passed = false },
		"interaction-short":   func(c *ReleaseConfig) { c.Interaction.Covered-- },
		"provenance-rejected": func(c *ReleaseConfig) { c.Provenance[0].Accepted = false },
		"ledger-incomplete":   func(c *ReleaseConfig) { c.Ledger.Complete = false },
		"missing-gate-domain": func(c *ReleaseConfig) { c.GateDomains = c.GateDomains[:2] },
	} {
		c := releaseFixture(t)
		mutate(&c)
		if rep, err := ReleaseGate(ctx, c); err == nil || rep.UnresolvedCount == 0 {
			t.Fatalf("%s accepted", name)
		}
	}
	// The unrun, unlocked and unresolved state of the real, still-pending ledger
	// must be reported rather than glossed over.
	var real Ledger
	if err := ReadJSON(queryRoot("obligations.json"), &real); err != nil {
		t.Fatal(err)
	}
	c := releaseFixture(t)
	c.Ledger, c.Bindings, c.Cases = real, nil, nil
	rep, err := ReleaseGate(ctx, c)
	if err == nil || rep.ObligationCount != len(real.Obligations) || rep.UnboundCount != len(real.Obligations) || rep.BoundCount != 0 {
		t.Fatalf("the real pending ledger must be fully unbound: %v %d/%d", err, rep.UnboundCount, rep.ObligationCount)
	}
}

// TestProfileExpectedResultsStaySeparate feeds one version-difference fixture
// (end(), added in 3.13.5) and requires independent expected observations. The
// owned parser is the evaluator under test and genuinely answers differently.
func TestProfileExpectedResultsStaySeparate(t *testing.T) {
	var cases struct {
		Cases []struct {
			ID       string   `json:"id"`
			Profiles []string `json:"profiles"`
			Query    string   `json:"query"`
		} `json:"cases"`
	}
	if err := ReadJSON(queryRoot("cases", "promql-version-differences.json"), &cases); err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ID       string
		Profiles []string
		Query    string
	}
	for _, c := range cases.Cases {
		if c.ID == "promql-version/end" {
			fixture.ID, fixture.Profiles, fixture.Query = c.ID, c.Profiles, c.Query
		}
	}
	if fixture.ID == "" || len(fixture.Profiles) != 2 {
		t.Fatal("version-difference fixture missing")
	}
	files, err := profiles.Query()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := profile.Load(files)
	if err != nil {
		t.Fatal(err)
	}
	owned := func(id string) SemanticResult {
		p, err := ResolveEnabled(files, registry, id, []string{"promql-experimental-functions"})
		if err != nil {
			t.Fatal(err)
		}
		obs, err := observeOwnedSyntax(fixture.Query, p)
		if err != nil {
			t.Fatal(err)
		}
		if obs.Accepted {
			return SemanticResult{Kind: "syntax", Type: obs.Type}
		}
		return SemanticResult{Kind: "syntax", Type: "error", Diagnostics: []Diagnostic{{Code: obs.Category}}}
	}
	old, current := owned("promql-prometheus-3.1.0"), owned("promql-prometheus-3.13.5")
	if canonical(old) == canonical(current) {
		t.Fatalf("end() must differ between the pins: %+v", old)
	}
	cs, err := SplitProfileExpectations(fixture.ID, fixture.Profiles, nil, ExpectedByProfile{"promql-prometheus-3.1.0": old, "promql-prometheus-3.13.5": current})
	if err != nil || len(cs) != 2 || canonical(cs[0].Expected) == canonical(cs[1].Expected) {
		t.Fatalf("expectations were merged: %v", err)
	}
	// Mutating one profile's expectation must not affect the other.
	cs[0].Expected.Diagnostics = append(cs[0].Expected.Diagnostics, Diagnostic{Code: "x"})
	if canonical(cs[1].Expected) != canonical(current) {
		t.Fatal("profile expectations share memory")
	}
	if _, err = SplitProfileExpectations(fixture.ID, fixture.Profiles, nil, ExpectedByProfile{"promql-prometheus-3.13.5": current}); err == nil {
		t.Fatal("a missing per-profile expectation was accepted")
	}
	if _, err = SplitProfileExpectations(fixture.ID, fixture.Profiles, nil, ExpectedByProfile{"promql-prometheus-3.13.5": current, "promql-prometheus-3.1.0": old, "logql-loki-3.5.2": old}); err == nil {
		t.Fatal("an undeclared profile expectation was accepted")
	}
	// The wrong (shared) expectation fails against the owned evaluator.
	shared, _ := SplitProfileExpectations(fixture.ID, fixture.Profiles, nil, ExpectedByProfile{"promql-prometheus-3.1.0": current, "promql-prometheus-3.13.5": current})
	for _, c := range shared {
		got := old
		if c.Profile == "promql-prometheus-3.13.5" {
			got = current
		}
		fails := len(Compare(c.Expected, got, c.Ordering)) > 0
		if fails != (c.Profile == "promql-prometheus-3.1.0") {
			t.Fatalf("shared expectation was not detected on %s", c.Profile)
		}
	}
}

// The loss reasons name the actual damage, so a stale marker demoted to NaN and
// a histogram demoted to a float are told apart from a generic difference.
func TestNormalizationLossNamesTheDamage(t *testing.T) {
	stale := InputRecord{Kind: "float", Timestamp: "1", Name: "m", Bits: StaleBits}
	hist := InputRecord{Kind: "histogram", Timestamp: "1", Name: "h", Histogram: &Histogram{Kind: "integer", Count: "3"}}
	cases := []struct {
		name       string
		src, got   []InputRecord
		wantReason string
	}{
		{"stale to nan", []InputRecord{stale}, []InputRecord{{Kind: "float", Timestamp: "1", Name: "m", Bits: "7ff8000000000001"}}, "stale marker"},
		{"histogram to float", []InputRecord{hist}, []InputRecord{{Kind: "float", Timestamp: "1", Name: "h", Bits: "4008000000000000"}}, "native form"},
		{"count drift", []InputRecord{stale, hist}, []InputRecord{stale}, "record count"},
		{"lossless", []InputRecord{stale, hist}, []InputRecord{stale, hist}, ""},
	}
	for _, c := range cases {
		got := normalizationLoss(NormalizationCheck{ID: c.name, Source: c.src, Normalized: c.got})
		if (c.wantReason == "") != (got == "") || !strings.Contains(got, c.wantReason) {
			t.Errorf("%s: loss reason %q, want it to mention %q", c.name, got, c.wantReason)
		}
	}
}
