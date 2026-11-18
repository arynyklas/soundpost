// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// inRepoRoot makes the module root the working directory for the rest of the
// test, as the release tooling is run from it.
func inRepoRoot(t *testing.T) {
	t.Helper()
	here, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir("../../.."); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(here) })
}

// The scenario names the release policy, the smoke runner and the gate agree on.
// They are spelled out here, not read from the code under test, so that a change
// on either side is noticed.
func requiredPersistenceNames() []string {
	return []string{"hot-read", "flush", "compaction", "restart", "receipt-manifest-reconciles"}
}

func requiredIsolationNames() []string {
	return []string{"foreign-project-fails-closed", "revocation-during-compute", "cancellation-releases-everything", "complete-rules-never-use-partial-data", "no-production-path-reaches-an-oracle"}
}

func passedOutcomes(names []string) []ScenarioOutcome {
	out := make([]ScenarioOutcome, 0, len(names))
	for _, n := range names {
		out = append(out, ScenarioOutcome{Name: n, Passed: true})
	}
	return out
}

// validSmokeReport is what a complete, green `soundpost-querycheck smoke` run
// reports: both layouts, both case files, every required scenario passed and
// nothing unmet. Every call returns fresh memory.
func validSmokeReport() *SmokeReport {
	stale := InputRecord{Kind: "float", Timestamp: "10", Name: "m", Bits: StaleBits}
	hist := InputRecord{Kind: "histogram", Timestamp: "10", Name: "h", Histogram: &Histogram{Kind: "integer", Schema: 0, Count: "3", ZeroCount: "1", PositiveSpans: []HistogramSpan{{Offset: 0, Length: 1}}, NegativeSpans: []HistogramSpan{}, PositiveDeltas: []string{"2"}}}
	hist2 := hist
	hist2.Histogram = &Histogram{Kind: "integer", Schema: 0, Count: "3", ZeroCount: "1", PositiveSpans: []HistogramSpan{{Offset: 0, Length: 1}}, NegativeSpans: []HistogramSpan{}, PositiveDeltas: []string{"2"}}
	return &SmokeReport{
		Schema:        "soundpost-smoke-report/1",
		CaseFiles:     []string{"conformance/query/cases/persisted-path.json", "conformance/query/cases/profile-cross-products.json"},
		Storage:       "real",
		Control:       "real",
		Modes:         []string{"single", "distributed"},
		ModesNotRun:   []string{},
		Persistence:   passedOutcomes(requiredPersistenceNames()),
		Isolation:     passedOutcomes(requiredIsolationNames()),
		Normalization: []NormalizationCheck{{ID: "stale-and-histogram", Profile: "promql-prometheus-3.13.5", Source: []InputRecord{stale, hist}, Normalized: []InputRecord{stale, hist2}}},
		Steps:         []ScenarioOutcome{{Name: "persisted-path.json:hot/promql-prometheus-3.13.5/q1", Passed: true}, {Name: "distributed/persisted-path.json:hot/promql-prometheus-3.13.5/q1", Passed: true}},
		NotSatisfied:  []string{},
	}
}

// goTestStream renders the `go test -json` events of passing tests: the stream
// the observations of a fixture are hashed over.
func goTestStream(names ...string) []byte {
	var b strings.Builder
	b.WriteString(`{"Time":"2026-11-15T13:36:49Z","Action":"start","Package":"example.test/pkg"}` + "\n")
	for _, n := range names {
		fmt.Fprintf(&b, `{"Time":"2026-11-15T13:36:49Z","Action":"run","Package":"example.test/pkg","Test":%q}`+"\n", n)
		fmt.Fprintf(&b, `{"Time":"2026-11-15T13:36:49Z","Action":"pass","Package":"example.test/pkg","Test":%q,"Elapsed":0.01}`+"\n", n)
	}
	return []byte(b.String())
}

// observationOf is the passing observation of a test whose evidence is stream.
func observationOf(name string, stream []byte) TestObservation {
	sum := sha256.Sum256(stream)
	return TestObservation{Name: name, Passed: true, Command: "go test -json", EvidenceSHA256: hex.EncodeToString(sum[:])}
}

// requireReportInvariants checks the arithmetic that must hold between a
// report's counts whatever the verdict: a count that disagrees with the rows it
// summarises is itself a defect.
func requireReportInvariants(t testing.TB, rep Report) {
	t.Helper()
	if rep.MatchedCaseCount+len(rep.UnrunCases) != rep.RequiredCaseCount {
		t.Errorf("matched %d + unrun %d != required %d", rep.MatchedCaseCount, len(rep.UnrunCases), rep.RequiredCaseCount)
	}
	if !sort.StringsAreSorted(rep.UnrunCases) {
		t.Errorf("unrun cases are not sorted: %v", rep.UnrunCases)
	}
	if rep.BoundCount > rep.ObligationCount || rep.BoundCount < 0 || rep.UnboundCount < 0 {
		t.Errorf("bound %d unbound %d of %d obligations", rep.BoundCount, rep.UnboundCount, rep.ObligationCount)
	}
	want := rep.UnboundCount + len(rep.UnrunCases) + rep.SkippedCount + len(rep.Mismatches) + rep.UnobservedTests + rep.OracleUnverified + len(rep.Failures)
	for _, g := range rep.Generated {
		want += g.Mismatched + g.Unrun
		if g.Executed+g.Unrun != g.Generated || g.Matched+g.Mismatched != g.Executed {
			t.Errorf("seed %d: generated %d executed %d matched %d mismatched %d unrun %d do not add up", g.Seed, g.Generated, g.Executed, g.Matched, g.Mismatched, g.Unrun)
		}
		var sum GeneratedCounts
		for _, c := range g.ByPhase {
			if c.Executed+c.Unrun != c.Generated || c.Matched+c.Mismatched != c.Executed {
				t.Errorf("seed %d: a phase's counts do not add up: %+v", g.Seed, c)
			}
			sum.Generated += c.Generated
			sum.Executed += c.Executed
			sum.Matched += c.Matched
			sum.Mismatched += c.Mismatched
			sum.Unrun += c.Unrun
		}
		if sum != g.GeneratedCounts {
			t.Errorf("seed %d: phases sum to %+v, seed reports %+v", g.Seed, sum, g.GeneratedCounts)
		}
		if len(g.MismatchedRows) > generatedSampleLimit || len(g.UnrunRows) > generatedSampleLimit || len(g.MismatchedRows) > g.Mismatched || len(g.UnrunRows) > g.Unrun {
			t.Errorf("seed %d: row samples exceed their counts or the sample limit", g.Seed)
		}
	}
	if rep.UnresolvedCount != want {
		t.Errorf("unresolved %d, the counts add up to %d", rep.UnresolvedCount, want)
	}
	if rep.Failures == nil || rep.Mismatches == nil || rep.UnrunCases == nil {
		t.Errorf("a report list is nil and would marshal as null")
	}
}
