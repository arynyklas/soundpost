// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import "testing"

// The smoke report is what the persistence, isolation and normalization claims
// rest on. A report that says "not satisfied", names a failing step, skipped a
// layout, ran on something that is not real storage or never ran the persisted
// path is not evidence, whatever its scenario list says.
func TestReleaseRequiresTheSmokeReportToBeCompleteAndUnreserved(t *testing.T) {
	faults := []struct {
		name   string
		mutate func(s *SmokeReport)
		want   string
	}{
		{"schema", func(s *SmokeReport) { s.Schema = "soundpost-smoke-report/2" }, "smoke: report schema"},
		{"memory storage", func(s *SmokeReport) { s.Storage = "memory" }, "smoke: ran with storage"},
		{"fake control", func(s *SmokeReport) { s.Control = "fake" }, "smoke: ran with control"},
		{"single layout not run", func(s *SmokeReport) { s.Modes = []string{"distributed"} }, "smoke: layout single did not run"},
		{"no layout run", func(s *SmokeReport) { s.Modes = nil }, "smoke: layout single did not run"},
		{"layout recorded as not run", func(s *SmokeReport) { s.ModesNotRun = []string{"distributed"} }, "smoke: layout distributed is recorded as not run"},
		{"requirement not satisfied", func(s *SmokeReport) {
			s.NotSatisfied = []string{"binary call-graph check not run: no --production-binary given"}
		}, "smoke: requirement NOT satisfied: binary call-graph check not run"},
		{"failing step", func(s *SmokeReport) {
			s.Steps[1].Passed, s.Steps[1].Detail = false, "got 1 want 2"
		}, "smoke: step distributed/persisted-path.json:hot/promql-prometheus-3.13.5/q1 failed: got 1 want 2"},
		{"no steps", func(s *SmokeReport) { s.Steps = nil }, "smoke: report has no steps"},
		{"persisted path never ran", func(s *SmokeReport) {
			s.CaseFiles = []string{"conformance/query/cases/profile-cross-products.json"}
		}, "smoke: case file persisted-path.json was not run"},
		{"cross products never ran", func(s *SmokeReport) {
			s.CaseFiles = []string{"conformance/query/cases/persisted-path.json"}
		}, "smoke: case file profile-cross-products.json was not run"},
		{"no case file ran", func(s *SmokeReport) { s.CaseFiles = nil }, "smoke: case file persisted-path.json was not run"},
	}
	for _, f := range faults {
		t.Run(f.name, func(t *testing.T) {
			cfg := releaseFixture(t)
			f.mutate(cfg.Smoke)
			rep, err := runGate(t, cfg)
			requireRejected(t, rep, err, f.want)
		})
	}
	t.Run("no smoke report", func(t *testing.T) {
		cfg := releaseFixture(t)
		cfg.Smoke = nil
		rep, err := runGate(t, cfg)
		requireRejected(t, rep, err, "no smoke report")
	})
	t.Run("a report that ran more than required is fine", func(t *testing.T) {
		cfg := releaseFixture(t)
		cfg.Smoke.Modes = append(cfg.Smoke.Modes, "hybrid")
		cfg.Smoke.CaseFiles = append(cfg.Smoke.CaseFiles, "conformance/query/cases/rule-smoke.json")
		cfg.Smoke.Steps = append(cfg.Smoke.Steps, ScenarioOutcome{Name: "rule-smoke.json:fires", Passed: true})
		if rep, err := runGate(t, cfg); err != nil {
			t.Fatalf("extra layouts, case files and steps were refused: %v %q", err, rep.Failures)
		}
	})
	// The campaign (tools/qualify RunQueryConformance) feeds every release run the
	// report of the single layout alone: the distributed layout is gated by its own
	// smoke row, and the matrix pins the input-normalization identity over the
	// single layout's checks. A gate that demanded the distributed layout in the
	// same report could never pass in that flow.
	t.Run("the report of the single layout alone is what the campaign feeds", func(t *testing.T) {
		cfg := releaseFixture(t)
		cfg.Smoke.Modes = []string{"single"}
		cfg.Smoke.Steps = cfg.Smoke.Steps[:1]
		if rep, err := runGate(t, cfg); err != nil {
			t.Fatalf("a single-layout smoke report was refused: %v %q", err, rep.Failures)
		}
	})
	t.Run("case files recorded with Windows separators", func(t *testing.T) {
		cfg := releaseFixture(t)
		cfg.Smoke.CaseFiles = []string{`conformance\query\cases\persisted-path.json`, `conformance\query\cases\profile-cross-products.json`}
		if rep, err := runGate(t, cfg); err != nil {
			t.Fatalf("case files named with backslashes were refused: %v %q", err, rep.Failures)
		}
	})
	t.Run("a case file whose name only ends like the persisted path is not it", func(t *testing.T) {
		cfg := releaseFixture(t)
		cfg.Smoke.CaseFiles = []string{"conformance/query/cases/not-persisted-path.json", "conformance/query/cases/profile-cross-products.json"}
		rep, err := runGate(t, cfg)
		requireRejected(t, rep, err, "smoke: case file persisted-path.json was not run")
	})
	t.Run("every problem is reported, not the first", func(t *testing.T) {
		cfg := releaseFixture(t)
		s := cfg.Smoke
		s.Schema, s.Storage, s.Control, s.Modes, s.Steps, s.CaseFiles = "other", "memory", "fake", nil, nil, nil
		s.ModesNotRun, s.NotSatisfied = []string{"distributed"}, []string{"a requirement"}
		rep, err := runGate(t, cfg)
		requireRejected(t, rep, err, "")
		for _, want := range []string{"smoke: report schema", "smoke: ran with storage", "smoke: ran with control", "smoke: layout single did not run", "smoke: layout distributed is recorded as not run", "smoke: requirement NOT satisfied: a requirement", "smoke: report has no steps", "smoke: case file persisted-path.json was not run", "smoke: case file profile-cross-products.json was not run"} {
			if !failureContains(rep, want) {
				t.Errorf("no failure says %q: %q", want, rep.Failures)
			}
		}
	})
}

// Persistence and isolation: every required scenario must have run and passed;
// a scenario that ran and failed fails the gate whether or not the policy names
// it; one name reported twice cannot let a pass hide a failure.
func TestReleaseScenarioOutcomesAreAllHeld(t *testing.T) {
	type family struct {
		kind     string
		names    []string
		outcomes func(c *ReleaseConfig) *[]ScenarioOutcome
	}
	families := []family{
		{"persistence", requiredPersistenceNames(), func(c *ReleaseConfig) *[]ScenarioOutcome { return &c.Smoke.Persistence }},
		{"isolation", requiredIsolationNames(), func(c *ReleaseConfig) *[]ScenarioOutcome { return &c.Smoke.Isolation }},
	}
	for _, f := range families {
		f := f
		for i, name := range f.names {
			i, name := i, name
			t.Run(f.kind+" "+name+" absent", func(t *testing.T) {
				cfg := releaseFixture(t)
				list := f.outcomes(&cfg)
				*list = append(append([]ScenarioOutcome(nil), (*list)[:i]...), (*list)[i+1:]...)
				rep, err := runGate(t, cfg)
				requireRejected(t, rep, err, f.kind+" scenario "+name+" did not run")
				if rep.ScenarioFailures != 1 {
					t.Fatalf("scenario failures %d", rep.ScenarioFailures)
				}
			})
			t.Run(f.kind+" "+name+" failed", func(t *testing.T) {
				cfg := releaseFixture(t)
				list := f.outcomes(&cfg)
				(*list)[i].Passed, (*list)[i].Detail = false, "boom"
				rep, err := runGate(t, cfg)
				requireRejected(t, rep, err, f.kind+" scenario "+name+" failed: boom")
				if rep.ScenarioFailures != 1 {
					t.Fatalf("scenario failures %d", rep.ScenarioFailures)
				}
			})
		}
		t.Run(f.kind+" none at all", func(t *testing.T) {
			cfg := releaseFixture(t)
			*f.outcomes(&cfg) = nil
			rep, err := runGate(t, cfg)
			requireRejected(t, rep, err, "")
			if rep.ScenarioFailures != len(f.names) {
				t.Fatalf("scenario failures %d, want one per required scenario (%d)", rep.ScenarioFailures, len(f.names))
			}
		})
		t.Run(f.kind+" an extra scenario that failed", func(t *testing.T) {
			cfg := releaseFixture(t)
			list := f.outcomes(&cfg)
			*list = append(*list, ScenarioOutcome{Name: "adapter-loki-push", Passed: false, Detail: "stored 0 of 3"})
			rep, err := runGate(t, cfg)
			requireRejected(t, rep, err, f.kind+" scenario adapter-loki-push failed: stored 0 of 3")
			if rep.ScenarioFailures != 1 {
				t.Fatalf("scenario failures %d", rep.ScenarioFailures)
			}
		})
		t.Run(f.kind+" an extra scenario that passed", func(t *testing.T) {
			cfg := releaseFixture(t)
			list := f.outcomes(&cfg)
			*list = append(*list, ScenarioOutcome{Name: "adapter-loki-push", Passed: true})
			if rep, err := runGate(t, cfg); err != nil {
				t.Fatalf("an extra passing scenario was refused: %v %q", err, rep.Failures)
			}
		})
		t.Run(f.kind+" a failure that a later pass would hide", func(t *testing.T) {
			cfg := releaseFixture(t)
			list := f.outcomes(&cfg)
			first := f.names[0]
			*list = append([]ScenarioOutcome{{Name: first, Passed: false, Detail: "layout single"}}, *list...)
			rep, err := runGate(t, cfg)
			requireRejected(t, rep, err, f.kind+" scenario "+first+" reported twice")
			// the failed first outcome and the second report of the name are one failure each
			if rep.ScenarioFailures != 2 {
				t.Fatalf("scenario failures %d, want 2 (the failed outcome and the repeat)", rep.ScenarioFailures)
			}
		})
		t.Run(f.kind+" a pass that a later failure contradicts", func(t *testing.T) {
			cfg := releaseFixture(t)
			list := f.outcomes(&cfg)
			first := f.names[0]
			*list = append(*list, ScenarioOutcome{Name: first, Passed: false, Detail: "layout distributed"})
			rep, err := runGate(t, cfg)
			requireRejected(t, rep, err, f.kind+" scenario "+first+" reported twice")
			// the first outcome passed: only the repeat is a failure
			if rep.ScenarioFailures != 1 {
				t.Fatalf("scenario failures %d, want 1 (the repeat)", rep.ScenarioFailures)
			}
		})
	}
}

// Input normalization: every check must be lossless and there must be some.
func TestReleaseNormalizationEvidence(t *testing.T) {
	t.Run("a check with no source records", func(t *testing.T) {
		cfg := releaseFixture(t)
		cfg.Smoke.Normalization[0].Source, cfg.Smoke.Normalization[0].Normalized = nil, nil
		rep, err := runGate(t, cfg)
		requireRejected(t, rep, err, "no source inputs")
		if rep.NormalizationLoss != 1 {
			t.Fatalf("normalization loss %d", rep.NormalizationLoss)
		}
	})
	t.Run("no checks", func(t *testing.T) {
		cfg := releaseFixture(t)
		cfg.Smoke.Normalization = nil
		rep, err := runGate(t, cfg)
		requireRejected(t, rep, err, "no input normalization checks")
		if rep.NormalizationLoss != 0 {
			t.Fatalf("an absent check is missing evidence, not loss: %d", rep.NormalizationLoss)
		}
	})
	t.Run("two lossy checks are both counted", func(t *testing.T) {
		cfg := releaseFixture(t)
		bad := cfg.Smoke.Normalization[0]
		bad.ID = "second"
		bad.Normalized = append([]InputRecord(nil), bad.Normalized[:1]...)
		cfg.Smoke.Normalization[0].Normalized = append([]InputRecord(nil), cfg.Smoke.Normalization[0].Normalized[:1]...)
		cfg.Smoke.Normalization = append(cfg.Smoke.Normalization, bad)
		rep, err := runGate(t, cfg)
		requireRejected(t, rep, err, "input normalization promql-prometheus-3.13.5/stale-and-histogram: record count 2 became 1")
		if rep.NormalizationLoss != 2 {
			t.Fatalf("normalization loss %d", rep.NormalizationLoss)
		}
	})
	// The stale-marker branch of the loss check is only exercised by evidence that
	// holds a stale marker: a producer that stopped sending one must fail the gate.
	plain := InputRecord{Kind: "float", Timestamp: "10", Name: "m", Bits: "3ff0000000000000"}
	t.Run("no authored input is a stale marker", func(t *testing.T) {
		cfg := releaseFixture(t)
		cfg.Smoke.Normalization[0].Source = []InputRecord{plain}
		cfg.Smoke.Normalization[0].Normalized = []InputRecord{plain}
		rep, err := runGate(t, cfg)
		requireRejected(t, rep, err, "input normalization evidence carries no stale marker")
		if rep.NormalizationLoss != 0 {
			t.Fatalf("normalization loss %d: the inputs are lossless", rep.NormalizationLoss)
		}
	})
	t.Run("a stale marker in the normalized records only is not an authored one", func(t *testing.T) {
		cfg := releaseFixture(t)
		stale := InputRecord{Kind: "float", Timestamp: "10", Name: "m", Bits: StaleBits}
		cfg.Smoke.Normalization[0].Source = []InputRecord{plain}
		cfg.Smoke.Normalization[0].Normalized = []InputRecord{stale}
		rep, err := runGate(t, cfg)
		requireRejected(t, rep, err, "input normalization evidence carries no stale marker")
	})
	t.Run("one check with a stale marker among others is enough", func(t *testing.T) {
		cfg := releaseFixture(t)
		second := NormalizationCheck{ID: "plain", Profile: "promql-prometheus-3.13.5", Source: []InputRecord{plain}, Normalized: []InputRecord{plain}}
		cfg.Smoke.Normalization = append([]NormalizationCheck{second}, cfg.Smoke.Normalization...)
		if rep, err := runGate(t, cfg); err != nil {
			t.Fatalf("a stale marker in one of two checks was refused: %v %q", err, rep.Failures)
		}
	})
	// The histogram branch of the loss check is only exercised by evidence that holds a native
	// histogram of each form: a producer that fed it floats alone must fail the gate (GR-21).
	stale := InputRecord{Kind: "float", Timestamp: "10", Name: "m", Bits: StaleBits}
	t.Run("no authored input is a native histogram", func(t *testing.T) {
		cfg := releaseFixture(t)
		cfg.Smoke.Normalization = []NormalizationCheck{{ID: "floats", Profile: "promql-prometheus-3.13.5", Source: []InputRecord{stale, plain}, Normalized: []InputRecord{stale, plain}}}
		rep, err := runGate(t, cfg)
		requireRejected(t, rep, err, "input normalization evidence carries no integer native histogram")
		if !failureContains(rep, "input normalization evidence carries no float native histogram") {
			t.Fatalf("the missing float histogram was not reported: %q", rep.Failures)
		}
		if rep.NormalizationLoss != 0 {
			t.Fatalf("normalization loss %d: the inputs are lossless", rep.NormalizationLoss)
		}
	})
	t.Run("only a float histogram", func(t *testing.T) {
		cfg := releaseFixture(t)
		cfg.Smoke.Normalization[0].Source = []InputRecord{stale}
		cfg.Smoke.Normalization[0].Normalized = []InputRecord{stale}
		rep, err := runGate(t, cfg)
		requireRejected(t, rep, err, "input normalization evidence carries no integer native histogram")
		if failureContains(rep, "carries no float native histogram") {
			t.Fatalf("a float histogram is there: %q", rep.Failures)
		}
	})
	t.Run("only an integer histogram", func(t *testing.T) {
		cfg := releaseFixture(t)
		cfg.Smoke.Normalization = cfg.Smoke.Normalization[:1]
		rep, err := runGate(t, cfg)
		requireRejected(t, rep, err, "input normalization evidence carries no float native histogram")
		if failureContains(rep, "carries no integer native histogram") {
			t.Fatalf("an integer histogram is there: %q", rep.Failures)
		}
	})
	t.Run("histograms in the normalized records only are not authored ones", func(t *testing.T) {
		cfg := releaseFixture(t)
		intHist, floatHist := cfg.Smoke.Normalization[0].Normalized[1], cfg.Smoke.Normalization[1].Normalized[0]
		cfg.Smoke.Normalization = []NormalizationCheck{{ID: "floats", Profile: "promql-prometheus-3.13.5", Source: []InputRecord{stale, plain}, Normalized: []InputRecord{stale, intHist, floatHist}}}
		rep, err := runGate(t, cfg)
		requireRejected(t, rep, err, "input normalization evidence carries no integer native histogram")
		if !failureContains(rep, "input normalization evidence carries no float native histogram") {
			t.Fatalf("a float histogram in the normalized records counted as an authored one: %q", rep.Failures)
		}
	})
	t.Run("a histogram record without a histogram is not one", func(t *testing.T) {
		cfg := releaseFixture(t)
		hollow := InputRecord{Kind: "histogram", Timestamp: "30", Name: "hh"}
		cfg.Smoke.Normalization = []NormalizationCheck{{ID: "hollow", Profile: "promql-prometheus-3.13.5", Source: []InputRecord{stale, hollow}, Normalized: []InputRecord{stale, hollow}}}
		rep, err := runGate(t, cfg)
		requireRejected(t, rep, err, "input normalization evidence carries no integer native histogram")
	})
	t.Run("a lossy float histogram is loss", func(t *testing.T) {
		cfg := releaseFixture(t)
		cfg.Smoke.Normalization[1].Normalized[0].Histogram.PositiveBucketBits = []string{"4000000000000001"}
		rep, err := runGate(t, cfg)
		requireRejected(t, rep, err, "input normalization promql-prometheus-3.13.5/float-histogram: record 0 changed")
		if rep.NormalizationLoss != 1 {
			t.Fatalf("normalization loss %d", rep.NormalizationLoss)
		}
	})
	t.Run("a float histogram that became an integer one is loss", func(t *testing.T) {
		cfg := releaseFixture(t)
		cfg.Smoke.Normalization[1].Normalized[0].Histogram = &Histogram{Kind: "integer", Count: "3", ZeroCount: "1", PositiveSpans: []HistogramSpan{{Offset: 0, Length: 1}}, NegativeSpans: []HistogramSpan{}, PositiveDeltas: []string{"2"}}
		rep, err := runGate(t, cfg)
		requireRejected(t, rep, err, "record 0 changed")
	})
}
