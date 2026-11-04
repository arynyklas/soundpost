// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/query/profile"
	"soundpost/internal/storage"
)

func evaluationProfile(t *testing.T) profile.Profile {
	t.Helper()
	registry, err := profile.Load(os.DirFS("../../../profiles/query"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest profile.Profile
	if err = ReadJSON("../../../profiles/query/promql-prometheus-3.1.0.json", &manifest); err != nil {
		t.Fatal(err)
	}
	for _, set := range manifest.FeatureSets {
		if len(set.Enabled) == 0 {
			p, e := registry.Resolve(manifest.ID, set.ID)
			if e != nil {
				t.Fatal(e)
			}
			return p
		}
	}
	t.Fatal("default feature set absent")
	return profile.Profile{}
}

func TestEvaluationOwnedUsesActualPlanner(t *testing.T) {
	p := evaluationProfile(t)
	c := EvaluationCase{ID: "owned-scalar", Profiles: []string{p.ID}, Query: "1 + 2", Kind: "instant", Time: 2_000_000_000}
	got, err := observeOwnedEvaluation(context.Background(), c, p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Error != nil || got.Type != "scalar" || len(got.Series) != 1 || len(got.Series[0].Samples) != 1 {
		t.Fatalf("actual evaluation: %+v", got)
	}
	sample := got.Series[0].Samples[0]
	if sample.Time != 2_000_000_000 || sample.Float == nil || *sample.Float != model.FloatBits(0x4008000000000000) {
		t.Fatalf("actual scalar: %+v", sample)
	}
}

func TestEvaluationExactComparisonDoesNotRoundOrReorder(t *testing.T) {
	z, nz := model.FloatBits(0), model.FloatBits(0x8000000000000000)
	want := EvaluationObservation{ID: "x", Type: "vector", Series: []EvaluationSeries{{Labels: model.Labels{{Name: "a", Value: "one"}}, Samples: []EvaluationSample{{Time: 1, Float: &z}}}, {Labels: model.Labels{{Name: "a", Value: "two"}}, Samples: []EvaluationSample{{Time: 1, Float: &nz}}}}}
	raw, _ := json.Marshal(want)
	var got EvaluationObservation
	_ = json.Unmarshal(raw, &got)
	if d := CompareEvaluation(want, got); len(d) != 0 {
		t.Fatal(d)
	}
	got.Series[0].Samples[0].Time = 2
	if len(CompareEvaluation(want, got)) == 0 {
		t.Fatal("nanosecond changed without mismatch")
	}
	_ = json.Unmarshal(raw, &got)
	got.Series[0].Samples[0].Float = &nz
	if len(CompareEvaluation(want, got)) == 0 {
		t.Fatal("signed zero equated")
	}
	_ = json.Unmarshal(raw, &got)
	got.Series[0], got.Series[1] = got.Series[1], got.Series[0]
	if len(CompareEvaluation(want, got)) == 0 {
		t.Fatal("vector ordering silently discarded")
	}
}

func TestEvaluationHistogramIntegerCountAndAnnotationRemainExact(t *testing.T) {
	h := &model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Schema: 0, Count: 9_007_199_254_740_993, ZeroCount: 9_007_199_254_740_993, ResetHint: "unknown"}}
	want := EvaluationObservation{ID: "h", Type: "vector", Series: []EvaluationSeries{{Samples: []EvaluationSample{{Time: 1, Histogram: h}}}}, Annotations: []EvaluationAnnotation{{Severity: "warning", Message: "mixed", Start: 1, End: 2}}}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got EvaluationObservation
	if err = json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Series[0].Samples[0].Histogram.Integer.Count != 9_007_199_254_740_993 {
		t.Fatal("integer histogram rounded")
	}
	got.Series[0].Samples[0].Histogram.Integer.Count--
	if len(CompareEvaluation(want, got)) == 0 {
		t.Fatal("histogram count ignored")
	}
	_ = json.Unmarshal(raw, &got)
	got.Annotations[0].End++
	if len(CompareEvaluation(want, got)) == 0 {
		t.Fatal("annotation source range ignored")
	}
}

func TestEvaluationScannerUsesRealC05HalfOpenContract(t *testing.T) {
	project := evaluationProject
	one := model.FloatBits(0x3ff0000000000000)
	scanner := InMemoryEvaluationScanner{Project: project, Series: []EvaluationSeries{{Project: project, Labels: model.Labels{{Name: "__name__", Value: "m"}}, Samples: []EvaluationSample{{Time: 0, Float: &one}, {Time: 1, Float: &one}, {Time: 2, Float: &one}}}}}
	it, err := scanner.Scan(context.Background(), auth.Scope{}, storage.ScanRequest{Projects: []model.ID{project}, Signal: model.Metric, Start: 1, End: 2})
	if err != nil {
		t.Fatal(err)
	}
	page, err := it.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Times) != 1 || page.Times[0] != 1 || page.Values[0].Metric == nil || page.Values[0].Metric.Name != "m" {
		t.Fatalf("half-open scan: %+v", page)
	}
	if _, err = it.Next(context.Background()); err != io.EOF {
		t.Fatalf("exhaustion=%v", err)
	}
	if err = it.Close(); err != nil {
		t.Fatal(err)
	}
	foreign := project
	foreign[15]++
	if _, err = scanner.Scan(context.Background(), auth.Scope{}, storage.ScanRequest{Projects: []model.ID{foreign}, Signal: model.Metric, End: 2}); err == nil {
		t.Fatal("foreign project read")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = scanner.Scan(cancelled, auth.Scope{}, storage.ScanRequest{Projects: []model.ID{project}, Signal: model.Metric, End: 2}); err == nil {
		t.Fatal("cancel became successful scan")
	}
}

func TestEvaluationCasesRequireContentLocksAndEveryProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cases.json")
	raw := []byte(`{"phase":"evaluation","cases":[{"id":"x","profiles":["promql-prometheus-3.1.0","promql-prometheus-3.13.5"],"query":"1","kind":"instant","time":"0","series":[]}]}`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	lock := SourceLock{InventoryFiles: map[string]string{}}
	if _, err := readEvaluationCases(lock, []string{path}); err == nil {
		t.Fatal("unlocked fixture accepted")
	}
	hash := sha256.Sum256(raw)
	lock.InventoryFiles["cases/cases.json"] = hex.EncodeToString(hash[:])
	cases, err := readEvaluationCases(lock, []string{path})
	if err != nil || len(cases) != 1 {
		t.Fatal(cases, err)
	}
	raw = append(raw, ' ')
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readEvaluationCases(lock, []string{path}); err == nil {
		t.Fatal("changed fixture accepted")
	}
	if _, err = prepareEvaluationGroups([]EvaluationCase{{ID: "x", Profiles: []string{"promql-prometheus-3.1.0"}, Query: "1", Kind: "instant"}}, "../../../profiles/query", nil); err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("missing profile guard: %v", err)
	}
}

func TestEvaluationRejectsEmptyDuplicateAndUnregisteredCases(t *testing.T) {
	p := evaluationProfile(t)
	for _, c := range []EvaluationCase{
		{ID: "", Profiles: []string{p.ID}, Query: "1", Kind: "instant"},
		{ID: "x", Profiles: []string{p.ID}, Query: "1", Kind: "range", Step: 0},
		{ID: "x", Profiles: []string{p.ID}, Query: "1", Kind: "instant", Series: []EvaluationSeries{{Samples: []EvaluationSample{{Time: 0}}}}},
	} {
		if err := validateEvaluationCase(c); err == nil {
			t.Fatalf("invalid case accepted: %+v", c)
		}
	}
}

func TestEvaluationReferenceProtocolRejectsMissingCaseAndCompiler(t *testing.T) {
	probe := EvaluationCase{ID: "x", Query: "1", Kind: "instant"}
	p := evaluationProfile(t)
	batch := EvaluationBatch{Profile: p.ID, Commit: p.Commit, Compiler: "go0", ProfileIdentity: p.Identity, FeatureSet: p.ActiveFeatureSet.ID, ConfigurationHash: p.ConfigurationHash, Observations: []EvaluationObservation{{ID: "x", Type: "scalar", Complete: true}}}
	if err := validateEvaluationBatch(batch, p, []EvaluationCase{probe}); err == nil {
		t.Fatal("unverified compiler accepted")
	}
	batch.Compiler = "go1.23.4"
	batch.Observations = nil
	if err := validateEvaluationBatch(batch, p, []EvaluationCase{probe}); err == nil || !strings.Contains(err.Error(), "missing evaluation oracle observations") {
		t.Fatalf("zero-row guard not reached: %v", err)
	}
}

func TestEvaluationEmptyResultsRetainCompletenessMetadata(t *testing.T) {
	want := EvaluationObservation{ID: "removed", Type: "vector", Complete: true}
	got := want
	got.Complete = false
	got.Partial = true
	if len(CompareEvaluation(want, got)) == 0 {
		t.Fatal("empty partial vector became complete success")
	}
	got = want
	got.Watermarks = []model.Cursor{{Group: evaluationProject, Index: 9_007_199_254_740_993}}
	if len(CompareEvaluation(want, got)) == 0 {
		t.Fatal("empty result watermark discarded")
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip EvaluationObservation
	if err = json.Unmarshal(raw, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if roundtrip.Watermarks[0].Index != 9_007_199_254_740_993 {
		t.Fatal("watermark rounded")
	}
}

func TestEvaluationRejectsUnregisteredFeaturesAndDuplicateRows(t *testing.T) {
	c := EvaluationCase{ID: "x", Profiles: []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"}, Query: "1", Kind: "instant"}
	sources := map[string]SourceProfile{}
	for _, id := range c.Profiles {
		sources[id] = SourceProfile{ID: id, Commit: exactPins[id]}
	}
	if _, err := prepareEvaluationGroups([]EvaluationCase{c, c}, "../../../profiles/query", sources); err == nil || !strings.Contains(err.Error(), "duplicate evaluation case") {
		t.Fatalf("duplicate guard not reached: %v", err)
	}
	c.Enabled = []string{"not-a-registered-feature"}
	if _, err := prepareEvaluationGroups([]EvaluationCase{c}, "../../../profiles/query", sources); err == nil || !strings.Contains(err.Error(), "unregistered evaluation feature") {
		t.Fatalf("feature guard not reached: %v", err)
	}
}

func TestEvaluationProfileBytesAndBatchCompletenessCannotBeSubstituted(t *testing.T) {
	raw := []byte(`{"id":"locked"}`)
	sum := sha256.Sum256(raw)
	lock := SourceLock{ProfileFiles: map[string]string{"profiles/query/exact.json": hex.EncodeToString(sum[:])}}
	if err := checkEvaluationProfileHash(lock, "exact", raw); err != nil {
		t.Fatal(err)
	}
	if err := checkEvaluationProfileHash(lock, "exact", append(raw, ' ')); err == nil {
		t.Fatal("consumed profile bytes were not locked")
	}
	p := evaluationProfile(t)
	c := EvaluationCase{ID: "x"}
	batch := EvaluationBatch{Profile: p.ID, Commit: p.Commit, Compiler: "go1.23.4", ProfileIdentity: p.Identity, FeatureSet: p.ActiveFeatureSet.ID, ConfigurationHash: p.ConfigurationHash, Observations: []EvaluationObservation{{ID: "x", Type: "vector"}}}
	if err := validateEvaluationBatch(batch, p, []EvaluationCase{c}); err == nil || !strings.Contains(err.Error(), "complete result") {
		t.Fatalf("missing completion guard not reached: %v", err)
	}
	batch.Observations[0].Complete = true
	if err := validateEvaluationBatch(batch, p, []EvaluationCase{c}); err != nil {
		t.Fatal(err)
	}
	batch.ConfigurationHash = "wrong"
	if err := validateEvaluationBatch(batch, p, []EvaluationCase{c}); err == nil {
		t.Fatal("different actual configuration accepted")
	}
}

func TestEvaluationStartTimestampInputAndScanRemainDistinctFromObservedTime(t *testing.T) {
	for _, field := range []string{"", `,"start_timestamp_ns":"0"`, `,"start_timestamp_ns":"-1000001"`, `,"start_timestamp_ns":"9223372036854775807"`} {
		raw := []byte(`{"time":"2000000000","float_bits":"3ff0000000000000"` + field + `}`)
		var sample EvaluationSample
		if err := json.Unmarshal(raw, &sample); err != nil {
			t.Fatal(err)
		}
		if (field == "") != (sample.StartTimestamp == nil) {
			t.Fatalf("absent/present start timestamp changed: %s", raw)
		}
		scanner := InMemoryEvaluationScanner{Project: evaluationProject, Series: []EvaluationSeries{{Labels: model.Labels{{Name: "__name__", Value: "m"}}, Samples: []EvaluationSample{sample}}}}
		it, err := scanner.Scan(context.Background(), auth.Scope{}, storage.ScanRequest{Projects: []model.ID{evaluationProject}, Signal: model.Metric, Start: 0, End: 3_000_000_000})
		if err != nil {
			t.Fatal(err)
		}
		page, err := it.Next(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		got := page.Values[0].Metric.StartTimestamp
		if (got == nil) != (sample.StartTimestamp == nil) || got != nil && *got != *sample.StartTimestamp {
			t.Fatal("C05 fixture lost exact optional start metadata")
		}
		if page.ObservedTimes[0] != sample.Time {
			t.Fatal("start timestamp replaced observed time")
		}
		if len(scanner.StartTimestampObservations) != 1 {
			t.Fatal("raw scan proof absent")
		}
		proof := scanner.StartTimestampObservations[0].StartTimestamp
		if (proof == nil) != (got == nil) || proof != nil && *proof != *got {
			t.Fatal("raw start metadata proof changed")
		}
		if err = it.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
