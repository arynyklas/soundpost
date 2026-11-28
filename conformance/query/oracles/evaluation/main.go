//go:build soundpost_evaluation_oracle

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"time"

	"github.com/prometheus/prometheus/model/histogram"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/util/annotations"
)

// Filled only by the source-digest-verifying build recipe, not request input.
var compiledProfile, compiledCommit, compiledSourceSHA256 string

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(reader io.Reader, writer io.Writer) error {
	var in input
	decoder := json.NewDecoder(io.LimitReader(reader, (16<<20)+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&in); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing fixture input")
	}
	if err := validateIdentity(in); err != nil {
		return err
	}
	out := batch{Profile: compiledProfile, Commit: compiledCommit, Compiler: runtime.Version(), SourceSHA256: compiledSourceSHA256, ProfileIdentity: in.ProfileIdentity, FeatureSet: in.FeatureSet, ConfigurationHash: in.ConfigurationHash}
	seen := map[string]bool{}
	for _, c := range in.Cases {
		if c.ID == "" || seen[c.ID] {
			return fmt.Errorf("empty or duplicate native case")
		}
		seen[c.ID] = true
		observed, err := evaluate(in, c)
		if err != nil {
			return fmt.Errorf("%s: %w", c.ID, err)
		}
		out.Observations = append(out.Observations, observed)
	}
	if len(out.Observations) == 0 {
		return fmt.Errorf("empty native batch")
	}
	return json.NewEncoder(writer).Encode(out)
}
func validateIdentity(in input) error {
	expectedCompiler := ""
	expectedCommit := ""
	expectedSource := ""
	switch compiledProfile {
	case "promql-prometheus-3.1.0":
		expectedCompiler = "go1.23.4"
		expectedCommit = "7086161a93b262aa0949dbf2aba15a5a7b13e0a3"
		expectedSource = "1a394b385e1fca89a6b81eab782074de26c5d35fccdebfef15c68daa55029de5"
	case "promql-prometheus-3.13.5":
		expectedCompiler = "go1.26.10"
		expectedCommit = "f497435984d1ca1d84cda5ed309387ac2eb1f8f6"
		expectedSource = "c2f96e97afede2cb4b43266bf62d964bed9194c7a1ac37759e1c6fd68600b410"
	default:
		return fmt.Errorf("reference driver not built for an approved exact pin")
	}
	if compiledCommit != expectedCommit || compiledSourceSHA256 != expectedSource || runtime.Version() != expectedCompiler || in.Profile != compiledProfile || in.Commit != compiledCommit {
		return fmt.Errorf("actual reference source/compiler identity mismatch")
	}
	if in.ManifestVersion != 1 || len(in.Cases) == 0 || in.FeatureSet == "" {
		return fmt.Errorf("missing selected native profile context")
	}
	canonical, err := json.Marshal(in.Configuration)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(canonical)
	if hex.EncodeToString(sum[:]) != in.ConfigurationHash {
		return fmt.Errorf("native configuration digest mismatch")
	}
	enabled := append([]string(nil), in.Enabled...)
	sort.Strings(enabled)
	for j, g := range enabled {
		if j > 0 && enabled[j-1] == g {
			return fmt.Errorf("duplicate native feature")
		}
		if !allowedFeature(g) {
			return fmt.Errorf("unregistered native feature %s", g)
		}
	}
	identity, err := json.Marshal(struct {
		ID              string
		Commit          string
		ManifestVersion int
		FeatureSet      struct {
			ID      string   `json:"id"`
			Enabled []string `json:"enabled"`
		}
		ConfigurationHash string
	}{ID: in.Profile, Commit: in.Commit, ManifestVersion: in.ManifestVersion, FeatureSet: struct {
		ID      string   `json:"id"`
		Enabled []string `json:"enabled"`
	}{in.FeatureSet, enabled}, ConfigurationHash: in.ConfigurationHash})
	if err != nil {
		return err
	}
	sum = sha256.Sum256(identity)
	if hex.EncodeToString(sum[:]) != in.ProfileIdentity {
		return fmt.Errorf("native profile/feature identity mismatch")
	}
	for _, pair := range []struct {
		key   string
		value int64
	}{{"lookback_delta_ns", in.Lookback}, {"default_subquery_step_ns", in.SubqueryStep}} {
		var text string
		if err = json.Unmarshal(in.Configuration[pair.key], &text); err != nil {
			return err
		}
		if text != strconv.FormatInt(pair.value, 10) || pair.value <= 0 {
			return fmt.Errorf("native engine default does not match resolved configuration")
		}
	}
	return nil
}
func feature(enabled []string, name string) bool {
	for _, e := range enabled {
		if e == name {
			return true
		}
	}
	return false
}
func evaluate(in input, c fixtureCase) (observation, error) {
	out := observation{ID: c.ID}
	q, err := makeQueryable(c)
	if err != nil {
		return out, err
	}
	lookback, subquery := in.Lookback, in.SubqueryStep
	if c.Lookback > 0 {
		lookback = c.Lookback
	}
	if c.SubqueryStep > 0 {
		subquery = c.SubqueryStep
	}
	if lookback <= 0 || subquery < 1_000_000 {
		return out, fmt.Errorf("reference engine duration outside native millisecond domain")
	}
	maxText, err := configurationDefault(in.Configuration, "query.max-samples")
	if err != nil {
		return out, err
	}
	maxSamples, err := strconv.Atoi(maxText)
	if err != nil || maxSamples <= 0 {
		return out, fmt.Errorf("invalid pinned query.max-samples")
	}
	timeoutText, err := configurationDefault(in.Configuration, "query.timeout")
	if err != nil {
		return out, err
	}
	timeout, err := time.ParseDuration(timeoutText)
	if err != nil || timeout <= 0 {
		return out, fmt.Errorf("invalid pinned query.timeout")
	}
	atText, err := configurationDefault(in.Configuration, "engine.enable-at-modifier")
	if err != nil {
		return out, err
	}
	at, err := strconv.ParseBool(atText)
	if err != nil {
		return out, err
	}
	negativeText, err := configurationDefault(in.Configuration, "engine.enable-negative-offset")
	if err != nil {
		return out, err
	}
	negative, err := strconv.ParseBool(negativeText)
	if err != nil {
		return out, err
	}
	opts := promql.EngineOpts{MaxSamples: maxSamples, Timeout: timeout, LookbackDelta: time.Duration(lookback), NoStepSubqueryIntervalFn: func(int64) int64 { return subquery / 1_000_000 }, EnableAtModifier: at, EnableNegativeOffset: negative, EnableDelayedNameRemoval: feature(in.Enabled, "promql-delayed-name-removal")}
	configureEngine(&opts, in.Enabled)
	engine := promql.NewEngine(opts)
	defer engine.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	queryOpts := promql.NewPrometheusQueryOpts(false, time.Duration(lookback))
	var query promql.Query
	switch c.Kind {
	case "instant":
		query, err = engine.NewInstantQuery(ctx, q, queryOpts, c.Query, time.Unix(0, int64(c.Time)))
	case "range":
		if c.Step < 1_000_000 {
			return out, fmt.Errorf("reference range step below native millisecond domain")
		}
		query, err = engine.NewRangeQuery(ctx, q, queryOpts, c.Query, time.Unix(0, int64(c.Start)), time.Unix(0, int64(c.End)), time.Duration(c.Step))
	default:
		return out, fmt.Errorf("unknown fixture evaluation kind")
	}
	if err != nil {
		out.Error = observeError(err, "plan")
		return out, nil
	}
	defer query.Close()
	result := query.Exec(ctx)
	if result == nil {
		return out, fmt.Errorf("nil actual native evaluation")
	}
	out.Annotations, err = observeAnnotations(result.Warnings)
	if err != nil {
		return out, err
	}
	if result.Err != nil {
		var storageErr promql.ErrStorage
		if errors.As(result.Err, &storageErr) {
			return out, fmt.Errorf("reference fixture storage failure: %w", result.Err)
		}
		out.Error = observeError(result.Err, "execution")
		return out, nil
	}
	project := "00000000000000000000000000000001"
	for _, s := range c.Series {
		if s.Project != "" {
			project = s.Project
			break
		}
	}
	switch actual := result.Value.(type) {
	case promql.Scalar:
		out.Type = "scalar"
		s, e := floatSample(actual.T, actual.V)
		if e != nil {
			return out, e
		}
		out.Series = []series{{Samples: []sample{s}}}
	case promql.String:
		out.Type = "string"
		out.String = actual.V
		t, e := outputNano(actual.T)
		if e != nil {
			return out, e
		}
		out.Series = []series{{Samples: []sample{{Time: t}}}}
	case promql.Vector:
		out.Type = "vector"
		for _, s := range actual {
			p, e := observedSample(s.T, s.F, s.H)
			if e != nil {
				return out, e
			}
			out.Series = append(out.Series, series{Project: project, Labels: observedLabels(s.Metric), Samples: []sample{p}})
		}
	case promql.Matrix:
		out.Type = "matrix"
		for _, s := range actual {
			row := series{Project: project, Labels: observedLabels(s.Metric)}
			for _, f := range s.Floats {
				p, e := floatSample(f.T, f.F)
				if e != nil {
					return out, e
				}
				row.Samples = append(row.Samples, p)
			}
			for _, h := range s.Histograms {
				p, e := observedSample(h.T, 0, h.H)
				if e != nil {
					return out, e
				}
				row.Samples = append(row.Samples, p)
			}
			sort.SliceStable(row.Samples, func(i, j int) bool { return row.Samples[i].Time < row.Samples[j].Time })
			out.Series = append(out.Series, row)
		}
	default:
		return out, fmt.Errorf("unobserved native result type %T", result.Value)
	}
	out.Complete = true // The fixture Queryable is exhaustive, with no missing shards.
	return out, nil
}
func configurationDefault(configuration map[string]json.RawMessage, key string) (string, error) {
	var value struct {
		Default string `json:"default"`
	}
	if err := json.Unmarshal(configuration[key], &value); err != nil {
		return "", fmt.Errorf("missing native configuration %s: %w", key, err)
	}
	if value.Default == "" {
		return "", fmt.Errorf("empty native configuration %s", key)
	}
	return value.Default, nil
}
func outputNano(ms int64) (nano, error) {
	if ms > math.MaxInt64/1_000_000 || ms < math.MinInt64/1_000_000 {
		return 0, fmt.Errorf("native result timestamp outside C01 int64 nanoseconds")
	}
	return nano(ms * 1_000_000), nil
}
func floatSample(ms int64, value float64) (sample, error) {
	t, err := outputNano(ms)
	b := floatBits(value)
	return sample{Time: t, Float: &b}, err
}
func observedSample(ms int64, f float64, h *histogram.FloatHistogram) (sample, error) {
	if h == nil {
		return floatSample(ms, f)
	}
	t, err := outputNano(ms)
	return sample{Time: t, Histogram: &nativeHistogram{Float: observedHistogram(h)}}, err
}
func observedLabels(in labels.Labels) []label {
	var out []label
	in.Range(func(l labels.Label) { out = append(out, label{Name: l.Name, Value: l.Value}) })
	return out
}
func observedHistogram(h *histogram.FloatHistogram) *floatHistogram {
	flavor, hint := "counter", "unknown"
	switch h.CounterResetHint {
	case histogram.GaugeType:
		flavor = "gauge"
		hint = "gauge"
	case histogram.CounterReset:
		hint = "reset"
	case histogram.NotCounterReset:
		hint = "not_reset"
	}
	out := &floatHistogram{Flavor: flavor, Schema: h.Schema, ZeroThreshold: floatBits(h.ZeroThreshold), Sum: floatBits(h.Sum), Count: floatBits(h.Count), ZeroCount: floatBits(h.ZeroCount), ResetHint: hint}
	for _, s := range h.PositiveSpans {
		out.PositiveSpans = append(out.PositiveSpans, span{s.Offset, s.Length})
	}
	for _, s := range h.NegativeSpans {
		out.NegativeSpans = append(out.NegativeSpans, span{s.Offset, s.Length})
	}
	for _, f := range h.PositiveBuckets {
		out.PositiveBuckets = append(out.PositiveBuckets, floatBits(f))
	}
	for _, f := range h.NegativeBuckets {
		out.NegativeBuckets = append(out.NegativeBuckets, floatBits(f))
	}
	for _, f := range h.CustomValues {
		out.CustomBounds = append(out.CustomBounds, floatBits(f))
	}
	return out
}
func observeAnnotations(in annotations.Annotations) ([]annotation, error) {
	var out []annotation
	for _, err := range in {
		id := annotationIdentity(err)
		if id == "" {
			return nil, fmt.Errorf("unclassified actual native annotation: %s", err)
		}
		severity := "warning"
		if errors.Is(err, annotations.PromQLInfo) {
			severity = "info"
		}
		start, end, ok := annotationPosition(err)
		if !ok {
			return nil, fmt.Errorf("native annotation position not observed: %s", id)
		}
		out = append(out, annotation{ID: id, Severity: severity, Message: err.Error(), Start: start, End: end})
	}
	// Upstream is a map. This is deterministic serialization, NOT a fabricated
	// evaluator encounter order; the report declares that exact distinction.
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		if a.End != b.End {
			return a.End < b.End
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Message < b.Message
	})
	return out, nil
}
func annotationPosition(err error) (int, int, bool) {
	for err != nil {
		v := reflect.ValueOf(err)
		for v.IsValid() && v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return 0, 0, false
			}
			v = v.Elem()
		}
		if v.IsValid() && v.Kind() == reflect.Struct {
			position := v.FieldByName("PositionRange")
			if position.IsValid() && position.Kind() == reflect.Struct {
				start, end := position.FieldByName("Start"), position.FieldByName("End")
				if start.IsValid() && end.IsValid() && start.CanInt() && end.CanInt() {
					return int(start.Int()), int(end.Int()), true
				}
			}
		}
		err = errors.Unwrap(err)
	}
	return 0, 0, false
}
