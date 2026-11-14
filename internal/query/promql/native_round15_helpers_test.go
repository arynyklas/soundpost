// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// featureProfile resolves the registered feature set of a pinned profile whose
// enabled gates are exactly the given list.
func featureProfile(t *testing.T, id string, enabled ...string) profile.Profile {
	t.Helper()
	registry, err := profile.Load(os.DirFS("../../../profiles/query"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../../profiles/query/" + id + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest profile.Profile
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	want := append([]string(nil), enabled...)
	sort.Strings(want)
	for _, set := range manifest.FeatureSets {
		have := append([]string(nil), set.Enabled...)
		sort.Strings(have)
		if strings.Join(have, ",") == strings.Join(want, ",") {
			p, err := registry.Resolve(id, set.ID)
			if err != nil {
				t.Fatal(err)
			}
			return p
		}
	}
	t.Fatalf("no registered feature set %v for %s", enabled, id)
	return profile.Profile{}
}

// msSample builds a float sample at a millisecond timestamp.
func msSample(milliseconds int64, f float64) value.Sample {
	return sample(milliseconds*1_000_000, f)
}

func msStale(milliseconds int64) value.Sample {
	return value.Sample{Time: model.UnixNano(milliseconds * 1_000_000), Float: value.StaleBits}
}

func metricSeries(name string, extra model.Labels, samples ...value.Sample) value.Series {
	labels := model.Labels{{Name: "__name__", Value: name}}
	labels = append(labels, extra...)
	return value.Series{Labels: labels, Samples: samples}
}

// evalWith parses, checks, plans and evaluates one query under a profile.
func evalWith(t *testing.T, p profile.Profile, q string, ev value.Evaluation, series ...value.Series) (value.Result, []syntax.Diagnostic, error) {
	t.Helper()
	e, err := Parse(q, p)
	if err != nil {
		return value.Result{}, nil, err
	}
	typed, notes, err := Check(e, p)
	if err != nil {
		return value.Result{}, nil, err
	}
	plan, err := BuildPlan(typed, ev, p)
	if err != nil {
		return value.Result{}, nil, err
	}
	r, more, err := Evaluate(context.Background(), plan, seriesSource(series), value.NewBoundedAccount(1<<24))
	return r, append(notes, more...), err
}

func instantAt(milliseconds int64) value.Evaluation {
	return value.Evaluation{Instant: true, Time: model.UnixNano(milliseconds * 1_000_000)}
}

func rangeOf(startMS, endMS, stepMS int64) value.Evaluation {
	return value.Evaluation{Start: model.UnixNano(startMS * 1_000_000), End: model.UnixNano(endMS * 1_000_000), Step: stepMS * 1_000_000}
}

// vectorFloats flattens a one-sample-per-series vector result as (labels, time, bits).
type observedPoint struct {
	Time  int64
	Float float64
}

func floatsOf(t *testing.T, s value.Series) []observedPoint {
	t.Helper()
	out := make([]observedPoint, 0, len(s.Samples))
	for _, p := range s.Samples {
		if p.Histogram != nil {
			t.Fatalf("unexpected histogram sample at %d", p.Time)
		}
		out = append(out, observedPoint{Time: int64(p.Time), Float: math.Float64frombits(uint64(p.Float))})
	}
	return out
}

func samePoints(a, b []observedPoint) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Time != b[i].Time || math.Float64bits(a[i].Float) != math.Float64bits(b[i].Float) {
			return false
		}
	}
	return true
}

func diagnosticKeys(d []syntax.Diagnostic) []string {
	out := make([]string, 0, len(d))
	for _, x := range d {
		out = append(out, x.Category+"@"+itoa(x.Range.StartByte)+"-"+itoa(x.Range.EndByte))
	}
	sort.Strings(out)
	return out
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
