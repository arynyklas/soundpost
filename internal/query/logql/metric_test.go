// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"errors"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/scan"
	"github.com/arynyklas/soundpost/internal/query/value"
	"io"
	"math"
	"testing"
)

type metricSource struct {
	rows       []scan.LogRow
	partial    bool
	failure    error
	selections []scan.LogSelection
}

func (s *metricSource) ProjectID() model.ID { return model.ID{1} }
func (s *metricSource) Select(_ context.Context, r scan.LogSelection) (scan.LogIterator, error) {
	s.selections = append(s.selections, r)
	var rows []scan.LogRow
	for _, x := range s.rows {
		if x.Timestamp >= r.Start && x.Timestamp < r.End {
			rows = append(rows, x)
		}
	}
	return &metricRows{rows: rows, partial: s.partial, failure: s.failure}, nil
}

type metricRows struct {
	rows    []scan.LogRow
	at      int
	partial bool
	failure error
}

func (i *metricRows) Next(context.Context) (scan.LogRow, error) {
	if i.at == len(i.rows) {
		if i.failure != nil {
			return scan.LogRow{}, i.failure
		}
		return scan.LogRow{}, io.EOF
	}
	r := i.rows[i.at]
	i.at++
	return r, nil
}
func (i *metricRows) Watermarks() []model.Cursor {
	return []model.Cursor{{Group: model.ID{9}, Index: 7}}
}
func (i *metricRows) Partial() bool { return i.partial }
func (i *metricRows) Close() error  { return nil }
func metricRow(id byte, at int64, line string) scan.LogRow {
	return scan.LogRow{ID: model.ID{id}, Project: model.ID{1}, Source: model.ID{2}, Timestamp: model.UnixNano(at), Multiplicity: 1, Record: model.LogRecord{Line: line, StreamLabels: model.Labels{{Name: "app", Value: "api"}}}}
}
func metricPlan(t *testing.T, q string, e value.Evaluation) Plan {
	t.Helper()
	p := testProfile(t)
	x, err := Parse(q, p)
	if err != nil {
		t.Fatal(err)
	}
	typed, _, err := Check(x, p)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(typed, e, p)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
func metricValue(t *testing.T, q string, src *metricSource) float64 {
	t.Helper()
	a := value.NewBoundedAccount(32 << 20)
	r, _, err := Evaluate(context.Background(), metricPlan(t, q, value.Evaluation{Instant: true, Time: 2e9}), src, a)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release(value.ResultBytes(r))
	if len(r.Vector) != 1 {
		t.Fatalf("vector=%v", r.Vector)
	}
	return math.Float64frombits(uint64(r.Vector[0].Samples[0].Float))
}
func TestUnwrapErrorsAndWindows(t *testing.T) {
	s := &metricSource{rows: []scan.LogRow{metricRow(1, 0, `n=1`), metricRow(2, 1e9, `n=2`), metricRow(3, 15e8, `n=bad`), metricRow(4, 2e9, `n=4`)}}
	q := `sum_over_time({app="api"}|logfmt|unwrap n[2s])`
	a := value.NewBoundedAccount(32 << 20)
	_, _, err := Evaluate(context.Background(), metricPlan(t, q, value.Evaluation{Instant: true, Time: 2e9}), s, a)
	var pipeline *MetricPipelineError
	if !errors.As(err, &pipeline) {
		t.Fatalf("want pipeline error, got %v", err)
	}
	if a.Used() != 0 {
		t.Fatalf("failure leaked %d", a.Used())
	}
	if got := metricValue(t, `sum_over_time({app="api"}|logfmt|unwrap n|__error__=""[2s])`, s); got != 6 {
		t.Fatalf("left-open sum=%g", got)
	}
	last := s.selections[len(s.selections)-1]
	if last.Start != 1 || last.End != 2e9+1 {
		t.Fatalf("raw bounds=%+v", last)
	}
}
func TestEveryLogQLMetricObligation(t *testing.T) {
	s := &metricSource{rows: []scan.LogRow{metricRow(1, 1e9, `n=2`), metricRow(2, 2e9, `n=4`)}}
	tests := []struct {
		q    string
		want float64
	}{{`count_over_time({app="api"}[2s])`, 2}, {`rate({app="api"}[2s])`, 1}, {`bytes_over_time({app="api"}[2s])`, 6}, {`bytes_rate({app="api"}[2s])`, 3}, {`rate({app="api"}|logfmt|unwrap n[2s])`, 3}, {`sum_over_time({app="api"}|logfmt|unwrap n[2s])`, 6}, {`avg_over_time({app="api"}|logfmt|unwrap n[2s])`, 3}, {`min_over_time({app="api"}|logfmt|unwrap n[2s])`, 2}, {`max_over_time({app="api"}|logfmt|unwrap n[2s])`, 4}, {`stdvar_over_time({app="api"}|logfmt|unwrap n[2s])`, 1}, {`stddev_over_time({app="api"}|logfmt|unwrap n[2s])`, 1}, {`quantile_over_time(0.5,{app="api"}|logfmt|unwrap n[2s])`, 3}, {`first_over_time({app="api"}|logfmt|unwrap n[2s])`, 2}, {`last_over_time({app="api"}|logfmt|unwrap n[2s])`, 4}, {`sum(vector(2))`, 2}, {`avg(vector(2))`, 2}, {`count(vector(2))`, 1}, {`stddev(vector(2))`, 0}, {`stdvar(vector(2))`, 0}, {`min(vector(2))`, 2}, {`max(vector(2))`, 2}, {`topk(1,vector(2))`, 2}, {`bottomk(1,vector(2))`, 2}, {`sort(vector(2))`, 2}, {`sort_desc(vector(2))`, 2}, {`vector(2)+3`, 5}, {`3-vector(2)`, 1}, {`vector(2)==bool 3`, 0}, {`vector(2) or vector(3)`, 2}, {`vector(2) and vector(3)`, 2}, {`absent_over_time({app="missing"}[2s])`, 1}}
	for _, tc := range tests {
		t.Run(tc.q, func(t *testing.T) {
			if got := metricValue(t, tc.q, s); got != tc.want {
				t.Fatalf("got=%g want=%g", got, tc.want)
			}
		})
	}
}
func TestMetricGridAndUnknownMetadata(t *testing.T) {
	s := &metricSource{partial: true}
	a := value.NewBoundedAccount(32 << 20)
	r, _, err := Evaluate(context.Background(), metricPlan(t, `sum(count_over_time({app="api"}[1s]))`, value.Evaluation{Start: 1e9, End: 2e9, Step: 5e8}), s, a)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release(value.ResultBytes(r))
	if r.Type != "matrix" || len(r.Matrix) != 0 || !r.Partial || len(r.Watermarks) != 1 {
		t.Fatalf("zero result lost metadata: %+v", r)
	}
	s.failure = model.Fail(model.Unavailable)
	_, _, err = Evaluate(context.Background(), metricPlan(t, `absent_over_time({app="api"}[1s])`, value.Evaluation{Instant: true, Time: 2e9}), s, a)
	if err == nil {
		t.Fatal("unknown input became absent success")
	}
}
func TestMetricMultiplicityAndCounterReset(t *testing.T) {
	s := &metricSource{rows: []scan.LogRow{metricRow(1, 5e8, "n=5"), metricRow(2, 1e9, "n=1"), metricRow(3, 15e8, "n=3")}}
	s.rows[0].Multiplicity = 3
	if got := metricValue(t, `count_over_time({app="api"}[2s])`, s); got != 5 {
		t.Fatalf("multiplicity=%g", got)
	}
	// Loki 3.5.2 range_vector.go286-349 anchors at first/last observations,
	// not the evaluation window. FPoint.T remains nanoseconds, but the pinned
	// kernel divides its timestamp difference by1000 and subtracts range-ms
	// from the first raw timestamp. Do not substitute PromQL's unit model.
	// Reset correction: (3-5)+5=3. Five observations span1e9ns; the native
	// elapsed is1e6 and spacing250000. Start extension2 is below275000;
	// end extension is0. Result=3*((1000000+2)/1000000)/2.
	want := math.Float64frombits(0x3ff80003254e6e22)
	if got := metricValue(t, `rate_counter({app="api"}|logfmt|unwrap n[2s])`, s); math.Float64bits(got) != math.Float64bits(want) {
		t.Fatalf("counter reset extrapolation=%g bits=%016x want=%g bits=%016x", got, math.Float64bits(got), want, math.Float64bits(want))
	}
	selection := s.selections[len(s.selections)-1]
	if selection.Start != 1 || selection.End != 2e9+1 {
		t.Fatalf("counter changed exact left-open source bounds: %+v", selection)
	}
}
