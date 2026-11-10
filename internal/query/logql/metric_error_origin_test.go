// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"errors"
	"soundpost/internal/query/scan"
	"soundpost/internal/query/value"
	"testing"
)

// TestMetricPipelineErrorRecordsItsOrigin: the failure of a metric over an input
// with an __error__ label says whether the engine set that label (a pipeline
// stage failed) or the record's own data produced it (a JSON key spelled
// __error__). The language outcome is the same either way; the origin is what
// lets the service decide whether the label's text is a closed engine kind.
func TestMetricPipelineErrorRecordsItsOrigin(t *testing.T) {
	for name, tc := range map[string]struct {
		line       string
		query      string
		wantEngine bool
		wantKind   string
	}{
		"engine unwrap failure": {`n=bad`, `sum_over_time({app="api"}|logfmt|unwrap n[2s])`, true, "SampleExtractionErr"},
		"engine json failure":   {`not json`, `count_over_time({app="api"}|json[2s])`, true, "JSONParserErr"},
		"extracted data label":  {`{"__error__":"free text from the record"}`, `count_over_time({app="api"}|json[2s])`, false, "free text from the record"},
	} {
		t.Run(name, func(t *testing.T) {
			s := &metricSource{rows: []scan.LogRow{metricRow(1, 1e9, tc.line)}}
			a := value.NewBoundedAccount(32 << 20)
			_, _, err := Evaluate(context.Background(), metricPlan(t, tc.query, value.Evaluation{Instant: true, Time: 2e9}), s, a)
			var pipeline *MetricPipelineError
			if !errors.As(err, &pipeline) {
				t.Fatalf("want a pipeline error, got %v", err)
			}
			if pipeline.Category != tc.wantKind || pipeline.EngineSet != tc.wantEngine {
				t.Fatalf("category %q engine-set %v, want %q %v", pipeline.Category, pipeline.EngineSet, tc.wantKind, tc.wantEngine)
			}
			if a.Used() != 0 {
				t.Fatalf("failure leaked %d", a.Used())
			}
		})
	}
}
