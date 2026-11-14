// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"encoding/json"
	"strconv"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// defaultMaxSamples is the query.max-samples default of both pinned references.
const defaultMaxSamples = 50_000_000

// QueryOptions are the per-query options of the engine. A Lookback of zero or
// less inherits the engine lookback resolved from the profile; a positive value
// overrides it for this query only. Per-step statistics are produced only when
// both the engine switch (engine.enable-per-step-stats, off by default) and
// PerStepStats are enabled; they never change evaluated values. Stats, when set,
// receives the statistics of the evaluation.
type QueryOptions struct {
	Lookback     int64
	PerStepStats bool
	Stats        *QueryStatistics
}

// QueryStatistics is filled by Evaluate. PeakSamples is the peak of the sample
// units retained at the same time (see SampleUnits); PerStep holds, per
// evaluation step and only with per-step statistics enabled, the sample units the
// selectors loaded for that step.
type QueryStatistics struct {
	PeakSamples int64
	PerStep     []StepStatistics
}

type StepStatistics struct {
	Time    model.UnixNano
	Samples int64
}

// WithQueryOptions returns the plan for one query with the per-query options applied.
func (p Plan) WithQueryOptions(o QueryOptions) Plan {
	if o.Lookback > 0 {
		p.Lookback = o.Lookback
	}
	p.Stats = o.Stats
	p.perStepStats = o.PerStepStats && engineOptionDefault(p.Profile, "engine.enable-per-step-stats", false)
	return p
}

// SampleUnits is the cost of one retained point against query.max-samples: a float
// point costs 1, a native histogram point costs floor((byte size + 8) / 16), where
// the byte size is value.HistogramBytes of the retained (float) histogram.
func SampleUnits(s value.Sample) int64 {
	if s.Histogram != nil {
		return (value.HistogramBytes(*s.Histogram) + 8) / 16
	}
	return 1
}

func seriesUnits(series []value.Series) int64 {
	var n int64
	for _, s := range series {
		for _, sample := range s.Samples {
			n += SampleUnits(sample)
		}
	}
	return n
}

func resultUnits(r value.Result) int64 {
	n := seriesUnits(r.Vector) + seriesUnits(r.Matrix)
	if r.Type == "scalar" {
		n += SampleUnits(r.Scalar)
	}
	return n
}

// engineOptionDefault reads a boolean engine switch whose default is def when the
// profile does not carry it.
func engineOptionDefault(p profile.Profile, key string, def bool) bool {
	raw, ok := p.Configuration[key]
	if !ok {
		return def
	}
	var option struct {
		Default string `json:"default"`
	}
	if json.Unmarshal(raw, &option) != nil {
		return def
	}
	switch option.Default {
	case "true":
		return true
	case "false":
		return false
	}
	return def
}

// engineMaxSamples reads query.max-samples from the profile configuration.
func engineMaxSamples(p profile.Profile) int64 {
	raw, ok := p.Configuration["query.max-samples"]
	if !ok {
		return defaultMaxSamples
	}
	var option struct {
		Default string `json:"default"`
	}
	if json.Unmarshal(raw, &option) != nil {
		return defaultMaxSamples
	}
	n, err := strconv.ParseInt(option.Default, 10, 64)
	if err != nil || n < 0 {
		return defaultMaxSamples
	}
	return n
}

// reserveUnits charges n retained sample units; exceeding query.max-samples is an
// error of the quota class, never a truncated result.
func (s *evaluationState) reserveUnits(n int64) error {
	s.units += n
	if s.units > s.peakUnits {
		s.peakUnits = s.units
	}
	if s.plan.budgeted && s.units > s.plan.MaxSamples {
		return model.Fail(model.Quota)
	}
	return nil
}

// recordStep closes one outer evaluation step for per-step statistics.
func (s *evaluationState) recordStep(at model.UnixNano) {
	if s.plan.perStepStats && s.plan.Stats != nil {
		s.plan.Stats.PerStep = append(s.plan.Stats.PerStep, StepStatistics{Time: at, Samples: s.loaded})
	}
	s.loaded = 0
}
