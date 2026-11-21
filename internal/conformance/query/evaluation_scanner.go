// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"fmt"
	"io"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/scan"
	"github.com/arynyklas/soundpost/internal/storage"
)

// InMemoryEvaluationScanner is development fixture storage implementing the
// unchanged C05 Scanner seam. It is NOT a production authority or alternate
// evaluator. Its only namespace is the explicitly selected fixture project;
// zero auth.Scope is accepted here only, never by production storage.
// Matchers deliberately remain residual in the real MetricSource, avoiding a
// second regex engine or a potentially unsafe fixture-only pushdown.
type InMemoryEvaluationScanner struct {
	Project                    model.ID
	Series                     []EvaluationSeries
	StartTimestampObservations []EvaluationStartTimestamp
}

var _ scan.Scanner = (*InMemoryEvaluationScanner)(nil)

func (s *InMemoryEvaluationScanner) Scan(ctx context.Context, _ auth.Scope, r storage.ScanRequest) (storage.RowIterator, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.Signal != model.Metric || r.End < r.Start || len(r.Projects) != 1 || r.Projects[0] != s.Project || r.Fence.AllowPartial || len(r.Fence.Min) != 0 {
		return nil, fmt.Errorf("invalid or foreign evaluation fixture scan")
	}
	var page storage.Page
	var observations []EvaluationStartTimestamp
	var seq uint64
	for _, series := range s.Series {
		project := series.Project
		if project == (model.ID{}) {
			project = s.Project
		}
		if project != s.Project {
			return nil, fmt.Errorf("foreign fixture series")
		}
		name := ""
		var labels model.Labels
		for _, label := range series.Labels {
			if label.Name == "__name__" {
				name = label.Value
			} else {
				labels = append(labels, label)
			}
		}
		for _, sample := range series.Samples {
			if sample.Time < r.Start || sample.Time >= r.End {
				continue
			}
			if (sample.Float == nil) == (sample.Histogram == nil) {
				return nil, fmt.Errorf("invalid fixture sample variant")
			}
			metric := &model.MetricPoint{Name: name, Labels: labels, Value: sample.Float, Histogram: sample.Histogram, Type: "gauge", Unit: "1", SampleKind: "float"}
			metric.StartTimestamp = cloneEvaluationStartTimestamp(sample.StartTimestamp)
			observations = append(observations, EvaluationStartTimestamp{Project: project, Labels: append(model.Labels(nil), series.Labels...), Time: sample.Time, StartTimestamp: cloneEvaluationStartTimestamp(sample.StartTimestamp)})
			if sample.Float != nil && *sample.Float == model.FloatBits(0x7ff0000000000002) {
				metric.SampleKind = "stale"
			}
			if sample.Histogram != nil {
				metric.SampleKind = "float_histogram"
				if sample.Histogram.Integer != nil {
					metric.SampleKind = "integer_histogram"
				}
			}
			seq++
			id := model.ID{8: byte(seq >> 56), 9: byte(seq >> 48), 10: byte(seq >> 40), 11: byte(seq >> 32), 12: byte(seq >> 24), 13: byte(seq >> 16), 14: byte(seq >> 8), 15: byte(seq)}
			page.IDs = append(page.IDs, id)
			page.Times = append(page.Times, sample.Time)
			page.ObservedTimes = append(page.ObservedTimes, sample.Time)
			page.Resources = append(page.Resources, model.Resource{})
			page.Values = append(page.Values, model.Payload{Metric: metric})
			page.Origins = append(page.Origins, model.Cursor{})
			page.Projects = append(page.Projects, project)
			page.Sources = append(page.Sources, model.ID{})
			page.Loss = append(page.Loss, 0)
		}
	}
	return &evaluationRowIterator{page: page, source: s, observations: observations}, nil
}

type evaluationRowIterator struct {
	page         storage.Page
	done, closed bool
	source       *InMemoryEvaluationScanner
	observations []EvaluationStartTimestamp
}

func (it *evaluationRowIterator) Next(ctx context.Context) (storage.Page, error) {
	if err := ctx.Err(); err != nil {
		return storage.Page{}, err
	}
	if it.closed {
		return storage.Page{}, fmt.Errorf("evaluation iterator closed")
	}
	if it.done || len(it.page.IDs) == 0 {
		return storage.Page{}, io.EOF
	}
	it.done = true
	it.source.StartTimestampObservations = append(it.source.StartTimestampObservations, it.observations...)
	return it.page, nil
}
func (it *evaluationRowIterator) Watermarks() []model.Cursor { return nil }
func (it *evaluationRowIterator) Close() error {
	it.closed = true
	it.page = storage.Page{}
	it.observations = nil
	return nil
}
