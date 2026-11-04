// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"sync"
	"time"

	"soundpost/internal/model"
	"soundpost/internal/query/logql"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/scan"
	"soundpost/internal/query/syntax"
	"soundpost/internal/query/value"
)

// Development observations serialize their explicit process-local timezone.
// Keep actual time.Now untouched: time.In/UTC would strip its monotonic value.
var logQLWallClockMu sync.Mutex

func ownedLogQLError(err error) *LogQLError {
	var language *syntax.LanguageError
	if errors.As(err, &language) {
		start, end := language.Range.StartByte, language.Range.EndByte
		return &LogQLError{Semantic: language.Code, Category: language.Category, CategoryExposed: true, Message: language.SafeMessage, Start: &start, End: &end}
	}
	var template *logql.TemplateError
	if errors.As(err, &template) {
		return &LogQLError{Semantic: template.SemanticCode(), Category: "template", CategoryExposed: true, Message: err.Error(), LanguageDetail: template.LanguageDetail()}
	}
	// Unknown operational failures do not masquerade as language observations.
	var pipeline *logql.MetricPipelineError
	if errors.As(err, &pipeline) {
		return &LogQLError{Semantic: "pipeline.error:" + pipeline.Category, Category: "pipeline", CategoryExposed: true, Message: err.Error()}
	}
	return &LogQLError{Message: err.Error()}
}
func observeOwnedLogQL(ctx context.Context, c LogQLCase, p profile.Profile) (LogQLObservation, error) {
	o := LogQLObservation{ID: c.ID}
	account := value.NewBoundedAccount(256 << 20)
	var templateLocation *time.Location
	if c.Phase == "logql-template" {
		location, _, err := loadLogQLLocation(c.Timezone, p)
		if err != nil {
			return o, err
		}
		templateLocation = location
		logQLWallClockMu.Lock()
		oldLocation := time.Local
		time.Local = location
		defer func() { time.Local = oldLocation; logQLWallClockMu.Unlock() }()
	}
	fail := func(e error) (LogQLObservation, error) {
		o.Error = ownedLogQLError(e)
		if o.Error.Semantic == "" {
			return o, fmt.Errorf("unclassified owned LogQL failure in %s: %w", c.ID, e)
		}
		return o, nil
	}
	if c.Phase == "logql-template" && c.Kind != "pipeline" && c.Kind != "pipeline_query" {
		t, e := logql.CompileTemplate(c.Source, p, logql.TemplateRuntime{Now: time.Now, Location: templateLocation})
		if e != nil {
			return fail(e)
		}
		o.ClockStart = strconv.FormatInt(time.Now().UnixNano(), 10)
		o.Output, e = t.Execute(ctx, logql.TemplateInput{Line: c.Line, Timestamp: c.Timestamp, Labels: c.Labels, Fields: c.Fields}, account)
		o.ClockEnd = strconv.FormatInt(time.Now().UnixNano(), 10)
		if e != nil {
			return fail(e)
		}
		o.Accepted = true
		o.Type = "template"
		return o, nil
	}
	expression := c.Input.Expression
	if c.Phase == "logql-template" {
		expression = c.PipelineQuery
	}
	if c.Phase == "logql-metric" {
		expression = c.Query
	}
	ast, e := logql.Parse(expression, p)
	if e != nil {
		return fail(e)
	}
	typed, _, e := logql.Check(ast, p)
	if e != nil {
		return fail(e)
	}
	o.Type = string(typed.Type)
	if c.Phase == "syntax" {
		o.Accepted = true
		return o, nil
	}
	evaluation := value.Evaluation{Instant: c.Kind == "instant", Time: c.Time, Start: c.Start, End: c.End, Step: c.Step}
	plan, e := logql.BuildPlan(typed, evaluation, p)
	if e != nil {
		return fail(e)
	}
	if c.Phase == "pipeline" || c.Phase == "logql-template" {
		if len(plan.Pipelines) != 1 {
			return o, fmt.Errorf("pipeline observation requires exactly one native pipeline")
		}
		entry := c.Input.Entry
		if c.Phase == "logql-template" {
			entry = &LogQLEntry{Line: c.Line, Timestamp: c.Timestamp, Multiplicity: 1, StreamLabels: c.Labels, Fields: c.Fields}
			plan.Pipelines[0], e = plan.Pipelines[0].WithTemplateRuntime(logql.TemplateRuntime{Now: time.Now, Location: templateLocation})
			if e != nil {
				return fail(e)
			}
		}
		if entry == nil {
			return o, fmt.Errorf("missing pipeline entry")
		}
		o.ClockStart = strconv.FormatInt(time.Now().UnixNano(), 10)
		r, e := logql.RunPipeline(ctx, plan.Pipelines[0], logql.LogEntry{Timestamp: entry.Timestamp, ID: entry.ID, Multiplicity: entry.Multiplicity, Line: entry.Line, StreamLabels: entry.StreamLabels, StructuredMetadata: entry.Metadata, Fields: entry.Fields}, account)
		o.ClockEnd = strconv.FormatInt(time.Now().UnixNano(), 10)
		if e != nil {
			return fail(e)
		}
		defer account.Release(r.Bytes)
		o.Pipeline = &LogQLPipeline{Retained: r.Retained, Line: r.Entry.Line, Labels: r.Labels}
		if r.Unwrapped != nil {
			bits := model.FloatBits(math.Float64bits(*r.Unwrapped))
			o.Pipeline.Unwrapped = &bits
		}
		o.Accepted = true
		return o, nil
	}
	source := &logQLFixtureSource{entries: c.Entries}
	var result value.Result
	if typed.Type == logql.TypeLogs {
		order := logql.Forward
		if c.Direction == "backward" {
			order = logql.Backward
		}
		result, e = logql.EvaluateLogsInterval(ctx, plan, source, order, uint64(c.Limit), c.Interval, account)
	} else {
		result, _, e = logql.Evaluate(ctx, plan, source, account)
	}
	if e != nil {
		return fail(e)
	}
	defer account.Release(value.ResultBytes(result))
	if result.Partial {
		return o, fmt.Errorf("authored fixture unexpectedly partial")
	}
	o.Accepted = true
	o.Type = result.Type
	add := func(labels model.Labels, s value.Sample) {
		o.Values = append(o.Values, LogQLValue{Timestamp: strconv.FormatInt(int64(s.Time), 10), Bits: fmt.Sprintf("%016x", uint64(s.Float)), Labels: labels})
	}
	if result.Type == "scalar" {
		add(nil, result.Scalar)
	}
	for _, series := range result.Vector {
		for _, s := range series.Samples {
			add(series.Labels, s)
		}
	}
	for _, series := range result.Matrix {
		for _, s := range series.Samples {
			add(series.Labels, s)
		}
	}
	for _, l := range result.Logs {
		o.StoredRows = append(o.StoredRows, LogQLValue{Timestamp: strconv.FormatInt(int64(l.Timestamp), 10), Line: l.Line, Labels: l.Labels, ID: l.ID.String(), Multiplicity: strconv.FormatUint(uint64(l.Multiplicity), 10)})
		for n := uint64(0); n < uint64(l.Multiplicity); n++ {
			o.Values = append(o.Values, LogQLValue{Timestamp: strconv.FormatInt(int64(l.Timestamp), 10), Line: l.Line, Labels: l.Labels, Multiplicity: "1"})
		}
	}
	return o, nil
}

// This input-only in-memory LogSource is development harness storage, not a
// production authorization adapter. It applies the exact public scan contract.
type logQLFixtureSource struct{ entries []LogQLEntry }

func (s *logQLFixtureSource) ProjectID() model.ID { return evaluationProject }
func (s *logQLFixtureSource) Select(ctx context.Context, r scan.LogSelection) (scan.LogIterator, error) {
	matchers, e := scan.CompileMatchers(ctx, scan.MetricSelection{Matchers: r.Matchers, Profile: r.Profile, RegexScope: r.RegexScope})
	if e != nil {
		return nil, e
	}
	var rows []scan.LogRow
	for _, entry := range s.entries {
		if entry.Timestamp < r.Start || entry.Timestamp >= r.End {
			continue
		}
		ok, e := matchers.Match(ctx, entry.StreamLabels)
		if e != nil {
			return nil, e
		}
		if !ok {
			continue
		}
		fields := map[string]model.Scalar{}
		for _, f := range entry.Fields {
			fields[f.Name] = f.Value
		}
		metadata := map[string]model.Scalar{}
		for _, l := range entry.Metadata {
			raw, e := json.Marshal(l.Value)
			if e != nil {
				return nil, e
			}
			var v model.Scalar
			if e = json.Unmarshal(raw, &v); e != nil {
				return nil, e
			}
			metadata[l.Name] = v
		}
		rows = append(rows, scan.LogRow{ID: entry.ID, Project: evaluationProject, Timestamp: entry.Timestamp, Multiplicity: entry.Multiplicity, Record: model.LogRecord{Line: entry.Line, StreamLabels: entry.StreamLabels, Fields: fields, Metadata: metadata}})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Timestamp < rows[j].Timestamp })
	return &logQLFixtureIterator{rows: rows}, nil
}

type logQLFixtureIterator struct {
	rows   []scan.LogRow
	index  int
	closed bool
}

func (i *logQLFixtureIterator) Next(ctx context.Context) (scan.LogRow, error) {
	if e := ctx.Err(); e != nil {
		return scan.LogRow{}, e
	}
	if i.closed {
		return scan.LogRow{}, io.ErrClosedPipe
	}
	if i.index == len(i.rows) {
		return scan.LogRow{}, io.EOF
	}
	r := i.rows[i.index]
	i.index++
	return r, nil
}
func (i *logQLFixtureIterator) Watermarks() []model.Cursor { return nil }
func (i *logQLFixtureIterator) Partial() bool              { return false }
func (i *logQLFixtureIterator) Close() error               { i.closed = true; i.rows = nil; return nil }
