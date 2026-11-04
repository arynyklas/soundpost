// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"errors"
	"io"
	"math"
	"soundpost/internal/model"
	"soundpost/internal/query/scan"
	"soundpost/internal/query/value"
	"strconv"
	"strings"
)

type variantSource struct {
	project  model.ID
	rows     []scan.LogRow
	metadata value.Result
}

func (s *variantSource) ProjectID() model.ID { return s.project }
func (s *variantSource) Select(ctx context.Context, selection scan.LogSelection) (scan.LogIterator, error) {
	if err := selection.Account.Check(ctx); err != nil {
		return nil, err
	}
	return &variantRows{source: s, selection: selection}, nil
}

type variantRows struct {
	source    *variantSource
	selection scan.LogSelection
	at        int
	closed    bool
}

func (i *variantRows) Next(ctx context.Context) (scan.LogRow, error) {
	if err := i.selection.Account.Check(ctx); err != nil {
		return scan.LogRow{}, err
	}
	if i.closed {
		return scan.LogRow{}, io.EOF
	}
	for i.at < len(i.source.rows) {
		r := i.source.rows[i.at]
		i.at++
		if r.Timestamp >= i.selection.Start && r.Timestamp < i.selection.End {
			return r, nil
		}
	}
	return scan.LogRow{}, io.EOF
}
func (i *variantRows) Watermarks() []model.Cursor {
	return append([]model.Cursor(nil), i.source.metadata.Watermarks...)
}
func (i *variantRows) Partial() bool { return i.source.metadata.Partial }
func (i *variantRows) Close() error  { i.closed = true; return nil }

// A multi-variant expression shares one authorized read cut. Its common range
// determines source selection; each variant retains its own extraction stages
// and evaluation window. No variant is allowed to initiate a second C05 read.
func (s *metricState) variants(n *VariantsExpr, at model.UnixNano) (result value.Result, err error) {
	result.Type = "vector"
	right, e := metricSub(int64(at), n.Range.Offset)
	if e != nil {
		return result, e
	}
	left, e := metricSub(right, n.Range.Interval)
	if e != nil || right == math.MaxInt64 {
		return result, model.Fail(model.Invalid)
	}
	p, e := s.pipeline(n.Range.Log)
	if e != nil {
		return result, e
	}
	selector := PipelinePlan{Matchers: p.Matchers, Profile: p.Profile, Evaluation: p.Evaluation, Templates: p.Templates, RegexScope: p.RegexScope}
	if e = selector.compile(s.ctx); e != nil {
		return result, e
	}
	ms := make([]scan.LabelMatcher, len(p.Matchers))
	for i, m := range p.Matchers {
		ms[i] = scan.LabelMatcher{Name: m.Name, Op: m.Op, Value: m.Value}
	}
	input, e := s.src.Select(s.ctx, scan.LogSelection{Start: model.UnixNano(left + 1), End: model.UnixNano(right + 1), Matchers: ms, Profile: s.plan.Profile, Account: s.account, RegexScope: p.RegexScope})
	if e != nil {
		return result, e
	}
	if input == nil {
		return result, model.Fail(model.Corrupt)
	}
	snapshot := &variantSource{project: s.src.ProjectID()}
	defer func() {
		closeErr := input.Close()
		if err == nil {
			err = closeErr
		}
		value.InheritMetadata(&s.metadata, value.Result{Partial: input.Partial(), Watermarks: input.Watermarks()})
	}()
	for {
		if e = s.account.Check(s.ctx); e != nil {
			return result, e
		}
		row, e := input.Next(s.ctx)
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return result, e
		}
		selected, e := RunLogRow(s.ctx, selector, row, s.account)
		if e != nil {
			return result, e
		}
		if !selected.Retained {
			s.account.Release(selected.Bytes)
			continue
		}
		cost := selected.Bytes + 512
		if e = s.reserve(cost); e != nil {
			s.account.Release(selected.Bytes)
			return result, e
		}
		row.Record = cloneVariantRecord(row.Record)
		snapshot.rows = append(snapshot.rows, row)
		s.account.Release(selected.Bytes)
	}
	snapshot.metadata = value.Result{Partial: input.Partial(), Watermarks: input.Watermarks()}
	value.InheritMetadata(&s.metadata, snapshot.metadata)
	oldSource, oldVariant := s.src, s.variantInput
	s.src = snapshot
	s.variantInput = true
	defer func() { s.src = oldSource; s.variantInput = oldVariant }()
	for index, expr := range n.Variants {
		r, e := s.eval(expr, at)
		if e != nil {
			return result, e
		}
		if e = s.reserve(value.ResultBytes(r) * 2); e != nil {
			return result, e
		}
		for _, series := range r.Vector {
			series.Labels = value.SetLabel(series.Labels, "__variant__", strconv.Itoa(index))
			result.Vector = append(result.Vector, series)
		}
	}
	return result, nil
}
func cloneVariantRecord(r model.LogRecord) model.LogRecord {
	r.Line = strings.Clone(r.Line)
	r.TemplateID = strings.Clone(r.TemplateID)
	r.Severity = strings.Clone(r.Severity)
	r.StreamLabels = value.CloneLabels(r.StreamLabels)
	fields := make(map[string]model.Scalar, len(r.Fields))
	for k, v := range r.Fields {
		fields[strings.Clone(k)] = v
	}
	r.Fields = fields
	metadata := make(map[string]model.Scalar, len(r.Metadata))
	for k, v := range r.Metadata {
		metadata[strings.Clone(k)] = v
	}
	r.Metadata = metadata
	if r.Timestamp != nil {
		v := *r.Timestamp
		r.Timestamp = &v
	}
	if r.Trace != nil {
		v := *r.Trace
		r.Trace = &v
	}
	if r.Span != nil {
		v := *r.Span
		r.Span = &v
	}
	if r.Run != nil {
		v := *r.Run
		r.Run = &v
	}
	return r
}
