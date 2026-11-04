// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package scan

import (
	"context"
	"errors"
	"io"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/regexcompat"
	"soundpost/internal/query/value"
	"soundpost/internal/storage"
	"strings"
)

type LogSelection struct {
	Start, End model.UnixNano
	Matchers   []LabelMatcher
	Source     model.ID
	Profile    profile.Profile
	Account    value.Account
	RegexScope *regexcompat.Scope
}

// LogRow and its record data are borrowed until the next Next or Close. A
// retaining consumer copies only the selected values; identity is never a hash
// of line bytes and legitimate duplicate records remain distinct rows.
type LogRow struct {
	ID, Project, Source model.ID
	Timestamp           model.UnixNano
	Multiplicity        model.Uint64
	Record              model.LogRecord
}
type LogIterator interface {
	Next(context.Context) (LogRow, error)
	Watermarks() []model.Cursor
	Partial() bool
	Close() error
}
type LogSource interface {
	ProjectID() model.ID
	Select(context.Context, LogSelection) (LogIterator, error)
}
type logSource struct {
	scanner Scanner
	scope   auth.Scope
	project model.ID
	fence   storage.ReadFence
}

func NewLogSource(scanner Scanner, scope auth.Scope, project model.ID, fence storage.ReadFence) LogSource {
	fence.Min = append([]model.Cursor(nil), fence.Min...)
	return &logSource{scanner, scope, project, fence}
}
func (s *logSource) ProjectID() model.ID { return s.project }
func (s *logSource) Select(ctx context.Context, r LogSelection) (LogIterator, error) {
	if s.scanner == nil || r.Account == nil || r.Start >= r.End {
		return nil, model.Fail(model.Invalid)
	}
	if err := r.Account.Check(ctx); err != nil {
		return nil, err
	}
	matchers, err := CompileMatchers(ctx, MetricSelection{Matchers: r.Matchers, Profile: r.Profile, RegexScope: r.RegexScope})
	if err != nil {
		return nil, err
	}
	var selectors []storage.Matcher
	if s.scope.Permission() == auth.RawRead {
		if r.Source == (model.ID{}) || !s.scope.AllowsSource(r.Source) {
			return nil, model.Fail(model.Forbidden)
		}
		selectors = append(selectors, storage.Matcher{Target: storage.MatchField, Name: "source_id", Op: storage.MatchEqual, Literal: storage.Literal{Kind: storage.LiteralString, String: r.Source.String()}})
	}
	rows, err := s.scanner.Scan(ctx, s.scope, storage.ScanRequest{Projects: []model.ID{s.project}, Signal: model.Log, Start: r.Start, End: r.End, Selectors: selectors, Projection: []storage.Field{storage.FieldID, storage.FieldTime, storage.FieldLog}, Fence: s.fence})
	if err != nil {
		return nil, err
	}
	if rows == nil {
		return nil, model.Fail(model.Corrupt)
	}
	return &logIterator{rows: rows, source: s, selection: r, matchers: matchers}, nil
}

type logIterator struct {
	rows                       storage.RowIterator
	source                     *logSource
	selection                  LogSelection
	matchers                   *MatcherSet
	page                       storage.Page
	index                      int
	partial, closed, exhausted bool
	terminal                   error
	marks                      []model.Cursor
	held                       int64
	current                    LogRow
}

func (i *logIterator) Watermarks() []model.Cursor { return append([]model.Cursor(nil), i.marks...) }
func (i *logIterator) Partial() bool              { return i.partial }
func (i *logIterator) release() {
	i.selection.Account.Release(i.held)
	i.held = 0
	i.current = LogRow{}
}
func (i *logIterator) Close() error {
	if i.closed {
		return nil
	}
	i.closed = true
	i.release()
	i.page = storage.Page{}
	return i.rows.Close()
}
func (i *logIterator) fail(err error) (LogRow, error) {
	i.terminal = err
	closeErr := i.Close()
	if err == nil {
		err = closeErr
	}
	return LogRow{}, err
}
func (i *logIterator) Next(ctx context.Context) (LogRow, error) {
	if err := i.selection.Account.Check(ctx); err != nil {
		return i.fail(err)
	}
	if i.terminal != nil {
		return LogRow{}, i.terminal
	}
	if i.exhausted {
		return LogRow{}, io.EOF
	}
	if i.closed {
		return LogRow{}, io.ErrClosedPipe
	}
	i.release()
	for {
		if err := i.selection.Account.Check(ctx); err != nil {
			return i.fail(err)
		}
		if i.index >= i.page.Len() {
			page, err := i.rows.Next(ctx)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					return i.fail(err)
				}
				if err = i.selection.Account.Check(ctx); err != nil {
					return i.fail(err)
				}
				i.marks = append([]model.Cursor(nil), i.rows.Watermarks()...)
				if err = i.Close(); err != nil {
					return i.fail(err)
				}
				i.exhausted = true
				return LogRow{}, io.EOF
			}
			n := page.Len()
			if len(page.Times) != n || len(page.Values) != n || len(page.Projects) != n || len(page.Sources) != n {
				return i.fail(model.Fail(model.Corrupt))
			}
			if page.Partial && !i.source.fence.AllowPartial {
				return i.fail(model.Fail(model.Unavailable))
			}
			i.partial = i.partial || page.Partial
			i.marks = append([]model.Cursor(nil), i.rows.Watermarks()...)
			i.page = page
			i.index = 0
			if n == 0 {
				continue
			}
		}
		j := i.index
		i.index++
		if i.page.Projects[j] != i.source.project {
			return i.fail(model.Fail(model.Corrupt))
		}
		if i.selection.Source != (model.ID{}) && i.page.Sources[j] != i.selection.Source {
			continue
		}
		if i.page.Times[j] < i.selection.Start || i.page.Times[j] >= i.selection.End {
			continue
		}
		payload := i.page.Values[j]
		if _, err := payload.Value(model.Log); err != nil || payload.Log == nil {
			return i.fail(model.Fail(model.Corrupt))
		}
		log := payload.Log
		if err := log.StreamLabels.Validate(); err != nil {
			return i.fail(model.Fail(model.Corrupt))
		}
		match, err := i.matchers.Match(ctx, log.StreamLabels)
		if err != nil {
			return i.fail(err)
		}
		if !match {
			continue
		}
		cost := int64(160 + len(log.Line) + len(log.TemplateID) + len(log.Severity))
		for _, l := range log.StreamLabels {
			cost += int64(32 + len(l.Name) + len(l.Value))
		}
		for _, fields := range []map[string]model.Scalar{log.Fields, log.Metadata} {
			for n, v := range fields {
				raw, e := v.MarshalJSON()
				if e != nil {
					return i.fail(model.Fail(model.Corrupt))
				}
				cost += int64(64 + len(n) + len(raw))
			}
		}
		if err = i.selection.Account.Reserve(cost); err != nil {
			return i.fail(err)
		}
		i.held = cost
		owned := *log
		owned.Line = strings.Clone(log.Line)
		owned.TemplateID = strings.Clone(log.TemplateID)
		owned.Severity = strings.Clone(log.Severity)
		owned.StreamLabels = value.CloneLabels(log.StreamLabels)
		owned.Fields = cloneScalars(log.Fields)
		owned.Metadata = cloneScalars(log.Metadata)
		if log.Timestamp != nil {
			at := *log.Timestamp
			owned.Timestamp = &at
		}
		if log.Trace != nil {
			id := *log.Trace
			owned.Trace = &id
		}
		if log.Span != nil {
			id := *log.Span
			owned.Span = &id
		}
		if log.Run != nil {
			id := *log.Run
			owned.Run = &id
		}
		if err = i.selection.Account.Check(ctx); err != nil {
			return i.fail(err)
		}
		i.current = LogRow{ID: i.page.IDs[j], Project: i.page.Projects[j], Source: i.page.Sources[j], Timestamp: i.page.Times[j], Multiplicity: 1, Record: owned}
		return i.current, nil
	}
}
func cloneScalars(in map[string]model.Scalar) map[string]model.Scalar {
	out := make(map[string]model.Scalar, len(in))
	for n, v := range in {
		out[strings.Clone(n)] = v
	}
	return out
}
