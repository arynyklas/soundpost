// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package scan

import (
	"context"
	"errors"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/regexcompat"
	"github.com/arynyklas/soundpost/internal/query/value"
	"github.com/arynyklas/soundpost/internal/storage"
	"io"
	"unsafe"
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
	rows, err := s.scanner.Scan(ctx, s.scope, storage.ScanRequest{Projects: []model.ID{s.project}, Signal: model.Log, Start: r.Start, End: r.End, Selectors: selectors, Projection: []storage.Field{storage.FieldID, storage.FieldTime, storage.FieldLog}, Fence: s.fence, MaxPageRows: storage.MaxScanPageRows})
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
	// sawPage is set once a page was read: from then on the cut is certified when it is asked for, and
	// marked once it is certified for good (at the end of the rows or when the iterator closes early).
	// Certifying it at every page cost a second release barrier, a fence over every group of the cut
	// and an authority read, for each page.
	sawPage, marked bool
	held            int64
	current         LogRow
}

func (i *logIterator) Watermarks() []model.Cursor {
	if !i.marked && !i.closed && i.sawPage {
		return append([]model.Cursor(nil), i.rows.Watermarks()...)
	}
	return append([]model.Cursor(nil), i.marks...)
}
func (i *logIterator) Partial() bool { return i.partial }
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
	if !i.marked && i.sawPage && i.terminal == nil {
		// Closed before the end of the rows: the cut is certified now, while the rows can still say it.
		i.marks = append([]model.Cursor(nil), i.rows.Watermarks()...)
		i.marked = true
	}
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
				i.marked = true
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
			i.sawPage = true
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
		for n, v := range log.Fields {
			cost += int64(64 + len(n) + v.JSONLen())
		}
		for n, v := range log.Metadata {
			cost += int64(64 + len(n) + v.JSONLen())
		}
		if err = i.selection.Account.Reserve(cost); err != nil {
			return i.fail(err)
		}
		i.held = cost
		owned := ownLogRecord(log)
		if err = i.selection.Account.Check(ctx); err != nil {
			return i.fail(err)
		}
		i.current = LogRow{ID: i.page.IDs[j], Project: i.page.Projects[j], Source: i.page.Sources[j], Timestamp: i.page.Times[j], Multiplicity: 1, Record: owned}
		return i.current, nil
	}
}

// ownedPointers holds the optional scalars of one owned row in one allocation.
type ownedPointers struct {
	at    model.UnixNano
	trace model.ID
	span  model.SpanID
	run   model.ID
}

// ownLogRecord is a copy of a stored record that owns its strings and slices. The strings of a row (the
// line, the template, the severity, the label names and values) are copied into one buffer, the labels are
// one slice and the optional pointers one struct: a dozen allocations per row before, two for a row with
// labels. The field and metadata maps are shared read-only, see below.
func ownLogRecord(log *model.LogRecord) model.LogRecord {
	size := len(log.Line) + len(log.TemplateID) + len(log.Severity) + len(log.SourceClass)
	for _, l := range log.StreamLabels {
		size += len(l.Name) + len(l.Value)
	}
	buf := make([]byte, 0, size)
	own := func(s string) string {
		if s == "" {
			return ""
		}
		at := len(buf)
		buf = append(buf, s...)
		return unsafe.String(&buf[at], len(s))
	}
	owned := *log
	owned.Line = own(log.Line)
	owned.TemplateID = own(log.TemplateID)
	owned.Severity = own(log.Severity)
	owned.SourceClass = own(log.SourceClass)
	if log.StreamLabels != nil {
		owned.StreamLabels = make(model.Labels, len(log.StreamLabels))
		for i, l := range log.StreamLabels {
			owned.StreamLabels[i] = model.Label{Name: own(l.Name), Value: own(l.Value)}
		}
	}
	// owned.Fields and owned.Metadata stay the stored maps: the decoded page they belong to is immutable and
	// shared (the page cache), the pipeline and the evaluators only read them, and the scalars in them are
	// strings of the page either way. Copying them was a map allocation and an insert per field of every
	// row (34 CPU seconds, with the strings, of the 24 h log class in a 60 s mix profile).
	if log.Timestamp != nil || log.Trace != nil || log.Span != nil || log.Run != nil {
		p := new(ownedPointers)
		if log.Timestamp != nil {
			p.at = *log.Timestamp
			owned.Timestamp = &p.at
		}
		if log.Trace != nil {
			p.trace = *log.Trace
			owned.Trace = &p.trace
		}
		if log.Span != nil {
			p.span = *log.Span
			owned.Span = &p.span
		}
		if log.Run != nil {
			p.run = *log.Run
			owned.Run = &p.run
		}
	}
	return owned
}
