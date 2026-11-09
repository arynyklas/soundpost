// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	bolt "go.etcd.io/bbolt"
	"io"
	"reflect"
	"regexp"
	"soundpost/internal/auth"
	"soundpost/internal/model"
)

type compiledMatcher struct {
	Matcher
	re                 *regexp.Regexp
	idField, spanField bool
	id                 model.ID
	span               model.SpanID
}
type rowIterator struct {
	e         *Engine
	scope     auth.Scope
	req       ScanRequest
	prefixes  [][]byte
	partition int
	last      []byte
	marks     []model.Cursor
	matchers  []compiledMatcher
	page      Page
	closed    bool
	terminal  error
	stop      func() bool
	ctx       context.Context
	posting   string
	partial   bool
}

func compileMatchers(ms []Matcher) ([]compiledMatcher, error) {
	if len(ms) > 64 {
		return nil, model.Fail(model.TooLarge)
	}
	out := make([]compiledMatcher, 0, len(ms))
	for _, m := range ms {
		if m.Target != MatchLabel && m.Target != MatchField || len(m.Name) == 0 || len(m.Name) > 256 || m.Op < MatchEqual || m.Op > MatchNotRegexp || m.Literal.Kind < LiteralString || m.Literal.Kind > LiteralFloatBits || len(m.Literal.String) > 4096 || m.Target == MatchLabel && m.Literal.Kind != LiteralString {
			return nil, model.Fail(model.Invalid)
		}
		c := compiledMatcher{Matcher: m}
		if m.Op == MatchRegexp || m.Op == MatchNotRegexp {
			if m.Literal.Kind != LiteralString {
				return nil, model.Fail(model.Invalid)
			}
			re, err := regexp.Compile("^(?:" + m.Literal.String + ")$")
			if err != nil {
				return nil, model.Fail(model.Invalid)
			}
			c.re = re
		}
		if m.Target == MatchField && (isIDField(m.Name) || m.Name == "span_id") {
			if m.Literal.Kind != LiteralString {
				return nil, model.Fail(model.Invalid)
			}
			c.idField = isIDField(m.Name)
			c.spanField = m.Name == "span_id"
			if c.re == nil && m.Literal.String != "" {
				if c.idField {
					id, err := model.ParseID(m.Literal.String)
					if err != nil {
						return nil, model.Fail(model.Invalid)
					}
					c.id = id
				}
				if c.spanField {
					span, ok := parseSpanLiteral(m.Literal.String)
					if !ok {
						return nil, model.Fail(model.Invalid)
					}
					c.span = span
				}
			}
		}
		out = append(out, c)
	}
	return out, nil
}

const profilesRead auth.Permission = "profiles.read"

func (e *Engine) authorizeRead(ctx context.Context, s auth.Scope, projects []model.ID, signal model.Kind) error {
	if ctx.Err() != nil {
		return model.Fail(model.Cancelled)
	}
	permitted := s.Permission() == auth.Read || s.Permission() == auth.RawRead || s.Permission() == profilesRead && (signal == model.Profile || signal == model.CapabilityKind || signal == model.Loss)
	if !permitted || len(projects) == 0 || len(projects) > 128 {
		return model.Fail(model.Forbidden)
	}
	seen := map[model.ID]bool{}
	for _, p := range projects {
		if !s.AllowsProject(p) {
			return model.Fail(model.NotFound)
		}
		if seen[p] {
			return model.Fail(model.Invalid)
		}
		seen[p] = true
	}
	if err := e.validator.Revalidate(ctx, s); err != nil {
		return err
	}
	_, err := e.readDeletions(ctx, s.OrgID(), projects)
	return err
}
func readPrefixes(s auth.Scope, projects []model.ID, kind model.Kind, selectors []Matcher) ([][]byte, error) {
	var source model.ID
	if s.Permission() == auth.RawRead {
		for _, m := range selectors {
			if m.Target == MatchField && m.Name == "source_id" && m.Op == MatchEqual && m.Literal.Kind == LiteralString {
				id, err := model.ParseID(m.Literal.String)
				if err == nil && s.AllowsSource(id) {
					source = id
				}
			}
		}
		if source == (model.ID{}) {
			return nil, model.Fail(model.Forbidden)
		}
	}
	out := make([][]byte, 0, len(projects))
	for _, p := range projects {
		for _, subject := range scopeSubjects(s, kind) {
			out = append(out, pageNamespace(s.OrgID(), p, kind, s.Permission() == auth.RawRead, source, subject))
		}
	}
	return out, nil
}
func (e *Engine) Scan(ctx context.Context, scope auth.Scope, req ScanRequest) (RowIterator, error) {
	if err := e.authorizeRead(ctx, scope, req.Projects, req.Signal); err != nil {
		return nil, err
	}
	if !req.Signal.Valid() || req.End < req.Start {
		return nil, model.Fail(model.Invalid)
	}
	for _, f := range req.Projection {
		if f < FieldID || f > FieldObservedTime {
			return nil, model.Fail(model.Invalid)
		}
	}
	ms, err := compileMatchers(req.Selectors)
	if err != nil {
		return nil, err
	}
	prefixes, err := readPrefixes(scope, req.Projects, req.Signal, req.Selectors)
	if err != nil {
		return nil, err
	}
	req.Projects = append([]model.ID(nil), req.Projects...)
	req.Selectors = append([]Matcher(nil), req.Selectors...)
	req.Projection = append([]Field(nil), req.Projection...)
	req.Fence.Min = append([]model.Cursor(nil), req.Fence.Min...)
	marks, partial, err := e.replicaReadFence(ctx, req.Fence.Min, req.Fence.AllowPartial)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return nil, model.Fail(model.Unavailable)
	}
	if err = e.authorizeRead(ctx, scope, req.Projects, req.Signal); err != nil {
		return nil, err
	}
	if e.storageStats.ActiveIterators >= 32 {
		return nil, model.Fail(model.TooLarge)
	}
	term := postingTerm(req.Selectors, req.Signal)
	if term != "" {
		for i, prefix := range prefixes {
			prefixes[i] = termPrefix(prefix, term)
		}
	}
	it := &rowIterator{e: e, scope: scope, req: req, prefixes: prefixes, marks: marks, matchers: ms, ctx: ctx, posting: term, partial: partial}
	e.scans[it] = struct{}{}
	e.storageStats.ActiveIterators++
	it.stop = context.AfterFunc(ctx, func() { e.mu.Lock(); defer e.mu.Unlock(); it.terminal = model.Fail(model.Cancelled); it.closeLocked() })
	return it, nil
}
func (e *Engine) watermarksLocked() []model.Cursor {
	out := make([]model.Cursor, 0, 64)
	for slot, index := range e.indexes {
		out = append(out, model.Cursor{Group: e.group(uint16(slot)), Index: model.Uint64(index)})
	}
	return out
}
func (e *Engine) Stats() StorageStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.storageStats
	out.SegmentFiles = uint64(len(e.catalog.Manifest.Segments))
	out.ManifestRevision = uint64(e.catalog.Manifest.Revision)
	return out
}
func (it *rowIterator) Watermarks() []model.Cursor {
	it.e.mu.Lock()
	defer it.e.mu.Unlock()
	if it.certifyLocked(it.ctx, true) != nil {
		return nil
	}
	return append([]model.Cursor(nil), it.marks...)
}
func (it *rowIterator) closeLocked() {
	if it.closed {
		return
	}
	it.closed = true
	if it.terminal == nil {
		it.terminal = io.ErrClosedPipe
	}
	if it.stop != nil {
		it.stop()
		it.stop = nil
	}
	it.releaseLocked()
	it.last = nil
	it.prefixes = nil
	it.matchers = nil
	it.req.Selectors = nil
	it.req.Projection = nil
	it.req.Fence.Min = nil
	delete(it.e.scans, it)
	it.e.storageStats.ActiveIterators--
}
func (it *rowIterator) releaseLocked() {
	if it.page.Len() > 0 {
		it.e.storageStats.BorrowedPages--
	}
	it.page = Page{}
}
func (it *rowIterator) Close() error {
	it.e.mu.Lock()
	defer it.e.mu.Unlock()
	it.closeLocked()
	return nil
}
func (it *rowIterator) Next(ctx context.Context) (Page, error) {
	e := it.e
	e.mu.Lock()
	defer e.mu.Unlock()
	it.releaseLocked()
	if ctx.Err() != nil || it.ctx.Err() != nil {
		it.terminal = model.Fail(model.Cancelled)
		it.closeLocked()
		return Page{}, it.terminal
	}
	if it.closed {
		return Page{}, it.terminal
	}
	if e.closed || e.failed {
		it.terminal = model.Fail(model.Unavailable)
		it.closeLocked()
		return Page{}, it.terminal
	}
	if err := e.authorizeRead(ctx, it.scope, it.req.Projects, it.req.Signal); err != nil {
		it.terminal = err
		it.closeLocked()
		return Page{}, err
	}
	for it.partition < len(it.prefixes) {
		prefix := it.prefixes[it.partition]
		var selected Page
		var current model.ID
		var decoded Page
		startPartition, startLast := it.partition, append([]byte(nil), it.last...)
		if err := e.authorizeRead(ctx, it.scope, it.req.Projects, it.req.Signal); err != nil {
			it.terminal = err
			it.closeLocked()
			return Page{}, err
		}
		delPreds, err := e.readDeletions(ctx, it.scope.OrgID(), it.req.Projects)
		if err != nil {
			it.terminal = err
			it.closeLocked()
			return Page{}, err
		}
		err = e.db.View(func(tx *bolt.Tx) error {
			e.storageStats.IndexLookups++
			name := "scan_time"
			if it.posting != "" {
				name = "scan_postings"
			}
			bucket := tx.Bucket([]byte(name))
			if bucket == nil || tx.Bucket([]byte("scan_pages")) == nil {
				return model.Fail(model.Corrupt)
			}
			c := bucket.Cursor()
			start := append(append([]byte(nil), prefix...), timeKey(it.req.Start)...)
			var k, v []byte
			if len(it.last) > 0 {
				k, v = c.Seek(it.last)
				if bytes.Equal(k, it.last) {
					k, v = c.Next()
				}
			} else {
				k, v = c.Seek(start)
			}
			for ; samePrefix(k, prefix); k, v = c.Next() {
				if ctx.Err() != nil || it.ctx.Err() != nil {
					return model.Fail(model.Cancelled)
				}
				if len(k) != len(prefix)+50 || !validIndexValue(k, v) {
					return model.Fail(model.Corrupt)
				}
				suffix := k[len(prefix):]
				at := model.UnixNano(binary.BigEndian.Uint64(suffix) ^ 1<<63)
				if at >= it.req.End {
					it.partition++
					it.last = nil
					return nil
				}
				var group model.ID
				copy(group[:], suffix[24:40])
				originIndex := binary.BigEndian.Uint64(suffix[40:48])
				visible := false
				for _, mark := range it.marks {
					if mark.Group == group && originIndex <= uint64(mark.Index) {
						visible = true
						break
					}
				}
				if !visible {
					it.last = append(it.last[:0], k...)
					continue
				}
				var id model.ID
				copy(id[:], v[:16])
				if current != (model.ID{}) && current != id {
					return nil
				}
				it.last = append(it.last[:0], k...)
				if current == (model.ID{}) {
					raw := tx.Bucket([]byte("scan_pages")).Get(id[:])
					if raw == nil {
						return model.Fail(model.Corrupt)
					}
					ref, err := parsePageRef(raw)
					if err != nil {
						return err
					}
					if ref.Org != it.scope.OrgID() || ref.Kind != it.req.Signal || !it.scope.AllowsProject(ref.Project) || ref.Restricted != (it.scope.Permission() == auth.RawRead) || ref.Restricted && !it.scope.AllowsSource(ref.Source) || !allowsSubject(it.scope, ref.Kind, ref.Subject) {
						return model.Fail(model.Forbidden)
					}
					expected := pageNamespace(ref.Org, ref.Project, ref.Kind, ref.Restricted, ref.Source, ref.Subject)
					if it.posting != "" {
						expected = termPrefix(expected, it.posting)
					}
					if !bytes.Equal(expected, prefix) {
						return model.Fail(model.Corrupt)
					}
					resources, payload := scanColumns(it.req)
					if entityPredicateActive(delPreds) && (it.req.Signal == model.Replay || it.req.Signal == model.Profile) {
						payload = true
					}
					if it.scope.Permission() == profilesRead && partitionedSubject(ref.Kind) {
						payload = true
					}
					decoded, err = e.readPageColumns(ref, resources, payload)
					if err != nil {
						return err
					}
					current = id
				}
				row := int(binary.BigEndian.Uint16(v[16:18]))
				if row >= decoded.Len() {
					return model.Fail(model.Corrupt)
				}
				origin := decoded.Origins[row]
				if decoded.Times[row] != at || !bytes.Equal(decoded.IDs[row][:], suffix[8:24]) || origin.Group != group || uint64(origin.Index) != originIndex {
					return model.Fail(model.Corrupt)
				}
				if !coveredRow(delPreds, it.scope.OrgID(), it.req.Signal, decoded, row) && matchesRow(it.matchers, decoded, row, it.req.Signal) {
					appendPageRow(&selected, decoded, row)
				}
			}
			it.partition++
			it.last = nil
			return nil
		})
		if err != nil {
			it.terminal = err
			it.closeLocked()
			return Page{}, err
		}
		if selected.Len() > 0 {
			if err = it.certifyLocked(ctx, false); err != nil {
				it.terminal = err
				it.closeLocked()
				return Page{}, err
			}
			// The page was filtered with predicates fetched before the decode and
			// the release fence. A deletion that began since may cover rows already
			// accumulated, and its entity form may need payload columns this page
			// did not decode, so the page is discarded and rebuilt from the same
			// cursor under the new predicates instead of being patched.
			latest, cerr := e.readDeletions(ctx, it.scope.OrgID(), it.req.Projects)
			if cerr != nil {
				it.terminal = cerr
				it.closeLocked()
				return Page{}, cerr
			}
			if deletionsChanged(delPreds, latest) {
				it.partition, it.last = startPartition, append(it.last[:0], startLast...)
				continue
			}
			projectPage(&selected, it.req.Projection, it.req.Signal)
			selected.Partial = it.partial
			selected.Bytes = decoded.Bytes
			it.page = selected
			e.storageStats.BorrowedPages++
			return it.page, nil
		}
	}
	if err := it.certifyLocked(ctx, false); err != nil {
		it.terminal = err
		it.closeLocked()
		return Page{}, err
	}
	it.terminal = io.EOF
	it.closeLocked()
	return Page{}, io.EOF
}
func matchesRow(ms []compiledMatcher, p Page, i int, kind model.Kind) bool {
	for _, m := range ms {
		match := false
		switch {
		case m.idField:
			value, found := nativeIDField(p, i, m.Name)
			if m.re != nil {
				text := ""
				if found {
					text = value.String()
				}
				match = m.re.MatchString(text)
			} else if m.Literal.String == "" {
				match = !found
			} else {
				match = found && value == m.id
			}
		case m.spanField:
			value, found := nativeSpanField(p, i)
			if m.re != nil {
				text := ""
				if found {
					text = spanText(value)
				}
				match = m.re.MatchString(text)
			} else if m.Literal.String == "" {
				match = !found
			} else {
				match = found && value == m.span
			}
		default:
			var value Literal
			found := false
			if m.Target == MatchField {
				value, found = nativeValueField(p, i, m.Name)
			}
			if !found {
				value, found = rowField(p, i, kind, m.Target, m.Name)
			}
			if m.re != nil {
				match = value.Kind == LiteralString && m.re.MatchString(value.String)
			} else {
				match = equalLiteral(value, m.Literal)
			}
			if !found && m.re == nil {
				match = m.Literal.Kind == LiteralString && m.Literal.String == ""
			}
		}
		if m.Op == MatchNotEqual || m.Op == MatchNotRegexp {
			match = !match
		}
		if !match {
			return false
		}
	}
	return true
}
func rowField(p Page, i int, kind model.Kind, target MatchTarget, name string) (Literal, bool) {
	v := &p.Values[i]
	labels := p.Resources[i].Labels
	if v.Metric != nil {
		labels = v.Metric.Labels
	}
	if v.Log != nil {
		labels = v.Log.StreamLabels
	}
	if v.Condition != nil {
		labels = v.Condition.Labels
	}
	if target == MatchLabel {
		for _, l := range labels {
			if l.Name == name {
				return Literal{Kind: LiteralString, String: l.Value}, true
			}
		}
		return Literal{Kind: LiteralString}, false
	}
	if v.Log != nil {
		if x, ok := v.Log.Fields[name]; ok {
			return scalarLiteral(x), true
		}
		if x, ok := v.Log.Metadata[name]; ok {
			return scalarLiteral(x), true
		}
	}
	return Literal{Kind: LiteralString}, false
}
func projectionColumns(fields []Field, kind model.Kind) (resource, payload, observed bool) {
	if len(fields) == 0 {
		return true, true, true
	}
	payloadField := FieldMetric + Field(signalCode(kind)-1)
	for _, f := range fields {
		if f == FieldResource {
			resource = true
		}
		if f == payloadField {
			payload = true
		}
		if f == FieldObservedTime {
			observed = true
		}
	}
	return
}
func projectPage(p *Page, fields []Field, kind model.Kind) {
	resource, payload, observed := projectionColumns(fields, kind)
	if !resource {
		clear(p.Resources)
	}
	if !payload {
		clear(p.Values)
	}
	if !observed {
		clear(p.ObservedTimes)
	}
}
func scanColumns(req ScanRequest) (resources, payload bool) {
	resources, payload, _ = projectionColumns(req.Projection, req.Signal)
	for _, m := range req.Selectors {
		if m.Target == MatchLabel {
			if req.Signal == model.Metric || req.Signal == model.Log || req.Signal == model.Condition {
				payload = true
			} else {
				resources = true
			}
			continue
		}
		switch m.Name {
		case "id", "source_id":
		case "service_id", "environment_id", "build_id":
			resources = true
		default:
			payload = true
		}
	}
	return
}
func (it *rowIterator) certifyLocked(ctx context.Context, allowEOF bool) error {
	check := func() error {
		if ctx.Err() != nil || it.ctx.Err() != nil {
			return model.Fail(model.Cancelled)
		}
		if it.e.closed || it.e.failed {
			return model.Fail(model.Unavailable)
		}
		if it.closed && !(allowEOF && it.terminal == io.EOF) {
			return it.terminal
		}
		return it.e.authorizeRead(ctx, it.scope, it.req.Projects, it.req.Signal)
	}
	if err := check(); err != nil {
		return err
	}
	if err := it.e.replicaReleaseFenceLocked(ctx, it.marks); err != nil {
		return err
	}
	return check()
}

// deletionsChanged reports whether the active deletion set differs, which is
// when a page built under the old set can no longer be released as is.
func deletionsChanged(before, after []model.DeletePredicate) bool {
	if len(before) != len(after) {
		return true
	}
	for _, b := range before {
		found := false
		for _, a := range after {
			if a.Operation == b.Operation && reflect.DeepEqual(a, b) {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}
