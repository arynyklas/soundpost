// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/logql"
	"github.com/arynyklas/soundpost/internal/query/promql"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
	"math"
	"reflect"
	"strings"
	"unicode/utf8"
)

type valueCounts struct{ series, samples, logs uint64 }

func labelsOrEmpty(ls model.Labels) model.Labels {
	if ls == nil {
		return model.Labels{}
	}
	return ls
}

// wireSample keeps exact float bits (an ordinary NaN stays a NaN with its own
// bits) or the native histogram tree; it never converts one to the other.
func wireSample(s value.Sample) Sample {
	out := Sample{Time: s.Time, StartTimestamp: s.StartTimestamp}
	if s.Histogram != nil {
		out.Histogram = s.Histogram
	} else {
		f := s.Float
		out.Float = &f
	}
	return out
}

// wireValue converts an engine result into the typed C06 union. A stale marker
// is the semantic absence of a sample, so it is dropped here and a series left
// with no sample is not a result series.
func wireValue(res value.Result) (Value, valueCounts, error) {
	var counts valueCounts
	switch res.Type {
	case "scalar":
		counts.samples = 1
		return Value{Type: ValueScalar, Scalar: wireSample(res.Scalar)}, counts, nil
	case "string":
		return Value{Type: ValueString, String: res.String}, counts, nil
	case "vector":
		out := make([]VectorElement, 0, len(res.Vector))
		for _, s := range res.Vector {
			if len(s.Samples) != 1 {
				return Value{}, counts, model.Fail(model.Corrupt)
			}
			if s.Samples[0].Stale() {
				continue
			}
			out = append(out, VectorElement{Labels: labelsOrEmpty(s.Labels), Sample: wireSample(s.Samples[0])})
			counts.series++
			counts.samples++
		}
		return Value{Type: ValueVector, Vector: out}, counts, nil
	case "matrix":
		out := make([]Series, 0, len(res.Matrix))
		for _, s := range res.Matrix {
			samples := make([]Sample, 0, len(s.Samples))
			for _, p := range s.Samples {
				if !p.Stale() {
					samples = append(samples, wireSample(p))
				}
			}
			if len(samples) == 0 {
				continue
			}
			out = append(out, Series{Labels: labelsOrEmpty(s.Labels), Samples: samples})
			counts.series++
			counts.samples += uint64(len(samples))
		}
		return Value{Type: ValueMatrix, Matrix: out}, counts, nil
	case "streams":
		out := make([]LogStream, 0)
		index := map[string]int{}
		for i, l := range res.Logs {
			key := value.LabelKey(l.Labels)
			k, ok := index[key]
			if !ok {
				k = len(out)
				index[key] = k
				out = append(out, LogStream{Labels: labelsOrEmpty(l.Labels), Entries: []LogEntry{}})
				counts.series++
			}
			var source *model.ID
			if l.Source != (model.ID{}) {
				id := l.Source
				source = &id
			}
			out[k].Entries = append(out[k].Entries, LogEntry{Index: model.Uint64(i), Time: l.Timestamp, ID: l.ID, Source: source, Multiplicity: l.Multiplicity, Line: l.Line, StreamLabels: labelsOrEmpty(l.StreamLabels), StructuredMetadata: labelsOrEmpty(l.StructuredMetadata)})
			counts.logs += uint64(l.Multiplicity)
		}
		return Value{Type: ValueStreams, Streams: out}, counts, nil
	}
	return Value{}, counts, model.Fail(model.Corrupt)
}

// trimLogs keeps exactly the first limit entries (by multiplicity, splitting the
// last run) of an ordered log result and reports whether anything was cut.
func trimLogs(res *value.Result, limit uint64) bool {
	var kept uint64
	for i := range res.Logs {
		n := uint64(res.Logs[i].Multiplicity)
		if kept+n <= limit {
			kept += n
			continue
		}
		if left := limit - kept; left > 0 {
			res.Logs[i].Multiplicity = model.Uint64(left)
			res.Logs = res.Logs[:i+1]
		} else {
			res.Logs = res.Logs[:i]
		}
		return true
	}
	return false
}

// normalizeDiagnostics applies the documented rules and no others: engine order
// is the language-defined order and is kept; an exact repeat (same category,
// range and message) is dropped after its first occurrence; severity is "info"
// for categories ending in "Info" and "warning" otherwise; and after max
// distinct diagnostics one "diagnostics.truncated" warning ends the list.
func normalizeDiagnostics(in []syntax.Diagnostic, max int) []Diagnostic {
	out := make([]Diagnostic, 0, len(in))
	seen := make(map[syntax.Diagnostic]bool, len(in))
	for _, d := range in {
		if seen[d] {
			continue
		}
		seen[d] = true
		if len(out) == max {
			out = append(out, Diagnostic{Severity: "warning", Code: "diagnostics.truncated", SafeMessage: "further diagnostics were omitted"})
			break
		}
		severity := "warning"
		if strings.HasSuffix(d.Category, "Info") {
			severity = "info"
		}
		out = append(out, Diagnostic{Severity: severity, Code: d.Category, SourceRange: wireRange(d.Range), SafeMessage: d.SafeMessage})
	}
	return out
}

// Format returns the expression's canonical text for its language and pinned
// profile. A PromQL expression is printed from its typed tree. A LogQL
// expression keeps its token and string text exactly and only normalizes the
// whitespace between tokens. In both languages the result is parsed again under
// the same profile and must give the same typed tree; text that would change
// the tree is never returned.
func (e *Engine) Format(ctx context.Context, scope auth.Scope, req FormatRequest) (FormatResult, error) {
	res, err := e.format(ctx, scope, req)
	if err != nil {
		return FormatResult{}, normalizeError(err, false)
	}
	return res, nil
}

func (e *Engine) format(ctx context.Context, scope auth.Scope, req FormatRequest) (FormatResult, error) {
	if !validLanguage(req.Language) || req.Profile == "" || len(req.Profile) > 128 || req.FeatureSet == "" || len(req.FeatureSet) > 128 || !profileMatchesLanguage(req.Language, req.Profile) {
		return FormatResult{}, model.Fail(model.Invalid)
	}
	if len(req.Expression) == 0 || len(req.Expression) > e.limits.MaxExpressionBytes || !utf8.ValidString(req.Expression) {
		return FormatResult{}, model.Fail(model.Invalid)
	}
	if p := scope.Permission(); p != auth.Read && p != auth.RawRead {
		return FormatResult{}, model.Fail(model.Forbidden)
	}
	if err := ctx.Err(); err != nil {
		return FormatResult{}, ctxFault(err)
	}
	if err := e.policy.Revalidate(ctx, scope); err != nil {
		return FormatResult{}, err
	}
	prof, err := e.resolveProfile(req.Language, req.Profile, req.FeatureSet)
	if err != nil {
		return FormatResult{}, err
	}
	// Authorization is complete; the work below parses the expression twice and
	// compares both trees, so it is admitted like a query: one scheduler slot, a
	// deadline of its own and a charge for the two trees before either is built.
	l, err := e.admit(ctx, scope, e.limits.DefaultTimeout, e.limits.DefaultMemory)
	if err != nil {
		return FormatResult{}, err
	}
	defer l.close()
	if err = l.charge(2 * planCharge(req.Expression)); err != nil {
		return FormatResult{}, err
	}
	if req.Language == LanguagePromQL {
		expr, err := promql.Parse(req.Expression, prof)
		if err != nil {
			return FormatResult{}, normalizeError(err, true)
		}
		typed, ds, err := promql.Check(expr, prof)
		if err != nil {
			return FormatResult{}, normalizeError(err, true)
		}
		if err = l.stopped(); err != nil {
			return FormatResult{}, err
		}
		text := promql.Format(expr)
		again, err := promql.Parse(text, prof)
		if err != nil {
			return FormatResult{}, model.Fail(model.Unsupported)
		}
		retyped, _, err := promql.Check(again, prof)
		if err != nil || retyped.Type != typed.Type || promql.Format(again) != text {
			return FormatResult{}, model.Fail(model.Unsupported)
		}
		if err = l.stopped(); err != nil {
			return FormatResult{}, err
		}
		return FormatResult{Formatted: text, Diagnostics: normalizeDiagnostics(ds, e.limits.MaxDiagnostics)}, nil
	}
	expr, err := logql.Parse(req.Expression, prof)
	if err != nil {
		return FormatResult{}, normalizeError(err, true)
	}
	typed, ds, err := logql.Check(expr, prof)
	if err != nil {
		return FormatResult{}, normalizeError(err, true)
	}
	if err = l.stopped(); err != nil {
		return FormatResult{}, err
	}
	text, ok := collapseSpace(req.Expression)
	if !ok {
		return FormatResult{}, model.Fail(model.Unsupported)
	}
	again, err := logql.Parse(text, prof)
	if err != nil {
		return FormatResult{}, model.Fail(model.Unsupported)
	}
	retyped, _, err := logql.Check(again, prof)
	if err != nil || retyped.Type != typed.Type || !sameTree(reflect.ValueOf(expr), reflect.ValueOf(again)) {
		return FormatResult{}, model.Fail(model.Unsupported)
	}
	if err = l.stopped(); err != nil {
		return FormatResult{}, err
	}
	return FormatResult{Formatted: text, Diagnostics: normalizeDiagnostics(ds, e.limits.MaxDiagnostics)}, nil
}

// collapseSpace trims the source and turns every whitespace run outside a quoted
// string into one space. Quoted ("..." with backslash escapes, `...` raw) text is
// copied byte for byte. A comment marker outside a string cannot be normalized
// without deciding where the comment ends, so the source is refused.
func collapseSpace(src string) (string, bool) {
	var b strings.Builder
	b.Grow(len(src))
	pendingSpace := false
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '"' || c == '`':
			if pendingSpace && b.Len() > 0 {
				b.WriteByte(' ')
			}
			pendingSpace = false
			j := i + 1
			for ; j < len(src); j++ {
				if c == '"' && src[j] == '\\' {
					j++
					continue
				}
				if src[j] == c {
					break
				}
			}
			if j >= len(src) {
				return "", false
			}
			b.WriteString(src[i : j+1])
			i = j + 1
		case c == '#':
			return "", false
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			pendingSpace = true
			i++
		default:
			if pendingSpace && b.Len() > 0 {
				b.WriteByte(' ')
			}
			pendingSpace = false
			r, size := utf8.DecodeRuneInString(src[i:])
			_ = r
			b.WriteString(src[i : i+size])
			i += size
		}
	}
	return b.String(), true
}

var sourceRangeType = reflect.TypeOf(syntax.SourceRange{})

// sameTree is structural equality of two syntax trees that ignores source
// ranges (which necessarily differ between two spellings) and compares floats
// by their exact bits.
func sameTree(a, b reflect.Value) bool {
	if !a.IsValid() || !b.IsValid() {
		return a.IsValid() == b.IsValid()
	}
	if a.Type() != b.Type() {
		return false
	}
	if a.Type() == sourceRangeType {
		return true
	}
	switch a.Kind() {
	case reflect.Pointer, reflect.Interface:
		if a.IsNil() || b.IsNil() {
			return a.IsNil() == b.IsNil()
		}
		return sameTree(a.Elem(), b.Elem())
	case reflect.Struct:
		for i := range a.NumField() {
			if !sameTree(a.Field(i), b.Field(i)) {
				return false
			}
		}
		return true
	case reflect.Slice, reflect.Array:
		if a.Len() != b.Len() {
			return false
		}
		for i := range a.Len() {
			if !sameTree(a.Index(i), b.Index(i)) {
				return false
			}
		}
		return true
	case reflect.Map:
		if a.Len() != b.Len() {
			return false
		}
		for _, k := range a.MapKeys() {
			other := b.MapIndex(k)
			if !other.IsValid() || !sameTree(a.MapIndex(k), other) {
				return false
			}
		}
		return true
	case reflect.String:
		return a.String() == b.String()
	case reflect.Bool:
		return a.Bool() == b.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return a.Int() == b.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return a.Uint() == b.Uint()
	case reflect.Float32, reflect.Float64:
		return math.Float64bits(a.Float()) == math.Float64bits(b.Float())
	}
	return false
}
