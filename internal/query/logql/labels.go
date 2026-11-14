// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/regexcompat"
	"github.com/arynyklas/soundpost/internal/query/value"
	"slices"
	"sort"
	"strings"
)

func labelValue(ls model.Labels, n string) string {
	for _, l := range ls {
		if l.Name == n {
			return l.Value
		}
	}
	return ""
}
func labelPresent(ls model.Labels, n string) bool {
	for _, l := range ls {
		if l.Name == n {
			return true
		}
	}
	return false
}
func entryLabel(e *LogEntry, n string) (string, bool) {
	for _, ls := range []model.Labels{e.ParsedLabels, e.StructuredMetadata, e.StreamLabels} {
		for _, l := range ls {
			if l.Name == n {
				return l.Value, true
			}
		}
	}
	return "", false
}
func cloneLogEntry(e LogEntry) LogEntry {
	e.Line = strings.Clone(e.Line)
	e.languageError = strings.Clone(e.languageError)
	e.languageErrorDetails = strings.Clone(e.languageErrorDetails)
	e.StreamLabels = value.CloneLabels(e.StreamLabels)
	e.StructuredMetadata = value.CloneLabels(e.StructuredMetadata)
	e.ParsedLabels = value.CloneLabels(e.ParsedLabels)
	e.Fields = append([]TypedField(nil), e.Fields...)
	return e
}
func entryBytes(e LogEntry) int64 {
	n := int64(192 + len(e.Line) + len(e.languageError) + len(e.languageErrorDetails) + len(e.Fields)*48)
	for _, ls := range []model.Labels{e.StreamLabels, e.StructuredMetadata, e.ParsedLabels} {
		for _, l := range ls {
			n += int64(32 + len(l.Name) + len(l.Value))
		}
	}
	return n
}

// combinedLabels is the effective label set: the category order is stream,
// structured metadata, parsed, then the language error labels, a later category
// replacing the value of an earlier one. The result is sorted by name. It is
// built with one stable sort and one dedupe pass, not one insertion per label.
func combinedLabels(e LogEntry) model.Labels {
	if len(e.StructuredMetadata) == 0 && len(e.ParsedLabels) == 0 && e.languageError == "" && e.languageErrorDetails == "" {
		return value.CloneLabels(e.StreamLabels)
	}
	out := make(model.Labels, 0, len(e.StreamLabels)+len(e.StructuredMetadata)+len(e.ParsedLabels)+2)
	out = append(out, e.StreamLabels...)
	out = append(out, e.StructuredMetadata...)
	out = append(out, e.ParsedLabels...)
	if e.languageError != "" {
		out = append(out, model.Label{Name: "__error__", Value: e.languageError})
	}
	if e.languageErrorDetails != "" {
		out = append(out, model.Label{Name: "__error_details__", Value: e.languageErrorDetails})
	}
	slices.SortStableFunc(out, func(a, b model.Label) int { return strings.Compare(a.Name, b.Name) })
	kept := out[:0]
	for _, l := range out {
		if n := len(kept); n > 0 && kept[n-1].Name == l.Name {
			kept[n-1] = l
			continue
		}
		kept = append(kept, l)
	}
	return kept
}
func (e *LogEntry) deleteOrdinary(n string) {
	e.StreamLabels = removeLabel(e.StreamLabels, n)
	e.StructuredMetadata = removeLabel(e.StructuredMetadata, n)
	e.ParsedLabels = removeLabel(e.ParsedLabels, n)
}
func (e *LogEntry) delete(n string) {
	e.deleteOrdinary(n)
	if n == "__error__" {
		e.languageError = ""
	}
	if n == "__error_details__" {
		e.languageErrorDetails = ""
	}
}
func removeLabel(ls model.Labels, n string) model.Labels {
	for i, l := range ls {
		if l.Name == n {
			copy(ls[i:], ls[i+1:])
			ls[len(ls)-1] = model.Label{}
			return ls[:len(ls)-1]
		}
	}
	return ls
}
func setLabel(ls model.Labels, n, v string) model.Labels {
	at := len(ls)
	for i, l := range ls {
		if l.Name == n {
			ls[i].Value = v
			return ls
		}
		if l.Name > n {
			at = i
			break
		}
	}
	ls = append(ls, model.Label{})
	copy(ls[at+1:], ls[at:len(ls)-1])
	ls[at] = model.Label{Name: n, Value: v}
	return ls
}
func (e *LogEntry) setError(kind, details string) {
	e.languageError = kind
	e.languageErrorDetails = details
}
func (e *LogEntry) set(n, v string) {
	e.deleteOrdinary(n)
	e.ParsedLabels = setLabel(e.ParsedLabels, n, v)
}

// sanitizeLabel maps every rune outside [A-Za-z0-9_] to '_' (one underscore
// per rune, not per byte) and prefixes a leading digit with '_'.
func sanitizeLabel(s string) string {
	var b strings.Builder
	for i, c := range s {
		switch {
		case c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9':
			b.WriteByte(byte(c))
		case i == 0 && c >= '0' && c <= '9':
			b.WriteByte('_')
			b.WriteByte(byte(c))
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
func matchStatic(p profile.Profile, m Matcher, v string) (bool, error) {
	switch m.Op {
	case "", "=", "==":
		return v == m.Value, nil
	case "!=":
		return v != m.Value, nil
	case "=~", "!~":
		r, err := regexcompat.CompileLabel(p, m.Value)
		if err != nil {
			return false, err
		}
		ok := r.MatchString(v)
		if m.Op == "!~" {
			ok = !ok
		}
		return ok, nil
	}
	return false, model.Fail(model.Invalid)
}
func matchScoped(ctx context.Context, scope *regexcompat.Scope, m Matcher, v string) (bool, error) {
	if m.Op != "=~" && m.Op != "!~" {
		return matchStatic(profile.Profile{}, m, v)
	}
	re, err := scope.Compile(ctx, m.Value, regexcompat.Label)
	if err != nil {
		return false, err
	}
	ok, err := scope.MatchString(ctx, re, v)
	if m.Op == "!~" {
		ok = !ok
	}
	return ok, err
}

// mutateLabels runs `keep` and `drop`: every effective label is tested against
// the stage matchers of its name once, the names to remove are collected, and
// the three categories are filtered in one pass each.
func mutateLabels(ctx context.Context, e *LogEntry, s Stage, scope *regexcompat.Scope, plan *labelMatchers, check func() error) error {
	labels := combinedLabels(*e)
	var del map[string]struct{}
	for i, l := range labels {
		if i&255 == 0 {
			if err := check(); err != nil {
				return err
			}
		}
		selected := false
		for _, m := range plan.byName[l.Name] {
			if m.matcher.Op == "" {
				selected = true
				break
			}
			var ok bool
			if m.regex != nil {
				var err error
				ok, err = scope.MatchString(ctx, m.regex, l.Value)
				if err != nil {
					return err
				}
				if m.matcher.Op == "!~" {
					ok = !ok
				}
			} else {
				var err error
				if ok, err = matchStatic(profile.Profile{}, m.matcher, l.Value); err != nil {
					return err
				}
			}
			selected = selected || ok
		}
		if s.Kind == "drop" && selected || s.Kind == "keep" && !selected && l.Name != "__error__" && l.Name != "__error_details__" {
			if del == nil {
				del = make(map[string]struct{})
			}
			del[l.Name] = struct{}{}
		}
	}
	if len(del) == 0 {
		return nil
	}
	drop := func(ls model.Labels) model.Labels {
		kept := ls[:0]
		for _, l := range ls {
			if _, gone := del[l.Name]; !gone {
				kept = append(kept, l)
			}
		}
		clear(ls[len(kept):])
		return kept
	}
	e.StreamLabels = drop(e.StreamLabels)
	e.StructuredMetadata = drop(e.StructuredMetadata)
	e.ParsedLabels = drop(e.ParsedLabels)
	// Dropping the error label handles the failure: its details go with it.
	if _, gone := del["__error__"]; gone {
		e.languageError = ""
		e.languageErrorDetails = ""
	}
	if _, gone := del["__error_details__"]; gone {
		e.languageErrorDetails = ""
	}
	return nil
}
func sortedFields(fields map[string]model.Scalar) []TypedField {
	out := make([]TypedField, 0, len(fields))
	for n, v := range fields {
		out = append(out, TypedField{Name: n, Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
