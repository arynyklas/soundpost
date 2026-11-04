// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"sort"
	"soundpost/internal/model"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/regexcompat"
	"soundpost/internal/query/value"
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
func combinedLabels(e LogEntry) model.Labels {
	out := value.CloneLabels(e.StreamLabels)
	for _, ls := range []model.Labels{e.StructuredMetadata, e.ParsedLabels} {
		for _, l := range ls {
			out = setLabel(out, l.Name, l.Value)
		}
	}
	if e.languageError != "" {
		out = setLabel(out, "__error__", e.languageError)
	}
	if e.languageErrorDetails != "" {
		out = setLabel(out, "__error_details__", e.languageErrorDetails)
	}
	return out
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
func (e *LogEntry) extract(n, v string) {
	base := e.baseStream
	if base == nil {
		base = e.StreamLabels
	}
	if labelPresent(base, n) {
		n += "_extracted"
	}
	e.ParsedLabels = setLabel(e.ParsedLabels, n, v)
}
func sanitizeLabel(s string) string {
	var b strings.Builder
	for i, c := range []byte(s) {
		if c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9' {
			b.WriteByte(c)
		} else {
			if i == 0 && c >= '0' && c <= '9' {
				b.WriteByte('_')
				b.WriteByte(c)
			} else {
				b.WriteByte('_')
			}
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
func mutateLabels(ctx context.Context, e *LogEntry, s Stage, scope *regexcompat.Scope) error {
	labels := combinedLabels(*e)
	for _, l := range labels {
		selected := false
		for _, m := range s.Labels {
			if m.Name != l.Name {
				continue
			}
			if m.Op == "" {
				selected = true
				break
			}
			ok, err := matchScoped(ctx, scope, m, l.Value)
			if err != nil {
				return err
			}
			selected = selected || ok
		}
		if s.Kind == "drop" && selected || s.Kind == "keep" && !selected && l.Name != "__error__" && l.Name != "__error_details__" {
			e.delete(l.Name)
		}
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
