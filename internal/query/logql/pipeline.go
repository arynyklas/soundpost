// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"soundpost/internal/model"
	"soundpost/internal/query/scan"
	"soundpost/internal/query/value"
)

// RunPipeline retains language errors as labels, but never converts a policy,
// cancellation, missing-input, budget or iterator failure into filtered success.
// Returned retained data is owned; the caller releases PipelineResult.Bytes.
func RunPipeline(ctx context.Context, plan PipelinePlan, record LogEntry, account value.Account) (result PipelineResult, err error) {
	if ctx == nil || account == nil {
		return result, model.Fail(model.Invalid)
	}
	if err = account.Check(ctx); err != nil {
		return result, err
	}
	if len(plan.compiled) != len(plan.Stages) || plan.RegexScope == nil {
		if err = plan.compile(ctx); err != nil {
			return result, err
		}
	}
	for _, m := range plan.selectors {
		v := labelValue(record.StreamLabels, m.matcher.Name)
		var ok bool
		if m.regex != nil {
			ok, err = plan.RegexScope.MatchString(ctx, m.regex, v)
			if m.matcher.Op == "!~" {
				ok = !ok
			}
		} else {
			ok, err = matchStatic(plan.Profile, m.matcher, v)
		}
		if err != nil {
			return result, err
		}
		if !ok {
			return result, nil
		}
	}
	held := int64(0)
	reserve := func(n int64) error {
		if n < 0 || n > math.MaxInt64-held {
			return model.Fail(model.Quota)
		}
		if e := account.Reserve(n); e != nil {
			return e
		}
		held += n
		return nil
	}
	defer func() {
		if err != nil || !result.Retained {
			account.Release(held)
		}
	}()
	fieldBytes := int64(0)
	for _, f := range record.Fields {
		raw, e := f.Value.MarshalJSON()
		if e != nil {
			return result, model.Fail(model.Corrupt)
		}
		fieldBytes += int64(len(raw) + len(f.Name))
	}
	originalBytes := int64(0)
	for _, labels := range []model.Labels{record.StreamLabels, record.StructuredMetadata} {
		for _, label := range labels {
			originalBytes += int64(32 + len(label.Name) + len(label.Value))
		}
	}
	if err = reserve(entryBytes(record)*2 + fieldBytes + originalBytes + 128); err != nil {
		return result, err
	}
	record = cloneLogEntry(record)
	originalStream := value.CloneLabels(record.StreamLabels)
	originalMetadata := value.CloneLabels(record.StructuredMetadata)
	record.baseStream = originalStream
	var unwrapped *float64
	check := func() error { return account.Check(ctx) }
	for _, c := range plan.compiled {
		if err = account.Check(ctx); err != nil {
			return result, err
		}
		s := c.stage
		// Reserve a conservative parser/builder scratch bound before allocating. It
		// includes decoded keys, values, category slices and intermediate JSON nodes.
		scratch := int64(len(record.StreamLabels)+len(record.StructuredMetadata)+len(record.ParsedLabels))*192 + 512
		switch s.Kind {
		case "json", "unpack", "logfmt":
			scratch += int64(len(record.Line)) * 48
		case "pattern":
			scratch += int64(len(record.Line))*4 + int64(len(c.pattern.parts))*128
		case "decolorize":
			scratch += int64(len(record.Line)) * 4
		case "regexp":
			scratch += int64(c.regex.NumSubexp()+1) * 128
		}
		if s.Kind == "label_filter" {
			scratch += filterDetailBytes(s.Filter, &record)
		} else if s.Kind == "unwrap" {
			text, _ := entryLabel(&record, s.UnwrapLabel)
			scratch += int64(len(text))*4 + 512
		}
		if err = reserve(scratch); err != nil {
			return result, err
		}
		switch s.Kind {
		case "line_filter":
			negative := len(c.lines) > 0 && (c.lines[0].filter.Op == "!=" || c.lines[0].filter.Op == "!~" || c.lines[0].filter.Op == "!>")
			pass := negative
			for _, f := range c.lines {
				ok, e := lineMatches(ctx, f, record.Line, plan.RegexScope)
				if e != nil {
					return result, e
				}
				if negative {
					pass = pass && ok
					if !pass {
						break
					}
				} else {
					pass = pass || ok
					if pass {
						break
					}
				}
			}
			if !pass {
				return result, nil
			}
		case "label_filter":
			ok, e := evalPredicate(ctx, s.Filter, &record, plan.RegexScope)
			if e != nil {
				return result, e
			}
			if !ok {
				return result, nil
			}
		case "json":
			if e := parseJSONStage(s, &record, check); e != nil {
				return result, e
			}
		case "logfmt":
			if e := parseLogfmtStage(s, &record, check); e != nil {
				return result, e
			}
		case "regexp":
			if e := parseRegexpStage(ctx, c, &record, plan.RegexScope); e != nil {
				return result, e
			}
		case "pattern":
			parsePatternStage(c, &record)
		case "unpack":
			if e := parseUnpackStage(&record, check); e != nil {
				return result, e
			}
		case "decolorize":
			record.Line = decolorize(record.Line)
		case "drop", "keep":
			if e := mutateLabels(ctx, &record, s, plan.RegexScope); e != nil {
				return result, e
			}
		case "unwrap":
			var keep bool
			unwrapped, keep = unwrapValue(s, &record)
			if !keep {
				return result, nil
			}
		case "line_format":
			line, e := c.templates[0].Execute(ctx, TemplateInput{Line: record.Line, Timestamp: record.Timestamp, Labels: combinedLabels(record), Fields: record.Fields}, account)
			if e != nil {
				detail, language := templateFailureDetail(e)
				if !language {
					return result, e
				}
				if e = reserve(int64(len(detail))*2 + 128); e != nil {
					return result, e
				}
				record.setError("TemplateFormatErr", detail)
			} else {
				if e = reserve(int64(len(line)) * 2); e != nil {
					return result, e
				}
				record.Line = line
			}
		case "label_format":
			// All template assignments in one stage share the input label snapshot;
			// renames mutate the builder and are not visible to sibling templates.
			snapshot := combinedLabels(record)
			for i, a := range s.Assignments {
				if a.Rename {
					if v, ok := entryLabel(&record, a.Value); ok {
						record.delete(a.Value)
						record.set(a.Name, v)
					}
					continue
				}
				text, e := c.templates[i].Execute(ctx, TemplateInput{Line: record.Line, Timestamp: record.Timestamp, Labels: snapshot, Fields: record.Fields}, account)
				if e != nil {
					detail, language := templateFailureDetail(e)
					if !language {
						return result, e
					}
					if e = reserve(int64(len(detail))*2 + 128); e != nil {
						return result, e
					}
					record.setError("TemplateFormatErr", detail)
					continue
				}
				if e = reserve(int64(len(text))*2 + int64(len(a.Name)) + 64); e != nil {
					return result, e
				}
				record.set(a.Name, text)
			}
		default:
			return result, model.Fail(model.Invalid)
		}
		// Scratch and replaced category slices are dead at this stage boundary.
		account.Release(scratch)
		held -= scratch
		need := entryBytes(record)*2 + fieldBytes + originalBytes + 128
		if need > held {
			if err = reserve(need - held); err != nil {
				return result, err
			}
		}
	}
	if err = account.Check(ctx); err != nil {
		return result, err
	}
	record.baseStream = nil
	result = PipelineResult{Entry: record, Labels: combinedLabels(record), OriginalStreamLabels: originalStream, OriginalStructuredMetadata: originalMetadata, Retained: true, Unwrapped: unwrapped, Bytes: held}
	return result, nil
}

// LanguageDetail is authorized result data only; Error() remains the safe fault.
// A resource wrapper is fatal even if its cause happens to be a language error.
func templateFailureDetail(err error) (string, bool) {
	var limit *TemplateLimitError
	if errors.As(err, &limit) {
		return "", false
	}
	var language *TemplateError
	if !errors.As(err, &language) {
		return "", false
	}
	return language.LanguageDetail(), true
}

// RunLogRow is the C05-to-language projection. It never looks up a template:
// Line is exactly the safe rendering persisted at admission. Fields stay typed
// and metadata becomes a separate lookup category, not stream selector labels.
func RunLogRow(ctx context.Context, plan PipelinePlan, row scan.LogRow, account value.Account) (PipelineResult, error) {
	if ctx == nil || account == nil || row.ID == (model.ID{}) || row.Multiplicity == 0 {
		return PipelineResult{}, model.Fail(model.Invalid)
	}
	if err := account.Check(ctx); err != nil {
		return PipelineResult{}, err
	}
	held := int64(len(row.Record.Fields)+len(row.Record.Metadata)) * 128
	for name := range row.Record.Fields {
		held += int64(len(name))
	}
	for name := range row.Record.Metadata {
		held += int64(len(name))
	}
	if err := account.Reserve(held); err != nil {
		return PipelineResult{}, err
	}
	defer func() { account.Release(held) }()
	record := LogEntry{Timestamp: row.Timestamp, ID: row.ID, Source: row.Source, Multiplicity: row.Multiplicity, Line: row.Record.Line, StreamLabels: row.Record.StreamLabels, Fields: sortedFields(row.Record.Fields)}
	record.StructuredMetadata = make(model.Labels, 0, len(row.Record.Metadata))
	for name, v := range row.Record.Metadata {
		if err := account.Check(ctx); err != nil {
			return PipelineResult{}, err
		}
		raw, err := v.MarshalJSON()
		if err != nil {
			return PipelineResult{}, model.Fail(model.Corrupt)
		}
		cost := int64(len(raw)) * 4
		if err = account.Reserve(cost); err != nil {
			return PipelineResult{}, err
		}
		held += cost
		text := string(raw)
		if len(raw) > 0 && raw[0] == '"' {
			if json.Unmarshal(raw, &text) != nil {
				return PipelineResult{}, model.Fail(model.Corrupt)
			}
		}
		record.StructuredMetadata = append(record.StructuredMetadata, model.Label{Name: name, Value: text})
	}
	sort.Slice(record.StructuredMetadata, func(i, j int) bool { return record.StructuredMetadata[i].Name < record.StructuredMetadata[j].Name })
	return RunPipeline(ctx, plan, record, account)
}
