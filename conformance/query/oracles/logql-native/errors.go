//go:build soundpost_logql_oracle

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/grafana/loki/v3/pkg/logqlmodel"
)

// These are independently authored projections of stable exported native error
// identities and narrow diagnostic families at source-proven rejection origins.
// Unknown families remain empty and must fail the comparison, never all-errors
// equivalence. ParseError exposes no syntax/type discriminator or end range.
// Its Error() start line/character-column is converted only with the exact
// supplied UTF-8 source; native query_scanner.Position documents character count.
func projectError(err error, source ...string) *languageError {
	out := &languageError{Message: err.Error()}
	if len(source) == 1 {
		out.Start = nativeErrorStart(source[0], err.Error())
	}
	switch {
	case errors.Is(err, logqlmodel.ErrPipeline):
		out.Semantic = ""
		if m := nativePipelineFamily.FindStringSubmatch(err.Error()); m != nil {
			out.Semantic = "pipeline.error:" + m[1]
		}
		out.Category = "pipeline"
		out.CategoryExposed = true
		return out
	case errors.Is(err, logqlmodel.ErrVariantsDisabled):
		out.Semantic = "function.feature-disabled"
		out.Category = "feature"
		out.CategoryExposed = true
		return out
	case errors.Is(err, logqlmodel.ErrLimit):
		out.Semantic = "limit.exceeded"
		out.Category = "limit"
		out.CategoryExposed = true
		return out
	case errors.Is(err, logqlmodel.ErrUnsupportedSyntaxForInstantQuery):
		out.Semantic = "query.instant-logs"
		out.Category = "query"
		out.CategoryExposed = true
		return out
	}
	text := err.Error()
	if semantic, start := classifyNativeParseMessage(text); semantic != "" {
		out.Semantic = semantic
		if start != nil {
			out.Start = start
		}
		return out
	}
	families := []struct{ contains, semantic string }{
		{"queries require at least one regexp or equality matcher", "selector.empty-compatible"},
		{"approx_topk is not enabled. See -limits.shard_aggregations", "function.feature-disabled"},
		{"error parsing regexp", "regex.invalid"},
		{"at least one named capture", "regexp.capture-required"},
		{"invalid UTF-8 encoding", "syntax.encoding"}, {"invalid character NUL", "syntax.nul"},
		{"unexpected type for left leg of binary operation", "binary.operands-invalid"}, {"unexpected type for right leg of binary operation", "binary.operands-invalid"},
		{"unexpected literal for left leg of logical/set binary operation", "binary.set-invalid"}, {"unexpected literal for right leg of logical/set binary operation", "binary.set-invalid"},
		{"input size too long", "syntax.input-limit"},
		{"grouping not allowed for", "grouping.unsupported"}, {"doesn't allow grouping", "grouping.unsupported"},
		{"invalid aggregation", "range.unwrap-incompatible"},
		{"parameter required for operation", "function.arguments"},
		{"invalid regexp parser", "regexp.capture-invalid"},
		{"invalid pattern parser", "pattern.invalid"},
		{"invalid line template", "template.invalid"}, {"invalid template for label", "template.invalid"},
		{"multiple label name ", "label-format.duplicate"},
		{"__error__ cannot be formatted", "label-format.reserved"},
		{"cannot rename reserved label", "label-format.rename-invalid"},
		{"invalid IP", "ip.pattern-invalid"},
		{"invalid duration", "syntax.duration"},
	}
	for _, family := range families {
		if family.semantic != "" && strings.Contains(text, family.contains) {
			out.Semantic = family.semantic
			return out
		}
	}
	if errors.Is(err, logqlmodel.ErrParse) && nativeUnexpected.MatchString(text) {
		out.Semantic = "syntax.unexpected-token"
	}
	return out
}

var nativeUnexpected = regexp.MustCompile(`syntax error: unexpected|unexpected (IDENTIFIER|STRING|NUMBER|\$end)|unexpected character|: unexpected char `)
var nativePipelineFamily = regexp.MustCompile(`^pipeline error: '([^']*)'`)
var nativePosition = regexp.MustCompile(`^parse error at line ([0-9]+), col ([0-9]+):`)

func nativeErrorStart(source, text string) *int {
	m := nativePosition.FindStringSubmatch(text)
	if m == nil {
		return nil
	}
	line, _ := strconv.Atoi(m[1])
	column, _ := strconv.Atoi(m[2])
	if line < 1 || column < 1 {
		return nil
	}
	offset := 0
	for n := 1; n < line; n++ {
		i := strings.IndexByte(source[offset:], '\n')
		if i < 0 {
			return nil
		}
		offset += i + 1
	}
	runeColumn := 1
	for i := range source[offset:] {
		if runeColumn == column {
			at := offset + i
			return &at
		}
		if source[offset+i] == '\n' {
			return nil
		}
		runeColumn++
	}
	if runeColumn == column {
		at := len(source)
		return &at
	}
	return nil
}

// Go1.24 text/template's actual ExecError reports these distinct failure origins.
// Keep the complete native text separately; this is identity, not prose parity.
func nativeTemplateSemantic(phase string, err error) string {
	if phase == "parse" {
		return "template.parse"
	}
	text := err.Error()
	switch {
	case strings.Contains(text, "wrong number of args for "):
		return "template.arity"
	case strings.Contains(text, "wrong type for value;"), strings.Contains(text, "invalid value; expected "), strings.Contains(text, "; found "), strings.Contains(text, "can't handle "):
		return "template.argument-type"
	case strings.Contains(text, "can't evaluate field "), strings.Contains(text, "nil pointer evaluating "), strings.Contains(text, "is not a method but has arguments"), strings.Contains(text, "has arguments but cannot be invoked as function"), strings.Contains(text, "invalid function signature for ") && strings.Contains(text, ": second return value should be error; is "), nativeReturnCount.MatchString(text):
		return "template.field-method"
	case strings.Contains(text, "error calling "):
		return "template.helper-call"
	case strings.Contains(text, "is undefined"), strings.Contains(text, "is an incomplete or empty template"), strings.Contains(text, "range can't iterate over"), strings.Contains(text, "to iterate over more than one variable"), strings.Contains(text, " iterate over more than one variable"), strings.Contains(text, "nil is not a command"):
		return "template.execution"
	default:
		return ""
	}
}

// Source: actual Go1.24.5 funcs.go goodFunc's exported error family; no method
// name or case ID is enumerated, and no raw diagnostic text equality is used.
var nativeReturnCount = regexp.MustCompile(`function [^ ]+ has [0-9]+ return values; should be 1 or 2`)
