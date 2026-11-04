// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"math"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/regexcompat"
	"soundpost/internal/query/syntax"
)

func Check(e Expr, p profile.Profile) (TypedExpr, []syntax.Diagnostic, error) {
	if p.ID != "logql-loki-3.5.2" || p.Commit != "257d2f62bf8a81b44dea6fe88968d1d28c8e01e7" {
		return TypedExpr{}, nil, regexcompat.ErrProfile
	}
	typ, err := checkExpr(e, p)
	if err == nil && (typ == TypeRange || typ == TypeString) {
		err = typeError(e, "range and string expressions require a function", "type.root-invalid")
	}
	return TypedExpr{Expr: e, Type: typ}, nil, err
}
func typeError(e Expr, msg string, codes ...string) error {
	var span syntax.SourceRange
	if e != nil {
		span = e.Span()
	}
	code := "type.expression-invalid"
	if len(codes) > 0 {
		code = codes[0]
	}
	return languageErrorCode(code, "type", msg, span)
}
func enabled(p profile.Profile, n string) bool {
	for _, g := range p.ActiveFeatureSet.Enabled {
		if g == n {
			return true
		}
	}
	return false
}
func validLabel(n string) bool {
	if len(n) == 0 {
		return false
	}
	for i, c := range []byte(n) {
		if !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func uniqueNames(ns []string) bool {
	seen := map[string]bool{}
	for _, n := range ns {
		if seen[n] {
			return false
		}
		seen[n] = true
	}
	return true
}

// checkCapabilities enforces the profile's feature gates. The pinned reference
// accepts approx_topk and variants syntactically with every capability off, and
// refuses them only when a query is planned for execution, so Check never calls
// this; BuildPlan and Evaluate do.
func checkCapabilities(e Expr, p profile.Profile) error {
	switch n := e.(type) {
	case *UnaryExpr:
		return checkCapabilities(n.Expr, p)
	case *BinaryExpr:
		if err := checkCapabilities(n.Left, p); err != nil {
			return err
		}
		return checkCapabilities(n.Right, p)
	case *CallExpr:
		if n.Name == "approx_topk" && !enabled(p, "approx_topk") && !enabled(p, "shard-approx_topk") {
			return typeError(n, "approx_topk capability is disabled", "function.feature-disabled")
		}
		for _, a := range n.Args {
			if err := checkCapabilities(a, p); err != nil {
				return err
			}
		}
	case *VariantsExpr:
		if !enabled(p, "multi-variant-queries") {
			return typeError(n, "multi-variant queries are disabled", "function.feature-disabled")
		}
		for _, a := range n.Variants {
			if err := checkCapabilities(a, p); err != nil {
				return err
			}
		}
	}
	return nil
}
func checkExpr(e Expr, p profile.Profile) (Type, error) {
	switch n := e.(type) {
	case *LiteralExpr:
		return TypeScalar, nil
	case *StringExpr:
		return TypeString, nil
	case *LogExpr:
		if len(n.Matchers) == 0 {
			return "", typeError(e, "selector requires a nonempty matcher", "selector.empty-compatible")
		}
		nonempty := false
		for _, m := range n.Matchers {
			ok, err := matchStatic(p, m, "")
			if err != nil {
				return "", typeError(e, "invalid selector regular expression", "regex.invalid")
			}
			nonempty = nonempty || !ok
		}
		if !nonempty {
			return "", typeError(e, "selector must exclude empty labels", "selector.empty-compatible")
		}
		for _, s := range n.Stages {
			if err := checkStage(s, p); err != nil {
				return "", err
			}
		}
		return TypeLogs, nil
	case *RangeExpr:
		if n.Interval <= 0 {
			return "", typeError(e, "range must be positive", "range.duration-invalid")
		}
		if _, err := checkExpr(n.Log, p); err != nil {
			return "", err
		}
		return TypeRange, nil
	case *UnaryExpr:
		t, err := checkExpr(n.Expr, p)
		if err != nil {
			return "", err
		}
		if t != TypeScalar && t != TypeVector {
			return "", typeError(e, "unary operator requires samples", "unary.operands-invalid")
		}
		return t, nil
	case *BinaryExpr:
		a, err := checkExpr(n.Left, p)
		if err != nil {
			return "", err
		}
		b, err := checkExpr(n.Right, p)
		if err != nil {
			return "", err
		}
		if a != TypeScalar && a != TypeVector || b != TypeScalar && b != TypeVector {
			return "", typeError(e, "binary operators require scalar or vector operands", "binary.operands-invalid")
		}
		set := n.Op == "and" || n.Op == "or" || n.Op == "unless"
		comparison := n.Op == "==" || n.Op == "!=" || n.Op == ">" || n.Op == "<" || n.Op == ">=" || n.Op == "<="
		if set && (a != TypeVector || b != TypeVector || n.Bool || n.Matching.Cardinality != "") {
			return "", typeError(e, "invalid set-operator operands or modifiers", "binary.set-invalid")
		}
		if n.Bool && !comparison {
			return "", typeError(e, "bool requires comparison", "binary.bool-invalid")
		}
		matchesLabels := n.Matching.Labels != nil
		if n.Matching.Cardinality != "" && (a != TypeVector || b != TypeVector) || matchesLabels && a != TypeVector && b != TypeVector {
			return "", typeError(e, "vector matching requires two vectors", "binary.matching-invalid")
		}
		// The pinned engine accepts repeated labels in an on/ignoring list;
		// only the group_left/group_right include list stays unique.
		if !uniqueNames(n.Matching.Include) {
			return "", typeError(e, "invalid vector matching labels", "binary.matching-labels")
		}
		if n.Matching.On {
			for _, x := range n.Matching.Labels {
				for _, y := range n.Matching.Include {
					if x == y {
						return "", typeError(e, "matching and grouping labels overlap", "binary.matching-overlap")
					}
				}
			}
		}
		if a == TypeVector || b == TypeVector {
			return TypeVector, nil
		}
		return TypeScalar, nil
	case *CallExpr:
		return checkCall(n, p)
	case *VariantsExpr:
		if len(n.Variants) == 0 || n.Range == nil {
			return "", typeError(e, "variants requires expressions and source range", "variants.source-invalid")
		}
		for _, x := range n.Variants {
			t, err := checkExpr(x, p)
			if err != nil {
				return "", err
			}
			if t != TypeVector {
				return "", typeError(e, "variant requires metric expression", "variants.input-invalid")
			}
		}
		if _, err := checkExpr(n.Range, p); err != nil {
			return "", err
		}
		return TypeVector, nil
	default:
		return "", typeError(e, "unknown expression")
	}
}

var aggregateNames = map[string]bool{"sum": true, "avg": true, "min": true, "max": true, "count": true, "stddev": true, "stdvar": true, "topk": true, "bottomk": true, "sort": true, "sort_desc": true, "approx_topk": true}
var rangeNames = map[string]bool{"rate": true, "rate_counter": true, "count_over_time": true, "bytes_rate": true, "bytes_over_time": true, "sum_over_time": true, "avg_over_time": true, "min_over_time": true, "max_over_time": true, "stddev_over_time": true, "stdvar_over_time": true, "quantile_over_time": true, "first_over_time": true, "last_over_time": true, "absent_over_time": true}

func checkCall(n *CallExpr, p profile.Profile) (Type, error) {
	fail := func(code, msg string) (Type, error) { return "", typeError(n, msg, code) }
	if !uniqueNames(n.Grouping) {
		return fail("grouping.labels-invalid", "invalid grouping labels")
	}
	types := make([]Type, len(n.Args))
	for i, x := range n.Args {
		t, err := checkExpr(x, p)
		if err != nil {
			return "", err
		}
		types[i] = t
	}
	if (n.Name == "sort" || n.Name == "sort_desc") && len(n.Grouping) > 0 {
		return fail("grouping.unsupported", "sort operations do not allow grouping")
	}
	if aggregateNames[n.Name] {
		want := 1
		if n.Name == "topk" || n.Name == "bottomk" || n.Name == "approx_topk" {
			want = 2
		}
		// The reference grammar takes any metric expression, a scalar literal
		// included, as the operand; evaluating a scalar operand fails at run time.
		if len(types) != want || types[want-1] != TypeVector && types[want-1] != TypeScalar {
			return fail("function.arguments", "aggregation requires vector argument")
		}
		if want == 2 && types[0] != TypeScalar {
			return fail("function.arguments", "aggregation parameter requires scalar")
		}
		if n.Name == "approx_topk" {
			if n.Grouping != nil {
				return fail("grouping.unsupported", "approx_topk does not allow grouping")
			}
			if lit, ok := n.Args[0].(*LiteralExpr); ok && (lit.Value <= 0 || math.Trunc(lit.Value) != lit.Value) {
				return fail("aggregate.parameter-invalid", "approx_topk requires positive integer")
			}
		}
		return TypeVector, nil
	}
	if rangeNames[n.Name] {
		idx := 0
		if n.Name == "quantile_over_time" {
			idx = 1
		}
		if len(types) != idx+1 || types[idx] != TypeRange || idx == 1 && types[0] != TypeScalar {
			return fail("range.input-invalid", "range function requires a log range")
		}
		rg := n.Args[idx].(*RangeExpr)
		unwrap := false
		for _, s := range rg.Log.Stages {
			unwrap = unwrap || s.Kind == "unwrap"
		}
		logOnly := n.Name == "count_over_time" || n.Name == "bytes_over_time" || n.Name == "bytes_rate"
		either := n.Name == "rate" || n.Name == "absent_over_time"
		if logOnly && unwrap || !logOnly && !either && !unwrap {
			return fail("range.unwrap-incompatible", "range function has incompatible unwrap input")
		}
		groupable := n.Name == "avg_over_time" || n.Name == "min_over_time" || n.Name == "max_over_time" || n.Name == "stddev_over_time" || n.Name == "stdvar_over_time" || n.Name == "quantile_over_time" || n.Name == "first_over_time" || n.Name == "last_over_time"
		if n.Grouping != nil && !groupable {
			return fail("grouping.unsupported", "grouping is not allowed for this range function")
		}
		return TypeVector, nil
	}
	if n.Grouping != nil {
		return fail("grouping.unsupported", "function does not allow grouping")
	}
	switch n.Name {
	case "vector":
		if len(types) != 1 || types[0] != TypeScalar {
			return fail("function.arguments", "vector requires numeric literal")
		}
		if _, ok := n.Args[0].(*LiteralExpr); !ok {
			return fail("function.arguments", "vector requires numeric literal")
		}
		return TypeVector, nil
	case "label_replace":
		if len(types) != 5 || types[0] != TypeVector {
			return fail("function.arguments", "label_replace requires vector and four strings")
		}
		for _, t := range types[1:] {
			if t != TypeString {
				return fail("function.arguments", "label_replace requires strings")
			}
		}
		if !validLabel(n.Args[1].(*StringExpr).Value) {
			return fail("label.name-invalid", "invalid destination label")
		}
		if _, err := regexcompat.CompileLabel(p, n.Args[4].(*StringExpr).Value); err != nil {
			return fail("regex.invalid", "invalid label_replace regex")
		}
		return TypeVector, nil
	}
	return fail("function.unknown", "unknown LogQL function")
}
func checkStage(s Stage, p profile.Profile) error {
	fail := func(code, msg string) error { return languageErrorCode(code, "type", msg, s.Span()) }
	switch s.Kind {
	case "line_filter":
		for _, f := range s.Lines {
			if f.IP {
				if f.Op != "|=" && f.Op != "!=" {
					return fail("ip.operator-invalid", "IP line filter requires equality")
				}
				if _, err := parseIPSet(f.Value); err != nil {
					return fail("ip.pattern-invalid", "invalid IP pattern")
				}
			} else if f.Op == "|~" || f.Op == "!~" {
				if _, err := regexcompat.Compile(p, f.Value); err != nil {
					return fail("regex.invalid", "invalid line regex")
				}
			} else if f.Op == "|>" || f.Op == "!>" {
				if _, err := parsePattern(f.Value, false); err != nil {
					return fail("pattern.invalid", "invalid line pattern")
				}
			}
		}
	case "json":
		for _, x := range s.Extractions {
			if _, err := jsonPath(x.Path); err != nil {
				return fail("syntax.unexpected-token", "invalid JSON extraction path")
			}
		}
	case "logfmt":
		// A logfmt expression names one key: a plain identifier, never a path.
		for _, x := range s.Extractions {
			if !validLabel(x.Path) {
				return fail("syntax.unexpected-token", "invalid logfmt extraction key")
			}
		}
	case "regexp":
		re, err := regexcompat.Compile(p, s.Pattern)
		if err != nil {
			return fail("regex.invalid", "invalid parser regular expression")
		}
		found := false
		for _, n := range re.SubexpNames() {
			if n != "" {
				if !validLabel(n) {
					return fail("regexp.capture-invalid", "invalid regex capture name")
				}
				found = true
			}
		}
		if !found {
			return fail("regexp.capture-required", "regexp parser requires named captures")
		}
	case "pattern":
		if _, err := parsePattern(s.Pattern, true); err != nil {
			return fail("pattern.invalid", "invalid parser pattern")
		}
	case "line_format":
		if _, err := CompileTemplate(s.Pattern, p, defaultTemplateRuntime()); err != nil {
			return fail("template.invalid", "invalid line template")
		}
	case "label_format":
		names := map[string]bool{}
		for _, a := range s.Assignments {
			if a.Name == "" {
				return fail("label-format.destination-invalid", "invalid format destination")
			}
			if a.Name == "__error__" {
				return fail("label-format.reserved", "reserved format destination")
			}
			if names[a.Name] {
				return fail("label-format.duplicate", "duplicate format destination")
			}
			names[a.Name] = true
			if a.Rename {
				if a.Value == "__error__" {
					return fail("label-format.rename-invalid", "invalid rename source")
				}
			} else if _, err := compileLabelTemplate(a.Value, p, defaultTemplateRuntime()); err != nil {
				return fail("template.invalid", "invalid label template")
			}
		}
	case "drop", "keep":
		for _, m := range s.Labels {
			if m.Name == "" {
				return fail("label.name-invalid", "invalid label name")
			}
			if m.Op != "" {
				if _, err := matchStatic(p, m, ""); err != nil {
					return fail("regex.invalid", "invalid label matcher")
				}
			}
		}
	case "label_filter":
		if err := checkPredicate(s.Filter, p); err != nil {
			if diagnostic, ok := err.(*syntax.LanguageError); ok {
				copy := *diagnostic
				copy.Range = s.Span()
				return &copy
			}
			return err
		}
	case "unwrap":
		if s.UnwrapLabel == "" {
			return fail("label.name-invalid", "invalid unwrap label")
		}
		switch s.Conversion {
		case "", "bytes", "duration", "duration_seconds":
		default:
			return fail("unwrap.conversion-invalid", "unknown unwrap conversion")
		}
	case "unpack", "decolorize":
	default:
		return fail("pipeline.stage-unknown", "unknown pipeline stage")
	}
	return nil
}
func checkPredicate(f *LabelPredicate, p profile.Profile) error {
	fail := func(code, msg string) error { return languageErrorCode(code, "type", msg, syntax.SourceRange{}) }
	if f == nil {
		return fail("label-filter.expression-invalid", "missing label predicate")
	}
	if f.Left != nil {
		if err := checkPredicate(f.Left, p); err != nil {
			return err
		}
		return checkPredicate(f.Right, p)
	}
	if f.Name == "" {
		return fail("label.name-invalid", "invalid filter label")
	}
	switch f.Type {
	case "string":
		if f.Op != "=" && f.Op != "==" && f.Op != "!=" && f.Op != "=~" && f.Op != "!~" {
			return fail("label-filter.operator-invalid", "string filter requires equality or regex")
		}
		if f.Op == "=~" || f.Op == "!~" {
			if _, err := regexcompat.CompileLabel(p, f.Text); err != nil {
				return fail("regex.invalid", "invalid filter regex")
			}
		}
	case "ip":
		if f.Op != "=" && f.Op != "!=" {
			return fail("ip.operator-invalid", "IP filter requires equality")
		}
		if _, err := parseIPSet(f.Text); err != nil {
			return fail("ip.pattern-invalid", "invalid IP filter")
		}
	default:
		if f.Op == "=~" || f.Op == "!~" {
			return fail("label-filter.operator-invalid", "typed filter does not allow regex")
		}
	}
	return nil
}
