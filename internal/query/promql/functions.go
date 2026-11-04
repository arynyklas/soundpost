// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"math"
	"sort"
	"soundpost/internal/model"
	"soundpost/internal/query/regexcompat"
	"soundpost/internal/query/scan"
	"soundpost/internal/query/syntax"
	"soundpost/internal/query/value"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func functionFloat(s value.Sample) float64 { return math.Float64frombits(uint64(s.Float)) }
func functionSample(x float64, at model.UnixNano) value.Sample {
	return value.Sample{Time: at, Float: model.FloatBits(math.Float64bits(x))}
}
func functionScalar(x float64, at model.UnixNano) value.Result {
	return value.Result{Type: "scalar", Scalar: functionSample(x, at)}
}
func functionSeries(series value.Series, point value.Sample, drop bool) value.Series {
	series.Samples = []value.Sample{point}
	if drop {
		series.DropName = true
	}
	return series
}
func functionUnary(name string) (func(float64) float64, bool) {
	switch name {
	case "abs":
		return math.Abs, true
	case "acos":
		return math.Acos, true
	case "acosh":
		return math.Acosh, true
	case "asin":
		return math.Asin, true
	case "asinh":
		return math.Asinh, true
	case "atan":
		return math.Atan, true
	case "atanh":
		return math.Atanh, true
	case "ceil":
		return math.Ceil, true
	case "cos":
		return math.Cos, true
	case "cosh":
		return math.Cosh, true
	case "deg":
		return func(x float64) float64 { return x * 180 / math.Pi }, true
	case "exp":
		return math.Exp, true
	case "floor":
		return math.Floor, true
	case "ln":
		return math.Log, true
	case "log10":
		return math.Log10, true
	case "log2":
		return math.Log2, true
	case "rad":
		return func(x float64) float64 { return x * math.Pi / 180 }, true
	case "sgn":
		return func(x float64) float64 {
			if x < 0 {
				return -1
			}
			if x > 0 {
				return 1
			}
			return x
		}, true
	case "sin":
		return math.Sin, true
	case "sinh":
		return math.Sinh, true
	case "sqrt":
		return math.Sqrt, true
	case "tan":
		return math.Tan, true
	case "tanh":
		return math.Tanh, true
	}
	return nil, false
}
func functionDate(name string, x float64) float64 {
	date := time.Unix(int64(x), 0).UTC()
	switch name {
	case "day_of_month":
		return float64(date.Day())
	case "day_of_week":
		return float64(date.Weekday())
	case "day_of_year":
		return float64(date.YearDay())
	case "days_in_month":
		return float64(time.Date(date.Year(), date.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day())
	case "hour":
		return float64(date.Hour())
	case "minute":
		return float64(date.Minute())
	case "month":
		return float64(date.Month())
	case "year":
		return float64(date.Year())
	}
	return math.NaN()
}
func functionIsDate(n string) bool {
	switch n {
	case "day_of_month", "day_of_week", "day_of_year", "days_in_month", "hour", "minute", "month", "year":
		return true
	}
	return false
}
func functionLabelValid(name string, profiles ...string) bool {
	if name == "" || !utf8.ValidString(name) {
		return false
	}
	if len(profiles) == 0 || profiles[0] == "promql-prometheus-3.13.5" {
		return true
	}
	for index, r := range name {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || index > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
func EvalFunction(ctx context.Context, call CallPlan, args []value.Result, f Frame) (result value.Result, diagnostics []syntax.Diagnostic, err error) {
	defer func() {
		value.InheritMetadata(&result, args...)
		if err == nil && !enabled(f.Profile, "promql-delayed-name-removal") {
			err = finalizeNames(&result, f.Profile)
		}
	}()
	if err = validateProfile(f.Profile); err != nil {
		return value.Result{}, nil, err
	}
	out := value.Result{Type: "vector"}
	if e := functionCheck(ctx, f); e != nil {
		return out, nil, e
	}
	if call.Name == "" {
		if n, ok := call.Expr.Expr.(*Node); ok {
			call.Name = n.Text
		}
	}
	if e := functionValidate(call, args, f.Profile); e != nil {
		return out, nil, e
	}
	name := call.Name
	release, err := functionScratch(args, f.Account)
	if err != nil {
		return out, nil, err
	}
	defer release()
	switch name {
	case "time":
		return functionScalar(float64(f.Time)/1e9, f.Time), nil, nil
	case "pi":
		return functionScalar(math.Pi, f.Time), nil, nil
	case "start":
		at := f.Evaluation.Start
		if f.Evaluation.Instant {
			at = f.Evaluation.Time
		}
		return functionScalar(float64(at)/1e9, f.Time), nil, nil
	case "end":
		at := f.Evaluation.End
		if f.Evaluation.Instant {
			at = f.Evaluation.Time
		}
		return functionScalar(float64(at)/1e9, f.Time), nil, nil
	case "step":
		return functionScalar(float64(f.Evaluation.Step)/1e9, f.Time), nil, nil
	case "range":
		return functionScalar(float64(f.Evaluation.End-f.Evaluation.Start)/1e9, f.Time), nil, nil
	case "min_of":
		return functionScalar(math.Min(functionFloat(args[0].Scalar), functionFloat(args[1].Scalar)), f.Time), nil, nil
	case "max_of":
		return functionScalar(math.Max(functionFloat(args[0].Scalar), functionFloat(args[1].Scalar)), f.Time), nil, nil
	case "scalar":
		x := math.NaN()
		if f.Profile.ID == "promql-prometheus-3.1.0" {
			if len(args[0].Vector) == 1 && len(args[0].Vector[0].Samples) > 0 {
				point := args[0].Vector[0].Samples[0]
				x = functionFloat(point)
				if point.Histogram != nil {
					x = 0
				}
			}
			return functionScalar(x, f.Time), nil, nil
		}
		count := 0
		for _, series := range args[0].Vector {
			if len(series.Samples) == 0 {
				continue
			}
			point := series.Samples[len(series.Samples)-1]
			if point.Histogram == nil {
				count++
				x = functionFloat(point)
			}
		}
		if count != 1 {
			x = math.NaN()
		}
		return functionScalar(x, f.Time), nil, nil
	case "vector":
		out.Vector = []value.Series{{Project: f.Project, Samples: []value.Sample{functionSample(functionFloat(args[0].Scalar), f.Time)}}}
		return out, nil, nil
	case "absent", "absent_over_time":
		present := false
		if name == "absent" {
			present = len(args[0].Vector) > 0
		} else {
			for _, s := range args[0].Matrix {
				if len(s.Samples) > 0 {
					present = true
					break
				}
			}
		}
		if !present {
			out.Vector = []value.Series{{Project: f.Project, Labels: functionAbsentLabels(call.Expr), Samples: []value.Sample{functionSample(1, f.Time)}}}
		}
		return out, nil, nil
	case "label_join", "label_replace":
		return functionLabels(ctx, call, args, f)
	case "sort", "sort_desc", "sort_by_label", "sort_by_label_desc":
		return functionSort(call, args, f)
	case "info":
		return functionInfo(ctx, call, args, f)
	}
	if strings.HasPrefix(name, "histogram_") {
		return functionHistogram(ctx, call, args, f)
	}
	matrixIndex := -1
	for i, a := range args {
		if a.Type == "matrix" {
			matrixIndex = i
			break
		}
	}
	if matrixIndex >= 0 {
		return functionRange(ctx, call, args, matrixIndex, f)
	}
	var input []value.Series
	if len(args) > 0 {
		input = args[0].Vector
	} else if functionIsDate(name) {
		input = []value.Series{{Project: f.Project, Samples: []value.Sample{functionSample(float64(f.Time)/1e9, f.Time)}}}
	}
	unary, unaryOK := functionUnary(name)
	for _, s := range input {
		if e := functionCheck(ctx, f); e != nil {
			return out, nil, e
		}
		if len(s.Samples) == 0 {
			continue
		}
		p := s.Samples[len(s.Samples)-1]
		if name == "timestamp" {
			out.Vector = append(out.Vector, functionSeries(s, functionSample(float64(p.Time)/1e9, f.Time), true))
			continue
		}
		if p.Histogram != nil {
			continue
		}
		x := functionFloat(p)
		switch {
		case unaryOK:
			x = unary(x)
		case functionIsDate(name):
			x = functionDate(name, x)
		default:
			switch name {
			case "clamp":
				low, high := functionFloat(args[1].Scalar), functionFloat(args[2].Scalar)
				if low > high {
					continue
				}
				x = math.Max(low, math.Min(high, x))
			case "clamp_min":
				x = math.Max(x, functionFloat(args[1].Scalar))
			case "clamp_max":
				x = math.Min(x, functionFloat(args[1].Scalar))
			case "round":
				nearest := 1.0
				if len(args) > 1 {
					nearest = functionFloat(args[1].Scalar)
				}
				inverse := 1 / nearest
				x = math.Floor(x*inverse+.5) / inverse
			default:
				return out, nil, functionError(call.Expr, "function.internal-unbound", "unbound function implementation")
			}
		}
		out.Vector = append(out.Vector, functionSeries(s, functionSample(x, f.Time), true))
	}
	return out, nil, nil
}
func functionAbsentLabels(expression TypedExpr) model.Labels {
	if expression.Expr == nil {
		return nil
	}
	call, ok := expression.Expr.(*Node)
	if !ok || len(call.Children) == 0 {
		return nil
	}
	argument, ok := call.Children[0].(*Node)
	if !ok {
		return nil
	}
	for (argument.Kind == "range" || argument.Kind == "paren") && len(argument.Children) == 1 {
		argument, _ = argument.Children[0].(*Node)
		if argument == nil {
			return nil
		}
	}
	if argument.Kind != "selector" {
		return nil
	}
	labels := model.Labels{}
	seenEquality := map[string]bool{}
	for _, matcher := range argument.Matchers {
		if matcher.Name == "__name__" {
			continue
		}
		if matcher.Op == "=" && !seenEquality[matcher.Name] {
			labels = value.SetLabel(labels, matcher.Name, matcher.Value)
			seenEquality[matcher.Name] = true
		} else {
			labels = value.SetLabel(labels, matcher.Name, "")
		}
	}
	return labels
}
func functionLabels(ctx context.Context, call CallPlan, args []value.Result, f Frame) (value.Result, []syntax.Diagnostic, error) {
	out := value.Result{Type: "vector"}
	destination := args[1].String
	if !functionLabelValid(destination, f.Profile.ID) {
		return out, nil, functionError(call.Expr, "function.invalid-label", "invalid destination label name")
	}
	scope := f.RegexScope
	var compiled *regexcompat.Regexp
	var err error
	if call.Name == "label_replace" {
		if scope == nil {
			scope, err = scan.NewMatcherScope(f.Profile)
			if err != nil {
				return out, nil, err
			}
		}
		compiled, err = scope.Compile(ctx, "^(?s:"+args[4].String+")$", regexcompat.Search)
		if err != nil {
			if _, syntaxError := regexcompat.PatternErrorCode(err); syntaxError {
				return out, nil, functionError(call.Expr, "function.invalid-regex", "invalid label replacement regex")
			}
			return out, nil, err
		}
	}
	for _, series := range args[0].Vector {
		if err = functionCheck(ctx, f); err != nil {
			return out, nil, err
		}
		series = value.CloneSeries(series)
		if call.Name == "label_join" {
			parts := make([]string, 0, len(args)-3)
			for _, argument := range args[3:] {
				if !functionLabelValid(argument.String, f.Profile.ID) {
					return out, nil, functionError(call.Expr, "function.invalid-label", "invalid source label name")
				}
				parts = append(parts, value.Label(series.Labels, argument.String))
			}
			series.Labels = value.SetLabel(series.Labels, destination, strings.Join(parts, args[2].String))
		} else {
			source := value.Label(series.Labels, args[3].String)
			matched, err := scope.MatchString(ctx, compiled, source)
			if err != nil {
				return out, nil, err
			}
			if matched {
				replacement, err := scope.ReplaceAllString(ctx, compiled, source, args[2].String)
				if err != nil {
					return out, nil, err
				}
				series.Labels = value.SetLabel(series.Labels, destination, replacement)
			}
		}
		if destination == "__name__" {
			series.DropName = false
		}
		out.Vector = append(out.Vector, series)
	}
	return out, nil, nil
}

// Natural comparison treats a maximal digit run as an integer without parsing
// into a bounded machine number. Equal numeric runs fall through to spelling.
func functionNatural(a, b string) int {
	originalA, originalB := a, b
	for len(a) > 0 && len(b) > 0 {
		if a[0] >= '0' && a[0] <= '9' && b[0] >= '0' && b[0] <= '9' {
			i, j := 0, 0
			for i < len(a) && a[i] >= '0' && a[i] <= '9' {
				i++
			}
			for j < len(b) && b[j] >= '0' && b[j] <= '9' {
				j++
			}
			x, y := strings.TrimLeft(a[:i], "0"), strings.TrimLeft(b[:j], "0")
			if len(x) < len(y) {
				return -1
			}
			if len(x) > len(y) {
				return 1
			}
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
			a, b = a[i:], b[j:]
			continue
		}
		if a[0] < b[0] {
			return -1
		}
		if a[0] > b[0] {
			return 1
		}
		a, b = a[1:], b[1:]
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return strings.Compare(originalA, originalB)
}
func functionSort(call CallPlan, args []value.Result, frame Frame) (value.Result, []syntax.Diagnostic, error) {
	result := value.Result{Type: "vector"}
	byLabel := strings.HasPrefix(call.Name, "sort_by_label")
	descending := strings.HasSuffix(call.Name, "desc")
	for _, series := range args[0].Vector {
		if len(series.Samples) > 0 && (byLabel || series.Samples[0].Histogram == nil || frame.Profile.ID == "promql-prometheus-3.1.0") {
			result.Vector = append(result.Vector, series)
		}
	}
	sort.SliceStable(result.Vector, func(i, j int) bool {
		left, right := result.Vector[i], result.Vector[j]
		comparison := 0
		if byLabel {
			for _, argument := range args[1:] {
				comparison = functionNatural(value.Label(left.Labels, argument.String), value.Label(right.Labels, argument.String))
				if comparison != 0 {
					break
				}
			}
			if comparison == 0 {
				comparison = value.CompareLabels(left.Labels, right.Labels)
			}
		} else {
			a, b := functionFloat(left.Samples[0]), functionFloat(right.Samples[0])
			if math.IsNaN(a) && math.IsNaN(b) {
				comparison = 0
			} else if math.IsNaN(a) {
				comparison = -1
			} else if math.IsNaN(b) {
				comparison = 1
			} else if a < b {
				comparison = -1
			} else if a > b {
				comparison = 1
			}
		}
		if descending {
			return comparison > 0
		}
		return comparison < 0
	})
	var diagnostics []syntax.Diagnostic
	if !frame.Evaluation.Instant && frame.Profile.ID == "promql-prometheus-3.13.5" {
		diagnostics = append(diagnostics, functionDiagnostic(call.Expr, "SortInRangeQueryWarning"))
	}
	return result, diagnostics, nil
}
func functionInfo(ctx context.Context, call CallPlan, args []value.Result, f Frame) (value.Result, []syntax.Diagnostic, error) {
	out := value.Result{Type: "vector"}
	if len(args) < 2 {
		return args[0], nil, nil
	}
	identity := func(series value.Series) string {
		return string(series.Project[:]) + value.LabelKey(model.Labels{{Name: "instance", Value: value.Label(series.Labels, "instance")}, {Name: "job", Value: value.Label(series.Labels, "job")}})
	}
	byIdentity := map[string][]value.Series{}
	for _, series := range args[1].Vector {
		if len(series.Samples) == 0 || series.Samples[0].Histogram != nil {
			continue
		}
		key := identity(series)
		byIdentity[key] = append(byIdentity[key], series)
	}
	emptyMatches, err := functionInfoEmptyMatches(ctx, call, f)
	if err != nil {
		return out, nil, err
	}
	for _, base := range args[0].Vector {
		if err = functionCheck(ctx, f); err != nil {
			return out, nil, err
		}
		candidates := byIdentity[identity(base)]
		selected := map[string]value.Series{}
		for _, series := range candidates {
			name := value.Label(series.Labels, "__name__")
			old, exists := selected[name]
			if exists && series.Samples[0].Time == old.Samples[0].Time {
				return out, nil, functionError(call.Expr, "function.info-series-conflict", "conflicting info series at the same timestamp")
			}
			if !exists || series.Samples[0].Time > old.Samples[0].Time {
				selected[name] = series
			}
		}
		names := make([]string, 0, len(selected))
		for name := range selected {
			names = append(names, name)
		}
		sort.Strings(names)
		copied := map[string]string{}
		labels := value.CloneLabels(base.Labels)
		for _, name := range names {
			for _, label := range selected[name].Labels {
				if label.Name == "__name__" || label.Name == "job" || label.Name == "instance" {
					continue
				}
				if old, exists := copied[label.Name]; exists && old != label.Value {
					return out, nil, functionError(call.Expr, "function.info-label-conflict", "conflicting info data labels")
				}
				copied[label.Name] = label.Value
				if value.Label(base.Labels, label.Name) == "" {
					labels = value.SetLabel(labels, label.Name, label.Value)
				}
			}
		}
		keep := len(selected) > 0
		if f.Profile.ID == "promql-prometheus-3.1.0" {
			keep = len(copied) > 0
		}
		if !keep {
			keep = emptyMatches
		}
		if keep {
			base.Labels = labels
			out.Vector = append(out.Vector, base)
		}
	}
	return out, nil, nil
}
func functionInfoEmptyMatches(ctx context.Context, call CallPlan, f Frame) (bool, error) {
	node, ok := call.Expr.Expr.(*Node)
	if !ok || len(node.Children) < 2 {
		return true, nil
	}
	selector, ok := node.Children[1].(*Node)
	if !ok {
		return true, nil
	}
	scope := f.RegexScope
	for _, matcher := range selector.Matchers {
		if matcher.Name == "__name__" {
			continue
		}
		switch matcher.Op {
		case "=":
			if matcher.Value != "" {
				return false, nil
			}
		case "!=":
			if matcher.Value == "" {
				return false, nil
			}
		case "=~", "!~":
			var err error
			if scope == nil {
				scope, err = scan.NewMatcherScope(f.Profile)
				if err != nil {
					return false, err
				}
			}
			compiled, err := scope.Compile(ctx, matcher.Value, regexcompat.Label)
			if err != nil {
				return false, err
			}
			matched, err := scope.MatchString(ctx, compiled, "")
			if err != nil {
				return false, err
			}
			if matcher.Op == "=~" && !matched || matcher.Op == "!~" && matched {
				return false, nil
			}
		}
	}
	return true, nil
}
func functionValueString(point value.Sample) string {
	if point.Histogram == nil {
		return strconv.FormatFloat(functionFloat(point), 'f', -1, 64)
	}
	histogram := histogramView(*point.Histogram)
	var output strings.Builder
	number := func(x float64) { output.WriteString(strconv.FormatFloat(x, 'g', -1, 64)) }
	output.WriteString("{count:")
	number(math.Float64frombits(uint64(histogram.Count)))
	output.WriteString(", sum:")
	number(math.Float64frombits(uint64(histogram.Sum)))
	for _, bucket := range histogramObservationBuckets(*point.Histogram) {
		if bucket.count == 0 {
			continue
		}
		output.WriteString(", ")
		lowerInclusive, upperInclusive := false, true
		if histogram.Schema != -53 {
			if bucket.upper < 0 {
				lowerInclusive, upperInclusive = true, false
			} else if !bucket.exponential {
				lowerInclusive, upperInclusive = true, true
				threshold := math.Float64frombits(uint64(histogram.ZeroThreshold))
				bucket.lower, bucket.upper = -threshold, threshold
			}
		}
		if lowerInclusive {
			output.WriteByte('[')
		} else {
			output.WriteByte('(')
		}
		number(bucket.lower)
		output.WriteByte(',')
		number(bucket.upper)
		if upperInclusive {
			output.WriteByte(']')
		} else {
			output.WriteByte(')')
		}
		output.WriteByte(':')
		number(bucket.count)
	}
	output.WriteByte('}')
	return output.String()
}
