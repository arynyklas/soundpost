// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"fmt"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/regexcompat"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
	"math"
	"sort"
	"strings"
)

// Frame is a value snapshot of the outer evaluation, not an ambient clock.
type Frame struct {
	Profile                 profile.Profile
	Evaluation              value.Evaluation
	Time                    model.UnixNano
	Project                 model.ID
	Account                 value.Account
	RegexScope              *regexcompat.Scope
	WindowStart, WindowEnd  model.UnixNano
	WindowRange, WindowStep int64
	HasWindow               bool
}
type CallPlan struct {
	Name string
	Expr TypedExpr
}
type AggregationPlan struct {
	Name      string
	Expr      TypedExpr
	Parameter value.Result
}
type FunctionEvaluator func(context.Context, TypedExpr, []value.Result, Frame) (value.Result, []syntax.Diagnostic, error)
type FunctionSpec struct {
	ObligationID, Name, Signature, Gate string
	Eval                                FunctionEvaluator
}

func aggregationNames() []string {
	return []string{"avg", "bottomk", "count", "count_values", "group", "limit_ratio", "limitk", "max", "min", "quantile", "stddev", "stdvar", "sum", "topk"}
}
func FunctionCatalog(p profile.Profile) []FunctionSpec {
	if validateProfile(p) != nil {
		return nil
	}
	// A catalog owns its gate slice; a caller cannot mutate captured profile gates.
	p.ActiveFeatureSet.Enabled = append([]string(nil), p.ActiveFeatureSet.Enabled...)
	out := make([]FunctionSpec, 0, len(signatures[p.ID])+14)
	for name, s := range signatures[p.ID] {
		name := name
		args := make([]string, len(s.args))
		for i, a := range s.args {
			args[i] = string(a)
		}
		out = append(out, FunctionSpec{ObligationID: p.ID + "/function/" + name, Name: name, Signature: fmt.Sprintf("%s(%s)->%s; variadic=%d", name, strings.Join(args, ","), s.result, s.variadic), Gate: s.gate, Eval: func(ctx context.Context, e TypedExpr, args []value.Result, f Frame) (value.Result, []syntax.Diagnostic, error) {
			f.Profile = p
			return EvalFunction(ctx, CallPlan{Name: name, Expr: e}, args, f)
		}})
	}
	if _, ok := signatures[p.ID]; !ok {
		return out
	}
	for _, name := range aggregationNames() {
		name := name
		gate := ""
		if name == "limitk" || name == "limit_ratio" {
			gate = "promql-experimental-functions"
		}
		out = append(out, FunctionSpec{ObligationID: p.ID + "/aggregation/" + name, Name: name, Signature: name + "([parameter,] instant-vector) [by|without(labels)]", Gate: gate, Eval: func(ctx context.Context, e TypedExpr, args []value.Result, f Frame) (value.Result, []syntax.Diagnostic, error) {
			f.Profile = p
			a := AggregationPlan{Name: name, Expr: e}
			if len(args) == 0 {
				return value.Result{}, nil, functionError(e, "aggregation.arity", "aggregation input missing")
			}
			if len(args) > 1 {
				a.Parameter = args[0]
			}
			return EvalAggregation(ctx, a, args[len(args)-1], f)
		}})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ObligationID < out[j].ObligationID })
	return out
}
func functionEvaluators(p profile.Profile) (map[string]FunctionEvaluator, map[string]FunctionEvaluator) {
	functions, aggregations := map[string]FunctionEvaluator{}, map[string]FunctionEvaluator{}
	for _, s := range FunctionCatalog(p) {
		if strings.Contains(s.ObligationID, "/aggregation/") {
			aggregations[s.Name] = s.Eval
		} else {
			functions[s.Name] = s.Eval
		}
	}
	return functions, aggregations
}
func functionError(e TypedExpr, code, msg string) error {
	var r syntax.SourceRange
	if e.Expr != nil {
		r = e.Expr.SourceRange()
	}
	// Everything functionError reports is raised while the plan executes; the
	// pinned engines classify these failures as execution errors.
	return &syntax.LanguageError{Category: "execution", Code: code, Range: r, SafeMessage: msg}
}
func functionDiagnostic(e TypedExpr, id string) syntax.Diagnostic {
	return functionDiagnosticArg(e, id, -1)
}

// functionDiagnosticArg anchors an annotation at one argument of a call. A
// negative arg selects the argument the pinned engines attach id to.
func functionDiagnosticArg(e TypedExpr, id string, arg int) syntax.Diagnostic {
	var r syntax.SourceRange
	if e.Expr != nil {
		r = e.Expr.SourceRange()
		if n, ok := e.Expr.(*Node); ok && len(n.Children) > 0 && id != "SortInRangeQueryWarning" {
			if arg < 0 {
				arg = 0
				if n.Kind == "call" {
					arg = histogramAnnotationArg(n.Text, id)
				}
			}
			if n.Kind == "call" || n.Kind == "aggregate" && (id == "InvalidQuantileWarning" || id == "InvalidRatioWarning") {
				if arg < len(n.Children) {
					r = n.Children[arg].SourceRange()
				}
			}
		}
	}
	return syntax.Diagnostic{Category: id, Range: r, SafeMessage: functionAnnotationText(id)}
}

// histogramAnnotationArg is the argument each histogram function attaches an
// annotation to: histogram_quantile reports on the quantile except for input
// problems of the vector; the NaN information of histogram_fraction names its
// lower bound; histogram_quantiles names its vector for input problems and its
// label for forced monotonicity.
func histogramAnnotationArg(name, id string) int {
	switch name {
	case "histogram_quantile":
		if id == "InvalidQuantileWarning" || strings.HasPrefix(id, "NativeHistogramQuantile") {
			return 0
		}
		return 1
	case "histogram_fraction":
		if id == "NativeHistogramFractionNaNsInfo" {
			return 0
		}
		return 2
	case "histogram_quantiles":
		if id == "HistogramQuantileForcedMonotonicityInfo" {
			return 1
		}
	}
	return 0
}
func functionCheck(ctx context.Context, f Frame) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.Account != nil {
		return f.Account.Check(ctx)
	}
	return nil
}
func functionValidate(call CallPlan, args []value.Result, p profile.Profile) error {
	s, ok := signatures[p.ID][call.Name]
	if !ok {
		return functionError(call.Expr, "function.unknown", "unknown function for pinned profile")
	}
	gate := s.gate
	if n, ok := call.Expr.Expr.(*Node); ok && n.Kind == "duration_call" {
		gate = "promql-duration-expr"
	}
	if !enabled(p, gate) {
		return functionError(call.Expr, "function.feature-disabled", "function feature is disabled")
	}
	min, max := len(s.args), len(s.args)
	if s.variadic != 0 {
		min--
		if s.variadic < 0 {
			max = -1
		} else {
			max = min + s.variadic
		}
	}
	if len(args) < min || max >= 0 && len(args) > max {
		return functionError(call.Expr, "function.arity", "invalid function argument count")
	}
	for i, a := range args {
		j := i
		if j >= len(s.args) {
			j = len(s.args) - 1
		}
		if j < 0 || a.Type != string(s.args[j]) {
			return functionError(call.Expr, "function.argument-type", "invalid function argument type")
		}
	}
	return nil
}
func functionScratch(args []value.Result, account value.Account) (func(), error) {
	if account == nil {
		return func() {}, nil
	}
	n := int64(256)
	for _, arg := range args {
		size := value.ResultBytes(arg)
		if size < 0 || size > (math.MaxInt64-n)/4 {
			return nil, model.Fail(model.Quota)
		}
		n += size * 4
	}
	if err := account.Reserve(n); err != nil {
		return nil, err
	}
	return func() { account.Release(n) }, nil
}
