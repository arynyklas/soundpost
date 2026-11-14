// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
	"strconv"
)

type Plan struct {
	Expr                   TypedExpr
	Evaluation             value.Evaluation
	Profile                profile.Profile
	Lookback, SubqueryStep int64
	// MaxSamples is query.max-samples in sample units (see SampleUnits); it applies
	// to plans made by BuildPlan.
	MaxSamples              int64
	Stats                   *QueryStatistics
	budgeted, perStepStats  bool
	Functions, Aggregations map[string]FunctionEvaluator
}

func BuildPlan(expr TypedExpr, evaluation value.Evaluation, p profile.Profile) (Plan, error) {
	out := Plan{Evaluation: evaluation}
	if err := validateProfile(p); err != nil {
		return out, err
	}
	if expr.Expr == nil || expr.ProfileID != p.ID || expr.ProfileIdentity != p.Identity || expr.FeatureSetID != p.ActiveFeatureSet.ID {
		return out, &syntax.LanguageError{Code: "plan.profile-mismatch", Category: "plan", SafeMessage: "typed expression profile does not match execution profile"}
	}
	if _, err := gridCount(evaluation); err != nil {
		return out, err
	}
	if !evaluation.Instant && expr.Type != Scalar && expr.Type != Vector {
		return out, &syntax.LanguageError{Code: "evaluation.range-type", Category: "type", Range: expr.Expr.SourceRange(), SafeMessage: "range evaluation requires scalar or instant vector"}
	}
	out.Expr = cloneTyped(expr)
	out.Profile = cloneProfile(p)
	out.Lookback = 300000000000
	out.SubqueryStep = 60000000000
	for name, dst := range map[string]*int64{"lookback_delta_ns": &out.Lookback, "default_subquery_step_ns": &out.SubqueryStep} {
		if raw, ok := p.Configuration[name]; ok {
			var text string
			if err := json.Unmarshal(raw, &text); err != nil {
				return out, timeError()
			}
			n, err := strconv.ParseInt(text, 10, 64)
			if err != nil || n < 0 || name == "default_subquery_step_ns" && n == 0 {
				return out, timeError()
			}
			if name != "lookback_delta_ns" || n != 0 { // engine lookback 0 falls back to the 5m default
				*dst = n
			}
		}
	}
	if err := validateEngineOptions(out.Expr.Expr, p, evaluation); err != nil {
		return out, err
	}
	out.MaxSamples, out.budgeted = engineMaxSamples(p), true
	out.Functions, out.Aggregations = functionEvaluators(out.Profile)
	return out, nil
}
func cloneProfile(p profile.Profile) profile.Profile {
	p.ActiveFeatureSet.Enabled = append([]string(nil), p.ActiveFeatureSet.Enabled...)
	p.Configuration = cloneConfiguration(p.Configuration)
	p.Obligations = append([]string(nil), p.Obligations...)
	p.FeatureSets = nil
	return p
}
func cloneConfiguration(in map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(in))
	for k, v := range in {
		out[k] = append(json.RawMessage(nil), v...)
	}
	return out
}
func cloneTyped(t TypedExpr) TypedExpr {
	t.Expr = cloneExpr(t.Expr)
	out := make([]TypedExpr, len(t.Children))
	for i, c := range t.Children {
		out[i] = cloneTyped(c)
	}
	t.Children = out
	return t
}
func cloneExpr(e Expr) Expr {
	if e == nil {
		return nil
	}
	n := *e.(*Node)
	n.Children = make([]Expr, len(e.(*Node).Children))
	for i, c := range e.(*Node).Children {
		n.Children[i] = cloneExpr(c)
	}
	n.Labels = append([]string(nil), n.Labels...)
	n.Matchers = append([]Matcher(nil), n.Matchers...)
	if n.Matching != nil {
		m := *n.Matching
		m.Labels = append([]string(nil), m.Labels...)
		m.Include = append([]string(nil), m.Include...)
		n.Matching = &m
	}
	n.RangeExpr = cloneExpr(n.RangeExpr)
	n.StepExpr = cloneExpr(n.StepExpr)
	n.OffsetExpr = cloneExpr(n.OffsetExpr)
	if n.FillLeft != nil {
		v := *n.FillLeft
		n.FillLeft = &v
	}
	if n.FillRight != nil {
		v := *n.FillRight
		n.FillRight = &v
	}
	return &n
}
