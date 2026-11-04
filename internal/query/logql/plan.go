// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/regexcompat"
	"soundpost/internal/query/value"
	"time"
)

type Plan struct {
	Expression TypedExpr
	Evaluation value.Evaluation
	Profile    profile.Profile
	Pipeline   *PipelinePlan
	Pipelines  []PipelinePlan
}
type PipelinePlan struct {
	Matchers   []Matcher
	Stages     []Stage
	Profile    profile.Profile
	Evaluation value.Evaluation
	Templates  TemplateRuntime
	RegexScope *regexcompat.Scope
	compiled   []compiledStage
	selectors  []compiledMatcher
}
type compiledMatcher struct {
	matcher Matcher
	regex   *regexcompat.Regexp
}
type compiledLine struct {
	filter  LineFilter
	regex   *regexcompat.Regexp
	pattern *linePattern
	ip      *ipSet
}
type compiledStage struct {
	stage     Stage
	lines     []compiledLine
	regex     *regexcompat.Regexp
	pattern   *linePattern
	templates []*Template
	labels    *labelMatchers
}

// labelMatchers are the keep/drop matchers of one stage, compiled with the plan
// and indexed by label name so a stage costs one lookup per label.
type labelMatchers struct {
	byName map[string][]compiledMatcher
}

func defaultTemplateRuntime() TemplateRuntime {
	return TemplateRuntime{Now: time.Now, Location: time.UTC}
}
func newRegexScope(p profile.Profile) (*regexcompat.Scope, error) {
	return regexcompat.NewScope(p, regexcompat.Limits{CacheEntries: 1024, CachePatternBytes: 4 << 20, ProgramUnits: 8 << 20, PatternBytes: 1 << 20, InputBytes: 256 << 20, Work: 1 << 40, Matches: 1 << 20, OutputBytes: 256 << 20})
}
func BuildPlan(e TypedExpr, evaluation value.Evaluation, p profile.Profile) (Plan, error) {
	checked, _, err := Check(e.Expr, p)
	if err != nil {
		return Plan{}, err
	}
	if err = checkCapabilities(e.Expr, p); err != nil {
		return Plan{}, err
	}
	if e.Type != checked.Type {
		return Plan{}, typeError(e.Expr, "typed expression does not match syntax")
	}
	plan := Plan{Expression: checked, Evaluation: evaluation, Profile: p}
	scope, err := newRegexScope(p)
	if err != nil {
		return Plan{}, err
	}
	var walk func(Expr) error
	walk = func(x Expr) error {
		switch n := x.(type) {
		case *LogExpr:
			q := PipelinePlan{Matchers: append([]Matcher(nil), n.Matchers...), Stages: append([]Stage(nil), n.Stages...), Profile: p, Evaluation: evaluation, Templates: defaultTemplateRuntime(), RegexScope: scope}
			if err := q.compile(context.Background()); err != nil {
				return err
			}
			plan.Pipelines = append(plan.Pipelines, q)
		case *RangeExpr:
			return walk(n.Log)
		case *UnaryExpr:
			return walk(n.Expr)
		case *BinaryExpr:
			if err := walk(n.Left); err != nil {
				return err
			}
			return walk(n.Right)
		case *CallExpr:
			for _, a := range n.Args {
				if err := walk(a); err != nil {
					return err
				}
			}
		case *VariantsExpr:
			for _, a := range n.Variants {
				if err := walk(a); err != nil {
					return err
				}
			}
			return walk(n.Range)
		}
		return nil
	}
	if err = walk(e.Expr); err != nil {
		return Plan{}, err
	}
	if e.Type == TypeLogs && len(plan.Pipelines) == 1 {
		plan.Pipeline = &plan.Pipelines[0]
	}
	return plan, nil
}

// WithTemplateRuntime binds wall time/timezone explicitly before execution.
// Existing compiled templates stay unchanged; the regex scope remains this query's.
func (p PipelinePlan) WithTemplateRuntime(runtime TemplateRuntime) (PipelinePlan, error) {
	p.Templates = runtime
	if err := p.compile(context.Background()); err != nil {
		return PipelinePlan{}, err
	}
	return p, nil
}
func (p *PipelinePlan) compile(ctx context.Context) error {
	if p.RegexScope == nil {
		scope, err := newRegexScope(p.Profile)
		if err != nil {
			return err
		}
		p.RegexScope = scope
	}
	p.selectors = nil
	p.compiled = nil
	for _, m := range p.Matchers {
		c := compiledMatcher{matcher: m}
		if m.Op == "=~" || m.Op == "!~" {
			re, err := p.RegexScope.Compile(ctx, m.Value, regexcompat.Label)
			if err != nil {
				return err
			}
			c.regex = re
		}
		p.selectors = append(p.selectors, c)
	}
	for _, s := range p.Stages {
		c := compiledStage{stage: s}
		switch s.Kind {
		case "line_filter":
			for _, f := range s.Lines {
				l := compiledLine{filter: f}
				var err error
				if f.IP {
					l.ip, err = parseIPSet(f.Value)
				} else if f.Op == "|~" || f.Op == "!~" {
					l.regex, err = p.RegexScope.Compile(ctx, f.Value, regexcompat.Search)
				} else if f.Op == "|>" || f.Op == "!>" {
					l.pattern, err = parsePattern(f.Value, false)
				}
				if err != nil {
					return err
				}
				c.lines = append(c.lines, l)
			}
		case "keep", "drop":
			lm := &labelMatchers{byName: make(map[string][]compiledMatcher, len(s.Labels))}
			for _, m := range s.Labels {
				cm := compiledMatcher{matcher: m}
				if m.Op == "=~" || m.Op == "!~" {
					re, err := p.RegexScope.Compile(ctx, m.Value, regexcompat.Label)
					if err != nil {
						return err
					}
					cm.regex = re
				}
				lm.byName[m.Name] = append(lm.byName[m.Name], cm)
			}
			c.labels = lm
		case "regexp":
			re, err := p.RegexScope.Compile(ctx, s.Pattern, regexcompat.Search)
			if err != nil {
				return err
			}
			c.regex = re
		case "pattern":
			pat, err := parsePattern(s.Pattern, true)
			if err != nil {
				return err
			}
			c.pattern = pat
		case "line_format":
			t, err := CompileTemplate(s.Pattern, p.Profile, p.Templates)
			if err != nil {
				return err
			}
			c.templates = append(c.templates, t)
		case "label_format":
			for _, a := range s.Assignments {
				var t *Template
				if !a.Rename {
					var err error
					t, err = compileLabelTemplate(a.Value, p.Profile, p.Templates)
					if err != nil {
						return err
					}
				}
				c.templates = append(c.templates, t)
			}
		}
		p.compiled = append(p.compiled, c)
	}
	return nil
}
