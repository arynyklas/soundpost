// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"math"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/syntax"
	"strconv"
	"strings"
	"time"
)

type parser struct {
	tokens     []token
	pos, depth int
	p          profile.Profile
}

func Parse(source string, p profile.Profile) (Expr, error) {
	if p.ID != "logql-loki-3.5.2" || p.Commit != "257d2f62bf8a81b44dea6fe88968d1d28c8e01e7" {
		return nil, languageError("profile", "unsupported LogQL profile", syntax.SourceRange{})
	}
	if len(source) >= 131072 {
		return nil, languageErrorCode("syntax.input-limit", "syntax", "query input exceeds profile limit", syntax.SourceRange{})
	}
	ts, err := lex(source, p)
	if err != nil {
		return nil, err
	}
	r := parser{tokens: ts, p: p}
	e, err := r.expression(0)
	if err != nil {
		return nil, err
	}
	if r.peek().kind != "eof" {
		return nil, r.fail("unexpected trailing input")
	}
	return e, nil
}
func (r *parser) peek() token { return r.tokens[r.pos] }
func (r *parser) take() token {
	t := r.peek()
	if t.kind != "eof" {
		r.pos++
	}
	return t
}
func (r *parser) is(s string) bool { return r.peek().text == s || r.peek().kind == s }
func (r *parser) accept(s string) bool {
	if r.is(s) {
		r.take()
		return true
	}
	return false
}
func (r *parser) expect(s string) error {
	if !r.accept(s) {
		return r.fail("expected " + s)
	}
	return nil
}
func (r *parser) fail(s string) error { return languageError("parse", s, r.peek().span) }
func (r *parser) name() (string, error) {
	if r.peek().kind != "ident" {
		return "", r.fail("expected identifier")
	}
	return r.take().value, nil
}
func (r *parser) str() (string, error) {
	if r.peek().kind != "string" {
		return "", r.fail("expected string")
	}
	return r.take().value, nil
}
func mergeSpan(a, b syntax.SourceRange) syntax.SourceRange {
	a.EndByte = b.EndByte
	a.EndRune = b.EndRune
	return a
}
func (r *parser) node(start syntax.SourceRange) Node {
	end := start
	if r.pos > 0 {
		end = r.tokens[r.pos-1].span
	}
	return Node{Range: mergeSpan(start, end)}
}
func precedence(op string) int {
	switch op {
	case "or":
		return 1
	case "and", "unless":
		return 2
	case "==", "!=", ">", "<", ">=", "<=":
		return 3
	case "+", "-":
		return 4
	case "*", "/", "%":
		return 5
	case "^":
		return 6
	}
	return -1
}
func (r *parser) expression(min int) (Expr, error) {
	r.depth++
	defer func() { r.depth-- }()
	if r.depth > 512 {
		return nil, languageErrorCode("syntax.nesting-limit", "syntax", "expression nesting limit", r.peek().span)
	}
	left, err := r.primary()
	if err != nil {
		return nil, err
	}
	for {
		op := r.peek().text
		prec := precedence(op)
		if prec < min {
			break
		}
		start := left.Span()
		r.take()
		b := &BinaryExpr{Op: op, Left: left}
		b.Bool = r.accept("bool")
		if r.is("on") || r.is("ignoring") {
			b.Matching.On = r.take().text == "on"
			b.Matching.Labels, err = r.names()
			if err != nil {
				return nil, err
			}
		}
		if r.is("group_left") || r.is("group_right") {
			b.Matching.Cardinality = r.take().text
			if r.is("(") {
				b.Matching.Include, err = r.names()
				if err != nil {
					return nil, err
				}
			}
		}
		next := prec + 1
		if op == "^" {
			next = prec
		}
		b.Right, err = r.expression(next)
		if err != nil {
			return nil, err
		}
		b.Node = r.node(start)
		left = b
	}
	return left, nil
}
func (r *parser) primary() (Expr, error) {
	start := r.peek().span
	if r.is("+") || r.is("-") {
		op := r.take().text
		e, err := r.expression(6)
		if err != nil {
			return nil, err
		}
		return &UnaryExpr{Node: r.node(start), Op: op, Expr: e}, nil
	}
	var e Expr
	switch {
	case r.accept("("):
		inner, err := r.expression(0)
		if err != nil {
			return nil, err
		}
		if err = r.expect(")"); err != nil {
			return nil, err
		}
		e = inner
	case r.is("{"):
		log, err := r.log()
		if err != nil {
			return nil, err
		}
		e = log
	case r.peek().kind == "number":
		t := r.take()
		v, err := strconv.ParseFloat(t.value, 64)
		if err != nil {
			return nil, languageErrorCode("syntax.number", "syntax", "invalid number", t.span)
		}
		e = &LiteralExpr{Node: r.node(start), Value: v}
	case r.peek().kind == "string":
		e = &StringExpr{Node: r.node(start), Value: r.take().value}
	case r.peek().kind == "ident":
		name := r.take().text
		if name == "variants" {
			return r.variants(start)
		}
		if name == "vector" {
			if err := r.expect("("); err != nil {
				return nil, err
			}
			argument := r.peek()
			if argument.kind != "number" {
				return nil, r.fail("vector requires a numeric token")
			}
			number, err := strconv.ParseFloat(argument.value, 64)
			if err != nil {
				return nil, r.fail("vector requires a numeric token")
			}
			r.take()
			if err = r.expect(")"); err != nil {
				return nil, err
			}
			e = &CallExpr{Node: r.node(start), Name: name, Args: []Expr{&LiteralExpr{Node: Node{Range: argument.span}, Value: number}}}
			break
		}
		c := &CallExpr{Name: name}
		var err error
		if r.is("by") || r.is("without") {
			c.Without = r.take().text == "without"
			c.Grouping, err = r.names()
			if err != nil {
				return nil, err
			}
		}
		if err = r.expect("("); err != nil {
			return nil, err
		}
		if !r.accept(")") {
			for {
				arg, err := r.expression(0)
				if err != nil {
					return nil, err
				}
				c.Args = append(c.Args, arg)
				if r.accept(")") {
					break
				}
				if err = r.expect(","); err != nil {
					return nil, err
				}
			}
		}
		if r.is("by") || r.is("without") {
			if c.Grouping != nil {
				return nil, r.fail("duplicate grouping")
			}
			c.Without = r.take().text == "without"
			c.Grouping, err = r.names()
			if err != nil {
				return nil, err
			}
		}
		c.Node = r.node(start)
		e = c
	default:
		return nil, r.fail("expected expression")
	}
	if log, ok := e.(*LogExpr); ok {
		for isStageStart(r.peek().text) {
			s, err := r.stage()
			if err != nil {
				return nil, err
			}
			log.Stages = append(log.Stages, s)
		}
		log.Node = r.node(start)
		if r.accept("[") {
			d, err := r.duration(false)
			if err != nil {
				return nil, err
			}
			if err = r.expect("]"); err != nil {
				return nil, err
			}
			rg := &RangeExpr{Log: log, Interval: d}
			offsetSeen := false
			if r.accept("offset") {
				offsetSeen = true
				rg.Offset, err = r.duration(true)
				if err != nil {
					return nil, err
				}
			}
			for isStageStart(r.peek().text) {
				s, err := r.stage()
				if err != nil {
					return nil, err
				}
				log.Stages = append(log.Stages, s)
			}
			if r.accept("offset") {
				if offsetSeen {
					return nil, languageErrorCode("range.offset-duplicate", "syntax", "duplicate offset", r.peek().span)
				}
				rg.Offset, err = r.duration(true)
				if err != nil {
					return nil, err
				}
			}
			rg.Node = r.node(start)
			e = rg
		}
	}
	return e, nil
}
func (r *parser) names() ([]string, error) {
	if err := r.expect("("); err != nil {
		return nil, err
	}
	out := []string{}
	if r.accept(")") {
		return out, nil
	}
	for {
		n, err := r.name()
		if err != nil {
			return nil, err
		}
		out = append(out, n)
		if r.accept(")") {
			return out, nil
		}
		if err = r.expect(","); err != nil {
			return nil, err
		}
		if r.accept(")") {
			return out, nil
		}
	}
}
func (r *parser) duration(signed bool) (int64, error) {
	sign := int64(1)
	if signed {
		if r.accept("-") {
			sign = -1
		} else {
			r.accept("+")
		}
	}
	t := r.take()
	if t.kind != "number" {
		if !signed {
			return 0, languageErrorCode("syntax.duration", "syntax", "invalid duration", t.span)
		}
		return 0, r.fail("expected duration")
	}
	var d int64
	var err error
	if signed {
		d, err = parseQueryDuration(t.value)
	} else {
		d, err = parseRangeDuration(t.value)
	}
	if err != nil {
		return 0, languageErrorCode("syntax.duration", "syntax", "invalid duration", t.span)
	}
	return sign * d, nil
}
func parseRangeDuration(s string) (int64, error) {
	if s == "0" {
		return 0, nil
	}
	total := uint64(0)
	previous := int64(math.MaxInt64)
	parts := 0
	for len(s) > 0 {
		i := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == 0 {
			return 0, strconv.ErrSyntax
		}
		n, err := strconv.ParseUint(s[:i], 10, 64)
		if err != nil {
			return 0, err
		}
		s = s[i:]
		unit := ""
		var scale int64
		for _, u := range []struct {
			name  string
			scale int64
		}{{"ms", int64(time.Millisecond)}, {"y", 365 * 24 * int64(time.Hour)}, {"w", 7 * 24 * int64(time.Hour)}, {"d", 24 * int64(time.Hour)}, {"h", int64(time.Hour)}, {"m", int64(time.Minute)}, {"s", int64(time.Second)}} {
			if strings.HasPrefix(s, u.name) {
				unit = u.name
				scale = u.scale
				break
			}
		}
		if unit == "" || scale >= previous {
			return 0, strconv.ErrSyntax
		}
		if n > uint64(math.MaxInt64)/uint64(scale) || total > uint64(math.MaxInt64)-n*uint64(scale) {
			return 0, strconv.ErrRange
		}
		total += n * uint64(scale)
		previous = scale
		s = s[len(unit):]
		parts++
	}
	if parts == 0 {
		return 0, strconv.ErrSyntax
	}
	return int64(total), nil
}
func parseQueryDuration(s string) (int64, error) {
	if d, err := parseRangeDuration(s); err == nil {
		return d, nil
	}
	d, err := time.ParseDuration(s)
	return int64(d), err
}
func (r *parser) log() (*LogExpr, error) {
	start := r.take().span
	l := &LogExpr{}
	if r.accept("}") {
		l.Node = r.node(start)
		return l, nil
	}
	for {
		n, err := r.name()
		if err != nil {
			return nil, err
		}
		op := r.take().text
		if op != "=" && op != "!=" && op != "=~" && op != "!~" {
			return nil, r.fail("expected stream matcher")
		}
		v, err := r.str()
		if err != nil {
			return nil, err
		}
		l.Matchers = append(l.Matchers, Matcher{n, op, v})
		if r.accept("}") {
			break
		}
		if err = r.expect(","); err != nil {
			return nil, err
		}
		if r.accept("}") {
			break
		}
	}
	for isStageStart(r.peek().text) {
		s, err := r.stage()
		if err != nil {
			return nil, err
		}
		l.Stages = append(l.Stages, s)
	}
	l.Node = r.node(start)
	return l, nil
}
func isLineOp(op string) bool {
	switch op {
	case "|=", "!=", "|~", "!~", "|>", "!>":
		return true
	}
	return false
}
func isStageStart(op string) bool { return op == "|" || isLineOp(op) }
func (r *parser) stage() (Stage, error) {
	start := r.peek().span
	s := Stage{}
	if isLineOp(r.peek().text) {
		s.Head = start
		s.Kind = "line_filter"
		op := r.take().text
		for {
			f := LineFilter{Op: op}
			var err error
			if r.accept("ip") {
				f.IP = true
				if err = r.expect("("); err != nil {
					return s, err
				}
				f.Value, err = r.str()
				if err == nil {
					err = r.expect(")")
				}
			} else {
				f.Value, err = r.str()
			}
			if err != nil {
				return s, err
			}
			s.Lines = append(s.Lines, f)
			if !r.accept("or") {
				break
			}
			if isLineOp(r.peek().text) {
				op = r.take().text
			}
		}
		s.Node = r.node(start)
		return s, nil
	}
	if err := r.expect("|"); err != nil {
		return s, err
	}
	s.Head = r.peek().span
	kind := r.peek().text
	switch kind {
	case "json", "logfmt":
		s.Kind = r.take().text
		if s.Kind == "logfmt" {
			for r.is("--strict") || r.is("--keep-empty") {
				if r.take().text == "--strict" {
					s.Strict = true
				} else {
					s.KeepEmpty = true
				}
			}
		}
		if r.peek().kind == "ident" && !r.is("offset") {
			for {
				n, err := r.name()
				if err != nil {
					return s, err
				}
				path := n
				if r.accept("=") {
					path, err = r.str()
					if err != nil {
						return s, err
					}
				}
				s.Extractions = append(s.Extractions, Extraction{n, path})
				if !r.accept(",") {
					break
				}
			}
		}
	case "regexp", "pattern", "line_format":
		s.Kind = r.take().text
		v, err := r.str()
		if err != nil {
			return s, err
		}
		s.Pattern = v
	case "unpack", "decolorize":
		s.Kind = r.take().text
	case "label_format":
		s.Kind = r.take().text
		for {
			n, err := r.name()
			if err != nil {
				return s, err
			}
			if err = r.expect("="); err != nil {
				return s, err
			}
			a := Assignment{Name: n}
			if r.peek().kind == "string" {
				a.Value, err = r.str()
			} else {
				a.Rename = true
				a.Value, err = r.name()
			}
			if err != nil {
				return s, err
			}
			s.Assignments = append(s.Assignments, a)
			if !r.accept(",") {
				break
			}
		}
	case "drop", "keep":
		s.Kind = r.take().text
		for {
			n, err := r.name()
			if err != nil {
				return s, err
			}
			m := Matcher{Name: n}
			if r.is("=") || r.is("!=") || r.is("=~") || r.is("!~") {
				m.Op = r.take().text
				m.Value, err = r.str()
				if err != nil {
					return s, err
				}
			}
			s.Labels = append(s.Labels, m)
			if !r.accept(",") {
				break
			}
		}
	case "unwrap":
		s.Kind = r.take().text
		n, err := r.name()
		if err != nil {
			return s, err
		}
		if r.accept("(") {
			s.Conversion = n
			s.UnwrapLabel, err = r.name()
			if err != nil {
				return s, err
			}
			if err = r.expect(")"); err != nil {
				return s, err
			}
		} else {
			s.UnwrapLabel = n
		}
	default:
		s.Kind = "label_filter"
		f, err := r.predicate(0)
		if err != nil {
			return s, err
		}
		s.Filter = f
	}
	s.Node = r.node(start)
	return s, nil
}
func (r *parser) predicate(min int) (*LabelPredicate, error) {
	r.depth++
	defer func() { r.depth-- }()
	if r.depth > 512 {
		return nil, languageErrorCode("syntax.nesting-limit", "syntax", "filter nesting limit", r.peek().span)
	}
	var f *LabelPredicate
	if r.accept("(") {
		var err error
		f, err = r.predicate(0)
		if err != nil {
			return nil, err
		}
		if err = r.expect(")"); err != nil {
			return nil, err
		}
	} else {
		n, err := r.name()
		if err != nil {
			return nil, err
		}
		op := r.take().text
		if op != "=" && op != "==" && op != "!=" && op != "=~" && op != "!~" && op != ">" && op != "<" && op != ">=" && op != "<=" {
			return nil, r.fail("expected label comparison")
		}
		f = &LabelPredicate{Name: n, Op: op}
		if r.peek().kind == "string" {
			f.Type = "string"
			f.Text = r.take().value
		} else if r.accept("ip") {
			f.Type = "ip"
			if err = r.expect("("); err != nil {
				return nil, err
			}
			f.Text, err = r.str()
			if err != nil {
				return nil, err
			}
			if err = r.expect(")"); err != nil {
				return nil, err
			}
		} else {
			sign := ""
			if r.is("+") || r.is("-") {
				sign = r.take().text
			}
			t := r.take()
			if t.kind != "number" {
				return nil, r.fail("expected filter value")
			}
			f.Text = sign + t.value
			if v, err := strconv.ParseFloat(f.Text, 64); err == nil {
				f.Type = "number"
				f.Number = v
			} else if v, err := parseQueryDuration(f.Text); err == nil {
				f.Type = "duration"
				f.Number = float64(v)
			} else if v, err := parseByteQuantity(f.Text); err == nil {
				f.Type = "bytes"
				f.Number = v
			} else {
				// The reference scanner rejects an out-of-range quantity after
				// consuming it, so the error sits at the end of the token.
				at := syntax.SourceRange{StartByte: t.span.EndByte, EndByte: t.span.EndByte, StartRune: t.span.EndRune, EndRune: t.span.EndRune}
				return nil, languageError("syntax", "invalid typed filter value", at)
			}
		}
	}
	for {
		op := r.peek().text
		prec := -1
		implicit := false
		switch op {
		case "or":
			prec = 1
		case "and", ",":
			prec = 2
		default:
			if r.peek().kind == "ident" && op != "offset" {
				prec = 2
				implicit = true
				op = "and"
			}
		}
		if prec < min {
			break
		}
		if !implicit {
			r.take()
		}
		rhs, err := r.predicate(prec + 1)
		if err != nil {
			return nil, err
		}
		if op == "," {
			op = "and"
		}
		f = &LabelPredicate{Op: op, Left: f, Right: rhs}
	}
	return f, nil
}
func (r *parser) variants(start syntax.SourceRange) (Expr, error) {
	v := &VariantsExpr{}
	if err := r.expect("("); err != nil {
		return nil, err
	}
	for {
		e, err := r.expression(0)
		if err != nil {
			return nil, err
		}
		v.Variants = append(v.Variants, e)
		if r.accept(")") {
			break
		}
		if err = r.expect(","); err != nil {
			return nil, err
		}
	}
	if err := r.expect("of"); err != nil {
		return nil, err
	}
	r.accept("(")
	e, err := r.primary()
	if err != nil {
		return nil, err
	}
	rg, ok := e.(*RangeExpr)
	if !ok {
		return nil, r.fail("variants requires log range")
	}
	v.Range = rg
	r.accept(")")
	v.Node = r.node(start)
	return v, nil
}
