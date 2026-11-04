// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"errors"
	"math"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/syntax"
	"strconv"
	"strings"
	"time"
)

// parser is a recursive-descent reader over a demand-driven lexer. Every
// decision looks at the next token and rejects it where the grammar cannot
// continue, BEFORE consuming it, so a syntax error names the first token the
// reference grammar cannot accept. A lexical failure is recorded when its token
// is scanned and then outranks any grammar error, as in the reference where the
// scanner reports while the grammar is still deciding.
type parser struct {
	l        lexer
	cur      token
	last     token
	have     bool
	consumed bool
	lexErr   error
	// numErr is the first NUMBER token whose text is no float. The reference
	// grammar only reports it when no syntax error precedes the reduction, so
	// it is returned after a complete parse.
	numErr error
	depth  int
	p      profile.Profile
}

func Parse(source string, p profile.Profile) (Expr, error) {
	if p.ID != "logql-loki-3.5.2" || p.Commit != "257d2f62bf8a81b44dea6fe88968d1d28c8e01e7" {
		return nil, languageError("profile", "unsupported LogQL profile", syntax.SourceRange{})
	}
	if len(source) >= 131072 {
		return nil, languageErrorCode("syntax.input-limit", "syntax", "query input exceeds profile limit", syntax.SourceRange{})
	}
	r := parser{l: lexer{source: source, p: p}, p: p}
	e, err := r.expression(0)
	if err == nil && r.peek().kind != "eof" {
		err = r.fail("unexpected trailing input")
	}
	if r.lexErr != nil {
		return nil, r.lexErr
	}
	if err != nil {
		return nil, err
	}
	if r.numErr != nil {
		return nil, r.numErr
	}
	return e, nil
}

// peek scans the next token on first use. A lexical error becomes an "error"
// token that no grammar rule accepts, so the parser stops at it.
func (r *parser) peek() token {
	if !r.have {
		t, err := r.l.next()
		if err != nil {
			r.lexErr = err
			t = token{kind: "error"}
			var d *syntax.LanguageError
			if errors.As(err, &d) {
				t.span = d.Range
			}
		}
		r.cur, r.have = t, true
	}
	return r.cur
}
func (r *parser) take() token {
	t := r.peek()
	if t.kind != "eof" && t.kind != "error" {
		r.have = false
		r.last = t
		r.consumed = true
	}
	return t
}

// is matches a punctuation/operator kind or a reserved word.
func (r *parser) is(s string) bool {
	t := r.peek()
	return t.kind == s || t.kind == "kw" && t.text == s
}
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
	if r.consumed {
		end = r.last.span
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

// binaryOp is the operator text of a binary-operator token, or "".
func binaryOp(t token) string {
	switch t.kind {
	case "kw":
		if t.text == "or" || t.text == "and" || t.text == "unless" {
			return t.text
		}
	case "==", "!=", ">", "<", ">=", "<=", "+", "-", "*", "/", "%", "^":
		return t.kind
	}
	return ""
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
	return r.binary(left, min)
}

// binary extends an operand with the binary operators that bind at least as
// tightly as min.
func (r *parser) binary(left Expr, min int) (Expr, error) {
	for {
		op := binaryOp(r.peek())
		prec := precedence(op)
		if prec < min {
			break
		}
		start := left.Span()
		r.take()
		b := &BinaryExpr{Op: op, Left: left}
		b.Bool = r.accept("bool")
		var err error
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

// metricExpr is an expression that is not a bare log expression: a vector or
// scalar, or a binary expression of anything.
func (r *parser) metricExpr() (Expr, error) {
	e, err := r.expression(0)
	if err != nil {
		return nil, err
	}
	if _, bare := e.(*LogExpr); bare {
		return nil, r.fail("a log expression is not a metric expression")
	}
	return e, nil
}

// floatOf is the value of a NUMBER token in a metric expression (a literal
// operand, `vector(..)`, a `topk` parameter). The reference converts it with
// the float parser when the grammar reduces it and rejects the query when that
// fails: `0x10` (a hexadecimal mantissa needs a `p` exponent), `0o10` and an
// out-of-range `1e999` are `syntax.number` without a position. The failure is
// remembered and reported only after a complete parse, since a syntax error
// that precedes the reduction wins.
func (r *parser) floatOf(t token) float64 {
	v, err := strconv.ParseFloat(t.value, 64)
	if err != nil && r.numErr == nil {
		r.numErr = languageErrorCode("syntax.number", "syntax", "invalid number", t.span)
	}
	return v
}

// labelFloat is the value of a NUMBER token in a label filter. The reference
// ignores the conversion error there: a text the float parser refuses
// (`0x10`, `0o10`) is the value 0 and an out-of-range text is infinite.
func labelFloat(t token) float64 {
	v, _ := strconv.ParseFloat(t.value, 64)
	return v
}

func (r *parser) number(t token) *LiteralExpr {
	return &LiteralExpr{Node: r.node(t.span), Value: r.floatOf(t)}
}
func (r *parser) primary() (Expr, error) {
	t := r.peek()
	start := t.span
	switch {
	case t.kind == "+" || t.kind == "-":
		// The reference grammar has `+NUMBER` / `-NUMBER` literals only: a sign
		// before anything else fails at the token after the sign.
		op := r.take().text
		if r.peek().kind != "number" {
			return nil, r.fail("expected number after sign")
		}
		lit := r.number(r.take())
		return &UnaryExpr{Node: r.node(start), Op: op, Expr: lit}, nil
	case t.kind == "(":
		r.take()
		inner, err := r.expression(0)
		if err != nil {
			return nil, err
		}
		if err = r.expect(")"); err != nil {
			return nil, err
		}
		return inner, nil
	case t.kind == "{":
		return r.logExpr()
	case t.kind == "number":
		return r.number(r.take()), nil
	case t.kind == "kw":
		switch name := t.text; {
		case name == "variants":
			return r.variants(start)
		case name == "vector":
			return r.vector(start)
		case name == "label_replace":
			return r.labelReplace(start)
		case aggregateNames[name]:
			return r.vectorCall(start)
		case rangeNames[name]:
			return r.rangeCall(start)
		}
	}
	return nil, r.fail("expected expression")
}

// logExpr is a selector with its pipeline outside any range: no range, offset
// or unwrap is possible here.
func (r *parser) logExpr() (*LogExpr, error) {
	start := r.peek().span
	log, err := r.selector()
	if err != nil {
		return nil, err
	}
	if err = r.stages(log, false); err != nil {
		return nil, err
	}
	log.Node = r.node(start)
	return log, nil
}
func (r *parser) vector(start syntax.SourceRange) (Expr, error) {
	name := r.take().text
	if err := r.expect("("); err != nil {
		return nil, err
	}
	argument := r.peek()
	if argument.kind != "number" {
		return nil, r.fail("vector requires a numeric token")
	}
	number := r.floatOf(argument)
	r.take()
	if err := r.expect(")"); err != nil {
		return nil, err
	}
	return &CallExpr{Node: r.node(start), Name: name, Args: []Expr{&LiteralExpr{Node: Node{Range: argument.span}, Value: number}}}, nil
}
func (r *parser) labelReplace(start syntax.SourceRange) (Expr, error) {
	c := &CallExpr{Name: r.take().text}
	if err := r.expect("("); err != nil {
		return nil, err
	}
	first, err := r.metricExpr()
	if err != nil {
		return nil, err
	}
	c.Args = append(c.Args, first)
	for i := 0; i < 4; i++ {
		if err = r.expect(","); err != nil {
			return nil, err
		}
		t := r.peek()
		if t.kind != "string" {
			return nil, r.fail("expected string")
		}
		r.take()
		c.Args = append(c.Args, &StringExpr{Node: Node{Range: t.span}, Value: t.value})
	}
	if err = r.expect(")"); err != nil {
		return nil, err
	}
	c.Node = r.node(start)
	return c, nil
}

// grouping reads `by (...)` or `without (...)` into the call.
func (r *parser) grouping(c *CallExpr) error {
	c.Without = r.take().text == "without"
	var err error
	c.Grouping, err = r.names()
	return err
}

// vectorCall: vectorOp [grouping] ( metricExpr {, metricExpr} ) [grouping].
// The reference grammar takes an optional leading NUMBER parameter; the argument
// count is left to the type checker, which reports it with its own code.
func (r *parser) vectorCall(start syntax.SourceRange) (Expr, error) {
	c := &CallExpr{Name: r.take().text}
	var err error
	if r.is("by") || r.is("without") {
		if err = r.grouping(c); err != nil {
			return nil, err
		}
	}
	if err = r.expect("("); err != nil {
		return nil, err
	}
	for {
		arg, err := r.metricExpr()
		if err != nil {
			return nil, err
		}
		c.Args = append(c.Args, arg)
		if !r.accept(",") {
			break
		}
	}
	if err = r.expect(")"); err != nil {
		return nil, err
	}
	if r.is("by") || r.is("without") {
		if c.Grouping != nil {
			return nil, r.fail("duplicate grouping")
		}
		if err = r.grouping(c); err != nil {
			return nil, err
		}
	}
	c.Node = r.node(start)
	return c, nil
}

// rangeCall: rangeOp ( [NUMBER ,] logRange ) [grouping].
func (r *parser) rangeCall(start syntax.SourceRange) (Expr, error) {
	c := &CallExpr{Name: r.take().text}
	if err := r.expect("("); err != nil {
		return nil, err
	}
	if r.peek().kind == "number" {
		lit := r.number(r.take())
		if err := r.expect(","); err != nil {
			return nil, err
		}
		c.Args = append(c.Args, lit)
	}
	rg, err := r.logRange()
	if err != nil {
		return nil, err
	}
	c.Args = append(c.Args, rg)
	if err = r.expect(")"); err != nil {
		return nil, err
	}
	if r.is("by") || r.is("without") {
		if err = r.grouping(c); err != nil {
			return nil, err
		}
	}
	c.Node = r.node(start)
	return c, nil
}

// logRange is the only place a range, an offset and an unwrap are accepted. The
// reference reads `[(] selector [pipeline] [unwrap] [)] RANGE [offset]` or
// `[(] selector [)] RANGE [offset] [pipeline] [unwrap]`; once stages have been
// read before the range none may follow it (observed with an unwrap before the
// range). A trailing offset after post-range stages is kept as before: no
// observation covers it.
func (r *parser) logRange() (*RangeExpr, error) {
	start := r.peek().span
	paren := r.accept("(")
	if paren && r.is("(") {
		// `( logRange )`: the reference lets a whole range expression sit in
		// parentheses, so a doubly opened call argument is read to its end.
		inner, err := r.logRange()
		if err != nil {
			return nil, err
		}
		if err = r.expect(")"); err != nil {
			return nil, err
		}
		return inner, nil
	}
	if !r.is("{") {
		return nil, r.fail("expected selector")
	}
	log, err := r.selector()
	if err != nil {
		return nil, err
	}
	if err = r.stages(log, true); err != nil {
		return nil, err
	}
	if paren && r.peek().kind == "range" {
		// `( selector [stages] RANGE ... )`: the range is inside the parentheses.
		rg, err := r.rangeTail(log, start)
		if err != nil {
			return nil, err
		}
		if err = r.expect(")"); err != nil {
			return nil, err
		}
		return rg, nil
	}
	if paren {
		if err = r.expect(")"); err != nil {
			return nil, err
		}
	}
	return r.rangeTail(log, start)
}

// rangeTail reads `RANGE [offset] [stages]` after the selector part.
func (r *parser) rangeTail(log *LogExpr, start syntax.SourceRange) (*RangeExpr, error) {
	var err error
	log.Node = r.node(start)
	interval := r.peek()
	if interval.kind != "range" {
		return nil, r.fail("expected range")
	}
	r.take()
	rg := &RangeExpr{Log: log, Interval: interval.dur}
	offsetSeen := false
	if r.accept("offset") {
		offsetSeen = true
		if rg.Offset, err = r.offset(); err != nil {
			return nil, err
		}
	}
	if len(log.Stages) == 0 {
		if err = r.stages(log, true); err != nil {
			return nil, err
		}
		if !offsetSeen && r.accept("offset") {
			if rg.Offset, err = r.offset(); err != nil {
				return nil, err
			}
		}
	}
	rg.Node = r.node(start)
	return rg, nil
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
	}
}

// offset reads the signed duration after the offset keyword.
func (r *parser) offset() (int64, error) {
	sign := int64(1)
	if r.accept("-") {
		sign = -1
	} else {
		r.accept("+")
	}
	t := r.peek()
	if t.kind != "duration" {
		return 0, r.fail("expected duration")
	}
	r.take()
	d, _ := parseQueryDuration(t.value) // validated when the token was scanned
	return sign * d, nil
}

// selector reads `{ [matcher {, matcher}] }`; a comma needs a matcher after it.
func (r *parser) selector() (*LogExpr, error) {
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
		op := r.peek()
		if !isMatcherOp(op.kind) {
			return nil, r.fail("expected stream matcher")
		}
		r.take()
		v, err := r.str()
		if err != nil {
			return nil, err
		}
		l.Matchers = append(l.Matchers, Matcher{n, op.kind, v})
		if r.accept("}") {
			break
		}
		if err = r.expect(","); err != nil {
			return nil, err
		}
	}
	l.Node = r.node(start)
	return l, nil
}
func isMatcherOp(kind string) bool {
	return kind == "=" || kind == "!=" || kind == "=~" || kind == "!~"
}
func isLineOp(kind string) bool {
	switch kind {
	case "|=", "!=", "|~", "!~", "|>", "!>":
		return true
	}
	return false
}
func (r *parser) stageStart() bool {
	k := r.peek().kind
	return k == "|" || isLineOp(k)
}

// stages reads the pipeline stages that follow a selector or a range. Outside a
// range an unwrap is not accepted; after an unwrap only label filters are.
func (r *parser) stages(log *LogExpr, inRange bool) error {
	for r.stageStart() {
		unwrapped := false
		for _, s := range log.Stages {
			unwrapped = unwrapped || s.Kind == "unwrap"
		}
		s, err := r.stage(inRange, unwrapped)
		if err != nil {
			return err
		}
		log.Stages = append(log.Stages, s)
	}
	return nil
}
func (r *parser) stage(inRange, unwrapped bool) (Stage, error) {
	start := r.peek().span
	s := Stage{}
	if isLineOp(r.peek().kind) {
		if unwrapped {
			return s, r.fail("only label filters may follow unwrap")
		}
		return r.lineFilter(start)
	}
	r.take() // the pipe
	head := r.peek()
	s.Head = head.span
	if unwrapped && head.kind != "ident" && head.kind != "(" {
		return s, r.fail("only label filters may follow unwrap")
	}
	switch {
	case head.kind == "kw":
		switch head.text {
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
			if r.peek().kind == "ident" {
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
				if isMatcherOp(r.peek().kind) {
					m.Op = r.take().kind
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
			if !inRange {
				return s, r.fail("unwrap requires a range")
			}
			if err := r.unwrap(&s); err != nil {
				return s, err
			}
		default:
			return s, r.fail("expected pipeline stage")
		}
	case head.kind == "ident" || head.kind == "(":
		s.Kind = "label_filter"
		f, err := r.predicate(0)
		if err != nil {
			return s, err
		}
		s.Filter = f
	default:
		return s, r.fail("expected pipeline stage")
	}
	s.Node = r.node(start)
	return s, nil
}

// unwrap reads `unwrap label` or `unwrap conversion(label)`.
func (r *parser) unwrap(s *Stage) error {
	s.Kind = r.take().text
	t := r.peek()
	switch {
	case t.kind == "kw" && (t.text == "bytes" || t.text == "duration" || t.text == "duration_seconds"):
		s.Conversion = r.take().text
		if err := r.expect("("); err != nil {
			return err
		}
		n, err := r.name()
		if err != nil {
			return err
		}
		s.UnwrapLabel = n
		return r.expect(")")
	case t.kind == "ident":
		s.UnwrapLabel = r.take().value
		return nil
	}
	return r.fail("expected unwrap label")
}
func (r *parser) lineFilter(start syntax.SourceRange) (Stage, error) {
	s := Stage{Head: start, Kind: "line_filter"}
	op := r.take().kind
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
		if isLineOp(r.peek().kind) {
			op = r.take().kind
		}
	}
	s.Node = r.node(start)
	return s, nil
}
func isLabelComparison(kind string) bool {
	switch kind {
	case "=", "==", "!=", "=~", "!~", ">", "<", ">=", "<=":
		return true
	}
	return false
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
		op := r.peek()
		if !isLabelComparison(op.kind) {
			return nil, r.fail("expected label comparison")
		}
		r.take()
		f = &LabelPredicate{Name: n, Op: op.kind}
		// `==` and the relational operators take only a number, duration or
		// byte size; `=`, `!=`, `=~`, `!~` take strings and only `=` and `!=`
		// also take ip() (op11 rows: after `=~`/`!~` the `ip` token itself is the
		// unexpected one, unlike `|~ ip(...)` in a line filter).
		numericOnly := op.kind == "==" || op.kind == ">" || op.kind == "<" || op.kind == ">=" || op.kind == "<="
		regexOp := op.kind == "=~" || op.kind == "!~"
		if r.peek().kind == "string" {
			if numericOnly {
				return nil, r.fail("a numeric filter takes a number, duration or byte size")
			}
			f.Type = "string"
			f.Text = r.take().value
		} else if r.is("ip") && (numericOnly || regexOp) {
			return nil, r.fail("ip() is only a value of = and !=")
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
		} else if regexOp {
			return nil, r.fail("a regular expression filter takes a string")
		} else {
			sign := ""
			if r.is("+") || r.is("-") {
				sign = r.take().kind
			}
			t := r.peek()
			if t.kind != "number" && t.kind != "duration" && t.kind != "bytes" {
				return nil, r.fail("expected filter value")
			}
			r.take()
			f.Text = sign + t.value
			f.Type = t.kind
			switch t.kind {
			case "number":
				f.Number = labelFloat(t)
				if sign == "-" {
					f.Number = -f.Number
				}
			case "duration":
				v, _ := parseQueryDuration(f.Text)
				f.Number = float64(v)
			default:
				v, err := parseByteQuantity(f.Text)
				if err != nil {
					// A signed quantity is no byte size; the reference has
					// consumed the token by now, so the error sits at its end.
					at := syntax.SourceRange{StartByte: t.span.EndByte, EndByte: t.span.EndByte, StartRune: t.span.EndRune, EndRune: t.span.EndRune}
					return nil, languageError("syntax", "invalid typed filter value", at)
				}
				f.Number = v
			}
		}
	}
	// `or` and the `,` separator share one right-associative level that binds
	// looser than `and` (and than juxtaposition): `a, b or c` is a, (b or c) and
	// `a or b, c` is a or (b, c). Observed on the pinned reference. A name or a
	// parenthesis right after a filter starts a juxtaposed filter, an implicit
	// `and`.
	for {
		t := r.peek()
		op := t.kind
		prec := -1
		implicit := false
		switch {
		case op == "," || t.kind == "kw" && t.text == "or":
			prec = 1
		case t.kind == "kw" && t.text == "and":
			prec = 2
		case t.kind == "ident" || t.kind == "(":
			prec = 2
			implicit = true
		}
		if t.kind == "kw" {
			op = t.text
		}
		if implicit {
			op = "and"
		}
		if prec < min {
			break
		}
		if !implicit {
			r.take()
		}
		next := prec + 1
		if prec == 1 {
			next = prec
		}
		rhs, err := r.predicate(next)
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

// variants: variants ( expr {, expr} ) of ( logRange ).
func (r *parser) variants(start syntax.SourceRange) (Expr, error) {
	r.take()
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
	if err := r.expect("("); err != nil {
		return nil, err
	}
	rg, err := r.logRange()
	if err != nil {
		return nil, err
	}
	if err = r.expect(")"); err != nil {
		return nil, err
	}
	v.Range = rg
	v.Node = r.node(start)
	return v, nil
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
