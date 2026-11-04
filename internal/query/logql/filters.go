// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"errors"
	"net/netip"
	"soundpost/internal/query/regexcompat"
	"strconv"
	"strings"
	"time"
)

type ipSet struct {
	first, last netip.Addr
	prefix      netip.Prefix
}

func parseIPSet(s string) (*ipSet, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return &ipSet{prefix: p.Masked()}, nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return &ipSet{first: a.Unmap(), last: a.Unmap()}, nil
	}
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return nil, errors.New("invalid IP pattern")
	}
	lo, err := netip.ParseAddr(a)
	if err != nil {
		return nil, errors.New("invalid IP range")
	}
	hi, err := netip.ParseAddr(b)
	if err != nil {
		return nil, errors.New("invalid IP range")
	}
	lo, hi = lo.Unmap(), hi.Unmap()
	if lo.BitLen() != hi.BitLen() || lo.Compare(hi) > 0 {
		return nil, errors.New("invalid IP range")
	}
	return &ipSet{first: lo, last: hi}, nil
}
func (s *ipSet) contains(a netip.Addr) bool {
	if s.prefix.IsValid() {
		return s.prefix.Contains(a) || s.prefix.Contains(a.Unmap())
	}
	a = a.Unmap()
	return a.BitLen() == s.first.BitLen() && s.first.Compare(a) <= 0 && s.last.Compare(a) >= 0
}
func isIPByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == '.' || c == ':' || c == '%'
}
func (s *ipSet) search(line string) bool {
	for pos := 0; pos < len(line); {
		if !isIPByte(line[pos]) {
			pos++
			continue
		}
		start := pos
		for pos < len(line) && isIPByte(line[pos]) {
			pos++
		}
		raw := line[start:pos]
		if a, err := netip.ParseAddr(raw); err == nil && s.contains(a) {
			return true
		}
		if ap, err := netip.ParseAddrPort(raw); err == nil && s.contains(ap.Addr()) {
			return true
		}
		if strings.HasPrefix(raw, ":") {
			if a, err := netip.ParseAddr(strings.TrimLeft(raw, ":")); err == nil && s.contains(a) {
				return true
			}
		}
	}
	return false
}

type patternPart struct {
	literal, name string
	capture       bool
}
type linePattern struct{ parts []patternPart }

func parsePattern(s string, named bool) (*linePattern, error) {
	if s == "" {
		return nil, errors.New("empty pattern")
	}
	p := &linePattern{}
	seen := map[string]bool{}
	captures := 0
	literals := 0
	for len(s) > 0 {
		i := strings.IndexByte(s, '<')
		if i < 0 {
			p.parts = append(p.parts, patternPart{literal: s})
			literals++
			break
		}
		if i > 0 {
			p.parts = append(p.parts, patternPart{literal: s[:i]})
			literals++
		}
		s = s[i+1:]
		j := strings.IndexByte(s, '>')
		if j < 0 {
			return nil, errors.New("unterminated pattern capture")
		}
		n := s[:j]
		s = s[j+1:]
		if !validLabel(n) {
			return nil, errors.New("invalid pattern capture")
		}
		if !named && n != "_" {
			return nil, errors.New("line patterns allow only wildcard captures")
		}
		if len(p.parts) > 0 && p.parts[len(p.parts)-1].capture {
			return nil, errors.New("adjacent pattern captures")
		}
		if n != "_" {
			if seen[n] {
				return nil, errors.New("duplicate pattern capture")
			}
			seen[n] = true
			captures++
		}
		p.parts = append(p.parts, patternPart{name: n, capture: true})
	}
	if named && captures == 0 {
		return nil, errors.New("parser pattern requires named capture")
	}
	if !named && literals == 0 {
		return nil, errors.New("filter pattern requires literal")
	}
	return p, nil
}

// match walks the pattern over the line. Every capture reached is recorded,
// an empty value included (`<a> <b>` on "  x" gives a="", b=" x"; `x<a>` on
// "x" gives a=""). A capture whose following literal is missing takes the rest
// of the line and ends the walk. An empty line produces no captures at all, and
// a leading literal that is not a prefix of the line produces none either.
func (p *linePattern) match(line string) (map[string]string, bool) {
	pos := 0
	values := map[string]string{}
	if line == "" {
		return values, false
	}
	for i, part := range p.parts {
		if !part.capture {
			if !strings.HasPrefix(line[pos:], part.literal) {
				return values, false
			}
			pos += len(part.literal)
			continue
		}
		end := len(line)
		if i+1 < len(p.parts) {
			at := strings.Index(line[pos:], p.parts[i+1].literal)
			if at < 0 {
				if part.name != "_" {
					values[part.name] = line[pos:]
				}
				return values, false
			}
			end = pos + at
		}
		if part.name != "_" {
			values[part.name] = line[pos:end]
		}
		pos = end
	}
	return values, pos == len(line)
}
func lineMatches(ctx context.Context, c compiledLine, line string, scope *regexcompat.Scope) (bool, error) {
	var ok bool
	var err error
	switch {
	case c.ip != nil:
		ok = c.ip.search(line)
	case c.regex != nil:
		ok, err = scope.MatchString(ctx, c.regex, line)
	case c.pattern != nil:
		_, ok = c.pattern.match(line)
	default:
		ok = strings.Contains(line, c.filter.Value)
	}
	if c.filter.Op == "!=" || c.filter.Op == "!~" || c.filter.Op == "!>" {
		ok = !ok
	}
	return ok, err
}

// The shared independently authored primitive freezes Unicode15 suffix/space
// handling and uint64 truncation; callers retain their own stage error category.
func parseByteQuantity(s string) (float64, error) { return templateParseBytes(s) }
func numericCompare(op string, a, b float64) bool {
	switch op {
	case "=", "==":
		return a == b
	case "!=":
		return a != b
	case ">":
		return a > b
	case "<":
		return a < b
	case ">=":
		return a >= b
	case "<=":
		return a <= b
	}
	return false
}
func evalPredicate(ctx context.Context, f *LabelPredicate, e *LogEntry, scope *regexcompat.Scope) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if f.Left != nil {
		left, err := evalPredicate(ctx, f.Left, e, scope)
		if err != nil {
			return false, err
		}
		if f.Op == "or" && left {
			return true, nil
		}
		right, err := evalPredicate(ctx, f.Right, e, scope)
		if err != nil {
			return false, err
		}
		if f.Op == "and" {
			return left && right, nil
		}
		return left || right, nil
	}
	v, present := entryLabel(e, f.Name)
	if f.Type == "string" {
		if f.Name == "__error__" {
			v = e.languageError
		}
		return matchScoped(ctx, scope, Matcher{Name: f.Name, Op: f.Op, Value: f.Text}, v)
	}
	if !present {
		return false, nil
	}
	if f.Type == "ip" {
		s, err := parseIPSet(f.Text)
		if err != nil {
			return false, err
		}
		a, err := netip.ParseAddr(v)
		ok := err == nil && s.contains(a)
		if f.Op == "!=" {
			ok = !ok
		}
		return ok, nil
	}
	var n float64
	var err error
	switch f.Type {
	case "number":
		n, err = strconv.ParseFloat(v, 64)
	case "duration":
		var d time.Duration
		d, err = time.ParseDuration(v)
		n = float64(d)
	case "bytes":
		n, err = parseByteQuantity(v)
	}
	if err != nil {
		if e.languageError == "" {
			e.setError("LabelFilterErr", err.Error())
		}
		return true, nil
	}
	return numericCompare(f.Op, n, f.Number), nil
}

// unwrapValue extracts the sample value. An absent or empty label drops the
// entry (keep=false). A failed conversion keeps the label and records
// SampleExtractionErr, replacing any earlier error. A successful conversion
// consumes the label only while no earlier stage left an __error__; with one
// present the label stays in the stream.
func unwrapValue(s Stage, e *LogEntry) (n *float64, keep bool) {
	v, ok := entryLabel(e, s.UnwrapLabel)
	if !ok || v == "" {
		return nil, false
	}
	var f float64
	var err error
	switch s.Conversion {
	case "bytes":
		f, err = parseByteQuantity(v)
	case "duration", "duration_seconds":
		var d time.Duration
		d, err = time.ParseDuration(v)
		f = d.Seconds()
	default:
		f, err = strconv.ParseFloat(v, 64)
	}
	if err != nil {
		e.setError("SampleExtractionErr", err.Error())
		f = 0
	} else if e.languageError == "" {
		e.deleteOrdinary(s.UnwrapLabel)
	}
	return &f, true
}
func filterDetailBytes(f *LabelPredicate, e *LogEntry) int64 {
	if f == nil {
		return 0
	}
	if f.Left != nil {
		return filterDetailBytes(f.Left, e) + filterDetailBytes(f.Right, e)
	}
	if f.Type == "string" {
		return 0
	}
	v, _ := entryLabel(e, f.Name)
	return int64(len(v))*4 + 512
}
