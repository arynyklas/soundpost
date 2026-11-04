// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"
	"strconv"
	"strings"
)

func identifier(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if c != '_' && c != ':' && !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}
func label(s string) string {
	if identifier(s) && !strings.Contains(s, ":") {
		return s
	}
	return strconv.Quote(s)
}
func labels(xs []string) string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = label(x)
	}
	return strings.Join(out, ", ")
}

// Format preserves explicit parentheses and adds parentheses around binary operands.
// No canonicalization reorders operands, label matchers, or function arguments.
func Format(e Expr) string {
	if e == nil {
		return ""
	}
	n := e.(*Node)
	var s string
	child := func(i int) string { return Format(n.Children[i]) }
	switch n.Kind {
	case "number":
		f := math.Float64frombits(n.FloatBits)
		s = strconv.FormatFloat(f, 'g', -1, 64)
		if math.IsInf(f, 1) {
			s = "Inf"
		}
	case "string":
		s = strconv.Quote(n.Text)
	case "selector":
		s = n.Text
		var ms []string
		if !identifier(n.Text) && n.Text != "" {
			s = ""
			ms = append(ms, strconv.Quote(n.Text))
		}
		for _, m := range n.Matchers {
			ms = append(ms, label(m.Name)+m.Op+strconv.Quote(m.Value))
		}
		if len(ms) > 0 || s == "" {
			s += "{" + strings.Join(ms, ", ") + "}"
		}
	case "paren":
		s = "(" + child(0) + ")"
	case "unary":
		s = n.Text + child(0)
		if n.Children[0].(*Node).Kind == "binary" {
			s = n.Text + "(" + child(0) + ")"
		}
	case "call", "duration_call", "aggregate":
		args := make([]string, len(n.Children))
		for i := range args {
			args[i] = child(i)
		}
		s = n.Text
		if n.Kind == "aggregate" && n.Labels != nil {
			group := "by"
			if n.GroupWithout {
				group = "without"
			}
			s += " " + group + " (" + labels(n.Labels) + ")"
		}
		s += "(" + strings.Join(args, ", ") + ")"
	case "binary":
		left, right := child(0), child(1)
		if n.Children[0].(*Node).Kind == "binary" {
			left = "(" + left + ")"
		}
		if n.Children[1].(*Node).Kind == "binary" {
			right = "(" + right + ")"
		}
		s = left + " " + n.Text
		if n.Bool {
			s += " bool"
		}
		if n.Matching != nil {
			m := n.Matching
			mode := "ignoring"
			if m.On {
				mode = "on"
			}
			s += " " + mode + " (" + labels(m.Labels) + ")"
			if m.Cardinality != "" {
				s += " " + m.Cardinality
				if len(m.Include) > 0 {
					s += " (" + labels(m.Include) + ")"
				}
			}
		}
		if n.FillLeft != nil {
			s += " fill_left(" + literalText(*n.FillLeft) + ")"
		}
		if n.FillRight != nil {
			s += " fill_right(" + literalText(*n.FillRight) + ")"
		}
		s += " " + right
	case "range", "subquery":
		s = child(0)
		if n.Kind == "subquery" && n.Children[0].(*Node).Kind == "binary" {
			s = "(" + s + ")"
		}
		s += "[" + n.RangeText
		if n.Kind == "subquery" {
			s += ":" + n.Step
		}
		s += "]"
	}
	if n.Offset != "" {
		s += " offset " + n.Offset
	}
	if n.At != "" {
		s += " @ " + n.At
	}
	if n.Extension != "" {
		s += " " + n.Extension
	}
	return s
}
func literalText(bits uint64) string {
	f := math.Float64frombits(bits)
	if math.IsInf(f, 1) {
		return "Inf"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}
