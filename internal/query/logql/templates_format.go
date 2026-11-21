// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"strings"
	"unicode/utf8"
)

// This scanner only computes a conservative admission bound. All observable
// formatting, including malformed directives, remains in the pinned formatter.
// It tracks star/index argument consumption; unrelated large integer arguments
// must not be mistaken for widths. Compound formatting propagates width/precision
// to leaves, so padding cannot be bounded by the number of directives alone.
type templateFormatValue struct{ bytes, leaves int64 }

func (s *templateState) formatLeaves(v any, depth int) (int64, error) {
	if e := s.charge(1); e != nil {
		return 0, e
	}
	if depth > templateMaxDepth {
		return 0, &TemplateLimitError{Resource: "depth"}
	}
	if root, ok := v.(templateRoot); ok {
		v = map[string]any(root)
	}
	leaves := int64(0)
	switch x := v.(type) {
	case []byte:
		leaves = int64(len(x))
	case []any:
		for _, v := range x {
			n, e := s.formatLeaves(v, depth+1)
			if e != nil {
				return 0, e
			}
			leaves += n
		}
	case map[string]any:
		for _, v := range x {
			n, e := s.formatLeaves(v, depth+1)
			if e != nil {
				return 0, e
			}
			leaves += n + 1
		}
	case map[string]string:
		leaves = int64(len(x)) * 2
	default:
		leaves = 1
	}
	if leaves > templateMaxWork {
		return 0, &TemplateLimitError{Resource: "format leaves"}
	}
	return max(1, leaves), nil
}
func (s *templateState) printfAdmission(format string, args []any, base int64) (int64, error) {
	if e := s.reserve(int64(len(args))*32 + 128); e != nil {
		return 0, e
	}
	values := make([]templateFormatValue, len(args))
	for i, v := range args {
		n, e := s.valueSize(v, 0)
		if e != nil {
			return 0, e
		}
		leaves, e := s.formatLeaves(v, 0)
		if e != nil {
			return 0, e
		}
		values[i] = templateFormatValue{n, leaves}
		base += n
		if base > templateMaxBytes/8 {
			return 0, &TemplateLimitError{Resource: "format"}
		}
	}
	position, cursor := 0, 0
	digits := func() (int64, bool) {
		start := position
		n := int64(0)
		for position < len(format) && format[position] >= '0' && format[position] <= '9' {
			if n <= 1000000 {
				n = n*10 + int64(format[position]-'0')
			}
			position++
		}
		// The pinned fmt grammar itself rejects numbers beyond 1e6; they cannot
		// allocate that requested padding. Preserve its normal diagnostic output.
		return n, position > start && n <= 1000000
	}
	index := func() {
		if position >= len(format) || format[position] != '[' {
			return
		}
		start := position
		position++
		n, valid := digits()
		if position >= len(format) || format[position] != ']' {
			position = start
			return
		}
		position++
		if !valid || n <= 0 || n > int64(len(args)) {
			cursor = len(args)
			return
		}
		cursor = int(n) - 1
	}
	star := func(precision bool) int64 {
		n := int64(0)
		if cursor < len(args) {
			switch x := templateNumericKind(args[cursor]).(type) {
			case int:
				n = int64(x)
			case int64:
				n = x
			case uint64:
				if x <= 1000000 {
					n = int64(x)
				}
			}
		}
		cursor++
		if precision && n < 0 {
			return 0
		}
		if n < 0 {
			if n < -1000000 {
				return 0
			}
			n = -n
		}
		if n > 1000000 {
			return 0
		}
		return n
	}
	total := base
	for position < len(format) {
		if e := s.charge(1); e != nil {
			return 0, e
		}
		if format[position] != '%' {
			position++
			continue
		}
		position++
		if position < len(format) && format[position] == '%' {
			position++
			continue
		}
		for position < len(format) && strings.ContainsRune(" +-#0", rune(format[position])) {
			position++
		}
		index()
		width, precision := int64(0), int64(0)
		if position < len(format) && format[position] == '*' {
			width = star(false)
			position++
		} else {
			if n, valid := digits(); valid {
				width = n
			}
		}
		if position < len(format) && format[position] == '.' {
			position++
			index()
			if position < len(format) && format[position] == '*' {
				precision = star(true)
				position++
			} else {
				if n, valid := digits(); valid {
					precision = n
				}
			}
		}
		index()
		if position >= len(format) {
			break
		}
		verb, bytes := utf8.DecodeRuneInString(format[position:])
		position += bytes
		if verb == '%' {
			continue
		}
		if cursor < len(values) {
			v := values[cursor]
			padding := width + precision + 128
			if padding > templateMaxBytes/v.leaves {
				return 0, &TemplateLimitError{Resource: "format"}
			}
			addition := v.bytes + padding*v.leaves
			if addition > templateMaxBytes/8 || total > templateMaxBytes/8-addition {
				return 0, &TemplateLimitError{Resource: "format"}
			}
			total += addition
		} else {
			total += 128
		}
		cursor++
		if total > templateMaxBytes/8 {
			return 0, &TemplateLimitError{Resource: "format"}
		}
	}
	return total * 8, nil
}
