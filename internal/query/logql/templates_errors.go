// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"errors"
	fmt "soundpost/third_party/format/go124/fmt"
	strconv "soundpost/third_party/format/go124/strconv"
	"strings"
	"text/template/parse"
	"time"
)

// LanguageDetail is authorized LogQL result-label data, never a default
// diagnostic/JSON field. Error() remains safe even when the detail has literals.
func (e *TemplateError) LanguageDetail() string { return e.languageDetail }
func (e *TemplateError) SemanticCode() string {
	if e.semanticCode != "" {
		return e.semanticCode
	}
	return "template." + e.Phase
}

// Codes derive from fixed failure-origin contracts, never safe Error() prose or
// user-controlled detail text. Exact detail is retained independently.
func templateFailureCode(origin string) string {
	switch {
	case strings.HasPrefix(origin, "wrong number of args for "):
		return "template.arity"
	case strings.HasPrefix(origin, "expected "), strings.HasPrefix(origin, "cannot assign nil"), strings.HasPrefix(origin, "wrong type for value"), strings.HasPrefix(origin, "invalid value; expected"), strings.HasPrefix(origin, "can't handle "), strings.HasSuffix(origin, "overflows int"):
		return "template.argument-type"
	case strings.HasPrefix(origin, "error calling "):
		return "template.helper-call"
	case strings.HasPrefix(origin, "nil pointer evaluating"), strings.HasPrefix(origin, "can't evaluate field"), strings.Contains(origin, "unexported field"), strings.HasPrefix(origin, "invalid function signature"), strings.HasPrefix(origin, "function "), strings.Contains(origin, "method but has arguments"), strings.HasPrefix(origin, "can't give argument"):
		return "template.field-method"
	}
	return "template.execution"
}

func (s *templateState) failure(node parse.Node, format string, args ...any) error {
	// Parse-node context rendering and quoted literals can amplify source bytes.
	// Admission precedes ErrorContext, fmt and all detail allocations.
	bytes := s.template.sourceBytes*16 + 4096
	for _, arg := range args {
		n, e := s.valueSize(arg, 0)
		if e != nil {
			return e
		}
		bytes += n
	}
	if e := s.reserve(bytes); e != nil {
		return e
	}
	reason := fmt.Sprintf(format, args...)
	tree := s.tree
	if tree == nil {
		tree = s.template.root
	}
	name := tree.Name
	detail := ""
	if node == nil {
		detail = fmt.Sprintf("template: %s: %s", name, reason)
	} else {
		location, expression := tree.ErrorContext(node)
		if call, ok := node.(*parse.TemplateNode); ok {
			expression = "{{template " + strconv.Quote(call.Name)
			if call.Pipe != nil {
				expression += " " + call.Pipe.String()
			}
			expression += "}}"
		}
		detail = fmt.Sprintf("template: %s: executing %q at <%s>: %s", location, name, expression, reason)
	}
	if int64(len(detail)) > templateMaxBytes {
		return &TemplateLimitError{Resource: "error detail"}
	}
	return &TemplateError{Phase: "execution", languageDetail: detail, semanticCode: templateFailureCode(format)}
}
func (s *templateState) fail(format string, args ...any) error {
	return s.failure(s.node, format, args...)
}
func templateType(v any) string {
	switch v.(type) {
	case nil:
		return "<nil>"
	case bool:
		return "bool"
	case string:
		return "string"
	case int:
		return "int"
	case int64:
		return "int64"
	case uint8:
		return "uint8"
	case uint64:
		return "uint64"
	case float64:
		return "float64"
	case complex128:
		return "complex128"
	case []any:
		return "[]interface {}"
	case []byte:
		return "[]uint8"
	case map[string]any, templateRoot:
		return "map[string]interface {}"
	case map[string]string:
		return "map[string]string"
	case time.Time:
		return "time.Time"
	case time.Duration:
		return "time.Duration"
	case time.Month:
		return "time.Month"
	case time.Weekday:
		return "time.Weekday"
	case *time.Location:
		return "*time.Location"
	}
	return "<invalid>"
}
func templateSignature(name string) (string, bool) {
	if sig, ok := templateSignatures[name]; ok {
		return sig, true
	}
	switch name {
	case "and", "or", "eq", "index", "slice", "call":
		return "aa*", true
	case "not", "len":
		return "a", true
	case "ne", "lt", "le", "gt", "ge":
		return "aa", true
	case "print", "println", "html", "js", "urlquery":
		return "a*", true
	case "printf":
		return "sa*", true
	}
	return "", false
}
func (s *templateState) arity(name, signature string, count, explicit int) error {
	variadic := strings.HasSuffix(signature, "*")
	fixed := len(signature)
	if variadic {
		fixed -= 2
	}
	if !variadic && count != fixed {
		return s.fail("wrong number of args for %s: want %d got %d", name, fixed, count)
	}
	if variadic && count < fixed {
		return s.fail("wrong number of args for %s: want at least %d got %d", name, fixed, explicit)
	}
	return nil
}
func templateParameter(signature string, index int) byte {
	signature = strings.TrimSuffix(signature, "*")
	if index >= len(signature) {
		index = len(signature) - 1
	}
	return signature[index]
}
func templateParameterType(kind byte) string {
	switch kind {
	case 's':
		return "string"
	case 'i':
		return "int"
	case 'f':
		return "float64"
	case 't':
		return "time.Time"
	case 'd':
		return "time.Duration"
	case 'b':
		return "[]uint8"
	case 'l':
		return "*time.Location"
	}
	return "interface {}"
}
func (s *templateState) argument(node parse.Node, dot any, kind byte) (any, error) {
	s.node = node
	if kind == 'a' {
		v, e := s.atom(node, dot)
		if e != nil {
			return nil, e
		}
		v, e = templateDefault(v)
		if e != nil {
			return nil, s.fail("%s overflows int", node)
		}
		return v, nil
	}
	expected := templateParameterType(kind)
	if _, nilValue := node.(*parse.NilNode); nilValue {
		if kind == 'b' {
			return []byte(nil), nil
		}
		if kind == 'l' {
			return (*time.Location)(nil), nil
		}
		return nil, s.fail("cannot assign nil to %s", expected)
	}
	switch n := node.(type) {
	case *parse.StringNode:
		if kind == 's' {
			return n.Text, nil
		}
	case *parse.NumberNode:
		switch kind {
		case 'i':
			if n.IsInt {
				return int(n.Int64), nil
			}
		case 'f':
			if n.IsFloat {
				return n.Float64, nil
			}
		case 'd':
			if n.IsInt {
				return time.Duration(n.Int64), nil
			}
		}
	}
	switch node.(type) {
	case *parse.StringNode, *parse.NumberNode, *parse.BoolNode:
		switch kind {
		case 's':
			return nil, s.fail("expected string; found %s", node)
		case 'i', 'd':
			return nil, s.fail("expected integer; found %s", node)
		case 'f':
			return nil, s.fail("expected float; found %s", node)
		}
		return nil, s.fail("can't handle %s for arg of type %s", node, expected)
	}
	value, e := s.atom(node, dot)
	if e != nil {
		return nil, e
	}
	return s.argumentValue(value, kind)
}
func (s *templateState) argumentValue(v any, kind byte) (any, error) {
	if kind == 'a' {
		return v, nil
	}
	valid := false
	switch kind {
	case 's':
		_, valid = v.(string)
	case 'i':
		_, valid = v.(int)
	case 'f':
		_, valid = v.(float64)
	case 't':
		_, valid = v.(time.Time)
	case 'd':
		_, valid = v.(time.Duration)
	case 'l':
		_, valid = v.(*time.Location)
		if v == nil {
			return (*time.Location)(nil), nil
		}
	case 'b':
		_, valid = v.([]byte)
		if v == nil {
			return []byte(nil), nil
		}
	}
	if valid {
		return v, nil
	}
	if v == nil {
		return nil, s.fail("invalid value; expected %s", templateParameterType(kind))
	}
	return nil, s.fail("wrong type for value; expected %s; got %s", templateParameterType(kind), templateType(v))
}

// primitiveFailure carries raw language failure data only until failure() wraps
// it with the exact source frame. It never exposes that data through Error().
type templatePrimitiveFailure struct{ reason string }

func (e *templatePrimitiveFailure) Error() string    { return "LogQL template primitive failed" }
func (e *templatePrimitiveFailure) GoString() string { return e.Error() }
func primitiveFailure(e error) error {
	if e == nil {
		return nil
	}
	return &templatePrimitiveFailure{reason: e.Error()}
}
func (s *templateState) helperFailure(name string, args []any) error {
	if e := s.reserve(1024); e != nil {
		return e
	}
	reason := ""
	switch name {
	case "div", "mod":
		reason = "runtime error: integer divide by zero"
	case "repeat", "indent", "nindent":
		reason = "strings: negative Repeat count"
	case "addf", "subf", "mulf", "divf":
		for _, v := range args {
			f := templateFloat(v)
			if f != f || f > 1.7976931348623157e308 || f < -1.7976931348623157e308 {
				reason = fmt.Sprintf("Cannot create a Decimal from %v", f)
				break
			}
		}
		if reason == "" {
			reason = "decimal division by 0"
		}
	case "substr":
		start, end, source := args[0].(int), args[1].(int), args[2].(string)
		if start < 0 {
			if end < 0 {
				reason = fmt.Sprintf("runtime error: slice bounds out of range [:%d]", end)
			} else {
				reason = fmt.Sprintf("runtime error: slice bounds out of range [:%d] with length %d", end, len(source))
			}
		} else if end < 0 || end > len(source) {
			reason = fmt.Sprintf("runtime error: slice bounds out of range [%d:%d]", start, len(source))
		} else {
			reason = fmt.Sprintf("runtime error: slice bounds out of range [%d:%d]", start, end)
		}
	}
	if reason == "" {
		return errors.New("LogQL template internal helper contract failure")
	}
	return s.fail("error calling %s: %s", name, reason)
}
func (s *templateState) call(name string, args []any) (any, error) {
	return s.callAt(name, args, s.node)
}
func (s *templateState) callAt(name string, args []any, callNode parse.Node) (any, error) {
	signature, registered := templateSignature(name)
	if !registered {
		return nil, s.fail("%q is not a defined function", name)
	}
	if e := s.arity(name, signature, len(args), len(args)); e != nil {
		return nil, e
	}
	v, e := s.invoke(name, args)
	if e == nil {
		return v, nil
	}
	var primitive *templatePrimitiveFailure
	if errors.As(e, &primitive) {
		s.node = callNode
		return nil, s.fail("error calling %s: %s", name, primitive.reason)
	}
	if e == templateBad {
		s.node = callNode
		if _, helper := templateSignatures[name]; helper {
			return nil, s.helperFailure(name, args)
		}
		return nil, s.builtinFailure(name, args)
	}
	return nil, e
}
func unixPrimitiveFailure(text string, e error) error {
	reason := "%!w(<nil>)"
	if e != nil {
		reason = e.Error()
	}
	return &templatePrimitiveFailure{reason: fmt.Sprintf("unable to parse time '%v': %s", text, reason)}
}
