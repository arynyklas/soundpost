// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"errors"
	"text/template/parse"
	"time"
)

func templateMethodSignature(receiver any, name string) (string, string) {
	switch receiver.(type) {
	case time.Time:
		switch name {
		case "Add", "Round", "Truncate":
			return "d", ""
		case "AddDate":
			return "iii", ""
		case "After", "Before", "Equal", "Compare", "Sub":
			return "t", ""
		case "Format":
			return "s", ""
		case "AppendFormat":
			return "bs", ""
		case "AppendBinary", "AppendText":
			return "b", ""
		case "In":
			return "l", ""
		case "Clock", "Date":
			return "", "three"
		case "ISOWeek", "Zone":
			return "", "second-int"
		case "ZoneBounds":
			return "", "second-time"
		case "Day", "GoString", "Hour", "IsDST", "IsZero", "Local", "Location", "MarshalBinary", "MarshalJSON", "MarshalText", "Minute", "Month", "Nanosecond", "Second", "String", "UTC", "Unix", "UnixMicro", "UnixMilli", "UnixNano", "Weekday", "Year", "YearDay":
			return "", ""
		}
	case time.Duration:
		switch name {
		case "Round", "Truncate":
			return "d", ""
		case "Abs", "Hours", "Microseconds", "Milliseconds", "Minutes", "Nanoseconds", "Seconds", "String":
			return "", ""
		}
	case time.Month, time.Weekday, *time.Location:
		if name == "String" {
			return "", ""
		}
	}
	return "", "unknown"
}
func (s *templateState) methodShape(receiver any, name string) (string, error) {
	signature, bad := templateMethodSignature(receiver, name)
	switch bad {
	case "three":
		return "", s.fail("function %s has 3 return values; should be 1 or 2", name)
	case "second-int":
		return "", s.fail("invalid function signature for %s: second return value should be error; is int", name)
	case "second-time":
		return "", s.fail("invalid function signature for %s: second return value should be error; is time.Time", name)
	case "unknown":
		switch receiver.(type) {
		case time.Time:
			if name == "wall" || name == "ext" || name == "loc" {
				return "", s.fail("%s is an unexported field of struct type time.Time", name)
			}
		case *time.Location:
			if name == "name" || name == "zone" || name == "tx" || name == "extend" || name == "cacheStart" || name == "cacheEnd" || name == "cacheZone" {
				return "", s.fail("%s is an unexported field of struct type time.Location", name)
			}
		}
		return "", s.fail("can't evaluate field %s in type %s", name, templateType(receiver))
	}
	return signature, nil
}
func (s *templateState) invokeMethod(receiver any, name string, args []any) (any, error) {
	return s.invokeMethodAt(receiver, name, args, s.node)
}
func (s *templateState) invokeMethodAt(receiver any, name string, args []any, callNode parse.Node) (any, error) {
	signature, e := s.methodShape(receiver, name)
	if e != nil {
		return nil, e
	}
	if e = s.arity(name, signature, len(args), len(args)); e != nil {
		return nil, e
	}
	if e := s.reserve(256); e != nil {
		return nil, e
	}
	var v any
	switch x := receiver.(type) {
	case time.Time:
		v, e = s.timeMethod(x, name, args)
	case time.Duration:
		v, e = s.durationMethod(x, name, args)
	case time.Month:
		v = x.String()
	case time.Weekday:
		v = x.String()
	case *time.Location:
		v = x.String()
	default:
		return nil, s.fail("can't evaluate field %s in type %s", name, templateType(receiver))
	}
	var primitive *templatePrimitiveFailure
	if errors.As(e, &primitive) {
		s.node = callNode
		return nil, s.fail("error calling %s: %s", name, primitive.reason)
	}
	if e == templateBad {
		return nil, errors.New("LogQL template internal method contract failure")
	}
	return v, e
}
func (s *templateState) methodCommand(node parse.Node, dot any, raw []parse.Node, prior any, have bool) (any, error) {
	s.node = node
	var receiver any
	var names []string
	var e error
	switch n := node.(type) {
	case *parse.FieldNode:
		receiver = dot
		names = n.Ident
	case *parse.VariableNode:
		receiver, e = s.variable(n.Ident[0])
		names = n.Ident[1:]
	case *parse.ChainNode:
		receiver, e = s.atom(n.Node, dot)
		names = n.Field
	default:
		return nil, s.fail("can't give argument to non-function %s", node)
	}
	if e != nil {
		return nil, e
	}
	if len(names) == 0 {
		return nil, s.fail("can't give argument to non-function %s", node)
	}
	var interfaceNil bool
	receiver, interfaceNil, e = s.fieldChain(receiver, names[:len(names)-1])
	if e != nil {
		return nil, e
	}
	name := names[len(names)-1]
	if interfaceNil {
		return nil, s.fail("nil pointer evaluating interface {}.%s", name)
	}
	if receiver == nil {
		return nil, nil
	}
	switch receiver.(type) {
	case map[string]any, map[string]string, templateRoot:
		return nil, s.fail("%s is not a method but has arguments", name)
	}
	signature, e := s.methodShape(receiver, name)
	if e != nil {
		return nil, e
	}
	count := len(raw)
	if have {
		count++
	}
	if e = s.arity(name, signature, count, len(raw)); e != nil {
		return nil, e
	}
	if e = s.reserve(int64(count)*24 + 64); e != nil {
		return nil, e
	}
	args := make([]any, 0, count)
	for i, n := range raw {
		v, e := s.argument(n, dot, templateParameter(signature, i))
		if e != nil {
			return nil, e
		}
		args = append(args, v)
	}
	if have {
		v, e := s.argumentValue(prior, templateParameter(signature, len(args)))
		if e != nil {
			return nil, e
		}
		args = append(args, v)
	}
	return s.invokeMethodAt(receiver, name, args, node)
}
