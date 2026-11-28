// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import "errors"
import (
	"text/template/parse"
	"time"
)

func (s *templateState) builtinError(name, format string, args ...any) error {
	if e := s.reserve(int64(len(args)+1)*24 + 128); e != nil {
		return e
	}
	parameters := make([]any, 0, len(args)+1)
	parameters = append(parameters, name)
	parameters = append(parameters, args...)
	return s.fail("error calling %s: "+format, parameters...)
}
func templateNil(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case []byte:
		return x == nil
	case []any:
		return x == nil
	case map[string]any:
		return x == nil
	case map[string]string:
		return x == nil
	case templateRoot:
		return x == nil
	case *time.Location:
		return x == nil
	}
	return false
}
func (s *templateState) badIndex(name string, key any, limit int) (int, error) {
	if key == nil {
		return 0, s.builtinError(name, "cannot index slice/array with nil")
	}
	normalized := templateNumericKind(key)
	var index int64
	switch n := normalized.(type) {
	case int:
		index = int64(n)
	case int64:
		index = n
	case uint64:
		index = int64(n)
	default:
		return 0, s.builtinError(name, "cannot index slice/array with type %s", templateType(key))
	}
	if index < 0 || index > int64(limit) {
		return 0, s.builtinError(name, "index out of range: %d", index)
	}
	return int(index), nil
}
func (s *templateState) builtinFailure(name string, args []any) error {
	switch name {
	case "len":
		if args[0] == nil {
			return s.builtinError(name, "reflect: call of reflect.Value.Type on zero Value")
		}
		if location, ok := args[0].(*time.Location); ok {
			if location == nil {
				return s.builtinError(name, "len of nil pointer")
			}
			return s.builtinError(name, "len of type time.Location")
		}
		return s.builtinError(name, "len of type %s", templateType(args[0]))
	case "eq", "ne", "lt", "le", "gt", "ge":
		if len(args) < 2 {
			return s.builtinError(name, "missing argument for comparison")
		}
		if name != "eq" && name != "ne" {
			ka, kb := templateBasicKind(args[0]), templateBasicKind(args[1])
			if ka == 0 || kb == 0 || ka == kb && (ka == 'b' || ka == 'c') {
				return s.builtinError(name, "invalid type for comparison")
			}
		}
		first := args[0]
		for _, other := range args[1:] {
			_, _, e := templateCompare(first, other)
			if e == nil {
				continue
			}
			primitive := func(v any) bool {
				switch templateNumericKind(v).(type) {
				case bool, string, int, int64, uint64, float64, complex128:
					return true
				}
				return false
			}
			if primitive(first) || primitive(other) {
				return s.builtinError(name, "incompatible types for comparison")
			}
			if templateType(first) != templateType(other) {
				return s.builtinError(name, "non-comparable types %s: %s, %s: %v", first, templateType(first), templateType(other), other)
			}
			return s.builtinError(name, "non-comparable type %s: %s", other, templateType(other))
		}
	case "index":
		item := args[0]
		if item == nil {
			return s.builtinError(name, "index of untyped nil")
		}
		for _, key := range args[1:] {
			if item == nil {
				return s.builtinError(name, "index of nil pointer")
			}
			switch x := item.(type) {
			case map[string]any:
				if key == nil {
					return s.builtinError(name, "value is nil; should be of type string")
				}
				k, ok := key.(string)
				if !ok {
					return s.builtinError(name, "value has type %s; should be string", templateType(key))
				}
				item = x[k]
			case map[string]string:
				if key == nil {
					return s.builtinError(name, "value is nil; should be of type string")
				}
				k, ok := key.(string)
				if !ok {
					return s.builtinError(name, "value has type %s; should be string", templateType(key))
				}
				item = x[k]
			case templateRoot:
				if key == nil {
					return s.builtinError(name, "value is nil; should be of type string")
				}
				k, ok := key.(string)
				if !ok {
					return s.builtinError(name, "value has type %s; should be string", templateType(key))
				}
				v, ok := x[k]
				if !ok {
					v = ""
				}
				item = v
			case string:
				i, e := s.badIndex(name, key, len(x))
				if e != nil {
					return e
				}
				if i == len(x) {
					return s.builtinError(name, "reflect: string index out of range")
				}
				item = x[i]
			case []any:
				i, e := s.badIndex(name, key, len(x))
				if e != nil {
					return e
				}
				if i == len(x) {
					return s.builtinError(name, "reflect: slice index out of range")
				}
				item = x[i]
			case []byte:
				i, e := s.badIndex(name, key, len(x))
				if e != nil {
					return e
				}
				if i == len(x) {
					return s.builtinError(name, "reflect: slice index out of range")
				}
				item = x[i]
			case *time.Location:
				if x == nil {
					return s.builtinError(name, "index of nil pointer")
				}
				return s.builtinError(name, "can't index item of type time.Location")
			default:
				return s.builtinError(name, "can't index item of type %s", templateType(item))
			}
		}
	case "slice":
		item := args[0]
		if item == nil {
			return s.builtinError(name, "slice of untyped nil")
		}
		if len(args) > 4 {
			return s.builtinError(name, "too many slice indexes: %d", len(args)-1)
		}
		length, capacity := 0, 0
		switch x := item.(type) {
		case string:
			if len(args) == 4 {
				return s.builtinError(name, "cannot 3-index slice a string")
			}
			length = len(x)
			capacity = length
		case []any:
			length = len(x)
			capacity = cap(x)
		case []byte:
			length = len(x)
			capacity = cap(x)
		default:
			return s.builtinError(name, "can't slice item of type %s", templateType(item))
		}
		indexes := [3]int{0, length, 0}
		for i, key := range args[1:] {
			value, e := s.badIndex(name, key, capacity)
			if e != nil {
				return e
			}
			indexes[i] = value
		}
		if indexes[0] > indexes[1] {
			return s.builtinError(name, "invalid slice index: %d > %d", indexes[0], indexes[1])
		}
		if len(args) == 4 && indexes[1] > indexes[2] {
			return s.builtinError(name, "invalid slice index: %d > %d", indexes[1], indexes[2])
		}
	case "call":
		if args[0] == nil {
			return s.builtinError(name, "call of nil")
		}
		callee := ""
		if command, ok := s.node.(*parse.CommandNode); ok && len(command.Args) > 1 {
			if e := s.reserve(s.template.sourceBytes*8 + 128); e != nil {
				return e
			}
			callee = command.Args[1].String()
		} else {
			v, e := s.stringify(args[0])
			if e != nil {
				return e
			}
			callee = v
		}
		return s.builtinError(name, "non-function %s of type %s", callee, templateType(args[0]))
	}
	// A new reachable primitive failure must receive its native factual reason,
	// not be emitted as a misleading successful/partially formatted line.
	return errors.New("LogQL template internal builtin contract failure")
}
