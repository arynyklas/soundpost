// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	fmt "github.com/arynyklas/soundpost/third_party/format/go124/fmt"
	strconv "github.com/arynyklas/soundpost/third_party/format/go124/strconv"
	u15 "github.com/arynyklas/soundpost/third_party/regex/go124/unicode"
	"math"
	"net/url"
	"strings"
	"text/template"
	"time"
	"unicode/utf8"
)

func templateIndex(v any) (int, error) {
	v = templateNumericKind(v)
	switch x := v.(type) {
	case int:
		if x >= 0 {
			return x, nil
		}
	case int64:
		if x >= 0 && int64(int(x)) == x {
			return int(x), nil
		}
	case uint64:
		if x <= uint64(math.MaxInt) {
			return int(x), nil
		}
	}
	return 0, templateBad
}
func templateNumericKind(v any) any {
	switch x := v.(type) {
	case time.Month:
		return int64(x)
	case time.Weekday:
		return int64(x)
	case time.Duration:
		return int64(x)
	case uint8:
		return uint64(x)
	}
	return v
}
func templateBasicKind(v any) byte {
	switch templateNumericKind(v).(type) {
	case int, int64:
		return 'i'
	case uint64:
		return 'u'
	case float64:
		return 'f'
	case string:
		return 's'
	case bool:
		return 'b'
	case complex128:
		return 'c'
	}
	return 0
}
func templateCompare(a, b any) (int, bool, error) {
	// Equality between unequal scalar kinds follows Go template's integer exception,
	// not loose string/numeric coercion. JSON numbers stay float64.
	a, b = templateNumericKind(a), templateNumericKind(b)
	if a == nil || b == nil {
		return 0, templateNil(a) && templateNil(b), nil
	}
	if templateType(a) == templateType(b) && templateNil(a) && templateNil(b) {
		return 0, true, nil
	}
	signed := func(v any) (int64, bool) {
		switch x := v.(type) {
		case int:
			return int64(x), true
		case int64:
			return x, true
		}
		return 0, false
	}
	if ai, ok := signed(a); ok {
		if bi, ok := signed(b); ok {
			if ai < bi {
				return -1, false, nil
			}
			if ai > bi {
				return 1, false, nil
			}
			return 0, true, nil
		}
		if bu, ok := b.(uint64); ok {
			if ai < 0 || uint64(ai) < bu {
				return -1, false, nil
			}
			if uint64(ai) > bu {
				return 1, false, nil
			}
			return 0, true, nil
		}
		return 0, false, templateBad
	}
	if au, ok := a.(uint64); ok {
		if bi, ok := signed(b); ok {
			c, eq, e := templateCompare(b, a)
			_ = bi
			return -c, eq, e
		}
		if bu, ok := b.(uint64); ok {
			if au < bu {
				return -1, false, nil
			}
			if au > bu {
				return 1, false, nil
			}
			return 0, true, nil
		}
		return 0, false, templateBad
	}
	switch x := a.(type) {
	case nil:
		if b == nil {
			return 0, true, nil
		}
		return 0, false, nil
	case string:
		y, ok := b.(string)
		if !ok {
			return 0, false, templateBad
		}
		return strings.Compare(x, y), x == y, nil
	case bool:
		y, ok := b.(bool)
		if !ok {
			return 0, false, templateBad
		}
		if x == y {
			return 0, true, nil
		}
		return 0, false, nil
	case float64:
		y, ok := b.(float64)
		if !ok {
			return 0, false, templateBad
		}
		if math.IsNaN(x) || math.IsNaN(y) {
			return 0, false, nil
		}
		if x < y {
			return -1, false, nil
		}
		if x > y {
			return 1, false, nil
		}
		return 0, true, nil
	case complex128:
		y, ok := b.(complex128)
		if !ok {
			return 0, false, templateBad
		}
		return 0, x == y, nil
	case time.Time:
		y, ok := b.(time.Time)
		if !ok {
			return 0, false, templateBad
		}
		return 0, x == y, nil
	case *time.Location:
		y, ok := b.(*time.Location)
		if !ok {
			return 0, false, templateBad
		}
		return 0, x == y, nil
	case map[string]any, map[string]string, templateRoot, []any, []byte:
		if b == nil {
			return 0, false, nil
		}
		return 0, false, templateBad
	}
	return 0, false, templateBad
}
func (s *templateState) builtin(name string, args []any) (any, error) {
	for i, a := range args {
		v, e := templateDefault(a)
		if e != nil {
			return nil, e
		}
		args[i] = v
	}
	switch name {
	case "not":
		if len(args) != 1 {
			return nil, templateBad
		}
		return !templateTruth(args[0]), nil
	case "len":
		if len(args) != 1 {
			return nil, templateBad
		}
		switch x := args[0].(type) {
		case string:
			return len(x), nil
		case []any:
			return len(x), nil
		case []byte:
			return len(x), nil
		case map[string]any:
			return len(x), nil
		case map[string]string:
			return len(x), nil
		case templateRoot:
			return len(x), nil
		}
		return nil, templateBad
	case "eq", "ne", "lt", "le", "gt", "ge":
		if len(args) < 2 || name != "eq" && len(args) != 2 {
			return nil, templateBad
		}
		if name != "eq" && name != "ne" {
			ka, kb := templateBasicKind(args[0]), templateBasicKind(args[1])
			if ka == 0 || kb == 0 || ka == kb && (ka == 'b' || ka == 'c') {
				return nil, templateBad
			}
		}
		for _, b := range args[1:] {
			if e := s.charge(1); e != nil {
				return nil, e
			}
			// A comparison reads both operands.
			for _, operand := range []any{args[0], b} {
				if text, ok := operand.(string); ok {
					if e := s.stringWork(text); e != nil {
						return nil, e
					}
				}
			}
			cmp, equal, e := templateCompare(args[0], b)
			if e != nil {
				return nil, e
			}
			switch name {
			case "eq":
				if equal {
					return true, nil
				}
			case "ne":
				return !equal, nil
			case "lt", "le", "gt", "ge":
				switch name {
				case "lt":
					return cmp < 0, nil
				case "le":
					return cmp < 0 || equal, nil
				case "gt":
					return !(cmp < 0 || equal), nil
				case "ge":
					return !(cmp < 0), nil
				}
			}
		}
		return false, nil
	case "index":
		if len(args) < 1 {
			return nil, templateBad
		}
		v := args[0]
		if v == nil {
			return nil, templateBad
		}
		for _, key := range args[1:] {
			if e := s.charge(1); e != nil {
				return nil, e
			}
			switch x := v.(type) {
			case templateRoot:
				k, ok := key.(string)
				if !ok {
					return nil, templateBad
				}
				var exists bool
				v, exists = x[k]
				if !exists {
					v = ""
				}
			case map[string]string:
				k, ok := key.(string)
				if !ok {
					return nil, templateBad
				}
				v = x[k]
			case map[string]any:
				k, ok := key.(string)
				if !ok {
					return nil, templateBad
				}
				v = x[k]
			case []any:
				i, e := templateIndex(key)
				if e != nil || i >= len(x) {
					return nil, templateBad
				}
				v = x[i]
			case []byte:
				i, e := templateIndex(key)
				if e != nil || i >= len(x) {
					return nil, templateBad
				}
				v = x[i]
			case string:
				i, e := templateIndex(key)
				if e != nil || i >= len(x) {
					return nil, templateBad
				}
				v = x[i]
			default:
				return nil, templateBad
			}
		}
		return v, nil
	case "slice":
		if len(args) < 1 || len(args) > 4 {
			return nil, templateBad
		}
		length, capacity := 0, 0
		switch x := args[0].(type) {
		case string:
			length = len(x)
			capacity = length
			if len(args) == 4 {
				return nil, templateBad
			}
		case []any:
			length = len(x)
			capacity = cap(x)
		case []byte:
			length = len(x)
			capacity = cap(x)
		default:
			return nil, templateBad
		}
		lo, hi, capLimit := 0, length, capacity
		bounds := []*int{&lo, &hi, &capLimit}
		for i, a := range args[1:] {
			v, e := templateIndex(a)
			if e != nil {
				return nil, e
			}
			*bounds[i] = v
		}
		if lo > hi || hi > capLimit || capLimit > capacity {
			return nil, templateBad
		}
		switch x := args[0].(type) {
		case string:
			return x[lo:hi], nil
		case []any:
			if len(args) == 4 {
				return x[lo:hi:capLimit], nil
			}
			return x[lo:hi], nil
		case []byte:
			if len(args) == 4 {
				return x[lo:hi:capLimit], nil
			}
			return x[lo:hi], nil
		}
	case "call":
		return nil, templateBad // No caller-supplied function values exist in the closed value domain.
	case "print", "println", "printf":
		return s.format(name, args)
	case "html", "js", "urlquery":
		text, e := s.format("print", args)
		if e != nil {
			return nil, e
		}
		str := text.(string)
		if e = s.reserve(int64(len(str))*12 + 64); e != nil {
			return nil, e
		}
		switch name {
		case "html":
			return template.HTMLEscapeString(str), nil
		case "js":
			return templateJSEscape(str), nil
		case "urlquery":
			return url.QueryEscape(str), nil
		}
	}
	return nil, templateBad
}
func (s *templateState) format(name string, args []any) (any, error) {
	for i, a := range args {
		if root, ok := a.(templateRoot); ok {
			args[i] = map[string]any(root)
		}
	}
	if name == "printf" {
		if len(args) == 0 {
			return nil, templateBad
		}
		format, ok := args[0].(string)
		if !ok {
			return nil, templateBad
		}
		bytes, e := s.printfAdmission(format, args[1:], 128+int64(len(format))*8)
		if e != nil {
			return nil, e
		}
		if e = s.reserve(bytes); e != nil {
			return nil, e
		}
		return fmt.Sprintf(format, args[1:]...), nil
	}
	size := int64(128)
	for _, a := range args {
		n, e := s.valueSize(a, 0)
		if e != nil {
			return nil, e
		}
		size += n
		if size > templateMaxBytes/2 {
			return nil, &TemplateLimitError{Resource: "intermediate"}
		}
	}
	if e := s.reserve(size*2 + 1024); e != nil {
		return nil, e
	}
	if name == "println" {
		return fmt.Sprintln(args...), nil
	}
	return fmt.Sprint(args...), nil
}

// Only this closed method table can operate on time values produced by audited
// helpers. No reflect.Method, input object, mutation method or function escapes.
func (s *templateState) timeMethod(t time.Time, name string, args []any) (any, error) {
	if e := s.charge(1); e != nil {
		return nil, e
	}
	noargs := func() error {
		if len(args) != 0 {
			return templateBad
		}
		return nil
	}
	switch name {
	case "Add":
		if len(args) != 1 {
			return nil, templateBad
		}
		n, ok := templateDurationArg(args[0])
		if !ok {
			return nil, templateBad
		}
		return t.Add(n), nil
	case "AddDate":
		if templateArgs("iii", args) != nil {
			return nil, templateBad
		}
		return t.AddDate(args[0].(int), args[1].(int), args[2].(int)), nil
	case "After", "Before", "Equal", "Compare", "Sub":
		if templateArgs("t", args) != nil {
			return nil, templateBad
		}
		other := args[0].(time.Time)
		switch name {
		case "After":
			return t.After(other), nil
		case "Before":
			return t.Before(other), nil
		case "Equal":
			return t.Equal(other), nil
		case "Compare":
			return t.Compare(other), nil
		case "Sub":
			return t.Sub(other), nil
		}
	case "Format":
		if templateArgs("s", args) != nil {
			return nil, templateBad
		}
		layout := args[0].(string)
		if e := s.reserve(int64(len(layout))*64 + 256); e != nil {
			return nil, e
		}
		return t.Format(layout), nil
	case "AppendFormat":
		if len(args) != 2 {
			return nil, templateBad
		}
		buf, ok := args[0].([]byte)
		if !ok && args[0] != nil {
			return nil, templateBad
		}
		layout, ok := args[1].(string)
		if !ok {
			return nil, templateBad
		}
		if e := s.reserve(int64(len(buf))*2 + int64(len(layout))*128 + 512); e != nil {
			return nil, e
		}
		return t.AppendFormat(buf, layout), nil
	case "AppendBinary", "AppendText":
		if len(args) != 1 {
			return nil, templateBad
		}
		buf, ok := args[0].([]byte)
		if !ok && args[0] != nil {
			return nil, templateBad
		}
		if e := s.reserve(int64(len(buf))*2 + 512); e != nil {
			return nil, e
		}
		var out []byte
		var e error
		if name == "AppendBinary" {
			out, e = t.AppendBinary(buf)
		} else {
			out, e = t.AppendText(buf)
		}
		if e != nil {
			return nil, primitiveFailure(e)
		}
		return out, nil
	case "In":
		if len(args) != 1 {
			return nil, templateBad
		}
		location, ok := args[0].(*time.Location)
		if !ok {
			return nil, templateBad
		}
		if location == nil {
			return nil, &templatePrimitiveFailure{reason: "time: missing Location in call to Time.In"}
		}
		return t.In(location), nil
	case "Round", "Truncate":
		if len(args) != 1 {
			return nil, templateBad
		}
		d, ok := templateDurationArg(args[0])
		if !ok {
			return nil, templateBad
		}
		if name == "Round" {
			return t.Round(d), nil
		}
		return t.Truncate(d), nil
	}
	if e := noargs(); e != nil {
		return nil, e
	}
	switch name {
	case "Day":
		return t.Day(), nil
	case "GoString":
		if e := s.reserve(512); e != nil {
			return nil, e
		}
		return t.GoString(), nil
	case "Hour":
		return t.Hour(), nil
	case "IsDST":
		return t.IsDST(), nil
	case "IsZero":
		return t.IsZero(), nil
	case "Local":
		return t.In(s.template.runtime.Location), nil
	case "Location":
		return t.Location(), nil
	case "MarshalBinary":
		if e := s.reserve(128); e != nil {
			return nil, e
		}
		b, e := t.MarshalBinary()
		if e != nil {
			return nil, primitiveFailure(e)
		}
		return b, nil
	case "MarshalJSON":
		if e := s.reserve(256); e != nil {
			return nil, e
		}
		b, e := t.MarshalJSON()
		if e != nil {
			return nil, primitiveFailure(e)
		}
		return b, nil
	case "MarshalText":
		if e := s.reserve(256); e != nil {
			return nil, e
		}
		b, e := t.MarshalText()
		if e != nil {
			return nil, primitiveFailure(e)
		}
		return b, nil
	case "Minute":
		return t.Minute(), nil
	case "Month":
		return t.Month(), nil
	case "Nanosecond":
		return t.Nanosecond(), nil
	case "Second":
		return t.Second(), nil
	case "String":
		if e := s.reserve(256); e != nil {
			return nil, e
		}
		return t.String(), nil
	case "UTC":
		return t.UTC(), nil
	case "Unix":
		return t.Unix(), nil
	case "UnixMicro":
		return t.UnixMicro(), nil
	case "UnixMilli":
		return t.UnixMilli(), nil
	case "UnixNano":
		return t.UnixNano(), nil
	case "Weekday":
		return t.Weekday(), nil
	case "Year":
		return t.Year(), nil
	case "YearDay":
		return t.YearDay(), nil
		// Clock/Date/ISOWeek/Zone/ZoneBounds have multiple non-error results. Native
		// text/template rejects those method signatures; do not turn them into lists.
	}
	return nil, templateBad
}
func templateDurationArg(v any) (time.Duration, bool) {
	switch x := v.(type) {
	case templateLiteral:
		if x.number.IsInt {
			return time.Duration(x.number.Int64), true
		}
	case time.Duration:
		return x, true
	}
	return 0, false
}
func (s *templateState) durationMethod(d time.Duration, name string, args []any) (any, error) {
	if e := s.charge(1); e != nil {
		return nil, e
	}
	if name == "Round" || name == "Truncate" {
		if len(args) != 1 {
			return nil, templateBad
		}
		unit, ok := templateDurationArg(args[0])
		if !ok {
			return nil, templateBad
		}
		if name == "Round" {
			return d.Round(unit), nil
		}
		return d.Truncate(unit), nil
	}
	if len(args) != 0 {
		return nil, templateBad
	}
	switch name {
	case "Abs":
		return d.Abs(), nil
	case "Hours":
		return d.Hours(), nil
	case "Microseconds":
		return d.Microseconds(), nil
	case "Milliseconds":
		return d.Milliseconds(), nil
	case "Minutes":
		return d.Minutes(), nil
	case "Nanoseconds":
		return d.Nanoseconds(), nil
	case "Seconds":
		return d.Seconds(), nil
	case "String":
		if e := s.reserve(128); e != nil {
			return nil, e
		}
		return d.String(), nil
	}
	return nil, templateBad
}

// Independently authored escaping for the pinned observable JS-string primitive.
// Hex digits are uppercase, control bytes use four digits, and non-printing
// non-BMP runes retain the primitive's minimum-four-digit (not surrogate) form.
func templateJSEscape(text string) string {
	var out strings.Builder
	out.Grow(len(text))
	for position := 0; position < len(text); {
		r, width := utf8.DecodeRuneInString(text[position:])
		original := text[position : position+width]
		position += width
		if r >= 128 && u15.IsPrint(r) {
			out.WriteString(original)
			continue
		}
		escape := ""
		switch r {
		case '\\':
			escape = `\\`
		case '\'':
			escape = `\'`
		case '"':
			escape = `\"`
		case '<':
			escape = `\u003C`
		case '>':
			escape = `\u003E`
		case '&':
			escape = `\u0026`
		case '=':
			escape = `\u003D`
		}
		if escape != "" {
			out.WriteString(escape)
			continue
		}
		if r < 32 || r >= 128 {
			out.WriteString(`\u`)
			hex := strconv.FormatUint(uint64(r), 16)
			for range max(0, 4-len(hex)) {
				out.WriteByte('0')
			}
			for _, digit := range hex {
				if digit >= 'a' && digit <= 'f' {
					digit -= 'a' - 'A'
				}
				out.WriteRune(digit)
			}
		} else {
			out.WriteString(original)
		}
	}
	return out.String()
}
