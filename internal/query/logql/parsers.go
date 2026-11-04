// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"soundpost/internal/query/regexcompat"
	jsonparser "soundpost/third_party/jsonparser/v1.1.1"
	"strconv"
	"strings"
)

type pathStep struct {
	key   string
	index int
	array bool
}

func jsonPath(s string) ([]pathStep, error) {
	var out []pathStep
	for len(s) > 0 {
		if s[0] == '[' {
			s = s[1:]
			if len(s) == 0 {
				return nil, errors.New("unclosed JSON path")
			}
			if s[0] == '"' {
				end := 1
				for end < len(s) {
					if s[end] == '\\' {
						end += 2
						continue
					}
					if s[end] == '"' {
						break
					}
					end++
				}
				if end >= len(s) || end+1 >= len(s) || s[end+1] != ']' {
					return nil, errors.New("invalid JSON path key")
				}
				if strings.IndexByte(s[:end+1], ']') >= 0 {
					return nil, errors.New("invalid JSON path key")
				}
				var key string
				if json.Unmarshal([]byte(s[:end+1]), &key) != nil {
					return nil, errors.New("invalid JSON path key")
				}
				out = append(out, pathStep{key: key})
				s = s[end+2:]
			} else {
				end := strings.IndexByte(s, ']')
				if end <= 0 {
					return nil, errors.New("invalid JSON index")
				}
				digits := s[:end]
				for _, c := range digits {
					if c < '0' || c > '9' {
						return nil, errors.New("invalid JSON index")
					}
				}
				i, err := strconv.Atoi(digits)
				if err != nil {
					return nil, errors.New("invalid JSON index")
				}
				out = append(out, pathStep{index: i, array: true})
				s = s[end+1:]
			}
		} else {
			end := 0
			for end < len(s) && s[end] != '.' && s[end] != '[' {
				end++
			}
			key := s[:end]
			if !validLabel(key) {
				return nil, errors.New("invalid JSON path key")
			}
			out = append(out, pathStep{key: key})
			s = s[end:]
		}
		if s == "" {
			break
		}
		if s[0] == '[' {
			continue
		}
		if s[0] != '.' {
			return nil, errors.New("invalid JSON path separator")
		}
		s = s[1:]
		if s == "" || s[0] == '[' {
			return nil, errors.New("invalid JSON path separator")
		}
	}
	if len(out) == 0 {
		return nil, errors.New("empty JSON path")
	}
	return out, nil
}

type jsonMember struct {
	name  string
	value *jsonValue
}
type jsonValue struct {
	kind      byte
	text, raw string
	object    []jsonMember
	array     []*jsonValue
}
type parserStop struct{ cause error }

func (e *parserStop) Error() string { return "query parsing interrupted" }
func (e *parserStop) Unwrap() error { return e.cause }
func stoppedParser(err error) error {
	var stop *parserStop
	if errors.As(err, &stop) {
		return stop.cause
	}
	return nil
}
func decodeJSON(line string, check func() error) (*jsonValue, error) {
	d := json.NewDecoder(strings.NewReader(line))
	d.UseNumber()
	v, err := readJSONValue(d, line, 0, check)
	if err != nil {
		return v, err
	}
	if err = check(); err != nil {
		return nil, &parserStop{err}
	}
	if _, err = d.Token(); err != io.EOF {
		return v, errors.New("trailing JSON input")
	}
	return v, nil
}
func readJSONValue(d *json.Decoder, line string, depth int, check func() error) (*jsonValue, error) {
	if err := check(); err != nil {
		return nil, &parserStop{err}
	}
	if depth > 10000 {
		return nil, errors.New("JSON nesting limit")
	}
	start := int(d.InputOffset())
	for start < len(line) && (line[start] == ' ' || line[start] == '\t' || line[start] == '\r' || line[start] == '\n' || line[start] == ':' || line[start] == ',') {
		start++
	}
	tok, err := d.Token()
	if err != nil {
		return nil, err
	}
	v := &jsonValue{}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			v.kind = 'o'
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return v, err
				}
				name, ok := key.(string)
				if !ok {
					return v, errors.New("invalid JSON key")
				}
				child, err := readJSONValue(d, line, depth+1, check)
				if child != nil {
					v.object = append(v.object, jsonMember{name, child})
				}
				if err != nil {
					return v, err
				}
			}
			if _, err = d.Token(); err != nil {
				return v, err
			}
		case '[':
			v.kind = 'a'
			for d.More() {
				child, err := readJSONValue(d, line, depth+1, check)
				if child != nil {
					v.array = append(v.array, child)
				}
				if err != nil {
					return v, err
				}
			}
			if _, err = d.Token(); err != nil {
				return v, err
			}
		default:
			return nil, errors.New("unexpected JSON delimiter")
		}
	case string:
		v.kind = 's'
		v.text = t
	case json.Number:
		v.kind = 'n'
		v.text = t.String()
	case bool:
		v.kind = 'b'
		v.text = strconv.FormatBool(t)
	case nil:
		v.kind = '0'
	default:
		return nil, errors.New("invalid JSON token")
	}
	end := int(d.InputOffset())
	if start <= end && end <= len(line) {
		v.raw = line[start:end]
	}
	return v, nil
}
func (v *jsonValue) lookup(path []pathStep) *jsonValue {
	for _, s := range path {
		if v == nil {
			return nil
		}
		if s.array {
			if v.kind != 'a' || s.index >= len(v.array) {
				return nil
			}
			v = v.array[s.index]
		} else {
			if v.kind != 'o' {
				return nil
			}
			var child *jsonValue
			for _, m := range v.object {
				if m.name == s.key {
					child = m.value
					break
				}
			}
			v = child
		}
	}
	return v
}

// parseJSONStage drives the vendored lenient streaming scanner. Labels
// extracted before a scanner error are kept and the scanner's own message is
// reported, so the observable result for any line is the scanner's.
func parseJSONStage(s Stage, e *LogEntry, check func() error) error {
	data := []byte(e.Line)
	var failure error
	if len(s.Extractions) > 0 {
		// Whole-line scan only to learn whether the input is well formed.
		failure = jsonparser.ObjectEach(data, func(_, _ []byte, _ jsonparser.ValueType, _ int) error {
			if stop := check(); stop != nil {
				return &parserStop{stop}
			}
			return nil
		})
		if stop := check(); stop != nil {
			return stop
		}
		seen := map[string]bool{}
		for _, x := range s.Extractions {
			if stop := check(); stop != nil {
				return stop
			}
			if seen[x.Name] {
				continue
			}
			seen[x.Name] = true
			path, _ := jsonPath(x.Path)
			keys := make([]string, len(path))
			for i, st := range path {
				if st.array {
					keys[i] = "[" + strconv.Itoa(st.index) + "]"
				} else {
					keys[i] = st.key
				}
			}
			text := ""
			if raw, kind, _, err := jsonparser.Get(data, keys...); err == nil {
				text = jsonValueText(raw, kind)
			}
			e.extract(x.Name, text)
		}
	} else {
		origins := map[string]string{}
		var walk func(obj []byte, prefix, sourcePrefix string, depth int) error
		walk = func(obj []byte, prefix, sourcePrefix string, depth int) error {
			if depth > jsonMaxDepth {
				return errors.New("Malformed JSON error")
			}
			return jsonparser.ObjectEach(obj, func(k, v []byte, kind jsonparser.ValueType, _ int) error {
				if stop := check(); stop != nil {
					return &parserStop{stop}
				}
				name := jsonValueText(k, jsonparser.String)
				key := sanitizeLabel(name)
				if prefix != "" {
					key = prefix + "_" + key
				}
				origin := sourcePrefix + strconv.Itoa(len(name)) + ":" + name
				switch kind {
				case jsonparser.Object:
					return walk(v, key, origin, depth+1)
				case jsonparser.String, jsonparser.Number, jsonparser.Boolean:
					previous, exists := origins[key]
					if !exists || previous == origin {
						origins[key] = origin
						e.extract(key, jsonValueText(v, kind))
					}
				}
				return nil
			})
		}
		failure = walk(data, "", "", 0)
	}
	if stop := stoppedParser(failure); stop != nil {
		return stop
	}
	if failure != nil {
		e.setError("JSONParserErr", failure.Error())
	}
	return nil
}

const jsonMaxDepth = 10000

// jsonValueText renders a scalar scanner value: strings are unescaped (an
// undecodable escape yields the empty string), everything else is verbatim.
func jsonValueText(raw []byte, kind jsonparser.ValueType) string {
	if kind != jsonparser.String {
		if kind == jsonparser.Null {
			return ""
		}
		return string(raw)
	}
	out, err := jsonparser.Unescape(raw, nil)
	if err != nil {
		return ""
	}
	return string(out)
}

type logfmtField struct{ key, value string }
type logfmtSyntaxError struct {
	position int
	reason   string
}

func (e *logfmtSyntaxError) Error() string {
	return fmt.Sprintf("logfmt syntax error at pos %d : %s", e.position, e.reason)
}
func decodeLogfmt(line string, strict bool, check func() error) ([]logfmtField, error) {
	var out []logfmtField
	var first error
	for pos := 0; pos < len(line); {
		if err := check(); err != nil {
			return nil, &parserStop{err}
		}
		for pos < len(line) && (line[pos] == ' ' || line[pos] == '\t' || line[pos] == '\r' || line[pos] == '\n') {
			pos++
		}
		if pos == len(line) {
			break
		}
		start := pos
		for pos < len(line) && line[pos] != '=' && line[pos] != ' ' && line[pos] != '\t' && line[pos] != '\r' && line[pos] != '\n' {
			pos++
		}
		key := line[start:pos]
		if key == "" || strings.ContainsAny(key, "\"\\") {
			if first == nil {
				first = errors.New("invalid logfmt key")
			}
			if strict {
				return out, first
			}
			for pos < len(line) && line[pos] != ' ' {
				pos++
			}
			continue
		}
		value := ""
		if pos < len(line) && line[pos] == '=' {
			pos++
			if pos < len(line) && line[pos] == '"' {
				start = pos
				pos++
				closed := false
				for pos < len(line) {
					if line[pos] == '\\' {
						pos += 2
						continue
					}
					if line[pos] == '"' {
						pos++
						closed = true
						break
					}
					pos++
				}
				if !closed || pos > len(line) {
					if first == nil {
						first = &logfmtSyntaxError{position: len(line) + 1, reason: "unterminated quoted value"}
					}
					if strict {
						return out, first
					}
					break
				}
				var err error
				value, err = strconv.Unquote(line[start:pos])
				if err != nil {
					if first == nil {
						first = errors.New("invalid logfmt escape")
					}
					if strict {
						return out, first
					}
					continue
				}
				if pos < len(line) && line[pos] != ' ' && line[pos] != '\t' && line[pos] != '\r' && line[pos] != '\n' {
					if first == nil {
						first = errors.New("invalid logfmt delimiter")
					}
					if strict {
						return out, first
					}
					for pos < len(line) && line[pos] != ' ' {
						pos++
					}
				}
			} else {
				start = pos
				for pos < len(line) && line[pos] != ' ' && line[pos] != '\t' && line[pos] != '\r' && line[pos] != '\n' {
					pos++
				}
				value = line[start:pos]
				if strings.ContainsAny(value, "=\"") {
					if first == nil {
						first = errors.New("invalid logfmt value")
					}
					if strict {
						return out, first
					}
					continue
				}
			}
		}
		out = append(out, logfmtField{key, value})
	}
	return out, first
}
func parseLogfmtStage(s Stage, e *LogEntry, check func() error) error {
	fields, err := decodeLogfmt(e.Line, s.Strict, check)
	if stop := stoppedParser(err); stop != nil {
		return stop
	}
	seen := map[string]bool{}
	origins := map[string]string{}
	for _, f := range fields {
		if stop := check(); stop != nil {
			return stop
		}
		if f.value == "" && !s.KeepEmpty {
			continue
		}
		if len(s.Extractions) == 0 {
			n := sanitizeLabel(f.key)
			previous, exists := origins[n]
			if n != "" && (!exists || previous == f.key) {
				e.extract(n, f.value)
				origins[n] = f.key
			}
		} else {
			for _, x := range s.Extractions {
				if x.Path == f.key && !seen[x.Name] {
					e.extract(x.Name, f.value)
					seen[x.Name] = true
				}
			}
		}
	}
	if err != nil && s.Strict {
		e.setError("LogfmtParserErr", err.Error())
	}
	return nil
}
func parseRegexpStage(ctx context.Context, c compiledStage, e *LogEntry, scope *regexcompat.Scope) error {
	indices, err := scope.FindStringSubmatchIndex(ctx, c.regex, e.Line)
	if err != nil {
		return err
	}
	if indices == nil {
		return nil
	}
	seen := map[string]bool{}
	for i, n := range c.regex.SubexpNames() {
		if i == 0 || n == "" || seen[n] || 2*i+1 >= len(indices) {
			continue
		}
		seen[n] = true
		if indices[2*i] >= 0 {
			e.extract(n, e.Line[indices[2*i]:indices[2*i+1]])
		}
	}
	return nil
}
func parsePatternStage(c compiledStage, e *LogEntry) {
	values, _ := c.pattern.match(e.Line)
	for _, part := range c.pattern.parts {
		if part.capture && part.name != "_" {
			if text, ok := values[part.name]; ok {
				e.extract(part.name, text)
			}
		}
	}
}
func parseUnpackStage(e *LogEntry, check func() error) error {
	v, err := decodeJSON(e.Line, check)
	if stop := stoppedParser(err); stop != nil {
		return stop
	}
	if err != nil || v == nil || v.kind != 'o' {
		e.setError("JSONParserErr", "Malformed JSON error")
		return nil
	}
	line := ""
	found := false
	for _, m := range v.object {
		if m.name == "_entry" && m.value.kind == 's' {
			line = m.value.text
			found = true
		}
	}
	if !found {
		return nil
	}
	origins := map[string]string{}
	for _, m := range v.object {
		if stop := check(); stop != nil {
			return stop
		}
		if m.value.kind != 's' || m.name == "_entry" {
			continue
		}
		name := sanitizeLabel(m.name)
		previous, exists := origins[name]
		if name != "" && (!exists || previous == m.name) {
			e.extract(name, m.value.text)
			origins[name] = m.name
		}
	}
	e.Line = line
	return nil
}
func decolorize(line string) string {
	if !strings.ContainsRune(line, '\x1b') {
		return line
	}
	var b strings.Builder
	b.Grow(len(line))
	for i := 0; i < len(line); {
		if line[i] != '\x1b' {
			b.WriteByte(line[i])
			i++
			continue
		}
		start := i
		i++
		if i >= len(line) {
			b.WriteString(line[start:])
			break
		}
		switch line[i] {
		case '[':
			i++
			for i < len(line) && line[i] >= 0x30 && line[i] <= 0x3f {
				i++
			}
			for i < len(line) && line[i] >= 0x20 && line[i] <= 0x2f {
				i++
			}
			if i < len(line) && line[i] >= 0x40 && line[i] <= 0x7e {
				i++
			} else {
				b.WriteString(line[start:i])
			}
		case ']':
			i++
			for i < len(line) && line[i] != 7 && !(line[i] == '\x1b' && i+1 < len(line) && line[i+1] == '\\') {
				i++
			}
			if i < len(line) && line[i] == 7 {
				i++
			} else if i+1 < len(line) {
				i += 2
			} else {
				b.WriteString(line[start:i])
			}
		default:
			if line[i] >= 0x40 && line[i] <= 0x5f {
				i++
			} else {
				b.WriteByte(line[start])
			}
		}
	}
	return b.String()
}
