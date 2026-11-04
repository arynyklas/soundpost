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

// jsonPath splits a JSON extraction expression into steps. Whitespace between
// tokens is insignificant (`a[ "b" ]`, `  k  `); a quoted key ends at the first
// double quote and takes no escapes, so a backslash inside it is rejected, as
// is a closing bracket.
func jsonPath(s string) ([]pathStep, error) {
	var out []pathStep
	isSpace := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
	skip := func() {
		for len(s) > 0 && isSpace(s[0]) {
			s = s[1:]
		}
	}
	afterDot := false
	needSep := false // a key or bracket was just read; a '.' or '[' must follow
	for {
		skip()
		if len(s) == 0 {
			break
		}
		switch {
		case s[0] == '[' && !afterDot:
			s = s[1:]
			skip()
			if len(s) == 0 {
				return nil, errors.New("unclosed JSON path")
			}
			if s[0] == '"' {
				end := strings.IndexByte(s[1:], '"')
				if end < 0 {
					return nil, errors.New("invalid JSON path key")
				}
				key := s[1 : 1+end]
				if strings.ContainsAny(key, "\\]") {
					return nil, errors.New("invalid JSON path key")
				}
				out = append(out, pathStep{key: key})
				s = s[end+2:]
			} else {
				end := 0
				for end < len(s) && s[end] >= '0' && s[end] <= '9' {
					end++
				}
				i, err := strconv.Atoi(s[:end])
				if end == 0 || err != nil {
					return nil, errors.New("invalid JSON index")
				}
				out = append(out, pathStep{index: i, array: true})
				s = s[end:]
			}
			skip()
			if len(s) == 0 || s[0] != ']' {
				return nil, errors.New("unclosed JSON path")
			}
			s = s[1:]
			needSep = true
		case s[0] == '.' && needSep:
			s = s[1:]
			afterDot, needSep = true, false
		case needSep:
			return nil, errors.New("invalid JSON path separator")
		default:
			end := 0
			for end < len(s) && !isSpace(s[end]) && s[end] != '.' && s[end] != '[' {
				end++
			}
			key := s[:end]
			if !validLabel(key) {
				return nil, errors.New("invalid JSON path key")
			}
			out = append(out, pathStep{key: key})
			s = s[end:]
			afterDot, needSep = false, true
		}
	}
	if afterDot {
		return nil, errors.New("invalid JSON path separator")
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

// parseJSONExpressions evaluates `| json name="path", ...` against the line
// without validating it first. The scanner walks the possibly truncated or
// malformed line once and reports each requested path it reaches:
//   - a path that is reached with a readable value sets that label;
//   - a path that is reached but whose value is malformed (an unterminated
//     array or object, an unknown literal) sets __error__ with the scanner's
//     message, and the label stays empty;
//   - a path that is never reached, or whose value cannot be located at all
//     (not-found), is an empty label and never an error;
//   - a scanner abort without a value error (stray closer before an array,
//     key syntax outside an object) is a bare JSONParserErr and stops the stage
//     before the remaining labels are filled in;
//   - an empty line produces nothing;
//   - a line whose first byte is neither '{' nor '[' (leading whitespace, a
//     byte-order mark, a no-break space) is a bare JSONParserErr with no labels.
func parseJSONExpressions(s Stage, e *LogEntry, check func() error) error {
	data := []byte(e.Line)
	if len(data) == 0 {
		return nil
	}
	if data[0] != '{' && data[0] != '[' {
		e.setError("JSONParserErr", "")
		return nil
	}
	if stop := check(); stop != nil {
		return stop
	}
	var names []string
	var paths [][]string
	seen := map[string]bool{}
	for _, x := range s.Extractions {
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
		names = append(names, x.Name)
		paths = append(paths, keys)
	}
	set := make([]bool, len(names))
	jsonparser.EachKey(data, func(idx int, raw []byte, kind jsonparser.ValueType, err error) {
		if idx < 0 {
			// A key outside the root object: the scanner reports it and
			// stops, but the requested labels still materialize.
			e.setError("JSONParserErr", err.Error())
			return
		}
		switch {
		case err == nil:
			e.putRequested(e.extractedName(names[idx]), jsonValueText(raw, kind))
			set[idx] = true
		case !errors.Is(err, jsonparser.KeyPathNotFoundError):
			e.setError("JSONParserErr", err.Error())
		}
	}, paths...)
	if stop := check(); stop != nil {
		return stop
	}
	for i, name := range names {
		if !set[i] {
			if _, held := entryLabel(e, name); !held {
				e.putRequested(name, "")
			}
		}
	}
	return nil
}

// parseJSONStage drives the vendored lenient streaming scanner. Labels
// extracted before a scanner error are kept and the scanner's own message is
// reported, so the observable result for any line is the scanner's.
func parseJSONStage(s Stage, e *LogEntry, check func() error) error {
	if len(s.Extractions) > 0 {
		return parseJSONExpressions(s, e, check)
	}
	data := []byte(e.Line)
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
			// Whitespace around a JSON key is dropped before sanitizing, at
			// every nesting level (" x-y" -> x_y; " " -> empty name).
			key := sanitizeLabel(strings.TrimSpace(name))
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
					e.putExtracted(key, jsonValueText(v, kind))
				}
			}
			return nil
		})
	}
	failure := walk(data, "", "", 0)
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
		if kind != jsonparser.Number {
			return string(raw)
		}
	}
	out, err := jsonparser.Unescape(raw, nil)
	if err != nil {
		return ""
	}
	return string(out)
}

// lone marks a value that held an unpaired UTF-16 surrogate escape: plain
// extraction sees a space where it stood, expression extraction sees an empty
// value.
type logfmtField struct {
	key, value string
	lone       bool
}
type logfmtSyntaxError struct {
	position int
	reason   string
}

func (e *logfmtSyntaxError) Error() string {
	return fmt.Sprintf("logfmt syntax error at pos %d : %s", e.position, e.reason)
}

// scanLogfmtPair reads one key[=value] token starting at pos (which is already
// past any whitespace). On success it returns the pair and the offset where the
// next scan starts (a quoted value needs no separator after its closing quote).
// On a syntax error it returns the error and the offset of the cursor at the
// time of the failure; the reported position is that cursor plus one, where the
// cursor is the offending byte for unexpected-byte errors, the end of the line
// for an unterminated quote and the byte after the closing quote for an
// invalid quoted value.
func scanLogfmtPair(line string, pos int) (logfmtField, int, *logfmtSyntaxError) {
	n := len(line)
	start := pos
	for pos < n && line[pos] > ' ' && line[pos] != '=' && line[pos] != '"' {
		pos++
	}
	if pos < n && line[pos] == '"' {
		return logfmtField{}, pos, &logfmtSyntaxError{pos + 1, "unexpected '\"'"}
	}
	if pos < n && line[pos] == '=' && pos == start {
		return logfmtField{}, pos, &logfmtSyntaxError{pos + 1, "unexpected '='"}
	}
	key := line[start:pos]
	if pos >= n || line[pos] != '=' {
		return logfmtField{key: key}, pos, nil
	}
	pos++
	if pos >= n || line[pos] <= ' ' {
		return logfmtField{key: key}, pos, nil
	}
	switch line[pos] {
	case '=':
		return logfmtField{}, pos, &logfmtSyntaxError{pos + 1, "unexpected '='"}
	case '"':
		i := pos + 1
		for i < n && line[i] != '"' {
			if line[i] == '\\' {
				i++
			}
			i++
		}
		if i >= n {
			return logfmtField{}, n, &logfmtSyntaxError{n + 1, "unterminated quoted value"}
		}
		value, lone, ok := unquoteLogfmt(line[pos+1 : i])
		if !ok {
			return logfmtField{}, i + 1, &logfmtSyntaxError{i + 2, "invalid quoted value"}
		}
		return logfmtField{key, value, lone}, i + 1, nil
	}
	vstart := pos
	for pos < n && line[pos] > ' ' {
		if line[pos] == '=' || line[pos] == '"' {
			return logfmtField{}, pos, &logfmtSyntaxError{pos + 1, "unexpected '" + line[pos:pos+1] + "'"}
		}
		pos++
	}
	return logfmtField{key: key, value: line[vstart:pos]}, pos, nil
}

// unquoteLogfmt decodes the body of a double-quoted logfmt value using JSON
// escape rules (\" \\ \/ \b \f \n \r \t \uXXXX); an unpaired surrogate
// becomes a space and sets the second result. Raw control bytes are kept.
func unquoteLogfmt(s string) (string, bool, bool) {
	if strings.IndexByte(s, '\\') < 0 {
		return s, false, true
	}
	lone := false
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(s) {
			return "", false, false
		}
		switch s[i] {
		case '"', '\\', '/':
			b.WriteByte(s[i])
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'u':
			r, ok := hex4(s[i+1:])
			if !ok {
				return "", false, false
			}
			i += 4
			if r >= 0xD800 && r < 0xE000 {
				low, ok := rune(0), false
				if r < 0xDC00 && strings.HasPrefix(s[i+1:], `\u`) {
					low, ok = hex4(s[i+3:])
				}
				if ok && low >= 0xDC00 && low < 0xE000 {
					r = 0x10000 + (r-0xD800)<<10 + (low - 0xDC00)
					i += 6
				} else {
					r = ' '
					lone = true
				}
			}
			b.WriteRune(r)
		default:
			return "", false, false
		}
	}
	return b.String(), lone, true
}

func hex4(s string) (rune, bool) {
	if len(s) < 4 {
		return 0, false
	}
	var r rune
	for i := range 4 {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			c -= '0'
		case c >= 'a' && c <= 'f':
			c = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			c = c - 'A' + 10
		default:
			return 0, false
		}
		r = r<<4 | rune(c)
	}
	return r, true
}

// decodeLogfmt tokenizes the line. Strict mode stops at the first syntax error
// and returns it together with the pairs read before it. Lenient mode drops the
// failing token, skips to the next whitespace byte and keeps going; its error
// return is always nil because the reference reports nothing for lenient lines.
func decodeLogfmt(line string, strict bool, check func() error) ([]logfmtField, error) {
	var out []logfmtField
	for pos := 0; ; {
		if err := check(); err != nil {
			return nil, &parserStop{err}
		}
		for pos < len(line) && line[pos] <= ' ' {
			pos++
		}
		if pos >= len(line) {
			return out, nil
		}
		f, next, serr := scanLogfmtPair(line, pos)
		if serr != nil {
			if strict {
				return out, serr
			}
			for next < len(line) && line[next] > ' ' {
				next++
			}
		} else {
			out = append(out, f)
		}
		pos = next
	}
}
func parseLogfmtStage(s Stage, e *LogEntry, check func() error) error {
	fields, err := decodeLogfmt(e.Line, s.Strict, check)
	if stop := stoppedParser(err); stop != nil {
		return stop
	}
	if len(s.Extractions) > 0 {
		stopped, stop := parseLogfmtRequests(s, e, fields, check)
		if stop != nil {
			return stop
		}
		if stopped {
			err = nil
		}
	} else {
		origins := map[string]string{}
		for _, f := range fields {
			if stop := check(); stop != nil {
				return stop
			}
			if f.value == "" && !s.KeepEmpty {
				continue
			}
			n := sanitizeLabel(f.key)
			previous, exists := origins[n]
			if n != "" && (!exists || previous == f.key) {
				e.putExtracted(n, f.value)
				origins[n] = f.key
			}
		}
	}
	if err != nil {
		e.setError("LogfmtParserErr", err.Error())
	}
	return nil
}

// parseLogfmtRequests evaluates `| logfmt name="key", ...`. A line key feeds the
// label whose requested path first claimed it (request order). A key that no
// request names as a path falls back to the label of that final name (after a
// stream-collision rename), so a label's own name never steals a key another
// label requested by path. Every later occurrence of a key overwrites its label
// (the last wins), except that a renamed label keeps its first value and a
// second write to it ends the scan (see labelbuilder.go). A label that no key
// reached is set empty unless it collides with the stream namespace. The result
// reports whether the scan ended early.
func parseLogfmtRequests(s Stage, e *LogEntry, fields []logfmtField, check func() error) (bool, error) {
	target := make(map[string]string, 2*len(s.Extractions))
	for _, x := range s.Extractions {
		if _, taken := target[x.Path]; !taken {
			target[x.Path] = x.Name
		}
	}
	for _, x := range s.Extractions {
		if _, taken := target[x.Name]; !taken {
			target[x.Name] = x.Name
		}
		if k := e.extractedName(x.Name); k != x.Name {
			if _, taken := target[k]; !taken {
				target[k] = x.Name
			}
		}
	}
	requested := make(map[string]bool, len(s.Extractions))
	for _, x := range s.Extractions {
		requested[x.Name] = true
	}
	keys := make([]string, len(fields))
	for i, f := range fields {
		keys[i] = e.shadowedKey(f.key, requested)
	}
	reached := make(map[string]bool, len(s.Extractions))
	stopped := false
	for i, f := range fields {
		if stop := check(); stop != nil {
			return false, stop
		}
		name, ok := target[keys[i]]
		if !ok {
			continue
		}
		final := e.extractedName(name)
		if final != name && labelPresent(e.ParsedLabels, final) {
			stopped = true
			break
		}
		value := f.value
		if f.lone {
			value = ""
		}
		e.putRequested(final, value)
		reached[name] = true
	}
	for _, x := range s.Extractions {
		if !reached[x.Name] && !e.streamHas(x.Name) {
			e.putRequested(x.Name, "")
		}
	}
	return stopped, nil
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
