// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"errors"
	"fmt"
	"runtime"
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
	var unsafe []bool
	seen := map[string]bool{}
	for _, x := range s.Extractions {
		if seen[x.Name] {
			continue
		}
		seen[x.Name] = true
		path, _ := jsonPath(x.Path)
		keys := make([]string, len(path))
		risky := false
		for i, st := range path {
			if st.array {
				keys[i] = "[" + strconv.Itoa(st.index) + "]"
			} else {
				keys[i] = st.key
				// The vendored scanner reads the first byte of a path key at
				// every array it enters; an empty key has none.
				risky = risky || st.key == ""
			}
		}
		names = append(names, x.Name)
		paths = append(paths, keys)
		unsafe = append(unsafe, risky)
	}
	lb := newStageLabels(e)
	defer lb.flush()
	set := make([]bool, len(names))
	deliver := func(idx int, raw []byte, kind jsonparser.ValueType, err error) {
		if idx < 0 {
			// A key outside the root object: the scanner reports it and
			// stops, but the requested labels still materialize.
			e.setError("JSONParserErr", err.Error())
			return
		}
		switch {
		case err == nil:
			lb.putRequested(lb.extractedName(names[idx]), jsonValueText(raw, kind))
			set[idx] = true
		case !errors.Is(err, jsonparser.KeyPathNotFoundError):
			e.setError("JSONParserErr", err.Error())
		}
	}
	// Paths without an empty key are scanned together, exactly as one request.
	// A path with an empty key is scanned alone so that a scanner fault is
	// confined to that path: the reference reads such a path as a key that is
	// absent from an array (an empty label), and its own scanner faults only
	// where the empty key follows an array index, which is reported as the
	// stage's malformed-JSON error. Any fault of the scanner is contained here.
	var safeIdx []int
	var safePaths [][]string
	for i := range names {
		if !unsafe[i] {
			safeIdx = append(safeIdx, i)
			safePaths = append(safePaths, paths[i])
		}
	}
	if len(safePaths) > 0 {
		fault := guardScanner(func() {
			jsonparser.EachKey(data, func(idx int, raw []byte, kind jsonparser.ValueType, err error) {
				if idx >= 0 {
					idx = safeIdx[idx]
				}
				deliver(idx, raw, kind, err)
			}, safePaths...)
		})
		if fault.happened {
			e.setError("JSONParserErr", errScannerFault)
		}
	}
	for i := range names {
		if !unsafe[i] {
			continue
		}
		if stop := check(); stop != nil {
			return stop
		}
		i := i
		fault := guardScanner(func() {
			jsonparser.EachKey(data, func(idx int, raw []byte, kind jsonparser.ValueType, err error) {
				if idx >= 0 {
					idx = i
				}
				deliver(idx, raw, kind, err)
			}, paths[i])
		})
		if fault.nested {
			e.setError("JSONParserErr", errScannerFault)
		}
	}
	if stop := check(); stop != nil {
		return stop
	}
	for i, name := range names {
		if !set[i] && !lb.has(name) {
			lb.putRequested(name, "")
		}
	}
	return nil
}

// errScannerFault is the stage error for a line on which the vendored scanner
// faulted (a Go panic inside it): the scanner's own malformed-input message.
const errScannerFault = "Malformed JSON error"

// scannerFault describes a Go panic inside the vendored scanner.
type scannerFault struct {
	// happened is set when the scanner panicked.
	happened bool
	// nested is set when the panic was raised by the scanner's recursive
	// key search into an array element (searchKeys), the one place where the
	// reference scanner itself faults on an empty path key.
	nested bool
}

// guardScanner runs one call into the vendored scanner and reports whether it
// panicked. No scanner fault may leave the query engine.
func guardScanner(fn func()) (fault scannerFault) {
	defer func() {
		if recover() == nil {
			return
		}
		fault.happened = true
		pcs := make([]uintptr, 32)
		frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
		for {
			frame, more := frames.Next()
			if strings.HasSuffix(frame.Function, "jsonparser/v1%2e1%2e1.searchKeys") {
				fault.nested = true
				break
			}
			if !more {
				break
			}
		}
	}()
	fn()
	return fault
}

// jsonWalker is the plain `| json` walk. Names are composed in one reusable
// buffer (append, then truncate when a level closes), so a deep object costs
// O(line) to walk; every retained key, origin and value is charged before it
// is allocated.
type jsonWalker struct {
	lb       *stageLabels
	check    func() error
	charge   func(int64) error
	key      []byte // composed label name of the current member
	origin   []byte // length-prefixed raw names of the current member
	origins  map[string]string
	maxDepth int
}

var errMalformedJSON = errors.New("Malformed JSON error")

func (w *jsonWalker) walk(obj []byte, depth int) error {
	if depth > w.maxDepth {
		return errMalformedJSON
	}
	return jsonparser.ObjectEach(obj, func(k, v []byte, kind jsonparser.ValueType, _ int) error {
		if stop := w.check(); stop != nil {
			return &parserStop{stop}
		}
		name := jsonValueText(k, jsonparser.String)
		keyMark, originMark := len(w.key), len(w.origin)
		// Whitespace around a JSON key is dropped before sanitizing, at
		// every nesting level (" x-y" -> x_y; " " -> empty name).
		if keyMark > 0 {
			w.key = append(w.key, '_')
		}
		w.key = append(w.key, sanitizeLabel(strings.TrimSpace(name))...)
		w.origin = strconv.AppendInt(w.origin, int64(len(name)), 10)
		w.origin = append(w.origin, ':')
		w.origin = append(w.origin, name...)
		defer func() { w.key, w.origin = w.key[:keyMark], w.origin[:originMark] }()
		switch kind {
		case jsonparser.Object:
			return w.walk(v, depth+1)
		case jsonparser.String, jsonparser.Number, jsonparser.Boolean:
			previous, exists := w.origins[string(w.key)]
			if exists && previous != string(w.origin) {
				return nil
			}
			text := jsonValueText(v, kind)
			cost := int64(len(w.key)) + int64(len(text)) + 96
			if !exists {
				cost += int64(len(w.origin)) + 64
			}
			if err := w.charge(cost); err != nil {
				return &parserStop{err}
			}
			label := string(w.key)
			if !exists {
				w.origins[label] = string(w.origin)
			}
			w.lb.putExtracted(label, text)
		}
		return nil
	})
}

// parseJSONStage drives the vendored lenient streaming scanner. Labels
// extracted before a scanner error are kept and the scanner's own message is
// reported, so the observable result for any line is the scanner's.
func parseJSONStage(s Stage, e *LogEntry, check func() error, charge func(int64) error) error {
	if len(s.Extractions) > 0 {
		return parseJSONExpressions(s, e, check)
	}
	lb := newStageLabels(e)
	defer lb.flush()
	w := &jsonWalker{lb: lb, check: check, charge: charge, origins: map[string]string{}, maxDepth: min(jsonMaxDepth, len(e.Line)/4+1)}
	var failure error
	if guardScanner(func() { failure = w.walk([]byte(e.Line), 0) }).happened {
		failure = errMalformedJSON
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
		if kind != jsonparser.Number {
			return string(raw)
		}
	}
	var out []byte
	var err error
	if guardScanner(func() { out, err = jsonparser.Unescape(raw, nil) }).happened || err != nil {
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
		lb := newStageLabels(e)
		defer lb.flush()
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
				lb.putExtracted(n, f.value)
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
	lb := newStageLabels(e)
	defer lb.flush()
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
		if k := lb.extractedName(x.Name); k != x.Name {
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
		keys[i] = lb.shadowedKey(f.key, requested)
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
		final := lb.extractedName(name)
		if final != name && lb.hasParsed(final) {
			stopped = true
			break
		}
		value := f.value
		if f.lone {
			value = ""
		}
		lb.putRequested(final, value)
		reached[name] = true
	}
	for _, x := range s.Extractions {
		if !reached[x.Name] && !lb.streamHas(x.Name) {
			lb.putRequested(x.Name, "")
		}
	}
	return stopped, nil
}

// parseRegexpStage writes one label per named group in group order. A group
// that does not take part in the match (an alternative or optional group that
// was not used) is written as the empty string, exactly like a group that
// matched nothing; a line the expression does not match writes nothing.
func parseRegexpStage(ctx context.Context, c compiledStage, e *LogEntry, scope *regexcompat.Scope, check func() error) error {
	indices, err := scope.FindStringSubmatchIndex(ctx, c.regex, e.Line)
	if err != nil {
		return err
	}
	if indices == nil {
		return nil
	}
	w := newStageLabels(e)
	defer w.flush()
	for i, n := range c.regex.SubexpNames() {
		if i&255 == 0 {
			if err := check(); err != nil {
				return err
			}
		}
		if i == 0 || n == "" || 2*i+1 >= len(indices) {
			continue
		}
		value := ""
		if indices[2*i] >= 0 {
			value = e.Line[indices[2*i]:indices[2*i+1]]
		}
		w.capture(n, value)
	}
	return nil
}
func parsePatternStage(c compiledStage, e *LogEntry, check func() error) error {
	values, _ := c.pattern.match(e.Line)
	w := newStageLabels(e)
	defer w.flush()
	for i, part := range c.pattern.parts {
		if i&255 == 0 {
			if err := check(); err != nil {
				return err
			}
		}
		if part.capture && part.name != "_" {
			if text, ok := values[part.name]; ok {
				w.capture(part.name, text)
			}
		}
	}
	return nil
}

// errUnpackNotObject is the detail reported for a non-empty line that does not
// start with an object brace (`[1]`, `"s"`, `5`, `true`, `null`, or an object
// behind leading whitespace).
const errUnpackNotObject = "expecting json object(6), but it is not"

// parseUnpackStage reads a packed entry. An empty line is left alone and a line
// whose first byte is not '{' is a JSONParserErr. Otherwise the object is
// walked with the lenient scanner of the json stage: only string values count
// (numbers, booleans, null, arrays and objects are skipped), `_entry` names the
// replacement line and the remaining string members become labels, but the
// labels are written, in member order, only when an `_entry` string was found;
// a packed object without it leaves the line and the labels alone. A scanner
// error anywhere in the object (the scan is not validated up front) reports the
// scanner's message and keeps the line and the labels untouched.
func parseUnpackStage(e *LogEntry, check func() error) error {
	if e.Line == "" {
		return nil
	}
	if e.Line[0] != '{' {
		e.setError("JSONParserErr", errUnpackNotObject)
		return nil
	}
	type member struct{ name, value string }
	var members []member
	line := ""
	packed := false
	var err error
	if guardScanner(func() {
		err = jsonparser.ObjectEach([]byte(e.Line), func(k, v []byte, kind jsonparser.ValueType, _ int) error {
			if stop := check(); stop != nil {
				return &parserStop{stop}
			}
			if kind != jsonparser.String {
				return nil
			}
			text := jsonValueText(v, kind)
			if string(k) == "_entry" {
				line = text
				packed = true
				return nil
			}
			members = append(members, member{string(k), text})
			return nil
		})
	}).happened {
		err = errMalformedJSON
	}
	if stop := stoppedParser(err); stop != nil {
		return stop
	}
	if err != nil {
		e.setError("JSONParserErr", err.Error())
		return nil
	}
	if !packed {
		return nil
	}
	w := newStageLabels(e)
	defer w.flush()
	for i, m := range members {
		if i&255 == 0 {
			if err := check(); err != nil {
				return err
			}
		}
		w.capture(m.name, m.value)
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
