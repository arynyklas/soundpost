// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sourcemap

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

type document struct {
	Version    int             `json:"version"`
	Sources    []string        `json:"sources"`
	SourceRoot string          `json:"sourceRoot"`
	Names      []string        `json:"names"`
	Mappings   *string         `json:"mappings"`
	Sections   json.RawMessage `json:"sections"`
}
type rawSection struct {
	Offset *struct {
		Line   *uint32 `json:"line"`
		Column *uint32 `json:"column"`
	} `json:"offset"`
	Map json.RawMessage `json:"map"`
	URL json.RawMessage `json:"url"`
}
type budget struct {
	limits                Limits
	files, segments, maps int
}

// Decode consumes at most MaxBytes+1 bytes and returns fixed, content-free errors.
// Unknown v3 extensions (including sourcesContent) are ignored, not retained.
func Decode(input io.Reader, limits Limits) (*Map, error) {
	l, e := ceilings(limits)
	if e != nil {
		return nil, e
	}
	if input == nil {
		return nil, ErrInvalid
	}
	b, e := io.ReadAll(io.LimitReader(input, l.MaxBytes+1))
	if e != nil {
		return nil, ErrInvalid
	}
	if int64(len(b)) > l.MaxBytes {
		return nil, ErrLimit
	}
	if !utf8.Valid(b) {
		return nil, ErrInvalid
	}
	state := budget{limits: l}
	return state.decode(b, 1)
}
func (b *budget) decode(raw []byte, depth int) (*Map, error) {
	if depth > b.limits.MaxDepth {
		return nil, ErrLimit
	}
	b.maps++
	if b.maps > b.limits.MaxFiles {
		return nil, ErrLimit
	}
	var d document
	if json.Unmarshal(raw, &d) != nil || d.Version != 3 {
		return nil, ErrInvalid
	}
	m := &Map{}
	if len(d.Sections) > 0 {
		if d.Mappings != nil || d.Sources != nil || d.Names != nil || d.SourceRoot != "" {
			return nil, ErrInvalid
		}
		var sections []rawSection
		if json.Unmarshal(d.Sections, &sections) != nil || bytes.Equal(d.Sections, []byte("null")) {
			return nil, ErrInvalid
		}
		if len(sections) > b.limits.MaxFiles {
			return nil, ErrLimit
		}
		for _, s := range sections {
			if len(s.URL) > 0 || s.Offset == nil || s.Offset.Line == nil || s.Offset.Column == nil || len(s.Map) == 0 {
				return nil, ErrInvalid
			}
			line, col := *s.Offset.Line, *s.Offset.Column
			// All stored/generated lines are zero-based internally; one-based public
			// positions must remain representable after section addition.
			if line == 0xffffffff {
				return nil, ErrInvalid
			}
			if n := len(m.sections); n > 0 {
				prev := m.sections[n-1]
				if !less(prev.line, prev.column, line, col) {
					return nil, ErrInvalid
				}
				if endLine, endCol, ok := prev.child.last(); ok {
					el, ec, e := offset(prev.line, prev.column, endLine, endCol)
					if e != nil || !less(el, ec, line, col) {
						return nil, ErrInvalid
					}
				}
			}
			child, e := b.decode(s.Map, depth+1)
			if e != nil {
				return nil, e
			}
			if el, ec, ok := child.last(); ok {
				if _, _, e = offset(line, col, el, ec); e != nil {
					return nil, e
				}
			}
			m.sections = append(m.sections, section{line, col, child})
		}
		return m, nil
	}
	if d.Mappings == nil || d.Sources == nil {
		return nil, ErrInvalid
	}
	b.files += len(d.Sources)
	if b.files > b.limits.MaxFiles {
		return nil, ErrLimit
	}
	sources := make([]string, len(d.Sources))
	for i, s := range d.Sources {
		id, e := sourceID(d.SourceRoot, s)
		if e != nil {
			return nil, e
		}
		sources[i] = id
	}
	for _, name := range d.Names {
		if !safeText(name, 256) {
			return nil, ErrInvalid
		}
	}
	if e := b.mappings(m, *d.Mappings, sources, d.Names); e != nil {
		return nil, e
	}
	return m, nil
}
func safeText(s string, max int) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
func sourceID(root, source string) (string, error) {
	if source == "" || !safeText(source, 4096) || !safeText(root, 4096) {
		return "", ErrInvalid
	}
	parts := []string{root, source}
	for i, s := range parts {
		decoded, e := url.PathUnescape(s)
		if e != nil || strings.ContainsAny(decoded, "\\:?#%") || strings.HasPrefix(decoded, "/") || !safeText(decoded, 4096) {
			return "", ErrInvalid
		}
		parts[i] = decoded
	}
	joined := parts[0] + "/" + parts[1]
	if parts[0] == "" {
		joined = parts[1]
	}
	depth := 0
	for _, p := range strings.Split(joined, "/") {
		switch p {
		case "", ".":
		case "..":
			depth--
			if depth < 0 {
				return "", ErrInvalid
			}
		default:
			depth++
		}
	}
	id := path.Clean(joined)
	if id == "." || id == ".." || len(id) > 4096 {
		return "", ErrInvalid
	}
	return id, nil
}
