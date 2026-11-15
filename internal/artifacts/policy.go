// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/sourcemap"
	"io"
	"slices"
)

// publicMap is the retained (source-content-free) document of an upload: the allowlisted fields
// of the map as decoded values, not yet encoded. WriteTo encodes them straight into a writer in
// the bytes json.Marshal gives the same value (sorted keys, compacted raw values, HTML escaping),
// so no whole-document buffer is ever built: the hash/size pass and the blob write each read the
// document as it is produced.
type publicMap struct{ doc map[string]any }

// WriteTo implements io.WriterTo.
func (p *publicMap) WriteTo(w io.Writer) (int64, error) {
	cw := &countWriter{w: w}
	err := writeValue(cw, p.doc)
	return cw.n, err
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	c.n += int64(n)
	return n, err
}

// writeValue encodes the value kinds transformDocument produces. Objects and arrays are written
// member by member; every leaf goes through json.Marshal, which is exactly what json.Marshal of
// the whole document does for it.
func writeValue(w io.Writer, v any) error {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		if _, err := w.Write([]byte{'{'}); err != nil {
			return err
		}
		for i, k := range keys {
			name, err := json.Marshal(k)
			if err != nil {
				return err
			}
			if i > 0 {
				name = append([]byte{','}, name...)
			}
			if _, err = w.Write(append(name, ':')); err != nil {
				return err
			}
			if err = writeValue(w, x[k]); err != nil {
				return err
			}
		}
		_, err := w.Write([]byte{'}'})
		return err
	case []any:
		if x == nil {
			_, err := w.Write([]byte("null"))
			return err
		}
		if _, err := w.Write([]byte{'['}); err != nil {
			return err
		}
		for i, e := range x {
			if i > 0 {
				if _, err := w.Write([]byte{','}); err != nil {
					return err
				}
			}
			if err := writeValue(w, e); err != nil {
				return err
			}
		}
		_, err := w.Write([]byte{']'})
		return err
	case json.RawMessage:
		// json.Marshal compacts a raw value and escapes <, >, & and U+2028/9 in it. A value that
		// needs neither (a bundler's mappings string, the bulk of a retained map) is its own
		// encoding: written as it is, with no copy.
		if len(x) > 0 && marshalsAsIs(x) {
			_, err := w.Write(x)
			return err
		}
		leaf, err := json.Marshal(x)
		if err != nil {
			return err
		}
		_, err = w.Write(leaf)
		return err
	default:
		leaf, err := json.Marshal(v)
		if err != nil {
			return err
		}
		_, err = w.Write(leaf)
		return err
	}
}

// marshalsAsIs reports whether json.Marshal(json.RawMessage(raw)) would return raw unchanged: no
// whitespace outside strings and no byte inside a string that Marshal escapes (<, >, & and the
// UTF-8 of U+2028 and U+2029). raw is valid JSON (it was decoded from a document that parsed).
func marshalsAsIs(raw []byte) bool {
	inString, escaped := false, false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !inString {
			switch c {
			case ' ', '\t', '\r', '\n':
				return false
			case '"':
				inString = true
			}
			continue
		}
		switch {
		case escaped:
			escaped = false
		case c == '\\':
			escaped = true
		case c == '"':
			inString = false
		case c == '<' || c == '>' || c == '&':
			return false
		case c == 0xE2 && i+2 < len(raw) && raw[i+1] == 0x80 && (raw[i+2] == 0xA8 || raw[i+2] == 0xA9):
			return false
		}
	}
	return true
}

// transformMap reuses the owned v3 decoder's path/section/index/CPU budgets,
// then allowlists retained fields; ignored extensions can never carry sources.
// The public document is returned as a publicMap (see there); the private sources, when
// asked for, are encoded here.
func transformMap(raw []byte, includeSources bool) (*publicMap, []byte, error) {
	if _, err := sourcemap.DecodeBytes(raw, sourcemap.Limits{MaxBytes: model.ArtifactBundleLimit, MaxFiles: 1024, MaxDepth: 8}); err != nil {
		return nil, nil, model.Fail(model.Invalid)
	}
	// Run every check on the buffer itself, with no second streaming copy.
	var input map[string]json.RawMessage
	// StrictJSON's streaming decoder would copy the whole body again, so the
	// same checks run directly on the buffer: ValidateJSON rejects duplicate
	// keys, invalid UTF-8, lone surrogates and excess depth; Unmarshal rejects
	// trailing data, exactly as StrictJSON's second Decode did.
	if model.ValidateJSON(raw) != nil || json.Unmarshal(raw, &input) != nil {
		return nil, nil, model.Fail(model.Invalid)
	}
	// input owns independent copies of every retained value: raw is not read
	// again, so the caller dropping its reference lets it be collected here.
	clean, private, err := transformDocument(input, includeSources, 1)
	if err != nil {
		return nil, nil, err
	}
	// transformDocument deleted sourcesContent from input; the decoded strings
	// in private are the only copy left.
	var sourceBytes []byte
	if includeSources {
		sourceBytes, err = json.Marshal(private)
	}
	if err != nil {
		return nil, nil, model.Fail(model.Invalid)
	}
	return &publicMap{doc: clean}, sourceBytes, nil
}
func transformDocument(input map[string]json.RawMessage, include bool, depth int) (map[string]any, map[string]any, error) {
	if depth > 8 {
		return nil, nil, model.Fail(model.TooLarge)
	}
	clean := map[string]any{}
	private := map[string]any{}
	for _, key := range []string{"version", "sources", "sourceRoot", "names", "mappings"} {
		if raw, ok := input[key]; ok {
			clean[key] = raw
		}
	}
	if sections, ok := input["sections"]; ok {
		var list []struct {
			Offset json.RawMessage            `json:"offset"`
			Map    map[string]json.RawMessage `json:"map"`
		}
		if json.Unmarshal(sections, &list) != nil || len(list) > 1024 {
			return nil, nil, model.Fail(model.Invalid)
		}
		publicSections := make([]any, 0, len(list))
		privateSections := make([]any, 0, len(list))
		for i := range list {
			c, p, err := transformDocument(list[i].Map, include, depth+1)
			if err != nil {
				return nil, nil, err
			}
			publicSections = append(publicSections, map[string]any{"offset": list[i].Offset, "map": c})
			if include {
				privateSections = append(privateSections, map[string]any{"offset": list[i].Offset, "map": p})
			}
			list[i].Map = nil
		}
		clean["sections"] = publicSections
		if include {
			private["sections"] = privateSections
		}
	}
	if include {
		var sources []string
		if raw, ok := input["sources"]; ok {
			if json.Unmarshal(raw, &sources) != nil {
				return nil, nil, model.Fail(model.Invalid)
			}
			private["sources"] = sources
		}
		if raw, ok := input["sourcesContent"]; ok {
			var content []*string
			if json.Unmarshal(raw, &content) != nil || len(content) != len(sources) {
				return nil, nil, model.Fail(model.Invalid)
			}
			private["sourcesContent"] = content
			// The decoded strings are the only copy needed from here on.
			delete(input, "sourcesContent")
		}
		if raw, ok := input["sourceRoot"]; ok {
			private["sourceRoot"] = raw
		}
	}
	return clean, private, nil
}
