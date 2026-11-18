// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
)

// decodeStrict decodes the single JSON document raw into target the way the
// release gate's own documents must be read. encoding/json by default ignores
// unknown fields (a requirement a newer document names but this code does not
// know would be silently unenforced), lets a duplicate key override the first
// occurrence, matches keys without regard to case and stops after the first
// value (a second value would be ignored). Each of those is an error here.
func decodeStrict(raw []byte, target any) error {
	if err := rejectDuplicateKeys(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("unexpected data after the JSON document")
	}
	return nil
}

// readStrictJSON reads the document at path through decodeStrict.
func readStrictJSON(path string, target any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err = decodeStrict(raw, target); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// jsonFrame is one open container of rejectDuplicateKeys' walk.
type jsonFrame struct {
	object bool
	key    bool // object: the next token is a member name
	seen   map[string]bool
}

// rejectDuplicateKeys walks every token of raw and rejects an object that names
// one member twice, at any depth. Names are compared the way encoding/json
// matches them to struct fields, without regard to case, so `{"a":1,"A":2}` is a
// duplicate as well.
func rejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var stack []jsonFrame
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		var top *jsonFrame
		if n := len(stack); n > 0 {
			top = &stack[n-1]
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				if top != nil && top.object {
					top.key = true // the member's value starts here; its next sibling is a name again
				}
				stack = append(stack, jsonFrame{object: d == '{', key: d == '{', seen: map[string]bool{}})
			default:
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if top == nil || !top.object {
			continue
		}
		if !top.key {
			top.key = true // a scalar value
			continue
		}
		name, _ := tok.(string)
		folded := foldKey(name)
		if top.seen[folded] {
			return fmt.Errorf("duplicate key %q", name)
		}
		top.seen[folded] = true
		top.key = false
	}
}

// foldKey maps a member name to the representative of its Unicode simple-folding
// orbit: two names are equal under encoding/json's matching exactly when their
// folded forms are equal.
func foldKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		low := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < low {
				low = f
			}
		}
		b.WriteRune(low)
	}
	return b.String()
}
