// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf8"
)

// referenceStrictJSON is StrictJSON exactly as it was before the scanner
// rewrite, except that it calls referenceValidateJSON. It is the test oracle.
func referenceStrictJSON(b []byte, v any) error {
	if referenceValidateJSON(b) != nil {
		return Fail(Invalid)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return Fail(Invalid)
	}
	if d.Decode(new(any)) != io.EOF {
		return Fail(Invalid)
	}
	return nil
}

// referenceValidateJSON is the original ValidateJSON, copied byte for byte
// (name changed only). It is the test oracle for the hand-written scanner.
func referenceValidateJSON(b []byte) error {
	if !utf8.Valid(b) {
		return Fail(Invalid)
	}
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		if i+1 >= len(b) {
			return Fail(Invalid)
		}
		if b[i+1] != 'u' {
			i++
			continue
		}
		if i+5 >= len(b) {
			return Fail(Invalid)
		}
		n, e := strconv.ParseUint(string(b[i+2:i+6]), 16, 16)
		if e != nil {
			return Fail(Invalid)
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+11 >= len(b) || b[i+6] != '\\' || b[i+7] != 'u' {
				return Fail(Invalid)
			}
			m, e := strconv.ParseUint(string(b[i+8:i+12]), 16, 16)
			if e != nil || m < 0xdc00 || m > 0xdfff {
				return Fail(Invalid)
			}
			i += 11
		} else if n >= 0xdc00 && n <= 0xdfff {
			return Fail(Invalid)
		} else {
			i += 5
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if referenceWalkJSON(d, 0) != nil {
		return Fail(Invalid)
	}
	if _, e := d.Token(); e != io.EOF {
		return Fail(Invalid)
	}
	return nil
}
func referenceWalkJSON(d *json.Decoder, depth int) error {
	if depth > 64 {
		return Fail(Invalid)
	}
	t, e := d.Token()
	if e != nil {
		return e
	}
	v, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch v {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			s, ok := k.(string)
			if !ok || seen[s] {
				return Fail(Invalid)
			}
			seen[s] = true
			if e = referenceWalkJSON(d, depth+1); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if e = referenceWalkJSON(d, depth+1); e != nil {
				return e
			}
		}
	default:
		return Fail(Invalid)
	}
	_, e = d.Token()
	return e
}
