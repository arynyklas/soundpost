// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// canonicalJSON re-encodes raw with sorted object keys, no insignificant whitespace and numbers kept verbatim, so two renderings of
// one value are byte-equal whatever order the producer wrote its members in.
func canonicalJSON(raw []byte) ([]byte, error) {
	v, err := decodeAny(raw)
	if err != nil {
		return nil, err
	}
	return encodeAny(v)
}

func decodeAny(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data after the JSON value")
	}
	return v, nil
}

func encodeAny(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // map keys are emitted sorted by encoding/json
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// digestValues is the digest of a PromQL/LogQL answer: sha256 over the canonical JSON of every project's value in the answer's own
// project order (the product orders projects by id), each followed by a newline.
func digestValues(values []json.RawMessage) (string, error) {
	h := sha256.New()
	for _, raw := range values {
		c, err := canonicalJSON(raw)
		if err != nil {
			return "", err
		}
		h.Write(c)
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// volatileMembers are the members of a trace view or RED answer that describe the request or the cache, not the data: the read cuts
// of a freshness block move with the clock and `cached` with the cache, neither with the immutable spans.
var volatileMembers = map[string]bool{"freshness": true, "cached": true, "request_time": true, "request_time_ns": true}

func stripVolatile(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k := range x {
			if volatileMembers[k] {
				delete(x, k)
				continue
			}
			x[k] = stripVolatile(x[k])
		}
	case []any:
		for i := range x {
			x[i] = stripVolatile(x[i])
		}
	}
	return v
}

// digestView is the digest of a trace view or service RED answer: sha256 of the canonical JSON of the body without its volatile members.
func digestView(body []byte) (string, error) {
	v, err := decodeAny(body)
	if err != nil {
		return "", err
	}
	c, err := encodeAny(stripVolatile(v))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

// writeGoldenFile writes golden.json once: id, class and a summary of each request of the fixed set.
func writeGoldenFile(path string, gold []golden) {
	must(os.WriteFile(path, append(mustJSON(gold), '\n'), 0o644), "write golden.json")
}
