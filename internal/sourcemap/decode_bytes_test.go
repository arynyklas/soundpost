// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sourcemap

import (
	"strings"
	"testing"
)

// DecodeBytes must agree with Decode on result class for every input shape.
func TestDecodeBytesMatchesDecode(t *testing.T) {
	good := `{"version":3,"sources":["a.ts"],"names":["n"],"mappings":"AAAAA","sourcesContent":["x"]}`
	for _, c := range []struct {
		name, in string
		limits   Limits
	}{
		{"valid", good, Limits{}},
		{"invalid utf8", "{\"version\":3,\"sources\":[\"\xff\"],\"names\":[],\"mappings\":\"AAAA\"}", Limits{}},
		{"bad version", `{"version":2,"sources":[],"names":[],"mappings":""}`, Limits{}},
		{"over limit", good, Limits{MaxBytes: 10}},
		{"not json", `nope`, Limits{}},
		{"sections", `{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":` + good + `}]}`, Limits{}},
		{"depth", `{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":` + good + `}]}`, Limits{MaxDepth: 1}},
	} {
		want, werr := Decode(strings.NewReader(c.in), c.limits)
		got, gerr := DecodeBytes([]byte(c.in), c.limits)
		if werr != gerr || (want == nil) != (got == nil) {
			t.Fatalf("%s: Decode=(%v,%v) DecodeBytes=(%v,%v)", c.name, want != nil, werr, got != nil, gerr)
		}
	}
	if _, err := DecodeBytes([]byte(good), Limits{MaxBytes: 1 << 40}); err != ErrLimit && err != nil {
		// ceilings() decides how an over-ceiling limit is reported; it must be the same as Decode.
		_, want := Decode(strings.NewReader(good), Limits{MaxBytes: 1 << 40})
		if err != want {
			t.Fatalf("ceiling error differs: %v vs %v", err, want)
		}
	}
}
