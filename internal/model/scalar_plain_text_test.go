// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
	"testing"
)

// PlainText answers only where it is the string Text gives, and does not allocate. The scalar keeps the
// canonical form encoding/json writes, so a string with a tab, a quote, a backslash, <, > or & is stored
// escaped and takes the decode.
func TestScalarPlainTextAgreesWithText(t *testing.T) {
	for _, c := range []struct {
		raw   string
		plain bool
	}{
		{`"plain"`, true}, {`""`, true}, {`"a b"`, true}, {`"caf\u00e9"`, true}, {`"日本語"`, true},
		{`"tab\t"`, false}, {`"q\"q"`, false}, {`"b\\b"`, false}, {`"<&>"`, false}, {`"\u003c"`, false}, {`"\u2028"`, false},
		{`7`, false}, {`true`, false}, {`null`, false},
	} {
		var s Scalar
		if err := json.Unmarshal([]byte(c.raw), &s); err != nil {
			t.Fatalf("%s: %v", c.raw, err)
		}
		text, ok := s.PlainText()
		if ok != c.plain {
			t.Fatalf("%s (stored %s): PlainText ok=%v, want %v", c.raw, s.raw, ok, c.plain)
		}
		if ok && text != s.Text() {
			t.Fatalf("%s: PlainText %q, Text %q", c.raw, text, s.Text())
		}
	}
	var s Scalar
	if err := json.Unmarshal([]byte(`"/v1/orders"`), &s); err != nil {
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(100, func() { _, _ = s.PlainText() }); n != 0 {
		t.Fatalf("PlainText made %.0f allocations", n)
	}
	if (Scalar{}).Text() != "null" {
		t.Fatal("zero scalar text changed")
	}
	if _, ok := (Scalar{}).PlainText(); ok {
		t.Fatal("zero scalar has plain text")
	}
}
