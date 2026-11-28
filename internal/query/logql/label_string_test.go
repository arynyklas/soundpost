// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"strconv"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func labelStringReference(ls model.Labels) string {
	var b strings.Builder
	b.WriteByte('{')
	for i, l := range ls {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(l.Name)
		b.WriteByte('=')
		b.WriteString(strconv.Quote(l.Value))
	}
	b.WriteByte('}')
	return b.String()
}

// labelString runs for every row of a metric query over logs. It grew its builder by doubling and quoted
// every value into a string of its own: one allocation for the plain labels of a stream, where it made 8.
func TestLabelStringIsOneAllocationForPlainLabels(t *testing.T) {
	ls := model.Labels{{Name: "app", Value: "checkout"}, {Name: "cluster", Value: "eu-west-1"}, {Name: "env", Value: "production"}, {Name: "host", Value: "node-0042.example.internal"}, {Name: "job", Value: "soundpost/api"}, {Name: "level", Value: "info"}, {Name: "namespace", Value: "payments"}, {Name: "pod", Value: "checkout-7d9f8c6b5-x2x4z"}}
	var s string
	n := testing.AllocsPerRun(200, func() { s = labelString(ls) })
	if s != labelStringReference(ls) {
		t.Fatalf("labelString = %s", s)
	}
	if n > 1 {
		t.Fatalf("labelString of %d plain labels made %v allocations, want 1", len(ls), n)
	}
}

func TestLabelStringEqualsTheQuotedReference(t *testing.T) {
	values := []string{"", "plain", `has "quotes"`, `back\slash`, "tab\tnew\nline", "\x00\x01\x1f\x7f", "caf\u00e9", "\u65e5\u672c\u8a9e", "\xff\xfe invalid", "\u2028 sep", "emoji \U0001F600", "~ end of ascii", " space ", "\u00a0 nbsp", "\U0010ffff"}
	for _, a := range values {
		for _, b := range values {
			ls := model.Labels{{Name: "a", Value: a}, {Name: "b", Value: b}}
			if got, want := labelString(ls), labelStringReference(ls); got != want {
				t.Fatalf("labelString(%q, %q) = %s, want %s", a, b, got, want)
			}
		}
	}
	if got := labelString(nil); got != "{}" {
		t.Fatalf("labelString(nil) = %s", got)
	}
}
