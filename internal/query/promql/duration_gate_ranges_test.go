// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/query/syntax"
)

// The experimental-duration and experimental-aggregation gates blame the
// ranges the pinned parsers blame (observations of the sha-pinned sources:
// internal/conformance/query/testdata/native-promql-syntax-ranges.json holds
// the full recorded set; these are the representative ones, with the reason).
func TestExperimentalGateRangesFollowThePinnedReductionOrder(t *testing.T) {
	p3135 := featureProfile(t, "promql-prometheus-3.13.5")
	p310 := featureProfile(t, "promql-prometheus-3.1.0")
	for _, tc := range []struct {
		name, query string
		p           bool // true: 3.13.5
		start, end  int
	}{
		{"binary duration blames its first operand", "foo[5m + 1m]", true, 4, 6},
		{"a call completing before the binary is blamed first", "foo[1m + step()]", true, 9, 15},
		{"parenthesis blames its content", "foo[(1m + 2m)]", true, 5, 7},
		{"min_of spans its two operands", "foo offset min_of(1h, 30m)", true, 18, 25},
		{"an inner parenthesis completes before min_of", "foo offset max_of((1m), 30m)", true, 19, 21},
		{"an inner binary completes before min_of", "foo offset min_of(1h+1m, 30m)", true, 18, 20},
		{"a signed call inside brackets excludes the sign", "foo[-step()]", true, 5, 11},
		{"a signed call after offset is one rule including the sign", "foo offset -step()", true, 11, 18},
		{"metric name twice spans the selector through its closing brace", `foo{__name__="bar", a="b"}`, true, 0, 26},
		{"3.13.5 blames the aggregation itself", "sum(limitk(2, foo))", true, 4, 18},
		{"3.1.0 reports through the lookahead closing parenthesis", "sum(limitk(2, foo))", false, 4, 19},
		{"3.1.0 without a closing lookahead blames the aggregation", "limitk(2, foo) by (a)", false, 0, 21},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := p310
			if tc.p {
				p = p3135
			}
			e, err := Parse(tc.query, p)
			if err == nil {
				_, _, err = Check(e, p)
			}
			var lang *syntax.LanguageError
			if !errors.As(err, &lang) {
				t.Fatalf("%q was not rejected: %v", tc.query, err)
			}
			if lang.Range.StartByte != tc.start || lang.Range.EndByte != tc.end {
				t.Fatalf("%q blamed %d..%d, reference %d..%d", tc.query, lang.Range.StartByte, lang.Range.EndByte, tc.start, tc.end)
			}
		})
	}
}

// "-(5m)" after offset is its own grammar rule and carries no gate; "(5m)" is gated.
func TestSignedParenthesisedOffsetNeedsNoDurationGate(t *testing.T) {
	p := featureProfile(t, "promql-prometheus-3.13.5")
	for _, query := range []string{"foo offset -(5m)", "foo offset +(5m)"} {
		if _, err := Parse(query, p); err != nil {
			t.Errorf("%q: %v", query, err)
		}
	}
	if _, err := Parse("foo offset (5m)", p); err == nil {
		t.Error("foo offset (5m) must stay gated")
	}
	if _, err := Parse("foo[-(5m)]", p); err == nil {
		t.Error("a signed parenthesis in brackets must stay gated")
	}
}
