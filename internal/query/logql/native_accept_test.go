// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"errors"
	"os"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/syntax"
	"soundpost/internal/query/value"
	"testing"
)

// These expectations come from running the pinned Loki 3.5.2 reference on the
// exact inputs with the empty feature set: it accepts the four vector forms and
// rejects the logfmt form with an unexpected-token syntax error.

func parseCheck(t *testing.T, source string, p profile.Profile) (TypedExpr, error) {
	t.Helper()
	expr, err := Parse(source, p)
	if err != nil {
		return TypedExpr{}, err
	}
	typed, _, err := Check(expr, p)
	return typed, err
}
func languageCode(t *testing.T, err error) string {
	t.Helper()
	var diagnostic *syntax.LanguageError
	if !errors.As(err, &diagnostic) {
		t.Fatalf("not an owned diagnostic: %v", err)
	}
	return diagnostic.Code
}
func profileWithGate(t *testing.T, gate string) profile.Profile {
	t.Helper()
	registry, err := profile.Load(os.DirFS("../../../profiles/query"))
	if err != nil {
		t.Fatal(err)
	}
	base := testProfile(t)
	for _, set := range base.FeatureSets {
		if len(set.Enabled) == 1 && set.Enabled[0] == gate {
			p, err := registry.Resolve(base.ID, set.ID)
			if err != nil {
				t.Fatal(err)
			}
			return p
		}
	}
	t.Fatalf("no registered feature set for %s", gate)
	return profile.Profile{}
}

func TestNativeAcceptsLabelMatchingAgainstScalarOperand(t *testing.T) {
	p := testProfile(t)
	for _, source := range []string{`1 + on(app) vector(2)`, `vector(2) * ignoring(app) 3`} {
		typed, err := parseCheck(t, source, p)
		if err != nil || typed.Type != TypeVector {
			t.Fatalf("native-accepted scalar/vector label matching: %s type=%s err=%v", source, typed.Type, err)
		}
	}
	// The matching modifier does not change scalar-operand arithmetic.
	src := &metricSource{}
	if got := metricValue(t, `1 + on(app) vector(2)`, src); got != 3 {
		t.Fatalf("scalar/vector arithmetic changed by matching modifier: %g", got)
	}
}
func TestNativeStillRejectsInvalidScalarVectorMatching(t *testing.T) {
	p := testProfile(t)
	for _, tc := range []struct{ source, code string }{
		{`1 + on(app) group_left vector(2)`, "binary.matching-invalid"},
		{`vector(2) + ignoring(app) group_right 1`, "binary.matching-invalid"},
		{`1 + on(app) 2`, "binary.matching-invalid"},
		{`1 and on(app) vector(2)`, "binary.set-invalid"},
		{`1 + bool on(app) vector(2)`, "binary.bool-invalid"},
	} {
		_, err := parseCheck(t, tc.source, p)
		if err == nil || languageCode(t, err) != tc.code {
			t.Fatalf("%s want %s got %v", tc.source, tc.code, err)
		}
	}
}
func TestNativeAcceptsDuplicateMatchingLabels(t *testing.T) {
	p := testProfile(t)
	for _, source := range []string{`vector(1) + on(app,app) vector(2)`, `vector(1) + ignoring(app,app) vector(2)`} {
		typed, err := parseCheck(t, source, p)
		if err != nil || typed.Type != TypeVector {
			t.Fatalf("native-accepted duplicate matching labels: %s type=%s err=%v", source, typed.Type, err)
		}
	}
	if got := metricValue(t, `vector(1) + on(app,app) vector(2)`, &metricSource{}); got != 3 {
		t.Fatalf("duplicate on() labels changed matching result: %g", got)
	}
}
func TestDuplicateAndOverlappingLabelsStayRejectedOutsideMatchingList(t *testing.T) {
	p := testProfile(t)
	for _, tc := range []struct{ source, code string }{
		{`vector(1) + on(app) group_left(zone,zone) vector(2)`, "binary.matching-labels"},
		{`vector(1) + on(app,app) group_left(app) vector(2)`, "binary.matching-overlap"},
		{`sum by(app,app)(vector(1))`, "grouping.labels-invalid"},
	} {
		_, err := parseCheck(t, tc.source, p)
		if err == nil || languageCode(t, err) != tc.code {
			t.Fatalf("%s want %s got %v", tc.source, tc.code, err)
		}
	}
}

func TestDisabledCapabilitiesAreAcceptedBySyntaxAndRejectedAtPlanning(t *testing.T) {
	p := testProfile(t)
	for _, source := range []string{
		`approx_topk(3,vector(1))`,
		`variants(rate({app="api"}[2m]),count_over_time({app="api"}[2m])) of ({app="api"}[2m])`,
	} {
		typed, err := parseCheck(t, source, p)
		if err != nil || typed.Type != TypeVector {
			t.Fatalf("native-accepted capability syntax: %s type=%s err=%v", source, typed.Type, err)
		}
		// The tenant/config gate is still enforced before any plan exists.
		_, err = BuildPlan(typed, value.Evaluation{Instant: true, Time: 2e9}, p)
		var diagnostic *syntax.LanguageError
		if !errors.As(err, &diagnostic) || diagnostic.Code != "function.feature-disabled" || diagnostic.Category != "type" {
			t.Fatalf("disabled capability planned: %s %v", source, err)
		}
	}
	// A nested occurrence is gated too, not only a root occurrence.
	typed, err := parseCheck(t, `1 + sum(approx_topk(3,vector(1)))`, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = BuildPlan(typed, value.Evaluation{Instant: true, Time: 2e9}, p); err == nil {
		t.Fatal("nested disabled approx_topk planned")
	}
	// Enabling exactly the matching capability admits only that capability.
	for _, tc := range []struct{ gate, source string }{
		{"approx_topk", `approx_topk(3,vector(1))`},
		{"multi-variant-queries", `variants(rate({app="api"}[2m]),count_over_time({app="api"}[2m])) of ({app="api"}[2m])`},
	} {
		enabled := profileWithGate(t, tc.gate)
		typed, err := parseCheck(t, tc.source, enabled)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = BuildPlan(typed, value.Evaluation{Instant: true, Time: 2e9}, enabled); err != nil {
			t.Fatalf("enabled %s rejected: %v", tc.gate, err)
		}
	}
	other := profileWithGate(t, "approx_topk")
	typed, err = parseCheck(t, `variants(vector(2)) of ({app="api"}[2m])`, other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = BuildPlan(typed, value.Evaluation{Instant: true, Time: 2e9}, other); err == nil {
		t.Fatal("approx_topk gate admitted variants")
	}
}
func TestCapabilityStructureIsValidatedEvenWhenDisabled(t *testing.T) {
	p := testProfile(t)
	for _, tc := range []struct{ source, code string }{
		{`variants({app="api"}) of ({app="api"}[2m])`, "variants.input-invalid"},
		{`approx_topk by(app) (3,vector(1))`, "grouping.unsupported"},
		{`approx_topk(vector(1),vector(1))`, "function.arguments"},
	} {
		_, err := parseCheck(t, tc.source, p)
		if err == nil || languageCode(t, err) != tc.code {
			t.Fatalf("%s want %s got %v", tc.source, tc.code, err)
		}
	}
}

func TestLogfmtExtractionSourceMustBeAString(t *testing.T) {
	p := testProfile(t)
	for _, source := range []string{
		`{app="api"}|logfmt --strict --keep-empty status=code,user`,
		`{app="api"}|logfmt status=code`,
		`{app="api"}|json status=code`,
	} {
		_, err := parseCheck(t, source, p)
		if err == nil || languageCode(t, err) != "syntax.unexpected-token" {
			t.Fatalf("bare extraction source accepted or misclassified: %s %v", source, err)
		}
	}
	_, err := Parse(`{app="api"}|logfmt --strict --keep-empty status=code,user`, p)
	var diagnostic *syntax.LanguageError
	if !errors.As(err, &diagnostic) || diagnostic.Range.StartByte != 48 {
		t.Fatalf("reference reports the unexpected identifier at byte 48: %+v", diagnostic)
	}
	for _, source := range []string{
		`{app="api"}|logfmt --strict --keep-empty status="code"`,
		`{app="api"}|logfmt status="code", user="user"`,
	} {
		typed, err := parseCheck(t, source, p)
		if err != nil || typed.Type != TypeLogs {
			t.Fatalf("string-source logfmt extraction rejected: %s %v", source, err)
		}
	}
}
