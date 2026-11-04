// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"reflect"
	"soundpost/internal/query/profile"
	"testing"
)

func testProfile() profile.Profile {
	return profile.Profile{ID: "promql-prometheus-3.13.5", Commit: "f497435984d1ca1d84cda5ed309387ac2eb1f8f6", ActiveFeatureSet: profile.FeatureSet{ID: "default"}}
}
func TestEveryPromQLGrammarProduction(t *testing.T) {
	for _, text := range []string{`1 + 2 * 3 ^ 4`, `sum by (job) (rate(http_requests_total{method!=""}[5m]))`, `foo / on(job) group_left(instance) bar`, `foo[5m:1m] offset -1h @ start()`, `{"测量", "标签"="值"}`, `-Inf`, `NaN`, `"hello\\nworld"`, `foo # comment\n`} {
		t.Run(text, func(t *testing.T) {
			if _, err := Parse(text, testProfile()); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, text := range []string{`{job=~".*"}`, `foo[0m]`, `foo +`, `foo @ 1 @ 2`} {
		if _, err := Parse(text, testProfile()); err == nil {
			t.Errorf("accepted %s", text)
		}
	}
}
func TestEveryPromQLSignatureAndGate(t *testing.T) {
	for _, text := range []string{`rate(1)`, `sum("bad")`, `foo + "bad"`, `foo group_left bar`} {
		e, err := Parse(text, testProfile())
		if err == nil {
			_, _, err = Check(e, testProfile())
		}
		if err == nil {
			t.Errorf("accepted %s", text)
		}
	}
	e, err := Parse(`rate(foo[5m])`, testProfile())
	if err != nil {
		t.Fatal(err)
	}
	v, _, err := Check(e, testProfile())
	if err != nil || v.Type != Vector {
		t.Fatalf("type %v error %v", v.Type, err)
	}
}
func TestFormatPreservesTypedTree(t *testing.T) {
	for _, text := range []string{`1 + 2 * 3`, `sum by(job)(rate(foo[5m]))`, `foo / on(job) group_left(instance) bar`, `foo[5m:1m] offset -1h @ start()`, `{"测量","标签"="值"}`, `-0`, `-2^2`, `foo offset -2^2`} {
		e, err := Parse(text, testProfile())
		if err != nil {
			t.Fatal(err)
		}
		s := Format(e)
		r, err := Parse(s, testProfile())
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if Format(r) != s {
			t.Fatalf("non-idempotent %s", s)
		}
		a, _, err := Check(e, testProfile())
		if err != nil {
			t.Fatal(err)
		}
		b, _, err := Check(r, testProfile())
		if err != nil || a.Type != b.Type || !reflect.DeepEqual(meaning(e), meaning(r)) {
			t.Fatalf("typed meaning changed %s => %s: %v", text, s, err)
		}
	}
}
