// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sourcemap

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func parse(t *testing.T, s string) *Map {
	t.Helper()
	m, e := Decode(strings.NewReader(s), Limits{})
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func TestIndexedOffsetsAndVLQBounds(t *testing.T) {
	m := parse(t, `{"version":3,"sections":[{"offset":{"line":2,"column":7},"map":{"version":3,"sources":["src/a.ts"],"names":["boom"],"mappings":"AAAAA;AACA"}}]}`)
	for _, c := range []struct {
		line, col, wantLine, wantCol uint32
		name                         string
	}{{3, 7, 1, 0, "boom"}, {4, 0, 2, 0, ""}} {
		p, ok, e := m.Lookup(c.line, c.col)
		if e != nil || !ok || p.SourceID != "src/a.ts" || p.Line != c.wantLine || p.Column != c.wantCol || p.Name != c.name {
			t.Fatalf("position: %+v %v %v", p, ok, e)
		}
	}
	if _, ok, _ := m.Lookup(3, 6); ok {
		t.Fatal("mapped before section")
	}
	for _, v := range []string{"!", "g", "gggggggggggggA", "D", "AAAA,DAAA", "AA", "AAAAAA", "AAAA,"} {
		if _, e := Decode(strings.NewReader(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"`+v+`"}`), Limits{}); e == nil {
			t.Fatalf("accepted malformed mapping %q", v)
		}
	}
}
func TestRecursiveRemoteTraversalMapRejected(t *testing.T) {
	for _, s := range []string{
		`{"version":3,"sections":[{"offset":{"line":0,"column":0},"url":"https://canary.invalid/map"}]}`,
		`{"version":3,"sources":["../secret.ts"],"mappings":"AAAA"}`,
		`{"version":3,"sources":["/secret.ts"],"mappings":"AAAA"}`,
		`{"version":3,"sourceRoot":"https://canary.invalid/","sources":["a.ts"],"mappings":"AAAA"}`,
		`{"version":3,"sources":["%2e%2e/secret.ts"],"mappings":"AAAA"}`,
		`{"version":3,"sources":["C:\\secret.ts"],"mappings":"AAAA"}`,
		`{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":{"version":3,"sources":[],"mappings":""}},{"offset":{"line":0,"column":0},"map":{"version":3,"sources":[],"mappings":""}}]}`,
	} {
		if _, e := Decode(strings.NewReader(s), Limits{}); e == nil || strings.Contains(e.Error(), "canary") || strings.Contains(e.Error(), "secret") {
			t.Fatalf("unsafe rejection: %v", e)
		}
	}
	nested := `{"version":3,"sources":[],"mappings":""}`
	for range 8 {
		nested = `{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":` + nested + `}]}`
	}
	if _, e := Decode(strings.NewReader(nested), Limits{}); e == nil {
		t.Fatal("accepted ninth depth")
	}
	if _, e := Decode(strings.NewReader(strings.Repeat(" ", 65)), Limits{MaxBytes: 64}); e == nil {
		t.Fatal("accepted oversize")
	}
}
func TestLookupUnmappedAndSourceRoot(t *testing.T) {
	m := parse(t, `{"version":3,"sourceRoot":"./src","sources":["lib/../a.ts"],"sourcesContent":["PRIVATE_CANARY"],"names":[],"mappings":"AAAA,K;AACA"}`)
	p, ok, e := m.Lookup(1, 4)
	if e != nil || !ok || p.SourceID != "src/a.ts" {
		t.Fatalf("normalization %+v %v %v", p, ok, e)
	}
	if _, ok, _ := m.Lookup(1, 5); ok {
		t.Fatal("unmapped segment inherited source")
	}
	if _, _, e := m.Lookup(0, 0); e == nil {
		t.Fatal("zero line accepted")
	}
}

func TestLimitsAndExactSectionArithmetic(t *testing.T) {
	for _, s := range []string{
		`{"version":3,"sources":["a","b"],"mappings":""}`,
		`{"version":3,"sources":["a"],"mappings":"AAAA,CAAA"}`,
	} {
		if _, e := Decode(strings.NewReader(s), Limits{MaxFiles: 1, MaxSegments: 1}); e == nil {
			t.Fatal("budget ignored")
		}
	}
	for _, s := range []string{
		`{"version":3,"sections":[{"offset":{"line":4294967294,"column":0},"map":{"version":3,"sources":["a"],"mappings":";AAAA"}}]}`,
		`{"version":3,"sections":[{"offset":{"line":0,"column":4294967295},"map":{"version":3,"sources":["a"],"mappings":"CAAA"}}]}`,
		`{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":{"version":3,"sources":["a"],"mappings":";AAAA"}},{"offset":{"line":1,"column":0},"map":{"version":3,"sources":["b"],"mappings":"AAAA"}}]}`,
	} {
		if _, e := Decode(strings.NewReader(s), Limits{}); e == nil {
			t.Fatal("section overflow/overlap accepted")
		}
	}
	m := parse(t, `{"version":3,"sections":[{"offset":{"line":1,"column":4},"map":{"version":3,"sections":[{"offset":{"line":0,"column":3},"map":{"version":3,"sources":["a"],"mappings":"AAAA;AACA"}}]}}]}`)
	p, ok, e := m.Lookup(2, 7)
	if e != nil || !ok || p.Line != 1 {
		t.Fatalf("nested offset: %+v %v %v", p, ok, e)
	}
	p, ok, e = m.Lookup(3, 0)
	if e != nil || !ok || p.Line != 2 {
		t.Fatalf("subsequent-line column: %+v %v %v", p, ok, e)
	}
}

// This exercises the public decoder across sibling maps, not a private budget.
func TestIndexedAggregateBudgets(t *testing.T) {
	makeMap := func(children, sourcesPerChild int) string {
		sections := make([]any, children)
		for i := range children {
			sources := make([]string, sourcesPerChild)
			for j := range sources {
				sources[j] = "source.ts"
			}
			sections[i] = map[string]any{
				"offset": map[string]uint32{"line": uint32(i), "column": 0},
				"map":    map[string]any{"version": 3, "sources": sources, "mappings": ""},
			}
		}
		raw, err := json.Marshal(map[string]any{"version": 3, "sections": sections})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	for _, tc := range []struct {
		name              string
		children, sources int
		limits            Limits
		wantLimit         bool
	}{
		{"sources exactly 1024 across siblings", 2, 512, Limits{}, false},
		{"sources exceed 1024 across siblings", 3, 342, Limits{}, true},
		{"nodes exactly 1024 including root", 1023, 0, Limits{}, false},
		{"nodes exceed 1024 including root", 1024, 0, Limits{}, true},
		{"tightened sources across siblings", 2, 2, Limits{MaxFiles: 3}, true},
		{"tightened nodes include root", 3, 0, Limits{MaxFiles: 3}, true},
		{"raised source ceiling still rejects", 3, 342, Limits{MaxFiles: 4096}, true},
		{"raised node ceiling still rejects", 1024, 0, Limits{MaxFiles: 4096}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(makeMap(tc.children, tc.sources)), tc.limits)
			if tc.wantLimit {
				if !errors.Is(err, ErrLimit) {
					t.Fatalf("want aggregate limit rejection, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("valid aggregate boundary rejected: %v", err)
			}
		})
	}
}

func TestInvalidIndexAndLimitBoundaries(t *testing.T) {
	for _, mappings := range []string{"AAAA,AAAA", "ACAA", "AAAAC"} {
		raw := `{"version":3,"sources":["a.ts"],"names":["only"],"mappings":"` + mappings + `"}`
		if _, err := Decode(strings.NewReader(raw), Limits{}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid duplicate/source/name mapping accepted: %q (%v)", mappings, err)
		}
	}
	for _, limits := range []Limits{{MaxBytes: -1}, {MaxFiles: -1}, {MaxDepth: -1}, {MaxSegments: -1}} {
		if _, err := Decode(strings.NewReader(`{"version":3,"sources":[],"mappings":""}`), limits); !errors.Is(err, ErrLimit) {
			t.Fatalf("negative limits accepted: %+v (%v)", limits, err)
		}
	}
}
