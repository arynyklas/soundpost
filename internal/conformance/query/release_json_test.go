// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The documents the release gate is configured by must not be decoded the way
// encoding/json decodes by default, which ignores unknown fields (a requirement
// a newer policy names but this code does not know is silently not enforced),
// lets a duplicate key override its first occurrence, matches keys without
// regard to case and stops reading after the first value.
func TestDecodeStrictRejectsWhatAnOrdinaryDecoderIgnores(t *testing.T) {
	type inner struct {
		X int `json:"x"`
	}
	type doc struct {
		A int     `json:"a"`
		B inner   `json:"b"`
		L []inner `json:"l"`
	}
	accept := []string{
		`{"a":1,"b":{"x":2},"l":[{"x":3},{"x":4}]}`,
		`{"a":1,"b":{"x":2}} `,
		"\n{\"a\":1}\n",
		`{"b":{"x":1},"l":[{"x":1},{"x":1}]}`, // the same key in different objects is not a duplicate
		`{}`,
	}
	for _, in := range accept {
		var d doc
		if err := decodeStrict([]byte(in), &d); err != nil {
			t.Errorf("%q was refused: %v", in, err)
		}
	}
	reject := map[string]string{
		"an unknown top-level field":            `{"a":1,"z":2}`,
		"an unknown nested field":               `{"b":{"x":1,"y":2}}`,
		"an unknown field in an array element":  `{"l":[{"x":1},{"q":1}]}`,
		"a duplicate top-level key":             `{"a":1,"a":2}`,
		"a duplicate nested key":                `{"b":{"x":1,"x":2}}`,
		"a duplicate key in an array element":   `{"l":[{"x":1},{"x":1,"x":2}]}`,
		"a duplicate that differs only in case": `{"a":1,"A":2}`,
		"trailing second value":                 `{"a":1} {"a":2}`,
		"trailing garbage":                      `{"a":1} x`,
		"not JSON":                              `not json`,
		"empty input":                           ``,
		"a type mismatch":                       `{"a":"one"}`,
	}
	for name, in := range reject {
		var d doc
		if err := decodeStrict([]byte(in), &d); err == nil {
			t.Errorf("%s was accepted: %q", name, in)
		}
	}
	// Duplicates are found at any depth, in objects nested in arrays of arrays.
	var anything map[string]any
	if err := decodeStrict([]byte(`{"k":[[{"d":1,"d":2}]]}`), &anything); err == nil {
		t.Error("a duplicate key nested in arrays was accepted")
	}
	if err := decodeStrict([]byte(`{"k":[[{"d":1},{"d":2}]],"e":null,"f":true,"g":1.5,"h":"s"}`), &anything); err != nil {
		t.Errorf("scalars and null values were refused: %v", err)
	}
}

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// withExtra inserts text as the first member of the top-level object of raw.
func withExtra(t *testing.T, raw []byte, text string) string {
	t.Helper()
	s := string(raw)
	i := strings.Index(s, "{")
	if i < 0 {
		t.Fatal("not an object")
	}
	return s[:i+1] + text + "," + s[i+1:]
}

// Loading a document through the gate's loaders is as strict as decodeStrict: the
// generation spec, the release-case manifest, the release policy and the smoke
// report each refuse an unknown field and a duplicate key.
func TestGateDocumentLoadersAreStrict(t *testing.T) {
	spec, err := os.ReadFile(queryRoot("generation.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(queryRoot("release-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	smoke, err := json.Marshal(validSmokeReport())
	if err != nil {
		t.Fatal(err)
	}
	loaders := []struct {
		name string
		raw  []byte
		dup  string
		load func(path string) error
	}{
		{"generation spec", spec, `"schema":"soundpost-query-generation/1"`, func(p string) error { _, err := LoadGenerationSpec(p); return err }},
		{"release case manifest", manifest, `"schema":"soundpost-query-release-cases/1"`, func(p string) error { _, err := LoadReleaseCaseManifest(p); return err }},
		{"smoke report", smoke, `"schema":"soundpost-smoke-report/1"`, func(p string) error { _, err := LoadSmokeReport(p); return err }},
	}
	for _, l := range loaders {
		if err := l.load(writeTemp(t, "ok.json", string(l.raw))); err != nil {
			t.Fatalf("%s: the unmodified document was refused: %v", l.name, err)
		}
		if err := l.load(writeTemp(t, "unknown.json", withExtra(t, l.raw, `"unknown_requirement":true`))); err == nil {
			t.Errorf("%s: an unknown field was ignored", l.name)
		}
		if err := l.load(writeTemp(t, "dup.json", withExtra(t, l.raw, l.dup))); err == nil {
			t.Errorf("%s: a duplicated key was accepted", l.name)
		}
		if err := l.load(writeTemp(t, "trailing.json", string(l.raw)+"\n{}")); err == nil {
			t.Errorf("%s: a second JSON value after the document was ignored", l.name)
		}
	}
}

// The policy the gate consumes is the content-locked release-policy.json, not any
// file a --policy flag names, and a locked policy that this code can only partly
// understand is refused rather than partly enforced.
func TestLoadReleaseConfigConsumesOnlyTheLockedPolicy(t *testing.T) {
	inRepoRoot(t)
	locked, err := os.ReadFile("conformance/query/release-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	weakened := strings.Replace(string(locked), `"restart",`, ``, 1)
	if weakened == string(locked) {
		t.Fatal("the fixture did not weaken the policy")
	}
	for name, body := range map[string]string{
		"a weakened copy":            weakened,
		"a copy with an extra field": withExtra(t, locked, `"require_zero_flaky":true`),
	} {
		if _, err := LoadReleaseConfig("conformance/query", writeTemp(t, "policy.json", body), nil, []uint64{20261110}); err == nil {
			t.Errorf("%s of the policy was consumed although it is not the content-locked one", name)
		}
	}
	same, err := LoadReleaseConfig("conformance/query", writeTemp(t, "copy-of-the-locked-policy.json", string(locked)), nil, []uint64{20261110})
	if err != nil || same.Policy.Validate() != nil {
		t.Fatalf("the locked policy, read from another path, must still load: %v", err)
	}
}
