// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package releaseevidence

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const commit = "0123456789abcdef0123456789abcdef01234567"

func TestNewRefusesAVacuousOrMalformedEnvelope(t *testing.T) {
	ok := []Row{{ID: "a", Status: StatusPassed}}
	for name, c := range map[string]struct {
		kind, commit string
		expected     []string
		rows         []Row
	}{
		"unknown kind":      {"overhead", commit, []string{"a"}, ok},
		"short commit":      {KindBrowser, "0123abc", []string{"a"}, ok},
		"symbolic commit":   {KindBrowser, "HEAD", []string{"a"}, ok},
		"upper-case commit": {KindBrowser, strings.ToUpper(commit), []string{"a"}, ok},
		"no expected rows":  {KindBrowser, commit, nil, ok},
		"duplicate expect":  {KindBrowser, commit, []string{"a", "a"}, ok},
		"empty expected id": {KindBrowser, commit, []string{""}, ok},
		"duplicate row":     {KindBrowser, commit, []string{"a"}, append(ok, ok...)},
		"row without state": {KindBrowser, commit, []string{"a"}, []Row{{ID: "a"}}},
	} {
		if _, err := New(c.kind, c.commit, c.expected, c.rows); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Failing and missing rows are valid envelopes: the gate decides.
	rep, err := New(KindNodeLoss, commit, []string{"a", "b"}, []Row{{ID: "a", Status: StatusFailed, Detail: "boom"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Missing(); len(got) != 1 || got[0] != "b" {
		t.Fatalf("missing %v", got)
	}
	s := rep.Summary()
	for _, want := range []string{"2 expected, 1 rows, 0 passed, 1 not passed, 1 missing", "NOT PASSED a=failed", "MISSING b"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary lacks %q:\n%s", want, s)
		}
	}
}

func TestWriteIsAtomicStrictEnvelopeJSON(t *testing.T) {
	rep, err := New(KindLanguage, commit, []string{"b", "a"}, []Row{{ID: "a", Status: StatusPassed}, {ID: "b", Status: "not_exercised", Detail: "no runner"}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "language.json")
	if err = rep.Write(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("\r")) || !bytes.HasSuffix(raw, []byte("}\n")) {
		t.Fatalf("not LF JSON: %q", raw)
	}
	// The gate decodes with unknown fields rejected; the file holds exactly the five envelope fields.
	var back Report
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&back); err != nil {
		t.Fatal(err)
	}
	if back.Schema != Schema || back.Kind != KindLanguage || back.Commit != commit || strings.Join(back.Expected, ",") != "a,b" || len(back.Rows) != 2 {
		t.Fatalf("round trip %+v", back)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil || len(fields) != 5 {
		t.Fatalf("fields %v %v", fields, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("a temp file was left behind: %v", entries)
	}
	// An invalid report is never written.
	bad := rep
	bad.Expected = nil
	other := filepath.Join(t.TempDir(), "bad.json")
	if err = bad.Write(other); err == nil {
		t.Fatal("wrote a vacuous report")
	}
	if _, err = os.Stat(other); err == nil {
		t.Fatal("a refused report left a file")
	}
}

func TestDetailIsBounded(t *testing.T) {
	if got := Detail(" a ", "", "b"); got != "a; b" {
		t.Errorf("%q", got)
	}
	if got := Detail(strings.Repeat("x", 5000)); len(got) > 1300 {
		t.Errorf("unbounded detail: %d", len(got))
	}
}
