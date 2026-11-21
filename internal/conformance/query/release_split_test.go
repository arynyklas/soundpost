// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// One version-difference fixture becomes exactly one case per declared profile,
// each with an expectation of its own and memory of its own.
func TestSplitProfileExpectationsDeclaresExactlyTheProfilesItNames(t *testing.T) {
	old := SemanticResult{Kind: "syntax", Type: "error", Diagnostics: []Diagnostic{{Code: "syntax"}}}
	current := SemanticResult{Kind: "syntax", Type: "vector"}
	both := []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"}
	expect := ExpectedByProfile{"promql-prometheus-3.1.0": old, "promql-prometheus-3.13.5": current}
	input := []byte(`{"query":"end()"}`)

	cs, err := SplitProfileExpectations("v/end", both, input, expect)
	if err != nil || len(cs) != 2 || cs[0].ID != "v/end" || cs[1].ID != "v/end" || cs[0].Profile != both[0] || cs[1].Profile != both[1] {
		t.Fatalf("%v %+v", err, cs)
	}
	if cs[0].Expected.Type != "error" || cs[1].Expected.Type != "vector" || len(cs[0].Expected.Diagnostics) != 1 || len(cs[1].Expected.Diagnostics) != 0 {
		t.Fatalf("expectations crossed: %+v %+v", cs[0].Expected, cs[1].Expected)
	}
	// Neither the expectation nor the input is shared between the copies or with the caller.
	cs[0].Expected.Diagnostics[0].Code = "changed"
	cs[0].Input[2] = 'X'
	if cs[1].Expected.Diagnostics != nil || old.Diagnostics[0].Code != "syntax" || string(cs[1].Input) != `{"query":"end()"}` || string(input) != `{"query":"end()"}` {
		t.Fatalf("the copies share memory: %+v %s %s", cs[1], cs[1].Input, input)
	}
	for name, c := range map[string]struct {
		profiles []string
		expected ExpectedByProfile
	}{
		"no declared profile":                   {nil, ExpectedByProfile{}},
		"a profile without an expectation":      {both, ExpectedByProfile{both[0]: old}},
		"an undeclared extra expectation":       {both, ExpectedByProfile{both[0]: old, both[1]: current, "logql-loki-3.5.2": old}},
		"a declared profile listed twice":       {[]string{both[0], both[0]}, ExpectedByProfile{both[0]: old, both[1]: current}},
		"an expectation for another profile":    {[]string{both[0], "promql-prometheus-9.9.9"}, ExpectedByProfile{both[0]: old, both[1]: current}},
		"a declared profile twice, one missing": {[]string{both[0], both[0]}, ExpectedByProfile{both[0]: old, "logql-loki-3.5.2": current}},
	} {
		if cs, err := SplitProfileExpectations("v/end", c.profiles, input, c.expected); err == nil {
			t.Errorf("%s was accepted: %+v", name, cs)
		}
	}
}

func digestOf(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func writeProvenance(t *testing.T, dir string, entries ...[2]string) {
	t.Helper()
	var b strings.Builder
	b.WriteString(`{"accepted_audits":[`)
	for i, e := range entries {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"path":"` + e[0] + `","sha256":"` + e[1] + `"}`)
	}
	b.WriteString(`]}`)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "provenance.json"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Provenance is accepted only for the audit bytes that were accepted, and only
// for files inside the query directory.
func TestProvenanceDecisionsAcceptOnlyTheAuditedBytesInsideTheQueryDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "query")
	if err := os.MkdirAll(filepath.Join(dir, "audits"), 0o755); err != nil {
		t.Fatal(err)
	}
	good, edited := "audit bytes", "audit bytes, edited"
	for name, body := range map[string]string{"audits/good.json": good, "audits/edited.json": edited} {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(name)), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "outside.json"), []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	writeProvenance(t, dir,
		[2]string{"audits/good.json", digestOf(good)},
		[2]string{"audits/edited.json", digestOf(good)},
		[2]string{"audits/missing.json", digestOf(good)},
		[2]string{"../outside.json", digestOf(good)},
		[2]string{"/etc/passwd", digestOf(good)},
	)
	got, err := ProvenanceDecisions(dir)
	if err != nil || len(got) != 5 {
		t.Fatalf("%v %+v", err, got)
	}
	if !got[0].Accepted || got[0].File != "audits/good.json" || got[0].Reason != "" {
		t.Errorf("the audited file was not accepted: %+v", got[0])
	}
	if got[1].Accepted || got[1].Reason != "content digest differs from the accepted audit" {
		t.Errorf("an edited audit was accepted: %+v", got[1])
	}
	if got[2].Accepted || got[2].Reason == "" {
		t.Errorf("a missing audit was accepted: %+v", got[2])
	}
	if got[3].Accepted || !strings.Contains(got[3].Reason, "outside the query directory") {
		t.Errorf("an audit outside the query directory was accepted: %+v", got[3])
	}
	if got[4].Accepted || !strings.Contains(got[4].Reason, "outside the query directory") {
		t.Errorf("an absolute audit path was accepted: %+v", got[4])
	}
	// No audit accepted at all is not a decision.
	writeProvenance(t, dir)
	if _, err := ProvenanceDecisions(dir); err == nil {
		t.Fatal("a provenance manifest that accepts no audit was loaded")
	}
	if _, err := ProvenanceDecisions(filepath.Join(root, "nowhere")); err == nil {
		t.Fatal("a missing provenance manifest was loaded")
	}
}

// The repository's own manifest: every audit it accepts is intact.
func TestRealProvenanceDecisionsAreAllAccepted(t *testing.T) {
	got, err := ProvenanceDecisions(queryRoot())
	if err != nil || len(got) == 0 {
		t.Fatalf("%v %d", err, len(got))
	}
	for _, d := range got {
		if !d.Accepted || d.Reason != "" {
			t.Errorf("%+v", d)
		}
	}
}
