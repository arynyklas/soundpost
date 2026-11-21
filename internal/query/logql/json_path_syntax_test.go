// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"encoding/json"
	"os"
	"testing"
)

type syntaxCorpusRow struct {
	ID    string
	Input struct{ Expression string }
	// Expected carries the native verdict.
	Expected struct{ Accepted bool }
}

func loadSyntaxCorpus(t *testing.T, path string) []syntaxCorpusRow {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f struct{ Cases []syntaxCorpusRow }
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f.Cases
}

// TestJSONExtractionPathsNativeRejects replays the JSON extraction expressions
// the pinned reference rejects at parse time; each must fail with the same
// syntax.unexpected-token diagnostic rather than being accepted or failing
// differently.
func TestJSONExtractionPathsNativeRejects(t *testing.T) {
	rows := loadSyntaxCorpus(t, "../../../conformance/query/cases/logql-json-path-syntax.json")
	if len(rows) < 75 {
		t.Fatalf("json path syntax corpus shrank to %d rows", len(rows))
	}
	p := testProfile(t)
	for _, c := range rows {
		t.Run(c.ID, func(t *testing.T) {
			if c.Expected.Accepted {
				t.Fatal("corpus row is not a rejection")
			}
			_, err := parseCheck(t, c.Input.Expression, p)
			if err == nil {
				t.Fatalf("accepted %q", c.Input.Expression)
			}
			if code := languageCode(t, err); code != "syntax.unexpected-token" {
				t.Fatalf("code=%s want syntax.unexpected-token for %q", code, c.Input.Expression)
			}
		})
	}
}

// TestPipelineCorpusExpressionsParse proves every expression the pipeline
// differential corpus observed on the reference also parses and type-checks here.
func TestPipelineCorpusExpressionsParse(t *testing.T) {
	raw, err := os.ReadFile("../../../conformance/query/cases/logql-pipeline-differential.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct{ Cases []syntaxCorpusRow }
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	p := testProfile(t)
	seen := map[string]bool{}
	for _, c := range f.Cases {
		e := c.Input.Expression
		if seen[e] {
			continue
		}
		seen[e] = true
		if _, err := parseCheck(t, e, p); err != nil {
			t.Errorf("%s: native-accepted expression rejected: %q: %v", c.ID, e, err)
		}
	}
	if len(seen) < 100 {
		t.Fatalf("only %d distinct expressions", len(seen))
	}
}
