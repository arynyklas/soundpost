// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package corpus

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func queryDir(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "conformance", "query", "source-lock.json")); err == nil {
			return filepath.Join(dir, "conformance", "query")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found")
		}
		dir = parent
	}
}

func corpusDoc(t *testing.T) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(queryDir(t), "cases", "input-normalization.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []map[string]any `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Cases
}

func runDoctored(t *testing.T, cases []map[string]any) (CorpusReport, error) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"cases": cases})
	if err != nil {
		t.Fatal(err)
	}
	return RunCorpus(context.Background(), queryDir(t), raw)
}

func expectedOf(t *testing.T, cases []map[string]any, id string) map[string]any {
	t.Helper()
	for _, c := range cases {
		if c["id"] == id {
			return c["expected"].(map[string]any)
		}
	}
	t.Fatalf("no corpus row %s", id)
	return nil
}

func TestRunCorpusMatchesEveryRow(t *testing.T) {
	rep, err := runDoctored(t, corpusDoc(t))
	if err != nil {
		t.Fatalf("%v\n%v", err, rep.Mismatches)
	}
	if rep.Cases != 30 || rep.Positive != 7 || rep.Negative != 23 || rep.Records != 33 || rep.Matched != 30 || rep.Mismatched != 0 || len(rep.Rows) != 30 {
		t.Fatalf("unexpected report %+v", rep)
	}
}

// The runner must compare every part of `expected`: a doctored row that the
// translators do not satisfy has to surface as a mismatch and a non-nil error.
func TestRunCorpusDetectsDoctoredExpectations(t *testing.T) {
	const positive = "input-remote-write-v2-lossless-kinds"
	negative := ""
	for _, c := range corpusDoc(t) {
		if e := c["expected"].(map[string]any); e["error"] != nil {
			negative = c["id"].(string)
			break
		}
	}
	tests := map[string]struct {
		id     string
		mutate func(e map[string]any)
		want   string
	}{
		"record dropped from expected": {positive, func(e map[string]any) { e["records"] = e["records"].([]any)[1:] }, "input mismatch"},
		"record altered in expected": {positive, func(e map[string]any) {
			r := e["records"].([]any)[0].(map[string]any)
			r["ts"] = "1"
		}, "input mismatch"},
		"report count altered":      {positive, func(e map[string]any) { e["report"] = map[string]any{"no_such_counter": 7} }, "report"},
		"error reason altered":      {negative, func(e map[string]any) { e["error"] = map[string]any{"reason": "no-such-reason"} }, "reason"},
		"error row expects success": {negative, func(e map[string]any) { delete(e, "error"); e["records"] = []any{} }, "unexpected rejection"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cases := corpusDoc(t)
			tc.mutate(expectedOf(t, cases, tc.id))
			rep, err := runDoctored(t, cases)
			if err == nil || rep.Mismatched != 1 || rep.Matched != 29 {
				t.Fatalf("doctored row accepted: err=%v report=%+v", err, rep)
			}
			if len(rep.Mismatches) != 1 || !strings.HasPrefix(rep.Mismatches[0], tc.id+": ") || !strings.Contains(rep.Mismatches[0], tc.want) {
				t.Fatalf("mismatch %v does not name %s / %q", rep.Mismatches, tc.id, tc.want)
			}
		})
	}
	// A positive row whose input is now rejected must also fail (expected success, got error).
	cases := corpusDoc(t)
	expectedOf(t, cases, negative)["error"] = nil
	if _, err := runDoctored(t, cases); err == nil {
		t.Fatal("negative row with error removed was accepted")
	}
}

func TestRunCorpusEnforcesCorpusFloor(t *testing.T) {
	if _, err := runDoctored(t, corpusDoc(t)[:10]); err == nil || !strings.Contains(err.Error(), "corpus floor") {
		t.Fatalf("shrunken corpus accepted: %v", err)
	}
}
