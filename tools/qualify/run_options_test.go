// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// A host runs the suite in parts (native rows as root, browser rows as an ordinary user): a part holds only the rows it selected, a row it
// did not select is absent from its report and never appears as not exercised, so merging the parts can never be outvoted by a part that
// could not look at a row.
func TestRunSuiteWithRunsOnlyTheSelectedRows(t *testing.T) {
	root := t.TempDir()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "qualification", "workloads.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "workloads.yaml"), string(raw))
	writeFile(t, filepath.Join(root, "matrix.yaml"), tinyMatrix)
	ids := func(opt RunOptions) []string {
		t.Helper()
		rep, err := RunSuiteWith(context.Background(), SuiteRuntime, filepath.Join(root, "matrix.yaml"), filepath.Join(root, "report"), opt)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range rep.Rows {
			out = append(out, r.ID)
		}
		return out
	}
	same := func(got []string, want ...string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("rows %v, want %v", got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("rows %v, want %v", got, want)
			}
		}
	}
	same(ids(RunOptions{}), "runtime.browser.firefox.sample", "runtime.python-3.13.linux-arm64", "runtime.optional")
	same(ids(RunOptions{Only: regexp.MustCompile(`^runtime\.browser\.`)}), "runtime.browser.firefox.sample")
	same(ids(RunOptions{Except: regexp.MustCompile(`^runtime\.browser\.`)}), "runtime.python-3.13.linux-arm64", "runtime.optional")
	same(ids(RunOptions{Only: regexp.MustCompile(`runtime\.`), Except: regexp.MustCompile(`optional|firefox`)}), "runtime.python-3.13.linux-arm64")
	same(ids(RunOptions{Only: regexp.MustCompile(`^nothing$`)}))
}
