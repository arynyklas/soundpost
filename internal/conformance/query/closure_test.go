// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestProductionClosureFlagsEveryWayToReachAnOracle(t *testing.T) {
	clean := map[string]string{
		"cmd/app/main.go":      "package main\nimport _ \"mod/internal/a\"\nfunc main(){}\n",
		"internal/a/a.go":      "package a\nimport \"os/exec\"\nfunc F(){ _ = exec.Command(\"/bin/true\") }\n",
		"internal/a/a_test.go": "package a\nimport _ \"mod/internal/conformance/query\"\n",
	}
	root := writeTree(t, clean)
	rep, err := ProductionClosure(root, "mod", []string{"mod/cmd/app"})
	if err != nil || len(rep.Violation) != 0 || len(rep.Packages) != 2 {
		t.Fatalf("a clean tree was flagged (a test file importing the harness is not production): %v %+v", err, rep)
	}
	cases := map[string]map[string]string{
		"import the harness":   {"internal/a/a.go": "package a\nimport _ \"mod/internal/conformance/query\"\n", "internal/conformance/query/q.go": "package query\n"},
		"import via a hop":     {"internal/a/a.go": "package a\nimport _ \"mod/internal/b\"\n", "internal/b/b.go": "package b\nimport _ \"mod/internal/conformance/query\"\n", "internal/conformance/query/q.go": "package query\n"},
		"upstream engine":      {"internal/a/a.go": "package a\nimport _ \"github.com/prometheus/prometheus/promql\"\n"},
		"call an oracle":       {"internal/a/a.go": "package a\nfunc F(){ RunOracle() }\nfunc RunOracle(){}\n"},
		"name an oracle image": {"internal/a/a.go": "package a\nvar x = \"soundpost-oracle-promql\"\n"},
		"exec docker":          {"internal/a/a.go": "package a\nimport \"os/exec\"\nfunc F(){ _ = exec.Command(\"/usr/bin/docker\", \"run\") }\n"},
		"exec an upstream":     {"internal/a/a.go": "package a\nimport \"os/exec\"\nfunc F(){ _ = exec.Command(\"/bin/prometheus\") }\n"},
		"windows-only file":    {"internal/a/a.go": "package a\n", "internal/a/a_windows.go": "package a\nimport _ \"mod/internal/conformance/query\"\n", "internal/conformance/query/q.go": "package query\n"},
	}
	for name, extra := range cases {
		files := map[string]string{"cmd/app/main.go": clean["cmd/app/main.go"]}
		for k, v := range extra {
			files[k] = v
		}
		rep, err := ProductionClosure(writeTree(t, files), "mod", []string{"mod/cmd/app"})
		if err != nil || len(rep.Violation) == 0 {
			t.Errorf("%s was not flagged: %v %+v", name, err, rep)
		}
	}
}

func TestBinarySymbolCheckNamesHarnessAndUpstreamSymbols(t *testing.T) {
	nm := " 4a0 T github.com/arynyklas/soundpost/internal/query.(*Engine).Execute\n 5b0 T github.com/arynyklas/soundpost/internal/conformance/query.RunOracle\n 6c0 T github.com/prometheus/prometheus/promql.NewEngine\n"
	bad := ForbiddenBinarySymbols(nm, "github.com/arynyklas/soundpost")
	if len(bad) != 2 || !strings.Contains(strings.Join(bad, " "), "RunOracle") {
		t.Fatalf("%v", bad)
	}
	if len(ForbiddenBinarySymbols(" 4a0 T github.com/arynyklas/soundpost/internal/query.(*Engine).Execute\n", "github.com/arynyklas/soundpost")) != 0 {
		t.Fatal("a production symbol was flagged")
	}
}

// The real tree: no production package reaches the harness, an upstream
// engine or an oracle runtime.
func TestRealProductionTreeReachesNoOracle(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	roots, err := ProductionRoots(root, "github.com/arynyklas/soundpost")
	if err != nil || len(roots) < 20 {
		t.Fatalf("production roots: %v (%d)", err, len(roots))
	}
	rep, err := ProductionClosure(root, "github.com/arynyklas/soundpost", roots)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d packages, %d files scanned", len(rep.Packages), rep.Files)
	if len(rep.Violation) != 0 {
		t.Fatalf("production code reaches an oracle: %v", rep.Violation)
	}
}
