// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import "testing"

const closureApp = "package main\nimport _ \"mod/internal/a\"\nfunc main(){}\n"

func closureOf(t *testing.T, extra map[string]string) (ClosureReport, error) {
	t.Helper()
	files := map[string]string{"cmd/app/main.go": closureApp}
	for k, v := range extra {
		files[k] = v
	}
	return ProductionClosure(writeTree(t, files), "mod", []string{"mod/cmd/app"})
}

// A production source that reaches an oracle on a platform, in a spelling or
// through a call the first scan did not look at is still a production path to an
// oracle. The closure must flag each of them.
func TestProductionClosureFlagsTheBypassesOfAnOrdinaryScan(t *testing.T) {
	harness := "package query\n"
	cases := map[string]map[string]string{
		"an aliased os/exec import": {
			"internal/a/a.go": "package a\nimport run \"os/exec\"\nfunc F(){ _ = run.Command(\"/usr/bin/docker\", \"run\") }\n",
		},
		"a dot-imported os/exec": {
			"internal/a/a.go": "package a\nimport . \"os/exec\"\nfunc F(){ _ = Command(\"/usr/bin/podman\", \"run\") }\n",
		},
		"CommandContext through an alias": {
			"internal/a/a.go": "package a\nimport (\n\t\"context\"\n\trun \"os/exec\"\n)\nfunc F(){ _ = run.CommandContext(context.Background(), \"/usr/bin/docker\") }\n",
		},
		"os.StartProcess of an OCI runtime": {
			"internal/a/a.go": "package a\nimport \"os\"\nfunc F(){ _, _ = os.StartProcess(\"/usr/bin/docker\", []string{\"docker\"}, &os.ProcAttr{}) }\n",
		},
		"syscall.Exec of an OCI runtime": {
			"internal/a/a.go": "package a\nimport \"syscall\"\nfunc F(){ _ = syscall.Exec(\"/usr/bin/podman\", []string{\"podman\"}, nil) }\n",
		},
		"syscall.ForkExec of an upstream engine": {
			"internal/a/a.go": "package a\nimport \"syscall\"\nfunc F(){ _, _ = syscall.ForkExec(\"/bin/prometheus\", nil, nil) }\n",
		},
		"a cgo file that imports the harness": {
			"internal/a/a.go":                 "package a\n",
			"internal/a/c.go":                 "package a\n\n// #include <stdio.h>\nimport \"C\"\nimport _ \"mod/internal/conformance/query\"\n",
			"internal/conformance/query/q.go": harness,
		},
		"a file only built for darwin": {
			"internal/a/a.go":                 "package a\n",
			"internal/a/a_darwin.go":          "package a\nimport _ \"mod/internal/conformance/query\"\n",
			"internal/conformance/query/q.go": harness,
		},
		"a file only built for arm64": {
			"internal/a/a.go":                 "package a\n",
			"internal/a/a_arm64.go":           "package a\nimport _ \"mod/internal/conformance/query\"\n",
			"internal/conformance/query/q.go": harness,
		},
		"a file only built for freebsd": {
			"internal/a/a.go":                 "package a\n",
			"internal/a/a_freebsd.go":         "package a\nimport _ \"mod/internal/conformance/query\"\n",
			"internal/conformance/query/q.go": harness,
		},
		"an oracle entry point behind a build tag": {
			"internal/a/a.go":      "package a\n",
			"internal/a/tagged.go": "//go:build darwin && arm64\n\npackage a\nfunc F(){ RunOracle() }\nfunc RunOracle(){}\n",
		},
	}
	for name, extra := range cases {
		rep, err := closureOf(t, extra)
		if err != nil || len(rep.Violation) == 0 {
			t.Errorf("%s was not flagged: %v %+v", name, err, rep)
		}
	}
}

// Precision: what is not a way to an oracle stays clean, on every platform.
func TestProductionClosureStaysCleanForPlatformFilesAndOrdinaryExec(t *testing.T) {
	rep, err := closureOf(t, map[string]string{
		"internal/a/a.go":         "package a\nimport run \"os/exec\"\nfunc F(){ _ = run.Command(\"/bin/true\") }\n",
		"internal/a/a_windows.go": "package a\nvar W = 1\n",
		"internal/a/a_darwin.go":  "package a\nvar D = 1\n",
		"internal/a/a_arm64.go":   "package a\nvar A = 1\n",
		"internal/a/a_test.go":    "package a\nimport _ \"mod/internal/conformance/query\"\n",
	})
	if err != nil || len(rep.Violation) != 0 {
		t.Fatalf("a clean tree was flagged: %v %+v", err, rep)
	}
	// main.go + a.go + one file per other platform, each counted once however many
	// platforms select it, and no test file.
	if rep.Files != 5 || len(rep.Packages) != 2 {
		t.Fatalf("scanned %d files of %v, want 5 files of 2 packages", rep.Files, rep.Packages)
	}
}
