// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"fmt"
	"strings"
	"testing"
)

// Each build configuration the production scan covers selects a file of its own
// (and no other configuration does): a scan that leaves one out misses it.
func TestProductionClosureScansEveryBuildTarget(t *testing.T) {
	harness := "package query\n"
	for _, tag := range []string{
		"linux && amd64 && !cgo",
		"linux && amd64 && cgo",
		"linux && arm64",
		"windows && amd64",
		"darwin && arm64",
		"freebsd && amd64",
	} {
		t.Run(tag, func(t *testing.T) {
			rep, err := closureOf(t, map[string]string{
				"internal/a/a.go":                 "package a\n",
				"internal/a/tagged.go":            fmt.Sprintf("//go:build %s\n\npackage a\nimport _ \"mod/internal/conformance/query\"\n", tag),
				"internal/conformance/query/q.go": harness,
			})
			if err != nil || len(rep.Violation) == 0 || !strings.Contains(strings.Join(rep.Violation, " "), "imports the conformance harness") {
				t.Fatalf("a file built only for %q was not scanned: %v %+v", tag, err, rep)
			}
		})
	}
	// A configuration no target builds is not production.
	rep, err := closureOf(t, map[string]string{
		"internal/a/a.go":                 "package a\n",
		"internal/a/ignored.go":           "//go:build ignore\n\npackage a\nimport _ \"mod/internal/conformance/query\"\n",
		"internal/a/other.go":             "//go:build plan9\n\npackage a\nimport _ \"mod/internal/conformance/query\"\n",
		"internal/conformance/query/q.go": harness,
	})
	if err != nil || len(rep.Violation) != 0 {
		t.Fatalf("a file no target builds was flagged: %v %+v", err, rep)
	}
}

// Every way to start a process under another name is resolved to the call it is.
func TestProductionClosureResolvesNamesOfProcessStarters(t *testing.T) {
	flagged := map[string]string{
		"an aliased os import":          "package a\nimport o \"os\"\nfunc F(){ _, _ = o.StartProcess(\"/usr/bin/docker\", nil, nil) }\n",
		"an aliased syscall import":     "package a\nimport sys \"syscall\"\nfunc F(){ _ = sys.Exec(\"/usr/bin/podman\", nil, nil) }\n",
		"a relative program path":       "package a\nimport \"syscall\"\nfunc F(){ _ = syscall.Exec(\"docker\", nil, nil) }\n",
		"an upper-case program":         "package a\nimport \"os/exec\"\nfunc F(){ _ = exec.Command(\"/usr/bin/Docker\") }\n",
		"a wrapper that names the tool": "package a\nimport \"os/exec\"\nfunc F(){ _ = exec.Command(\"sudo\", \"podman\", \"run\") }\n",
		"a raw string literal":          "package a\nimport \"os/exec\"\nfunc F(){ _ = exec.Command(`/usr/bin/loki`) }\n",
		"CommandContext of an upstream": "package a\nimport (\n\t\"context\"\n\t\"os/exec\"\n)\nfunc F(){ _ = exec.CommandContext(context.Background(), \"/bin/prometheus\") }\n",
	}
	for name, src := range flagged {
		rep, err := closureOf(t, map[string]string{"internal/a/a.go": src})
		if err != nil || len(rep.Violation) == 0 {
			t.Errorf("%s was not flagged: %v %+v", name, err, rep)
		}
	}
	clean := map[string]string{
		"os.StartProcess of an ordinary program":  "package a\nimport \"os\"\nfunc F(){ _, _ = os.StartProcess(\"/bin/true\", nil, nil) }\n",
		"syscall.Exec of an ordinary program":     "package a\nimport \"syscall\"\nfunc F(){ _ = syscall.Exec(\"/bin/sh\", nil, nil) }\n",
		"syscall.ForkExec of an ordinary program": "package a\nimport \"syscall\"\nfunc F(){ _, _ = syscall.ForkExec(\"/bin/echo\", nil, nil) }\n",
		"a dot-imported ordinary command":         "package a\nimport . \"os/exec\"\nfunc F(){ _ = Command(\"/bin/true\") }\n",
		"a call without arguments":                "package a\nimport \"syscall\"\nfunc F(){ _ = syscall.Exec }\n",
		"a method that only shares the name":      "package a\ntype t struct{}\nfunc (t) Command(string) {}\nfunc F(x t){ x.Command(\"docker\") }\n",
	}
	for name, src := range clean {
		rep, err := closureOf(t, map[string]string{"internal/a/a.go": src})
		if err != nil || len(rep.Violation) != 0 {
			t.Errorf("%s was flagged: %v %+v", name, err, rep)
		}
	}
}
