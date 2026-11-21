// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"strings"
	"testing"
)

// The file scan reads every file a target selects, the files that import "C" included: a cgo file
// that starts an OCI runtime, or names an oracle, is production code like any other.
func TestProductionClosureScansTheFilesThatImportC(t *testing.T) {
	for name, src := range map[string]string{
		"starts an OCI runtime":    "package a\n\n// #include <stdio.h>\nimport \"C\"\nimport \"os/exec\"\n\nfunc G() { _ = exec.Command(\"/usr/bin/docker\") }\n",
		"calls an oracle function": "package a\n\n// #include <stdio.h>\nimport \"C\"\n\nfunc G() { RunOracle() }\n",
		"names an oracle image":    "package a\n\n// #include <stdio.h>\nimport \"C\"\n\nvar image = \"oci-semantic-json-v1\"\n",
	} {
		rep, err := closureOf(t, map[string]string{"internal/a/a.go": "package a\n", "internal/a/c.go": src})
		if err != nil || !strings.Contains(strings.Join(rep.Violation, "\n"), "internal/a/c.go") {
			t.Errorf("a cgo file that %s was not scanned: %v %+v", name, err, rep)
		}
	}
	// ...and a clean cgo file is clean, and counted.
	rep, err := closureOf(t, map[string]string{"internal/a/a.go": "package a\n", "internal/a/c.go": "package a\n\n// #include <stdio.h>\nimport \"C\"\n"})
	if err != nil || len(rep.Violation) != 0 {
		t.Fatalf("a clean cgo file was flagged: %v %+v", err, rep)
	}
	plain, err := closureOf(t, map[string]string{"internal/a/a.go": "package a\n"})
	if err != nil || rep.Files != plain.Files+1 {
		t.Fatalf("the cgo file was not counted among the scanned files: %d files with it, %d without (%v)", rep.Files, plain.Files, err)
	}
}

// Every call that replaces or forks the process is a call that starts a program: ForkExec of an OCI
// runtime is flagged on its own, without any oracle literal to give it away.
func TestProductionClosureFlagsForkExecOfAnOCIRuntime(t *testing.T) {
	rep, err := closureOf(t, map[string]string{"internal/a/a.go": "package a\nimport \"syscall\"\nfunc F(){ _, _ = syscall.ForkExec(\"/usr/bin/docker\", nil, nil) }\n"})
	if err != nil || !strings.Contains(strings.Join(rep.Violation, "\n"), "executes docker") {
		t.Fatalf("syscall.ForkExec of docker was not flagged: %v %+v", err, rep)
	}
}

// Each program a production path may not start is flagged by its base name alone, wherever it
// lives, with no oracle literal in the file to give it away.
func TestProductionClosureFlagsEveryForbiddenExecutableByName(t *testing.T) {
	for _, tc := range []struct{ program, base string }{
		{"docker", "docker"}, {"/usr/local/bin/podman", "podman"}, {"prometheus", "prometheus"},
		{"/opt/monitoring/prometheus-2.0", "prometheus-2.0"}, {"loki", "loki"}, {"/srv/Loki/loki-canary", "loki-canary"},
	} {
		rep, err := closureOf(t, map[string]string{"internal/a/a.go": "package a\nimport \"os/exec\"\nfunc F(){ _ = exec.Command(\"" + tc.program + "\") }\n"})
		if err != nil || !strings.Contains(strings.Join(rep.Violation, "\n"), "executes "+tc.base) {
			t.Errorf("exec.Command(%q) was not flagged as executing %s: %v %+v", tc.program, tc.base, err, rep)
		}
	}
	rep, err := closureOf(t, map[string]string{"internal/a/a.go": "package a\nimport \"os/exec\"\nfunc F(){ _ = exec.Command(\"/bin/true\") }\n"})
	if err != nil || len(rep.Violation) != 0 {
		t.Errorf("an ordinary program was flagged: %v %+v", err, rep)
	}
}

// Each upstream engine the harness drives as an oracle is a package a production path may not
// import, whatever the engine's own import path below the prefix.
func TestProductionClosureFlagsEveryUpstreamEngineImport(t *testing.T) {
	for _, imp := range []string{
		"github.com/prometheus/prometheus/promql",
		"github.com/prometheus/client_golang/prometheus",
		"github.com/grafana/loki/v3/pkg/logql",
		"github.com/grafana/dskit/user",
	} {
		rep, err := closureOf(t, map[string]string{"internal/a/a.go": "package a\nimport _ \"" + imp + "\"\n"})
		if err != nil || !strings.Contains(strings.Join(rep.Violation, "\n"), "imports upstream engine "+imp) {
			t.Errorf("an import of %s was not flagged: %v %+v", imp, err, rep)
		}
	}
}

// The querycheck command is the conformance harness's own entry point: importing it is reached
// as the harness, even though it is a package of this module that is otherwise followed.
func TestProductionClosureFlagsAnImportOfTheQuerycheckCommand(t *testing.T) {
	rep, err := closureOf(t, map[string]string{
		"internal/a/a.go":               "package a\nimport _ \"mod/cmd/soundpost-querycheck\"\n",
		"cmd/soundpost-querycheck/m.go": "package main\nfunc main() {}\n",
	})
	if err != nil || !strings.Contains(strings.Join(rep.Violation, "\n"), "imports the conformance harness mod/cmd/soundpost-querycheck") {
		t.Fatalf("an import of the querycheck command was not flagged: %v %+v", err, rep)
	}
}
