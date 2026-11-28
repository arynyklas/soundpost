// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"strings"
	"testing"
)

// Writing a transient value to os.Stderr or os.Stdout without a print call is the same leak as a
// print: only the helper main's one reviewed line may name them.
func TestAuditGoSourceFlagsProcessOutputOutsideTheReviewedPrint(t *testing.T) {
	p, err := LoadPolicy("../policy.json")
	if err != nil {
		t.Fatal(err)
	}
	leak := "package x\nimport \"os\"\nfunc f(b []byte) { os.Stderr.Write(b); os.Stdout.WriteString(string(b)) }\n"
	got := strings.Join(AuditGoSource(p, "leak.go", leak, HelperMainPrintOK), "\n")
	if !strings.Contains(got, "writes_to_process_output os.Stderr") || !strings.Contains(got, "writes_to_process_output os.Stdout") {
		t.Fatalf("direct writes to process output not flagged: %q", got)
	}
	reviewed := "package x\nimport (\"fmt\"; \"os\")\nfunc f(e error) { fmt.Fprintln(os.Stderr, \"native helper:\", e) }\n"
	if got := AuditGoSource(p, "main.go", reviewed, HelperMainPrintOK); len(got) != 0 {
		t.Fatalf("the reviewed helper line was flagged: %v", got)
	}
}
