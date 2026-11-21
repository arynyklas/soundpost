// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/arynyklas/soundpost/internal/releaseevidence"
	"github.com/arynyklas/soundpost/tools/qualify"
)

// runMerge merges suite reports written by separate runs (one Node per host or per run) into one report:
//
//	qualify merge --out <merged-report.json> [--source <64-hex>] --report <suite-report.json> [--report ...]
//
// The merged report is built for --source (default: the source digest of the tree this command runs in). A report stamped against
// another source refuses the merge and nothing is written. The result is a suite report like any other, with every row bound to the
// run that observed it; `qualify evidence` reads it. It exits 0 when the merged report was written, 10 when the merged suite still has
// unqualified required rows and 1 for a measured failure, exactly like the suite run itself.
func runMerge(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("qualify merge", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	out := fs.String("out", "", "merged suite report to write")
	source := fs.String("source", "", "source digest the merged report is built for (default: this tree's, go run ./build source-digest)")
	var reports stringList
	fs.Var(&reports, "report", "a <suite>-report.json from one run (repeat)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *out == "" || len(reports) == 0 {
		fmt.Fprintln(stderr, "usage: qualify merge --out <merged-report.json> [--source <64-hex>] --report <suite-report.json> [--report ...]")
		return qualify.ExitUsage
	}
	stamp := *source
	if stamp == "" {
		var err error
		if stamp, err = releaseevidence.CurrentSourceDigest(); err != nil {
			fmt.Fprintln(stderr, "qualify merge: source digest of this tree:", err)
			return qualify.ExitUsage
		}
	}
	var suites []qualify.SuiteReport
	for _, path := range reports {
		rep, err := qualify.ReadSuiteReport(path)
		if err != nil {
			fmt.Fprintln(stderr, "qualify merge:", err)
			return qualify.ExitFail
		}
		suites = append(suites, rep)
	}
	merged, err := qualify.MergeSuiteReports(stamp, suites...)
	if err != nil {
		fmt.Fprintln(stderr, "qualify merge:", err)
		return qualify.ExitFail
	}
	raw, err := json.MarshalIndent(merged, "", " ")
	if err == nil {
		err = os.WriteFile(*out, append(raw, '\n'), 0o644)
	}
	if err != nil {
		fmt.Fprintln(stderr, "qualify merge:", err)
		return qualify.ExitFail
	}
	fmt.Fprint(stdout, merged.Summary())
	fmt.Fprintf(stdout, "merged %d report(s) into %d rows from %d run(s) for source %s: %s\n", len(suites), len(merged.Rows), len(merged.Runs), stamp, *out)
	return merged.ExitCode
}
