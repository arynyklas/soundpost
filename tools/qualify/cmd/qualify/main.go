// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Command qualify runs one runtime, privacy or overhead qualification suite
// against the builds actually installed on this host:
//
//	qualify --suite runtime|privacy|overhead --matrix qualification/matrix.yaml --report <dir>
//
// Every matrix row carries exactly one of exercised, not_exercised, unsupported
// or denied, with its measured evidence or its exact reason. The command exits 0
// only when every required row is exercised and within its design section 13
// budget; 1 for a measured failure (a missed budget or check blocks the claim),
// 2 for a usage or matrix error, and 10 when required rows were not exercised
// (NOT a pass). It prints every unqualified required row and measured failure.
//
// A host that cannot run every row as one user (the native-kernel rows need root, a browser refuses to run as root, the PostgreSQL rows
// need the Docker host) runs the suite in parts, `--only <regexp>` and `--except <regexp>` selecting rows by id; a row a part did not
// select is absent from its report (never reported as not exercised), and the parts are combined with `qualify merge`.
//
// The release gate reads the runtime and privacy suite reports through
//
//	qualify evidence --kind runtime|privacy --matrix <file> --commit <sha> --out <file> --report <suite-report.json> ...
//
// which only converts the written rows into the soundpost-release-evidence/1 envelope. The suites of one matrix run on several hosts
// (a host holds the Node builds installed on it) are combined first, row by row, bound to the run that observed each row:
//
//	qualify merge --out <merged-report.json> [--source <64-hex>] --report <suite-report.json> [--report ...]
//
// A report stamped against another source digest than the merged report is built for refuses the merge.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"regexp"

	"github.com/arynyklas/soundpost/tools/qualify"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) > 0 && args[0] == "merge" {
		return runMerge(args[1:], os.Stdout, os.Stderr)
	}
	if len(args) > 0 && args[0] == "evidence" {
		return runEvidence(args[1:], os.Stdout, os.Stderr)
	}
	fs := flag.NewFlagSet("qualify", flag.ContinueOnError)
	suite := fs.String("suite", "", "runtime, privacy or overhead")
	matrix := fs.String("matrix", "qualification/matrix.yaml", "qualification matrix")
	report := fs.String("report", "", "directory for the machine report and the raw safe evidence")
	only := fs.String("only", "", "run only the rows whose id matches this regular expression (a host runs the suite in parts: root for the native rows, an ordinary user for the browsers)")
	except := fs.String("except", "", "skip the rows whose id matches this regular expression")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *report == "" {
		fmt.Fprintln(os.Stderr, "usage: qualify --suite runtime|privacy|overhead --matrix <file> --report <dir> [--only <regexp>] [--except <regexp>]")
		return qualify.ExitUsage
	}
	var opt qualify.RunOptions
	for _, f := range []struct {
		name, expr string
		into       **regexp.Regexp
	}{{"--only", *only, &opt.Only}, {"--except", *except, &opt.Except}} {
		if f.expr == "" {
			continue
		}
		re, err := regexp.Compile(f.expr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "qualify: %s: %v\n", f.name, err)
			return qualify.ExitUsage
		}
		*f.into = re
	}
	switch s := qualify.Suite(*suite); s {
	case qualify.SuiteRuntime, qualify.SuitePrivacy, qualify.SuiteOverhead:
	default:
		fmt.Fprintf(os.Stderr, "qualify: unknown suite %q\n", *suite)
		return qualify.ExitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	rep, err := qualify.RunSuiteWith(ctx, qualify.Suite(*suite), *matrix, *report, opt)
	if len(rep.Rows) > 0 || err == nil {
		fmt.Print(rep.Summary())
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "qualify: %v\n", err)
		if rep.ExitCode == qualify.ExitOK || len(rep.Rows) == 0 {
			return qualify.ExitUsage
		}
	}
	return rep.ExitCode
}
