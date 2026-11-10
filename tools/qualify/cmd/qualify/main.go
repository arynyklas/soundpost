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
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"soundpost/tools/qualify"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	fs := flag.NewFlagSet("qualify", flag.ContinueOnError)
	suite := fs.String("suite", "", "runtime, privacy or overhead")
	matrix := fs.String("matrix", "qualification/matrix.yaml", "qualification matrix")
	report := fs.String("report", "", "directory for the machine report and the raw safe evidence")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *report == "" {
		fmt.Fprintln(os.Stderr, "usage: qualify --suite runtime|privacy|overhead --matrix <file> --report <dir>")
		return qualify.ExitUsage
	}
	switch s := qualify.Suite(*suite); s {
	case qualify.SuiteRuntime, qualify.SuitePrivacy, qualify.SuiteOverhead:
	default:
		fmt.Fprintf(os.Stderr, "qualify: unknown suite %q\n", *suite)
		return qualify.ExitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	rep, err := qualify.RunSuite(ctx, qualify.Suite(*suite), *matrix, *report)
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
