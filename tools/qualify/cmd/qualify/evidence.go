// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/arynyklas/soundpost/internal/releaseevidence"
	"github.com/arynyklas/soundpost/tools/qualify"
)

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// runEvidence converts existing suite reports into the soundpost-release-evidence/1 envelope:
//
//	qualify evidence --kind runtime|privacy --matrix <file> --commit <sha> --out <file> --report <suite-report.json> [--report ...]
//
// It exits 0 when the envelope was written, whatever the rows say: the release gate decides.
func runEvidence(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("qualify evidence", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	kind := fs.String("kind", "", "runtime (runtime and overhead suites) or privacy")
	matrix := fs.String("matrix", "qualification/matrix.yaml", "the matrix the reports were produced from")
	commit := fs.String("commit", "", "full 40-hex source commit the suites ran against")
	out := fs.String("out", "", "envelope file to write")
	var reports stringList
	fs.Var(&reports, "report", "a <suite>-report.json (repeat: runtime needs runtime and overhead)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *kind == "" || *out == "" || len(reports) == 0 {
		fmt.Fprintln(stderr, "usage: qualify evidence --kind runtime|privacy --matrix <file> --commit <sha> --out <file> --report <suite-report.json> [--report ...]")
		return qualify.ExitUsage
	}
	if err := releaseevidence.CheckCommit(*commit); err != nil {
		fmt.Fprintln(stderr, "qualify evidence:", err)
		return qualify.ExitUsage
	}
	var suites []qualify.SuiteReport
	for _, path := range reports {
		rep, err := qualify.ReadSuiteReport(path)
		if err != nil {
			fmt.Fprintln(stderr, "qualify evidence:", err)
			return qualify.ExitFail
		}
		suites = append(suites, rep)
	}
	env, err := qualify.SuiteEvidence(*kind, *matrix, suites, *commit)
	if err == nil {
		err = env.Write(*out)
	}
	if err != nil {
		fmt.Fprintln(stderr, "qualify evidence:", err)
		return qualify.ExitFail
	}
	fmt.Fprintln(stdout, env.Summary())
	return qualify.ExitOK
}
