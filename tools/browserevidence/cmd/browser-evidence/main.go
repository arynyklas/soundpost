// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Command browser-evidence converts the actual-browser acceptance results into the release gate's
// "browser" evidence:
//
//	browser-evidence --commit <sha> --out <file> --playwright-list <list.json> \
//	    [--playwright-results <run.json>] [--project chromium] [--journeys <observed.json>] [--evidence <evidence-summary.json>]
//
// A result file that does not exist leaves its expected rows without a result (the gate names
// them); the Playwright list is required because it names the tests that must run. The command
// exits 0 when the envelope was written, whatever the rows say: the release gate decides.
package main

import (
	"flag"
	"fmt"
	"os"

	"soundpost/internal/releaseevidence"
	"soundpost/tools/browserevidence"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "browser-evidence:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("browser-evidence", flag.ContinueOnError)
	commit := fs.String("commit", "", "full 40-hex source commit the acceptance ran against")
	out := fs.String("out", "", "envelope file to write")
	project := fs.String("project", "chromium", "Playwright project that ran in real Chrome")
	list := fs.String("playwright-list", "", "`playwright test --list --reporter=json` output of the same project and files")
	results := fs.String("playwright-results", "", "`playwright test --reporter=json` output of the run")
	journeys := fs.String("journeys", "", "observed.json of `tools/smoke journeys`")
	evidence := fs.String("evidence", "", "evidence-summary.json of `tools/smoke evidence`")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || *list == "" || fs.NArg() != 0 {
		return fmt.Errorf("usage: browser-evidence --commit <sha> --out <file> --playwright-list <file> [--playwright-results <file>] [--project chromium] [--journeys <file>] [--evidence <file>]")
	}
	if err := releaseevidence.CheckCommit(*commit); err != nil {
		return err
	}
	in := browserevidence.Inputs{Project: *project}
	for _, f := range []struct {
		path string
		dst  *[]byte
	}{{*list, &in.PlaywrightList}, {*results, &in.PlaywrightResults}, {*journeys, &in.Journeys}, {*evidence, &in.Evidence}} {
		raw, err := browserevidence.ReadFile(f.path)
		if err != nil {
			return err
		}
		*f.dst = raw
	}
	env, err := browserevidence.Export(in, *commit)
	if err != nil {
		return err
	}
	if err = env.Write(*out); err != nil {
		return err
	}
	fmt.Println(env.Summary())
	return nil
}
