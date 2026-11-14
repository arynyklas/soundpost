// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/arynyklas/soundpost/internal/releaseevidence"
	"github.com/arynyklas/soundpost/tools/qualify"
)

// runEvidence converts a written campaign-report.json into the "language" release evidence:
//
//	query-campaign evidence --matrix <file> --campaign-report <file> --commit <sha> --out <file>
//
// It exits 0 when the envelope was written, whatever the rows say: the release gate decides.
func runEvidence(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("query-campaign evidence", flag.ContinueOnError)
	matrixPath := fs.String("matrix", "qualification/query-matrix.yaml", "campaign matrix the report was produced from")
	reportPath := fs.String("campaign-report", "", "campaign-report.json written by the campaign")
	commit := fs.String("commit", "", "full 40-hex source commit the campaign ran against")
	out := fs.String("out", "", "envelope file to write")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *reportPath == "" || *out == "" || fs.NArg() != 0 {
		return fmt.Errorf("usage: query-campaign evidence --matrix <file> --campaign-report <file> --commit <sha> --out <file>")
	}
	if err := releaseevidence.CheckCommit(*commit); err != nil {
		return err
	}
	matrix, err := qualify.LoadQueryMatrix(*matrixPath)
	if err != nil {
		return err
	}
	rep, err := qualify.ReadCampaignReport(*reportPath)
	if err != nil {
		return err
	}
	env, err := qualify.QueryCampaignEvidence(matrix, rep, *commit)
	if err != nil {
		return err
	}
	if err = env.Write(*out); err != nil {
		return err
	}
	fmt.Fprintln(stdout, env.Summary())
	return nil
}
