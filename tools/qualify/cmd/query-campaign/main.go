// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Command query-campaign runs the query language qualification campaign and
// exits nonzero unless every required row is verified.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"soundpost/tools/qualify"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	matrixPath := flag.String("matrix", "qualification/query-matrix.yaml", "campaign matrix")
	artifacts := flag.String("artifact-dir", "", "directory for the reports and campaign-report.json")
	flag.Parse()
	if *artifacts == "" {
		return fmt.Errorf("--artifact-dir is required")
	}
	matrix, err := qualify.LoadQueryMatrix(*matrixPath)
	if err != nil {
		return err
	}
	report, err := qualify.RunQueryConformance(context.Background(), matrix, *artifacts)
	verified := 0
	for _, r := range report.Rows {
		if r.Verified {
			verified++
		}
	}
	fmt.Printf("query campaign: %d of %d rows verified; report %s/campaign-report.json\n", verified, len(report.Rows), *artifacts)
	return err
}
