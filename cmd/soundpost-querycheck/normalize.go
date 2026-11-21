// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/arynyklas/soundpost/internal/adapters/queryinput/corpus"
	q "github.com/arynyklas/soundpost/internal/conformance/query"
)

// runNormalize executes the content-locked input-normalization corpus against
// the real queryinput translators and prints a JSON report. It exits zero only
// when every row's expected records / error reason / report counts match, and
// fails closed on a missing --require-locked or any lock violation.
func runNormalize(args []string) error {
	f := flag.NewFlagSet("normalize", flag.ContinueOnError)
	lockPath := f.String("lock", "conformance/query/source-lock.json", "source lock")
	casesPath := f.String("cases", "conformance/query/cases/input-normalization.json", "input-normalization corpus")
	locked := f.Bool("require-locked", false, "assert the corpus digest lock; normalize refuses to run without it")
	if err := f.Parse(args); err != nil {
		return err
	}
	if !*locked {
		return fmt.Errorf("normalize requires --require-locked")
	}
	var lock q.SourceLock
	if err := q.ReadJSON(*lockPath, &lock); err != nil {
		return err
	}
	if err := q.ValidateSourceLock(lock); err != nil {
		return err
	}
	var corpusBytes json.RawMessage
	if err := q.ReadLockedJSON(lock, "cases/input-normalization.json", *casesPath, &corpusBytes); err != nil {
		return err
	}
	// Fixture references resolve beside the corpus: <query>/cases/<corpus> -> <query>/fixtures.
	queryDir := filepath.Dir(filepath.Dir(*casesPath))
	if _, err := os.Stat(filepath.Join(queryDir, "fixtures")); err != nil {
		return fmt.Errorf("corpus fixtures directory: %w", err)
	}
	report, runErr := corpus.RunCorpus(context.Background(), queryDir, corpusBytes)
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if _, err = os.Stdout.Write(append(raw, '\n')); err != nil {
		return err
	}
	return runErr
}
