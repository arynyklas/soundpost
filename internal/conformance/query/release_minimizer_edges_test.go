// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A runner that observed some of the rows and failed on another still answers for the rows it
// observed: the minimizer keeps shrinking on what was seen, as the mismatch is seen there.
func TestAMinimizerRunThatObservedSomeRowsAndFailedStillCountsWhatItObserved(t *testing.T) {
	problems := []string{"value: reference 1, owned 2"}
	_, row, minimizer, _ := minimizerFixture(t, problems, false)
	inner := minimizer.RunRows
	minimizer.RunRows = func(ctx context.Context, rows []GeneratedRow) (PhaseResults, error) {
		res, err := inner(ctx, rows)
		if err != nil {
			t.Fatal(err)
		}
		return res, errors.New("one row of the batch failed to run")
	}
	reg, err := minimizer.Minimize(context.Background(), GeneratedMismatch{Seed: 20261110, Row: row, Problems: problems})
	if err != nil {
		t.Fatalf("the observed rows were discarded with the runner's error: %v", err)
	}
	if len(reg.Case.Input) != 1 || len(reg.Case.Expression) >= len(row.Source.Expression) || !strings.Contains(reg.Case.Expression, "label_replace") {
		t.Fatalf("not minimized on the rows that were observed: %+v", reg)
	}
}

// A case that cannot be turned into rows (here: it names a feature set no profile registers) is not
// the mismatch: it is refused before anything runs, never shrunk as if it still failed.
func TestAMinimizerRefusesACaseItCannotBuildRowsFor(t *testing.T) {
	problems := []string{"value: reference 1, owned 2"}
	_, row, minimizer, runs := minimizerFixture(t, problems, false)
	row.Source.FeatureSet = "promql-prometheus-3.13.5/no-such-feature-set"
	_, err := minimizer.Minimize(context.Background(), GeneratedMismatch{Seed: 20261110, Row: row, Problems: problems})
	if err == nil || !strings.Contains(err.Error(), "does not reproduce") {
		t.Fatalf("a case without rows was minimized: %v", err)
	}
	if runs() != 0 {
		t.Fatalf("the runner was started %d times for a case that has no rows", runs())
	}
}
