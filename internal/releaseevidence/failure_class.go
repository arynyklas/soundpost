// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package releaseevidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// FailureClass says why a row did not pass. The exporter sets it from the structure of the producer's own result
// (never from the row's detail text) and the gate decides on it: the claim withdrawal (D65) takes a row only when it is
// FailureBudgetMiss, so a row that failed for any other reason can not be mistaken for a measured budget miss by what
// its detail says.
type FailureClass string

const (
	// FailureBudgetMiss: the row was measured and exceeded a budget, and nothing else went wrong with it.
	FailureBudgetMiss FailureClass = "budget_miss"
	// FailureHarness: the harness did not produce a usable measurement (it died, a series is missing, the
	// measurement protocol was not followed), or the row failed together with a failure that is not a budget.
	FailureHarness FailureClass = "harness"
	// FailureDroppedRecords: the capture under test dropped records, so its cost is not the claim.
	FailureDroppedRecords FailureClass = "dropped_records"
	// FailureAssertion: a check of behaviour failed (a drill check, a browser test, a campaign comparison, a canary).
	FailureAssertion FailureClass = "assertion"
	// FailureNotRun: the row was not run, not exercised or skipped.
	FailureNotRun FailureClass = "not_run"
	// FailureUnsupported: the subject does not support the capability.
	FailureUnsupported FailureClass = "unsupported"
	// FailureDenied: the subject denied the capability.
	FailureDenied FailureClass = "denied"
	// FailureOutOfScope: the row's platform is not part of the release (decision D10).
	FailureOutOfScope FailureClass = "out_of_scope"
)

// FailureClasses is the closed list, in documentation order.
var FailureClasses = []FailureClass{FailureBudgetMiss, FailureHarness, FailureDroppedRecords, FailureAssertion, FailureNotRun, FailureUnsupported, FailureDenied, FailureOutOfScope}

// Valid reports whether c is one of the closed list.
func (c FailureClass) Valid() bool {
	for _, k := range FailureClasses {
		if k == c {
			return true
		}
	}
	return false
}

// UnmarshalJSON decodes strictly: the value must be a JSON string naming a class of the closed list. A number, null,
// an empty string or an unknown name is refused, so a report cannot invent a class.
func (c *FailureClass) UnmarshalJSON(b []byte) error {
	var s string
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&s); err != nil || bytes.TrimSpace(b)[0] != '"' {
		return fmt.Errorf("failure_class must be a JSON string")
	}
	if !FailureClass(s).Valid() {
		return fmt.Errorf("failure_class %q is not one of %s", s, joinClasses())
	}
	*c = FailureClass(s)
	return nil
}

func joinClasses() string {
	names := make([]string, len(FailureClasses))
	for i, k := range FailureClasses {
		names[i] = string(k)
	}
	return strings.Join(names, ", ")
}

// classesOf lists the classes a row of the status may carry. A passed row carries none.
func classesOf(status string) []FailureClass {
	switch status {
	case StatusFailed:
		return []FailureClass{FailureBudgetMiss, FailureHarness, FailureDroppedRecords, FailureAssertion}
	case StatusNotRun, "not_exercised", "skipped":
		return []FailureClass{FailureNotRun}
	case "unsupported":
		return []FailureClass{FailureUnsupported}
	case "denied":
		return []FailureClass{FailureDenied}
	case StatusOutOfReleaseScope:
		return []FailureClass{FailureOutOfScope}
	}
	// flaky, expected_failure and any other producer status: a check of behaviour or the harness.
	return []FailureClass{FailureHarness, FailureAssertion}
}

// Validate checks the row's shape: a passed row carries no failure class, every other row carries exactly one that
// fits its status. It never inspects a verdict.
func (row Row) Validate() error {
	if row.ID == "" || row.Status == "" {
		return fmt.Errorf("row %q has an empty id or status", row.ID)
	}
	if row.Status == StatusPassed {
		if row.FailureClass != "" {
			return fmt.Errorf("row %s passed but carries failure_class %q", row.ID, row.FailureClass)
		}
		return nil
	}
	if row.FailureClass == "" {
		return fmt.Errorf("row %s is %s without a failure_class", row.ID, row.Status)
	}
	for _, k := range classesOf(row.Status) {
		if k == row.FailureClass {
			return nil
		}
	}
	return fmt.Errorf("row %s is %s, which can not carry failure_class %q", row.ID, row.Status, row.FailureClass)
}
