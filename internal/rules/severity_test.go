// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"errors"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

func TestAlertSeverityIsTheClosedConditionSet(t *testing.T) {
	for _, s := range []string{"info", "warning", "error", "critical"} {
		r := alertRule(time.Minute, time.Minute)
		r.Severity = s
		if err := r.Validate(); err != nil {
			t.Fatalf("%q refused: %v", s, err)
		}
	}
	for _, s := range []string{"major", "minor", "page", "Critical", "CRITICAL", " critical", "critical\n", "warn", ""} {
		r := alertRule(time.Minute, time.Minute)
		r.Severity = s
		err := r.Validate()
		var f *model.Fault
		if !errors.As(err, &f) || f.Code != model.Invalid || f.SafeDetail != ReasonUnknownSeverity {
			t.Fatalf("severity %q: err = %v, want invalid/%s", s, err, ReasonUnknownSeverity)
		}
	}
}
