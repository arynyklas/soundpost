// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import "testing"

func TestAcceptanceCannotSucceedWithoutObservedCases(t *testing.T) {
	report := AcceptanceReport{}
	if e := ValidateAcceptance(report); e == nil {
		t.Fatal("missing inventory/bindings/oracles reported release acceptance")
	}
}
