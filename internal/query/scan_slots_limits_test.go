// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import "testing"

// D105: the storage scan slots (2048) are sized for every admitted query to hold one iterator per
// selected project, so limits that admit more concurrent queries than the pool can serve are refused at
// construction instead of surfacing as a wait or a refusal under load.
func TestLimitsAdmitNoMoreQueriesThanTheScanSlotsServe(t *testing.T) {
	l := DefaultLimits()
	if l.MaxConcurrent*l.MaxProjects > 2048 {
		t.Fatalf("defaults admit %d x %d iterators, the pool holds 2048", l.MaxConcurrent, l.MaxProjects)
	}
	if err := l.validate(); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	l.MaxConcurrent, l.MaxPerOrg, l.MaxPerPrincipal = 17, 17, 2
	if err := l.validate(); err == nil {
		t.Fatal("17 concurrent queries x 128 projects exceed the 2048 scan slots and must be refused")
	}
	l.MaxProjects = 100
	if err := l.validate(); err != nil {
		t.Fatalf("17 x 100 fits the pool: %v", err)
	}
}
