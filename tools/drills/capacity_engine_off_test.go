//go:build !soundpost_faults

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"strings"
	"testing"
)

// Without the soundpost_faults tag the engine part of capacity-faults cannot run, and the scenario must
// fail with that reason instead of passing on its other parts.
func TestCapacityEngineFaultsNeedTheFaultsTag(t *testing.T) {
	got, err := capEngineFaults(nil, nil)
	if err == nil || got != nil || !strings.Contains(err.Error(), "-tags soundpost_faults") {
		t.Fatalf("capEngineFaults without the tag = %v, %v; want a refusal naming the tag", got, err)
	}
}
