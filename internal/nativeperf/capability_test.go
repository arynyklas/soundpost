// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"soundpost/internal/model"
	"testing"
)

func TestProbeRejectsInvalidTargets(t *testing.T) {
	if _, err := Probe(context.Background(), []Target{{TGID: 1}}); err == nil {
		t.Fatal("incomplete target accepted")
	}
}
func TestTargetIdentityValidation(t *testing.T) {
	good := Target{PIDNamespace: 1, TGID: 1, ProcessStart: 1}
	if good.Validate() != nil {
		t.Fatal("valid process target")
	}
	good.AllowedBuildIDs = []string{"../../secret"}
	if good.Validate() == nil {
		t.Fatal("unsafe build identity")
	}
}
func TestMeasureOverflow(t *testing.T) {
	if _, err := (Measure{Unit: UnitNanoseconds, Value: model.Uint64(^uint64(0))}).Add(Measure{Unit: UnitNanoseconds, Value: 1}); err == nil {
		t.Fatal("overflow accepted")
	}
}
