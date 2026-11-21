//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"os"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// 04.04-C11: Probe reports system-wide scheduler read exactly where the scheduler events opened (root on a real kernel)
// and target-only everywhere else.
func TestProbeReportsTheAcquisitionScopeOfThePathItOpened(t *testing.T) {
	target, e := ResolveLocalTarget(os.Getpid())
	if e != nil {
		t.Skip("local target unresolved")
	}
	caps, _ := Probe(context.Background(), []Target{target})
	want := model.AcquisitionScopeTargetOnly
	if caps.OffCPU == Supported {
		want = model.AcquisitionScopeSystemWideScheduler
	}
	if caps.AcquisitionScope != want {
		t.Fatalf("scope %q with off_cpu %s, want %q", caps.AcquisitionScope, caps.OffCPU, want)
	}
	if e := caps.Validate(); e != nil {
		t.Fatalf("probe evidence invalid: %v", e)
	}
	t.Logf("off_cpu %s scope %s", caps.OffCPU, caps.AcquisitionScope)
}
