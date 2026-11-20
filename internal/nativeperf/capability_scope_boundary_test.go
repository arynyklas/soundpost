// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// Pins for the acquisition scope of the capability evidence (l4w33 mutation battery C).

// A producer that did not declare a scope sends no scope at all; the wire name is the model's.
func TestCapabilitiesScopeIsAbsentFromTheWireWhenUndeclared(t *testing.T) {
	raw, err := json.Marshal(scopeCaps())
	if err != nil || strings.Contains(string(raw), "acquisition_scope") {
		t.Fatalf("%s %v", raw, err)
	}
	c := scopeCaps()
	c.AcquisitionScope = model.AcquisitionScopeTargetOnly
	if raw, _ = json.Marshal(c); !strings.Contains(string(raw), `"acquisition_scope":"target_only"`) {
		t.Fatalf("%s", raw)
	}
	var back Capabilities
	if err = json.Unmarshal(raw, &back); err != nil || back.AcquisitionScope != model.AcquisitionScopeTargetOnly {
		t.Fatalf("%+v %v", back, err)
	}
}

// The system-wide claim needs a supported scheduler read and nothing else of the scheduler path; the empty scope and
// target-only are valid on any path; anything else is not.
func TestCapabilitiesSystemWideScopeNeedsOnlyASupportedSchedulerRead(t *testing.T) {
	c := scopeCaps()
	c.AcquisitionScope = model.AcquisitionScopeSystemWideScheduler
	c.RunqueueSplit = Unsupported
	if err := c.Validate(); err != nil {
		t.Fatalf("a supported scheduler read without the runnable split: %v", err)
	}
	for _, scope := range []string{"", model.AcquisitionScopeTargetOnly} {
		d := scopeCaps()
		d.OffCPU, d.RunqueueSplit, d.Permissions.SchedulerEventOpen = Unsupported, Unsupported, Unsupported
		d.AcquisitionScope = scope
		if err := d.Validate(); err != nil {
			t.Fatalf("scope %q without a scheduler path: %v", scope, err)
		}
	}
	for _, scope := range []string{"system_wide", "TARGET_ONLY", " target_only", "x"} {
		d := scopeCaps()
		d.AcquisitionScope = scope
		if err := d.Validate(); err == nil {
			t.Fatalf("scope %q accepted", scope)
		}
	}
}
