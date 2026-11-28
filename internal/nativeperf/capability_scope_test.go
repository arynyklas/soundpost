// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func scopeCaps() Capabilities {
	return Capabilities{CPU: Supported, OffCPU: Supported, RunqueueSplit: Supported, Permissions: Permissions{CPUEventOpen: Supported, SchedulerEventOpen: Supported}, FrameCoverage: Coverage{Reasons: []Reason{ReasonUnmeasured}}, ThreadCoverage: Coverage{Reasons: []Reason{ReasonUnmeasured}}}
}

// 04.04-C11: the capability evidence says whether acquisition reaches only the authorized target's threads or reads the
// system-wide scheduler tracepoints (filtered to authorized tasks before export, operator authorized). The vocabulary
// is the model's, and the system-wide claim needs a supported scheduler path.
func TestCapabilitiesCarryAClosedAcquisitionScope(t *testing.T) {
	for _, scope := range model.AcquisitionScopes {
		c := scopeCaps()
		c.AcquisitionScope = scope
		if e := c.Validate(); e != nil {
			t.Errorf("scope %q rejected: %v", scope, e)
		}
		raw, _ := json.Marshal(c)
		if !strings.Contains(string(raw), `"acquisition_scope":"`+scope+`"`) {
			t.Errorf("scope %q is not in the capability JSON: %s", scope, raw)
		}
	}
	c := scopeCaps()
	c.AcquisitionScope = "host_wide"
	if c.Validate() == nil {
		t.Error("a scope outside the closed vocabulary was accepted")
	}
	c = scopeCaps()
	c.OffCPU, c.RunqueueSplit, c.Permissions.SchedulerEventOpen = Denied, Denied, Denied
	c.AcquisitionScope = model.AcquisitionScopeSystemWideScheduler
	if c.Validate() == nil {
		t.Error("a system-wide scheduler scope was claimed without a supported scheduler path")
	}
	c.AcquisitionScope = model.AcquisitionScopeTargetOnly
	if e := c.Validate(); e != nil {
		t.Errorf("target-only scope with a denied scheduler path rejected: %v", e)
	}
}
