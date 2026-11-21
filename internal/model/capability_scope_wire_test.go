// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// The acquisition scope is a wire vocabulary: the strings are stored in records and read by other programs, so they
// are pinned literally, and the closed list is exactly these two names (l4w33 mutation battery C).
func TestAcquisitionScopeVocabularyIsTheExactWireSet(t *testing.T) {
	if AcquisitionScopeTargetOnly != "target_only" || AcquisitionScopeSystemWideScheduler != "system_wide_scheduler_read_operator_authorized" {
		t.Fatalf("%q %q", AcquisitionScopeTargetOnly, AcquisitionScopeSystemWideScheduler)
	}
	if len(AcquisitionScopes) != 2 || AcquisitionScopes[0] != "target_only" || AcquisitionScopes[1] != "system_wide_scheduler_read_operator_authorized" {
		t.Fatalf("%v", AcquisitionScopes)
	}
	raw, err := json.Marshal(Capability{Clock: ClockDomain{Host: NewID(), Boot: NewID(), Runtime: NewID()}, AcquisitionScope: AcquisitionScopeSystemWideScheduler})
	if err != nil || !strings.Contains(string(raw), `"acquisition_scope":"system_wide_scheduler_read_operator_authorized"`) {
		t.Fatalf("%s %v", raw, err)
	}
}
