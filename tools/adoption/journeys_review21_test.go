// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import "testing"

// JR-01 (08.03 review): a capability row that names a profile must be decided from
// a record the profile actually holds. An absent record proves nothing about the
// runtime, so it must not satisfy an expectation of "unavailable".
func TestJourneyAbsentCapabilityRecordIsNotObservationReview21(t *testing.T) {
	w := newJTWorld(t)
	w.links.Capabilities.Rows[2] = JourneyCapabilityExpectation{
		Name: "never-reported", Profile: w.profile.String(),
		Window: w.links.Capabilities.Rows[0].Window, Runtime: jtRuntime, Method: "never-reported-method",
		Expect: "unavailable",
	}
	rep := jtVerify(t, w)
	jtWantFail(t, rep, JourneyRuntimeCapability, JourneyCodeCapabilityMismatch)
	rows := jtSection(rep, JourneyRuntimeCapability).Rows
	if len(rows) != 3 || rows[2].Status != JourneyRowUnavailable || rows[2].Reason != "no_capability_record" {
		t.Fatalf("the absent record must be reported as unobserved: %+v", rows)
	}
	if rep.Passed {
		t.Fatal("a required section passed on the absence of evidence")
	}
}
