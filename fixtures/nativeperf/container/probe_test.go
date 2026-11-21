//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"syscall"
	"testing"
)

func TestLevel3VerdictIsTriState(t *testing.T) {
	cases := []struct {
		name         string
		controlKnown bool
		control, at3 error
		want         level3Outcome
	}{
		{"Debian: refused at 3, allowed at 2", true, nil, syscall.EACCES, level3Enforced},
		{"refused with EPERM", true, nil, syscall.EPERM, level3Enforced},
		{"vanilla: allowed at 2 and at 3", true, nil, nil, level3NotEnforced},
		{"the control failed too: nothing proven", true, syscall.EACCES, syscall.EACCES, level3Unknown},
		{"the control failed, level 3 allowed", true, syscall.ENOSYS, nil, level3Unknown},
		{"unrelated error at 3", true, nil, syscall.ENOSYS, level3Unknown},
		{"kept host level 3 and refused", false, nil, syscall.EACCES, level3Enforced},
		{"kept host level 3 and allowed, no control", false, nil, nil, level3Unknown},
	}
	for _, c := range cases {
		got, why := level3Verdict(c.controlKnown, c.control, c.at3)
		if got != c.want || (got != level3Enforced && why == "") {
			t.Errorf("%s: outcome %v (%q), want %v", c.name, got, why, c.want)
		}
	}
}

func TestAScenarioTheKernelCannotHoldNeverPassesButDoesNotSpoilTheRun(t *testing.T) {
	pass := scenarioResult{Name: "a", Status: statusPass}
	na := scenarioResult{Name: "denied_perf_event_paranoid_3_with_perfmon", Status: statusNotExercised, Why: reasonNoParanoidLevel3}
	other := scenarioResult{Name: "b", Status: statusNotExercised, Why: "--keep-paranoid"}
	unknown := scenarioResult{Name: "c", Status: statusNotExercised, Why: reasonLevel3Unknown + ": control failed"}
	prefixOnly := scenarioResult{Name: "d", Status: statusNotExercised, Why: reasonNoParanoidLevel3 + ": allowed"}
	if got := reportStatus([]scenarioResult{pass, na}); got != statusPass {
		t.Errorf("inapplicable level-3 scenario: status %s", got)
	}
	if got := reportStatus([]scenarioResult{pass, na, other}); got != statusNotExercised {
		t.Errorf("another not_exercised scenario must still make the run not_exercised: %s", got)
	}
	if got := reportStatus([]scenarioResult{pass, unknown}); got != statusNotExercised {
		t.Errorf("an inconclusive probe must not exempt: %s", got)
	}
	if got := reportStatus([]scenarioResult{pass, prefixOnly}); got != statusNotExercised {
		t.Errorf("a prefix-only reason must not exempt: %s", got)
	}
	na.Status = statusFail
	if got := reportStatus([]scenarioResult{pass, na}); got != statusFail {
		t.Errorf("a failure stays a failure: %s", got)
	}
}
